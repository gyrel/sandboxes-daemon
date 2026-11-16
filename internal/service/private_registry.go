package service

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"sort"
	"strings"
	"sync/atomic"
	"time"

	core "github.com/rheic/sandboxes-core"
	"github.com/rheic/sandboxes-core/sandbox"
	"github.com/rheic/sandboxes-gateway/registryauth"

	"github.com/rheic/sandboxes-daemon/internal/registrycredentials"
	"github.com/rheic/sandboxes-daemon/internal/secretproxy"
)

const (
	privateRegistryProxyService = "registry-private"
	privateRegistryGuestPort    = uint16(43135)
)

// SetRegistryRepositoryGrants configures exact host-authorized OCI scopes.
// An empty list disables repository access for that registry.
func (s *Service) SetRegistryRepositoryGrants(docker, private []string) error {
	dockerGrants, err := registrycredentials.ParseSandboxRepositoryGrants(docker)
	if err != nil {
		return fmt.Errorf("docker hub repository grants: %w", err)
	}
	privateGrants, err := registrycredentials.ParseSandboxRepositoryGrants(private)
	if err != nil {
		return fmt.Errorf("private registry repository grants: %w", err)
	}
	s.registryDockerGrants = dockerGrants
	s.registryPrivateGrants = privateGrants
	return nil
}

func privateRegistrySettingKey(id string) string { return "sandbox.registry-private." + id }

// SetPrivateRegistry configures the single allowlisted private registry that
// the guest registry proxy may reach. Empty host disables the feature.
func (s *Service) SetPrivateRegistry(host, service string, realms, redirects []string, caPEM []byte) error {
	host = strings.TrimSuffix(strings.TrimSpace(host), ".")
	if host == "" {
		if service != "" || len(realms) != 0 || len(redirects) != 0 {
			return errors.New("private registry host is required")
		}
		return nil
	}
	normalizedHost, err := registrycredentials.NormalizeRegistryEndpoint(host)
	if err != nil {
		return fmt.Errorf("%w: private registry host is invalid", core.ErrConflict)
	}
	host = normalizedHost
	if service == "" || strings.ContainsAny(service, " \t\r\n") {
		return fmt.Errorf("%w: private registry service is required", core.ErrConflict)
	}
	parsed, err := parsePrivateRealms(realms)
	if err != nil {
		return err
	}
	cleanRedirects, err := parsePrivateRedirects(redirects)
	if err != nil {
		return err
	}
	var roots *x509.CertPool
	if len(caPEM) != 0 {
		roots = x509.NewCertPool()
		if !roots.AppendCertsFromPEM(caPEM) {
			return fmt.Errorf("%w: private registry CA bundle is invalid", core.ErrConflict)
		}
	}
	s.privateRegistryHost = host
	s.privateRegistrySvc = service
	s.privateRegistryRealms = parsed
	s.privateRegistryRedirects = cleanRedirects
	s.privateRegistryRoots = roots
	return nil
}

func parsePrivateRealms(realms []string) ([]registryauth.Realm, error) {
	parsed := make([]registryauth.Realm, 0, len(realms))
	for _, raw := range realms {
		realmHost, path, found := strings.Cut(raw, "/")
		realmHost = strings.TrimSuffix(strings.TrimSpace(realmHost), ".")
		normalizedHost, err := registrycredentials.NormalizeRegistryEndpoint(realmHost)
		if !found || err != nil || path == "" || strings.ContainsAny(path, "?#\\") || strings.Contains(path, "..") {
			return nil, fmt.Errorf("%w: private registry realm is invalid", core.ErrConflict)
		}
		parsed = append(parsed, registryauth.Realm{Host: normalizedHost, Path: "/" + strings.TrimPrefix(path, "/")})
	}
	if len(parsed) == 0 {
		return nil, fmt.Errorf("%w: private registry realm is required", core.ErrConflict)
	}
	return parsed, nil
}

func parsePrivateRedirects(redirects []string) ([]string, error) {
	clean := make([]string, 0, len(redirects))
	for _, redirect := range redirects {
		redirect = strings.TrimSuffix(strings.TrimSpace(redirect), ".")
		normalized, err := registrycredentials.NormalizeRegistryEndpoint(redirect)
		if err != nil {
			return nil, fmt.Errorf("%w: private registry redirect host is invalid", core.ErrConflict)
		}
		clean = append(clean, normalized)
	}
	return clean, nil
}

//nolint:unused // retained for package-level validation callers and tests.
func validRegistryHost(host string) bool {
	_, err := registrycredentials.NormalizeRegistryEndpoint(strings.TrimSuffix(strings.TrimSpace(host), "."))
	return err == nil
}

func (s *Service) privateRegistryScopeFor(ctx context.Context, id string) (registrycredentials.Scope, error) {
	value, err := s.store.GetSetting(ctx, privateRegistrySettingKey(id))
	if errors.Is(err, core.ErrNotFound) {
		return "", nil
	}
	if err != nil {
		return "", fmt.Errorf("load sandbox private registry scope: %w", err)
	}
	scope := registrycredentials.Scope(value)
	if scope != registrycredentials.ScopeSandbox && scope != registrycredentials.ScopeAllSandboxes {
		return "", errors.New("sandbox private registry scope is invalid")
	}
	return scope, nil
}

func (s *Service) privateRegistryConfigured() bool {
	return s.privateRegistryHost != "" && s.registryCredentials != nil
}

func (s *Service) availablePrivateRegistryScope(ctx context.Context, sandboxName string, allowAll bool) (registrycredentials.Scope, error) {
	if !s.privateRegistryConfigured() {
		return "", nil
	}
	if credential, err := s.registryCredentials.Load(ctx, s.privateRegistryHost, registrycredentials.ScopeSandbox, sandboxName); err == nil {
		clear(credential.Password)
		return registrycredentials.ScopeSandbox, nil
	} else if !errors.Is(err, registrycredentials.ErrNotFound) {
		return "", err
	}
	if !allowAll {
		return "", nil
	}
	if credential, err := s.registryCredentials.Load(ctx, s.privateRegistryHost, registrycredentials.ScopeAllSandboxes, ""); err == nil {
		clear(credential.Password)
		return registrycredentials.ScopeAllSandboxes, nil
	} else if !errors.Is(err, registrycredentials.ErrNotFound) {
		return "", err
	}
	return "", nil
}

type privateRegistryTransportFactory struct {
	service   *Service
	sandboxID string
	host      string
	realms    []registryauth.Realm
	redirects []string
	roots     *x509.CertPool
}

func (f privateRegistryTransportFactory) Registry(ctx context.Context, authority string) (http.RoundTripper, error) {
	if !registrycredentials.SameRegistryEndpoint(authority, f.host) {
		return nil, errors.New("untrusted private registry authority")
	}
	prefixes, err := f.prefixes(ctx, authority)
	if err != nil {
		return nil, err
	}
	return registrycredentials.NewForwardRegistryTransport(authority, prefixes, f.roots)
}

func (f privateRegistryTransportFactory) Token(ctx context.Context, realm registryauth.Realm) (http.RoundTripper, error) {
	trusted := false
	for _, candidate := range f.realms {
		if registrycredentials.SameRegistryEndpoint(candidate.Host, realm.Host) && candidate.Path == realm.Path {
			trusted = true
		}
	}
	if !trusted {
		return nil, errors.New("untrusted private registry token realm")
	}
	prefixes, err := f.prefixes(ctx, realm.Host)
	if err != nil {
		return nil, err
	}
	return registryauth.NewTokenTransport(realm, prefixes, f.roots)
}

func (f privateRegistryTransportFactory) Redirect(ctx context.Context, authority string) (http.RoundTripper, error) {
	trusted := false
	for _, candidate := range f.redirects {
		if registrycredentials.SameRegistryEndpoint(candidate, authority) {
			trusted = true
		}
	}
	if !trusted {
		return nil, errors.New("untrusted private registry redirect authority")
	}
	endpoint, err := registrycredentials.ParseRegistryEndpoint(authority)
	if err != nil {
		return nil, errors.New("untrusted private registry redirect authority")
	}
	prefixes, err := f.prefixes(ctx, authority)
	if err != nil {
		return nil, err
	}
	addresses := make([]string, 0, len(prefixes))
	for _, prefix := range prefixes {
		addresses = append(addresses, prefix.Addr().String())
	}
	var next atomic.Uint64
	return &http.Transport{
		Proxy: nil, DisableKeepAlives: true,
		// For IP-literal redirects ServerName is the IP itself: Go then checks
		// the certificate IP SAN and omits SNI instead of inventing a name.
		TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: f.roots, ServerName: endpoint.Hostname},
		DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
			if network != "tcp" || address != net.JoinHostPort(endpoint.Hostname, endpoint.PortString()) {
				return nil, errors.New("redirect transport rejected unexpected destination")
			}
			start := int(next.Add(1) % uint64(len(addresses))) //nolint:gosec // bounded by len(addresses).
			var failures []error
			for offset := range addresses {
				ip := addresses[(start+offset)%len(addresses)]
				conn, dialErr := (&net.Dialer{Timeout: 10 * time.Second}).DialContext(ctx, network, net.JoinHostPort(ip, endpoint.PortString()))
				if dialErr == nil {
					return conn, nil
				}
				failures = append(failures, dialErr)
			}
			return nil, errors.Join(failures...)
		},
	}, nil
}

func (f privateRegistryTransportFactory) prefixes(ctx context.Context, authority string) ([]netip.Prefix, error) {
	endpoint, err := registrycredentials.ParseRegistryEndpoint(authority)
	if err != nil {
		return nil, errors.New("private registry authority is invalid")
	}
	host := endpoint.Hostname
	var addresses []netip.Addr
	if address, parseErr := netip.ParseAddr(host); parseErr == nil {
		// An IP-literal registry has no DNS step and no second resolution that
		// could disagree with the address the broker dials.
		addresses = []netip.Addr{address}
	} else {
		addresses, err = net.DefaultResolver.LookupNetIP(ctx, "ip", host)
		if err != nil || len(addresses) == 0 {
			return nil, errors.New("private registry DNS lookup failed")
		}
	}
	prefixes := make([]netip.Prefix, 0, len(addresses))
	seen := make(map[netip.Addr]struct{}, len(addresses))
	for _, address := range addresses {
		address = address.Unmap()
		if !address.IsValid() || address.IsLoopback() || address.IsLinkLocalUnicast() || address.IsUnspecified() || address.IsMulticast() {
			// A hostname may resolve to loopback in addition to reachable
			// addresses; skip the unusable entry and keep the verified set.
			continue
		}
		// Policy is evaluated for the exact host and TCP port the broker will
		// dial, so a custom-port registry cannot borrow a rule for port 443.
		decision, err := f.service.checkResolvedEgress(ctx, f.sandboxID, host, address, endpoint.Port())
		if err != nil {
			return nil, err
		}
		if !decision.Allowed {
			continue
		}
		if _, exists := seen[address]; exists {
			continue
		}
		seen[address] = struct{}{}
		prefixes = append(prefixes, netip.PrefixFrom(address, address.BitLen()))
	}
	if len(prefixes) == 0 {
		return nil, errors.New("sandbox policy denied private registry")
	}
	sort.Slice(prefixes, func(i, j int) bool { return prefixes[i].Addr().Less(prefixes[j].Addr()) })
	return prefixes, nil
}

func (s *Service) buildPrivateRegistryProxy(ctx context.Context, sb sandbox.Sandbox, scope registrycredentials.Scope) (secretproxy.RouteConfig, string, error) {
	if !s.privateRegistryConfigured() {
		return secretproxy.RouteConfig{}, "", fmt.Errorf("%w: private registry is not configured (%q)", core.ErrConflict, s.privateRegistryHost)
	}
	if scope != registrycredentials.ScopeSandbox && scope != registrycredentials.ScopeAllSandboxes {
		return secretproxy.RouteConfig{}, "", fmt.Errorf("%w: private registry scope %q is invalid", core.ErrConflict, scope)
	}
	ca, err := s.registryCredentials.ProxyCA(ctx)
	if err != nil {
		return secretproxy.RouteConfig{}, "", fmt.Errorf("load private registry proxy CA: %w", err)
	}
	hosts := []string{s.privateRegistryHost}
	for _, realm := range s.privateRegistryRealms {
		hosts = append(hosts, realm.Host)
	}
	hosts = append(hosts, s.privateRegistryRedirects...)
	ca.AllowHosts(hosts...)
	proxy, err := registrycredentials.NewPullProxy(s.registryCredentials, registrycredentials.PullProxyConfig{
		RepositoryGrants: s.registryPrivateGrants[sb.Name],
		Registry:         s.privateRegistryHost, Authority: s.privateRegistryHost, SandboxName: sb.Name,
		CredentialScope: scope, Service: s.privateRegistrySvc,
		Realms: s.privateRegistryRealms, RedirectAuthorities: s.privateRegistryRedirects,
		TransportFactory: privateRegistryTransportFactory{
			service: s, sandboxID: sb.ID, host: s.privateRegistryHost,
			realms: s.privateRegistryRealms, redirects: s.privateRegistryRedirects, roots: s.privateRegistryRoots,
		},
		Limiter: s.registryPullLimiter, MaxBytes: 16 << 30, TLSAuthority: ca, PrivateRegistry: true,
	})
	if err != nil {
		return secretproxy.RouteConfig{}, "", fmt.Errorf("configure private registry broker: %w", err)
	}
	token, err := newProxyToken()
	if err != nil {
		return secretproxy.RouteConfig{}, "", err
	}
	return secretproxy.RouteConfig{
		Service: secretproxy.Service{Upstream: "https://" + s.privateRegistryHost, CredentialScope: string(scope)},
		Handler: proxy, Token: token, CACert: ca.Certificate(), MaxRequestBody: 16 << 30,
	}, fmt.Sprintf("%s=%s:%d", privateRegistryProxyService, s.privateRegistryHost, privateRegistryGuestPort), nil
}

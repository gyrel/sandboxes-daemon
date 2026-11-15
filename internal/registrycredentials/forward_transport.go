package registrycredentials

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"time"
)

// NewForwardRegistryTransport returns a host-only transport pinned to the
// supplied, policy-approved addresses. It permits only supported Docker
// Distribution pull and push operations at one HTTPS authority.
func NewForwardRegistryTransport(authority string, prefixes []netip.Prefix, roots *x509.CertPool) (http.RoundTripper, error) {
	endpoint, err := forwardRegistryEndpoint(authority)
	if err != nil {
		return nil, err
	}
	registry, err := ParseRegistryEndpoint(authority)
	if err != nil {
		return nil, err
	}
	allowed, err := exactRegistryPrefixes(prefixes)
	if err != nil {
		return nil, err
	}
	if roots != nil {
		roots = roots.Clone()
	}
	transport := &http.Transport{
		Proxy: nil, DisableKeepAlives: true,
		// ServerName is a DNS hostname for DNS registries and an IP literal for
		// IP registries. Go verifies an IP ServerName against the certificate
		// IP SAN and sends no SNI, so no hostname is invented for an IP endpoint.
		TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: roots, ServerName: registry.Hostname},
		DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
			return dialPinnedRegistryPort(ctx, network, address, registry.Hostname, registry.PortString(), allowed)
		},
	}
	return &forwardRegistryTransport{authority: endpoint.Host, transport: transport}, nil
}

func forwardRegistryEndpoint(authority string) (*url.URL, error) {
	endpoint, err := ParseRegistryEndpoint(authority)
	if err != nil {
		return nil, errors.New("invalid forward registry transport configuration")
	}
	return &url.URL{Scheme: registryHTTPScheme, Host: endpoint.Authority()}, nil
}

func exactRegistryPrefixes(prefixes []netip.Prefix) ([]netip.Prefix, error) {
	if len(prefixes) == 0 {
		return nil, errors.New("invalid forward registry transport configuration")
	}
	allowed := make([]netip.Prefix, len(prefixes))
	for i, prefix := range prefixes {
		if !prefix.IsValid() || prefix.Bits() != prefix.Addr().BitLen() {
			return nil, errors.New("invalid forward registry address prefix")
		}
		address := prefix.Addr().Unmap()
		allowed[i] = netip.PrefixFrom(address, address.BitLen())
	}
	return allowed, nil
}

type forwardRegistryTransport struct {
	authority string
	transport http.RoundTripper
}

func (t *forwardRegistryTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	if t == nil || t.transport == nil || request == nil || request.URL == nil || request.URL.Scheme != registryHTTPScheme ||
		!SameRegistryEndpoint(request.URL.Host, t.authority) || request.URL.User != nil || request.URL.Opaque != "" ||
		request.URL.Fragment != "" || request.URL.RawPath != "" || request.RequestURI != "" ||
		(request.Host != "" && !SameRegistryEndpoint(request.Host, t.authority)) {
		return nil, errors.New("forward registry request authority is invalid")
	}
	if _, err := parseRegistryOperation(request.Method, request.URL, t.authority); err != nil {
		return nil, errors.New("forward registry operation is unsupported")
	}
	return t.transport.RoundTrip(request) // #nosec G704 -- URL is fixed to one authority and DialContext pins the checked IP set.
}

// dialPinnedRegistry keeps the historical helper signature for package-level
// callers while accepting an authority with or without a custom port.
//
//nolint:unused // retained for callers that still pass an authority string.
func dialPinnedRegistry(ctx context.Context, network, address, authority string, prefixes []netip.Prefix) (net.Conn, error) {
	endpoint, err := ParseRegistryEndpoint(authority)
	if err != nil {
		return nil, errors.New("forward registry transport rejected an unexpected authority")
	}
	return dialPinnedRegistryPort(ctx, network, address, endpoint.Hostname, endpoint.PortString(), prefixes)
}

func dialPinnedRegistryPort(ctx context.Context, network, address, authority, port string, prefixes []netip.Prefix) (net.Conn, error) {
	host, dialPort, err := net.SplitHostPort(address)
	if err != nil || network != "tcp" || !strings.EqualFold(host, authority) || dialPort != port {
		return nil, errors.New("forward registry transport rejected an unexpected destination")
	}
	dialer := &net.Dialer{Timeout: 10 * time.Second}
	var failures []error
	for _, prefix := range prefixes {
		ip := prefix.Addr().Unmap()
		conn, dialErr := dialer.DialContext(ctx, network, net.JoinHostPort(ip.String(), dialPort))
		if dialErr == nil {
			return conn, nil
		}
		failures = append(failures, dialErr)
	}
	return nil, errors.Join(failures...)
}

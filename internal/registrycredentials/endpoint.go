package registrycredentials

import (
	"errors"
	"net"
	"net/netip"
	"strconv"
	"strings"
)

const registryDefaultPort = "443"

// RegistryEndpoint is a validated HTTPS registry authority. Hostname is a
// lower-case DNS name or an IP literal without brackets. Port is always the
// effective TCP port and defaults to 443.
//
// Accepted input grammar is deliberately small: HOST, HOST:PORT, IPv4,
// IPv4:PORT, [IPv6], or [IPv6]:PORT. A bare IPv6 literal is also accepted for
// compatibility with earlier credential entries. Schemes, userinfo, paths,
// queries, fragments, wildcards, zones, whitespace, and control characters are
// rejected. HOST:PORT is the canonical form for a non-default port and IPv6
// literals are always bracketed when an authority string is produced.
type RegistryEndpoint struct {
	Hostname string
	port     string
	portSet  bool
}

// ParseRegistryEndpoint validates and normalizes one registry authority.
func ParseRegistryEndpoint(value string) (RegistryEndpoint, error) {
	raw := strings.ToLower(strings.TrimSpace(value))
	if raw == "" {
		return RegistryEndpoint{}, errors.New("registry endpoint is empty")
	}
	if strings.ContainsAny(raw, "/@?#\\\x00\r\n \t") || strings.Contains(raw, "://") {
		return RegistryEndpoint{}, errors.New("registry endpoint must be a host with an optional port")
	}
	switch {
	case strings.HasPrefix(raw, "["):
		return parseBracketedRegistryEndpoint(raw)
	case strings.Count(raw, ":") == 0:
		hostname, err := normalizeRegistryHostname(raw)
		return RegistryEndpoint{Hostname: hostname}, err
	case strings.Count(raw, ":") == 1:
		return parseRegistryHostPort(raw)
	default:
		return parseBareIPv6RegistryEndpoint(raw)
	}
}

func parseBracketedRegistryEndpoint(raw string) (RegistryEndpoint, error) {
	closing := strings.Index(raw, "]")
	if closing < 0 {
		return RegistryEndpoint{}, errors.New("registry IPv6 literal is not bracketed")
	}
	address, err := netip.ParseAddr(raw[1:closing])
	if err != nil || !address.Is6() || address.Zone() != "" {
		return RegistryEndpoint{}, errors.New("registry IPv6 literal is invalid")
	}
	endpoint := RegistryEndpoint{Hostname: address.String()}
	rest := raw[closing+1:]
	switch {
	case rest == "":
		return endpoint, nil
	case strings.HasPrefix(rest, ":"):
		endpoint.port, endpoint.portSet = rest[1:], true
		return normalizeEndpointPort(endpoint)
	default:
		return RegistryEndpoint{}, errors.New("registry IPv6 literal has an invalid suffix")
	}
}

func parseRegistryHostPort(raw string) (RegistryEndpoint, error) {
	hostname, port, _ := strings.Cut(raw, ":")
	normalized, err := normalizeRegistryHostname(hostname)
	if err != nil {
		return RegistryEndpoint{}, err
	}
	return normalizeEndpointPort(RegistryEndpoint{Hostname: normalized, port: port, portSet: true})
}

func parseBareIPv6RegistryEndpoint(raw string) (RegistryEndpoint, error) {
	// Multiple colons without brackets are only valid as a bare IPv6 literal.
	// A trailing segment is not guessed to be a port because that would make
	// the accepted authority ambiguous.
	address, err := netip.ParseAddr(raw)
	if err != nil || !address.Is6() || address.Zone() != "" {
		return RegistryEndpoint{}, errors.New("registry IPv6 literal is invalid")
	}
	return RegistryEndpoint{Hostname: address.String()}, nil
}

func normalizeEndpointPort(endpoint RegistryEndpoint) (RegistryEndpoint, error) {
	port, err := normalizeRegistryPort(endpoint.port)
	if err != nil {
		return RegistryEndpoint{}, err
	}
	endpoint.port = port
	return endpoint, nil
}

func normalizeRegistryHostname(hostname string) (string, error) {
	hostname = strings.TrimSuffix(hostname, ".")
	if address, err := netip.ParseAddr(hostname); err == nil {
		if address.Zone() != "" {
			return "", errors.New("registry IP literal must not contain a zone")
		}
		return address.String(), nil
	}
	if !validRegistryHostname(hostname) {
		return "", errors.New("registry host name is invalid")
	}
	return hostname, nil
}

func normalizeRegistryPort(port string) (string, error) {
	if port == "" {
		return "", errors.New("registry port is invalid")
	}
	for i := range port {
		if port[i] < '0' || port[i] > '9' {
			return "", errors.New("registry port is invalid")
		}
	}
	number, err := strconv.ParseUint(port, 10, 16)
	if err != nil || number == 0 {
		return "", errors.New("registry port is invalid")
	}
	return strconv.FormatUint(number, 10), nil
}

// Port returns the effective TCP port, defaulting to 443.
func (e RegistryEndpoint) Port() uint16 {
	number, err := strconv.ParseUint(e.PortString(), 10, 16)
	if err != nil {
		return 443
	}
	return uint16(number)
}

// PortString returns the effective TCP port as a decimal string.
func (e RegistryEndpoint) PortString() string {
	if !e.portSet || e.port == "" {
		return registryDefaultPort
	}
	return e.port
}

func (e RegistryEndpoint) hostAuthority() string {
	if strings.Contains(e.Hostname, ":") {
		return "[" + e.Hostname + "]"
	}
	return e.Hostname
}

// Authority preserves whether the caller supplied an explicit port. That keeps
// existing credential keys and configuration values stable.
func (e RegistryEndpoint) Authority() string {
	if !e.portSet {
		return e.hostAuthority()
	}
	return net.JoinHostPort(e.Hostname, e.port)
}

// MatchAuthority normalizes the default port away so equivalent spellings
// compare identically without changing the dial target.
func (e RegistryEndpoint) MatchAuthority() string {
	if e.PortString() == registryDefaultPort {
		return e.hostAuthority()
	}
	return net.JoinHostPort(e.Hostname, e.port)
}

// NormalizeRegistryEndpoint validates one authority and returns its canonical
// spelling for configuration and credential storage.
func NormalizeRegistryEndpoint(value string) (string, error) {
	endpoint, err := ParseRegistryEndpoint(value)
	if err != nil {
		return "", err
	}
	return endpoint.Authority(), nil
}

// SameRegistryEndpoint reports whether two authorities name the same host and
// effective port, treating an omitted default port and :443 as equivalent.
func SameRegistryEndpoint(first, second string) bool {
	a, err := ParseRegistryEndpoint(first)
	if err != nil {
		return false
	}
	b, err := ParseRegistryEndpoint(second)
	if err != nil {
		return false
	}
	return strings.EqualFold(a.Hostname, b.Hostname) && a.PortString() == b.PortString()
}

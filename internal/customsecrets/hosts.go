// Package customsecrets models host-vault custom secrets: a sandbox-visible
// placeholder bound to one host-side value and a fixed set of destination
// host patterns. Values never enter SQLite, logs or responses; the record store
// keeps them in the host keychain only.
package customsecrets

import (
	"errors"
	"fmt"
	"net/netip"
	"strings"
)

// MaxHosts bounds the host patterns of one custom secret.
const MaxHosts = 16

const maxHostLength = 253

// ErrInvalidHost reports a host pattern outside the supported grammar. The
// message never echoes the input, which may be mistyped secret material.
var ErrInvalidHost = errors.New("invalid custom secret host pattern")

// NormalizeHost validates one host pattern and returns its canonical form.
// Accepted forms are exact DNS names, IP literals (IPv4 or unbracketed IPv6),
// "*.suffix" (exactly one label in place of "*") and "**.suffix" (one or more
// labels in place of "**"). Schemes, userinfo, ports, paths, queries and
// fragments are rejected, as are wildcards anywhere but as the full leading
// label, and wildcard suffixes shorter than two labels.
func NormalizeHost(raw string) (string, error) {
	if raw == "" || raw != strings.TrimSpace(raw) || len(raw) > maxHostLength {
		return "", ErrInvalidHost
	}
	host := strings.ToLower(raw)
	if strings.ContainsAny(host, "/\\?#@[]%\x00") || strings.Contains(host, "://") {
		return "", ErrInvalidHost
	}
	if strings.Contains(host, ":") {
		if addr, ok := parseIPLiteral(host); ok && addr.Is6() {
			return addr.String(), nil
		}
		return "", ErrInvalidHost
	}
	if addr, ok := parseIPLiteral(host); ok {
		return addr.String(), nil
	}
	return normalizeDNSPattern(host)
}

// parseIPLiteral parses an address without a zone. It reports false for DNS
// names and for zoned or otherwise unusable literals.
func parseIPLiteral(host string) (netip.Addr, bool) {
	addr, err := netip.ParseAddr(host)
	if err != nil || addr.Zone() != "" {
		return netip.Addr{}, false
	}
	return addr, true
}

func normalizeDNSPattern(host string) (string, error) {
	switch {
	case strings.HasPrefix(host, "**."):
		if !validWildcardSuffix(host[3:]) {
			return "", ErrInvalidHost
		}
	case strings.HasPrefix(host, "*."):
		if !validWildcardSuffix(host[2:]) {
			return "", ErrInvalidHost
		}
	default:
		if strings.Contains(host, "*") || !validDNSName(host, 1) {
			return "", ErrInvalidHost
		}
	}
	return host, nil
}

// validWildcardSuffix requires a DNS suffix of at least two labels. An IP
// literal is not a suffix: "*.192.0.2.10" would otherwise pass as DNS.
func validWildcardSuffix(suffix string) bool {
	if _, err := netip.ParseAddr(suffix); err == nil {
		return false
	}
	return validDNSName(suffix, 2)
}

// validDNSName accepts lowercase LDH labels of 1 to 63 bytes, at least
// minLabels labels, and a total length within maxHostLength.
func validDNSName(name string, minLabels int) bool {
	if name == "" || len(name) > maxHostLength {
		return false
	}
	labels := strings.Split(name, ".")
	if len(labels) < minLabels {
		return false
	}
	for _, label := range labels {
		if !validLabel(label) {
			return false
		}
	}
	return true
}

func validLabel(label string) bool {
	if label == "" || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
		return false
	}
	for i := 0; i < len(label); i++ {
		c := label[i]
		if !isLDHByte(c) {
			return false
		}
	}
	return true
}

func isLDHByte(c byte) bool {
	switch {
	case c >= 'a' && c <= 'z', c >= '0' && c <= '9', c == '-':
		return true
	}
	return false
}

// NormalizeHosts validates a host list, returns canonical patterns in request
// order and rejects duplicates after normalization.
func NormalizeHosts(raw []string) ([]string, error) {
	if len(raw) == 0 || len(raw) > MaxHosts {
		return nil, fmt.Errorf("%w: provide 1 to %d host patterns", ErrInvalidHost, MaxHosts)
	}
	seen := make(map[string]struct{}, len(raw))
	out := make([]string, 0, len(raw))
	for _, value := range raw {
		host, err := NormalizeHost(value)
		if err != nil {
			return nil, err
		}
		if _, dup := seen[host]; dup {
			return nil, fmt.Errorf("%w: duplicate host pattern", ErrInvalidHost)
		}
		seen[host] = struct{}{}
		out = append(out, host)
	}
	return out, nil
}

// MatchHost reports whether the canonical pattern covers host. host is the
// destination the proxy actually dials, so it is matched after lowercasing and
// trailing-dot removal. "*" matches exactly one non-empty label and "**" one or
// more labels; neither matches the bare suffix itself.
func MatchHost(pattern, host string) bool {
	host = strings.ToLower(strings.TrimSuffix(host, "."))
	if pattern == "" || host == "" {
		return false
	}
	if patternAddr, err := netip.ParseAddr(pattern); err == nil {
		hostAddr, err := netip.ParseAddr(host)
		return err == nil && hostAddr == patternAddr
	}
	switch {
	case strings.HasPrefix(pattern, "**."):
		return matchSuffix(pattern[3:], host, false)
	case strings.HasPrefix(pattern, "*."):
		return matchSuffix(pattern[2:], host, true)
	}
	return pattern == host
}

func matchSuffix(suffix, host string, single bool) bool {
	if !strings.HasSuffix(host, "."+suffix) {
		return false
	}
	prefix := host[:len(host)-len(suffix)-1]
	if prefix == "" {
		return false
	}
	labels := strings.Split(prefix, ".")
	if single && len(labels) != 1 {
		return false
	}
	for _, label := range labels {
		if label == "" {
			return false
		}
	}
	return true
}

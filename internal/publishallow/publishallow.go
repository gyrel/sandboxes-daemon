// Package publishallow parses and matches the operator allowlist that permits
// non-loopback host port publishes.
//
// The allowlist is deliberately strict: entries are CIDR prefixes with no host
// bits set, parsed by net/netip. Single-host /32 and /128 entries are accepted.
// An absent or invalid list grants nothing, so callers must treat a parse error
// as an empty list (fail closed).
package publishallow

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"strings"
)

// SettingKey is the canonical settings key.
const SettingKey = "network.publish.allowedCIDRs"

// Entry is one normalized allowlist prefix and the label that audits disclose.
type Entry struct {
	Prefix netip.Prefix
	Text   string
}

// Allowlist is an ordered, already-normalized set of entries.
type Allowlist []Entry

// ParseJSON parses the settings value. The value must be a JSON array of CIDR
// strings; an empty array is valid but grants nothing.
func ParseJSON(value string) (Allowlist, error) {
	value = strings.TrimSpace(value)
	if value == "" || value[0] != '[' {
		return nil, errors.New("network.publish.allowedCIDRs must be a JSON array of CIDR strings")
	}
	var entries []string
	if err := json.Unmarshal([]byte(value), &entries); err != nil {
		return nil, fmt.Errorf("network.publish.allowedCIDRs must be a JSON array of CIDR strings: %w", err)
	}
	return Parse(entries)
}

// Parse normalizes a list of CIDR strings. Host bits must already be clear.
func Parse(entries []string) (Allowlist, error) {
	out := make(Allowlist, 0, len(entries))
	seen := make(map[netip.Prefix]struct{}, len(entries))
	for _, raw := range entries {
		text := strings.TrimSpace(raw)
		if text == "" {
			return nil, errors.New("network.publish.allowedCIDRs contains an empty CIDR")
		}
		prefix, err := netip.ParsePrefix(text)
		if err != nil {
			return nil, fmt.Errorf("network.publish.allowedCIDRs entry %q is not a CIDR prefix", raw)
		}
		if prefix.Addr().Zone() != "" {
			return nil, fmt.Errorf("network.publish.allowedCIDRs entry %q must not carry an IPv6 zone", raw)
		}
		if prefix != prefix.Masked() {
			return nil, fmt.Errorf("network.publish.allowedCIDRs entry %q has host bits set", raw)
		}
		if _, exists := seen[prefix]; exists {
			return nil, fmt.Errorf("network.publish.allowedCIDRs contains duplicate entry %q", raw)
		}
		seen[prefix] = struct{}{}
		out = append(out, Entry{Prefix: prefix, Text: prefix.String()})
	}
	return out, nil
}

// Strings returns the canonical textual entries in order.
func (a Allowlist) Strings() []string {
	if len(a) == 0 {
		return nil
	}
	out := make([]string, 0, len(a))
	for _, entry := range a {
		out = append(out, entry.Text)
	}
	return out
}

// Match returns the first entry containing addr. Family mismatches never match.
func (a Allowlist) Match(addr netip.Addr) (Entry, bool) {
	for _, entry := range a {
		if entry.Prefix.Contains(addr) {
			return entry, true
		}
	}
	return Entry{}, false
}

// Compile converts raw configured entries into a usable allowlist. Any invalid
// entry discards the whole list so a partially valid configuration cannot
// grant more than the operator wrote.
func Compile(raw []string) Allowlist {
	if len(raw) == 0 {
		return nil
	}
	allow, err := Parse(raw)
	if err != nil {
		return nil
	}
	return allow
}

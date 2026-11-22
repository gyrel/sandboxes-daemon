// Package orgpolicy loads a locally stored, signed organization policy bundle
// and maps its network deny rules into the daemon's sandbox network rules.
//
// The store only persists bundles that the policy sync client verified with
// the pinned Ed25519 key. This package re-reads that stored artifact (it never
// contacts the control plane) and re-validates the canonical payload metadata,
// organization, revision, rule ordering and expiry before any rule is applied.
// A missing, expired, cross-organization or malformed deny rule fails closed.
//
// Only network deny rules are enforced in this slice. Organization allow rules
// are advisory and are ignored, as are filesystem, MCP and secret resources
// that the local gateway cannot enforce. Apply is the single pure evaluator
// that merges organization rules with local sandbox rules.
package orgpolicy

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/rheic/sandboxes-core/sandbox"

	"github.com/rheic/sandboxes-daemon/internal/controlplane"
	"github.com/rheic/sandboxes-daemon/internal/store"
)

var (
	// ErrNotConfigured reports enforcement being enabled without an organization.
	ErrNotConfigured = errors.New("organization policy enforcement requires org_policy.org")
	// ErrBundleMissing reports that no verified bundle is stored for the org.
	ErrBundleMissing = errors.New("organization policy bundle is not stored")
	// ErrBundleExpired reports a stored bundle whose expiry is not in the future.
	ErrBundleExpired = errors.New("organization policy bundle is expired")
	// ErrBundleOrgMismatch reports a stored payload for a different organization.
	ErrBundleOrgMismatch = errors.New("organization policy bundle belongs to another organization")
	// ErrBundleInvalid reports a stored payload that does not match its stored
	// metadata or violates the canonical policy constraints.
	ErrBundleInvalid = errors.New("organization policy bundle is invalid")
	// ErrMalformedDeny reports a network deny resource that cannot be mapped
	// without weakening the organization restriction.
	ErrMalformedDeny = errors.New("organization policy network deny rule is malformed")
	// ErrPolicyConflict reports an effective policy the gateway cannot enforce
	// without dropping an organization deny rule.
	ErrPolicyConflict = errors.New("organization policy deny conflicts with the effective sandbox policy")
)

const (
	networkResourcePrefix = "network:"
	tcpProtocol           = "tcp"
	udpProtocol           = "udp"
	allowAction           = "allow"
	denyAction            = "deny"
)

// Reader is the local persistence seam used to load a stored bundle.
type Reader interface {
	GetPolicyBundle(ctx context.Context, org string) (store.StoredPolicyBundle, bool, error)
}

// Snapshot is the enforceable part of one stored organization policy bundle.
type Snapshot struct {
	OrgID     string
	Revision  uint64
	ExpiresAt time.Time
	// Deny contains only network deny rules, expanded to both TCP and UDP.
	Deny []sandbox.NetworkRule
	// IgnoredRules counts allow, unsupported-resource and malformed allow rules
	// that this slice deliberately does not apply.
	IgnoredRules int
}

// Policy is one layer of network rules. Allow and Deny are independent sets:
// the gateway still applies deny precedence to a target that appears in both.
type Policy struct {
	Allow []sandbox.NetworkRule
	Deny  []sandbox.NetworkRule
}

// Apply returns the deterministic effective network policy for a sandbox.
// It is pure: it does not mutate either argument, read the store or contact the
// control plane.
//
// Organization deny rules are kept first in bundle order, so their signed rule
// IDs stay stable and they win over duplicate local denies. Local deny rules
// follow, and every local allow is preserved. Organization allow rules are
// advisory and are never copied into the result, so an organization bundle can
// only narrow access. Duplicate targets are removed by protocol, destination
// and port, keeping the first occurrence seen.
func Apply(local, organization Policy) (allow, deny []sandbox.NetworkRule) {
	allow = mergeRules(local.Allow)
	deny = mergeRules(organization.Deny, local.Deny)
	return allow, deny
}

// mergeRules concatenates rule groups in order and removes duplicate targets.
func mergeRules(groups ...[]sandbox.NetworkRule) []sandbox.NetworkRule {
	total := 0
	for _, group := range groups {
		total += len(group)
	}
	out := make([]sandbox.NetworkRule, 0, total)
	seen := make(map[string]struct{}, total)
	for _, group := range groups {
		for i := range group {
			rule := group[i]
			key := ruleKey(rule)
			if _, exists := seen[key]; exists {
				continue
			}
			seen[key] = struct{}{}
			out = append(out, rule)
		}
	}
	return out
}

// RuleView is one parsed network rule from a stored organization bundle.
// Enforceable reports whether this daemon knows how to enforce the rule when
// org_policy.enforce is on. It is not a statement about the current setting.
type RuleView struct {
	RuleID       string
	Action       string
	Source       string
	ResourceType string
	Protocol     string
	CIDR         string
	Domain       string
	Port         uint16
	Enforceable  bool
	// AdvisoryReason explains why the rule is advisory. It is empty for a rule
	// that this daemon can enforce.
	AdvisoryReason string
}

// View is the read-only, non-secret view of one stored organization policy
// bundle. It includes policy metadata and parsed network rules only. The
// stored signature, tokens and any other credentials are never included.
type View struct {
	OrgID         string
	SchemaVersion int
	Revision      uint64
	BundleID      string
	IssuedAt      time.Time
	ExpiresAt     time.Time
	LoadedAt      time.Time
	Rules         []RuleView
	IgnoredRules  int
}

// Load reads the locally stored bundle for org and maps its enforceable deny
// rules. It never fetches policy from the network.
func Load(ctx context.Context, reader Reader, org string, now time.Time) (Snapshot, error) {
	_, payload, err := loadValidated(ctx, reader, org, now)
	if err != nil {
		return Snapshot{}, err
	}
	deny, ignored, err := mapDenyRules(payload.Rules)
	if err != nil {
		return Snapshot{}, err
	}
	return Snapshot{
		OrgID:        org,
		Revision:     payload.Revision,
		ExpiresAt:    payload.ExpiresAt.UTC(),
		Deny:         deny,
		IgnoredRules: ignored,
	}, nil
}

// Inspect reads the locally stored bundle for org and returns a read-only view
// of its parsed network rules. Like Load it never fetches policy from the
// network and fails closed on missing, expired or malformed bundles. Inspect
// never mutates the store.
func Inspect(ctx context.Context, reader Reader, org string, now time.Time) (View, error) {
	bundle, payload, err := loadValidated(ctx, reader, org, now)
	if err != nil {
		return View{}, err
	}
	rules, ignored, err := mapRulesForView(payload.Rules)
	if err != nil {
		return View{}, err
	}
	return View{
		OrgID:         org,
		SchemaVersion: payload.SchemaVersion,
		Revision:      payload.Revision,
		BundleID:      bundleID(bundle.Payload),
		IssuedAt:      payload.IssuedAt.UTC(),
		ExpiresAt:     payload.ExpiresAt.UTC(),
		LoadedAt:      bundle.SyncedAt.UTC(),
		Rules:         rules,
		IgnoredRules:  ignored,
	}, nil
}

// loadValidated applies the same fail-closed checks to enforcement and
// visibility reads, so the two surfaces cannot disagree about a bundle.
func loadValidated(ctx context.Context, reader Reader, org string, now time.Time) (store.StoredPolicyBundle, controlplane.PolicyPayload, error) {
	if reader == nil {
		return store.StoredPolicyBundle{}, controlplane.PolicyPayload{}, ErrNotConfigured
	}
	if !controlplane.ValidOrgID(org) {
		return store.StoredPolicyBundle{}, controlplane.PolicyPayload{}, fmt.Errorf("%w: %q is not a valid organization ID", ErrNotConfigured, org)
	}
	bundle, found, err := reader.GetPolicyBundle(ctx, org)
	if err != nil {
		return store.StoredPolicyBundle{}, controlplane.PolicyPayload{}, fmt.Errorf("%w: %w", ErrBundleInvalid, err)
	}
	if !found {
		return store.StoredPolicyBundle{}, controlplane.PolicyPayload{}, ErrBundleMissing
	}
	payload, err := controlplane.DecodePolicyPayloadJSON(bundle.Payload)
	if err != nil {
		return store.StoredPolicyBundle{}, controlplane.PolicyPayload{}, fmt.Errorf("%w: %w", ErrBundleInvalid, err)
	}
	if payload.OrgID != org {
		return store.StoredPolicyBundle{}, controlplane.PolicyPayload{}, fmt.Errorf("%w: stored payload is for %q, enforcement is %q", ErrBundleOrgMismatch, payload.OrgID, org)
	}
	if payload.Revision != bundle.Revision {
		return store.StoredPolicyBundle{}, controlplane.PolicyPayload{}, fmt.Errorf("%w: payload revision %d does not match stored revision %d", ErrBundleInvalid, payload.Revision, bundle.Revision)
	}
	if !payload.IssuedAt.Equal(bundle.IssuedAt) || !payload.ExpiresAt.Equal(bundle.ExpiresAt) {
		return store.StoredPolicyBundle{}, controlplane.PolicyPayload{}, fmt.Errorf("%w: payload lifetime does not match stored metadata", ErrBundleInvalid)
	}
	if !payload.ExpiresAt.After(now) {
		return store.StoredPolicyBundle{}, controlplane.PolicyPayload{}, fmt.Errorf("%w: expiry %s is not in the future", ErrBundleExpired, payload.ExpiresAt.UTC().Format(time.RFC3339))
	}
	if err := controlplane.ValidatePolicyPayload(payload, org, now); err != nil {
		return store.StoredPolicyBundle{}, controlplane.PolicyPayload{}, fmt.Errorf("%w: %w", ErrBundleInvalid, err)
	}
	return bundle, payload, nil
}

func bundleID(payload []byte) string {
	sum := sha256.Sum256(payload)
	return "sha256:" + hex.EncodeToString(sum[:])
}

// mapDenyRules maps only enforceable network deny resources. Malformed network
// denies fail closed: silently dropping one would weaken the organization
// restriction the rule was meant to express. Malformed allow rules are ignored
// because this slice never grants access from organization rules.
func mapDenyRules(rules []controlplane.PolicyRule) ([]sandbox.NetworkRule, int, error) {
	deny := make([]sandbox.NetworkRule, 0, len(rules))
	seen := make(map[string]struct{}, len(rules))
	ignored := 0
	for _, rule := range rules {
		if rule.Action != denyAction {
			ignored++
			continue
		}
		if !strings.HasPrefix(rule.Resource, networkResourcePrefix) {
			// Filesystem, MCP, secret and other scopes are outside this slice.
			ignored++
			continue
		}
		destination, port, err := parseNetworkResource(rule.Resource)
		if err != nil {
			return nil, 0, fmt.Errorf("%w: %q: %w", ErrMalformedDeny, rule.Resource, err)
		}
		base, err := networkRule(destination, port)
		if err != nil {
			return nil, 0, fmt.Errorf("%w: %q: %w", ErrMalformedDeny, rule.Resource, err)
		}
		for _, protocol := range []string{tcpProtocol, udpProtocol} {
			mapped := base
			mapped.Protocol = protocol
			mapped.RuleID = rule.RuleID
			key := ruleKey(mapped)
			if _, exists := seen[key]; exists {
				continue
			}
			seen[key] = struct{}{}
			deny = append(deny, mapped)
		}
	}
	return deny, ignored, nil
}

// mapRulesForView expands enforceable network denies exactly as enforcement
// does and keeps network allows as advisory rows. Non-network rules and
// malformed advisory allows are counted but not displayed because this
// contract version only describes the network scope it can evaluate.
func mapRulesForView(rules []controlplane.PolicyRule) ([]RuleView, int, error) {
	out := make([]RuleView, 0, len(rules))
	seen := make(map[string]struct{}, len(rules))
	ignored := 0
	for _, rule := range rules {
		base, ok, err := networkRuleForView(rule)
		if err != nil {
			return nil, 0, err
		}
		if !ok {
			ignored++
			continue
		}
		switch rule.Action {
		case denyAction:
			for _, protocol := range []string{tcpProtocol, udpProtocol} {
				mapped := base
				mapped.Protocol = protocol
				key := ruleKey(mapped)
				if _, exists := seen[key]; exists {
					continue
				}
				seen[key] = struct{}{}
				out = append(out, RuleView{
					RuleID: rule.RuleID, Action: rule.Action, Source: "org",
					ResourceType: "network", Protocol: protocol,
					CIDR: mapped.CIDR, Domain: mapped.Domain, Port: mapped.Port,
					Enforceable: true,
				})
			}
		case allowAction:
			out = append(out, RuleView{
				RuleID: rule.RuleID, Action: rule.Action, Source: "org",
				ResourceType: "network", CIDR: base.CIDR, Domain: base.Domain, Port: base.Port,
				AdvisoryReason: "organization allow rules are advisory",
			})
		}
	}
	return out, ignored, nil
}

// networkRuleForView parses one network resource. Unsupported resources and
// malformed allows are reported as not displayable. A malformed deny fails
// closed because hiding it would misrepresent the effective policy.
func networkRuleForView(rule controlplane.PolicyRule) (sandbox.NetworkRule, bool, error) {
	if !strings.HasPrefix(rule.Resource, networkResourcePrefix) {
		return sandbox.NetworkRule{}, false, nil
	}
	destination, port, err := parseNetworkResource(rule.Resource)
	if err != nil {
		if rule.Action == denyAction {
			return sandbox.NetworkRule{}, false, fmt.Errorf("%w: %q: %w", ErrMalformedDeny, rule.Resource, err)
		}
		return sandbox.NetworkRule{}, false, nil
	}
	base, err := networkRule(destination, port)
	if err != nil {
		if rule.Action == denyAction {
			return sandbox.NetworkRule{}, false, fmt.Errorf("%w: %q: %w", ErrMalformedDeny, rule.Resource, err)
		}
		return sandbox.NetworkRule{}, false, nil
	}
	return base, true, nil
}

// parseNetworkResource parses network:<domain-or-cidr>:<port>. The port is
// mandatory and non-zero so a deny can never broaden to every port silently.
// The destination is split at the last colon, which keeps IPv6 literals and
// IPv6 CIDRs unambiguous.
func parseNetworkResource(resource string) (string, uint16, error) {
	rest := strings.TrimPrefix(resource, networkResourcePrefix)
	if rest == resource {
		return "", 0, errors.New("resource is not a network rule")
	}
	index := strings.LastIndexByte(rest, ':')
	if index <= 0 || index == len(rest)-1 {
		return "", 0, errors.New("network rule must be network:<destination>:<port>")
	}
	destination := rest[:index]
	portText := rest[index+1:]
	if destination == "" || strings.ContainsAny(destination, " \t\r\n") {
		return "", 0, errors.New("network destination is empty or contains whitespace")
	}
	if strings.ContainsAny(portText, " \t\r\n") {
		return "", 0, errors.New("network port contains whitespace")
	}
	port, err := strconv.ParseUint(portText, 10, 16)
	if err != nil || port == 0 {
		return "", 0, errors.New("network port must be 1..65535")
	}
	return destination, uint16(port), nil
}

// networkRule turns a destination into a domain or CIDR rule. A bare IP
// literal is treated as a single-address CIDR so it cannot be confused with a
// DNS name. Anything containing a colon that is neither a valid IP nor CIDR is
// rejected rather than guessed.
func networkRule(destination string, port uint16) (sandbox.NetworkRule, error) {
	if strings.Contains(destination, "/") {
		ip, network, err := net.ParseCIDR(destination)
		if err != nil || ip == nil || network.IP == nil {
			return sandbox.NetworkRule{}, errors.New("network CIDR is invalid")
		}
		return sandbox.NetworkRule{CIDR: network.String(), Port: port}, nil
	}
	if ip := net.ParseIP(destination); ip != nil {
		if ip.To4() != nil {
			return sandbox.NetworkRule{CIDR: ip.String() + "/32", Port: port}, nil
		}
		return sandbox.NetworkRule{CIDR: ip.String() + "/128", Port: port}, nil
	}
	if strings.Contains(destination, ":") {
		return sandbox.NetworkRule{}, errors.New("network destination is not a valid domain or CIDR")
	}
	domain := strings.ToLower(destination)
	if len(domain) > 253 || domain == "" {
		return sandbox.NetworkRule{}, errors.New("network domain is invalid")
	}
	return sandbox.NetworkRule{Domain: domain, Port: port}, nil
}

func ruleKey(rule sandbox.NetworkRule) string {
	return rule.Protocol + "|" + rule.CIDR + "|" + rule.Domain + "|" + strconv.Itoa(int(rule.Port))
}

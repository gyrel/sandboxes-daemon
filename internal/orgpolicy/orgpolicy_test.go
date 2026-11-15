package orgpolicy

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/rheic/sandboxes-daemon/internal/controlplane"
	"github.com/rheic/sandboxes-daemon/internal/store"
)

var orgTestNow = time.Date(2026, 11, 8, 12, 0, 0, 0, time.UTC)

type staticReader struct {
	bundle store.StoredPolicyBundle
	found  bool
	err    error
}

func (r staticReader) GetPolicyBundle(context.Context, string) (store.StoredPolicyBundle, bool, error) {
	return r.bundle, r.found, r.err
}

func storedPayload(t *testing.T, payload controlplane.PolicyPayload) store.StoredPolicyBundle {
	t.Helper()
	encoded, err := json.Marshal(payload)
	if err != nil {
		t.Fatal(err)
	}
	return store.StoredPolicyBundle{
		OrgID: payload.OrgID, Revision: payload.Revision, Payload: encoded, Signature: "synthetic",
		IssuedAt: payload.IssuedAt.UTC(), ExpiresAt: payload.ExpiresAt.UTC(), SyncedAt: orgTestNow,
	}
}

func validPayload(org string, rules ...controlplane.PolicyRule) controlplane.PolicyPayload {
	return controlplane.PolicyPayload{
		SchemaVersion: 1, OrgID: org, Revision: 3,
		IssuedAt: orgTestNow.Add(-time.Hour), ExpiresAt: orgTestNow.Add(time.Hour), Rules: rules,
	}
}

func TestLoadMapsNetworkDeniesToTCPAndUDP(t *testing.T) {
	bundle := storedPayload(t, validPayload("acme",
		controlplane.PolicyRule{Resource: "network:203.0.113.7:443", Action: "deny", RuleID: "rule-001"},
	))
	snapshot, err := Load(context.Background(), staticReader{bundle: bundle, found: true}, "acme", orgTestNow)
	if err != nil {
		t.Fatal(err)
	}
	if len(snapshot.Deny) != 2 {
		t.Fatalf("deny = %+v", snapshot.Deny)
	}
	for i, protocol := range []string{"tcp", "udp"} {
		rule := snapshot.Deny[i]
		if rule.Protocol != protocol || rule.CIDR != "203.0.113.7/32" || rule.Port != 443 || rule.RuleID != "rule-001" {
			t.Fatalf("deny[%d] = %+v", i, rule)
		}
	}
	if snapshot.OrgID != "acme" || snapshot.Revision != 3 {
		t.Fatalf("snapshot metadata = %+v", snapshot)
	}
}

func TestLoadIgnoresAllowAndUnsupportedResources(t *testing.T) {
	bundle := storedPayload(t, validPayload("acme",
		controlplane.PolicyRule{Resource: "network:bad host:443", Action: "allow", RuleID: "rule-001"},
		controlplane.PolicyRule{Resource: "filesystem:/work", Action: "deny", RuleID: "rule-002"},
		controlplane.PolicyRule{Resource: "network:198.51.100.0/24:8443", Action: "deny", RuleID: "rule-003"},
	))
	snapshot, err := Load(context.Background(), staticReader{bundle: bundle, found: true}, "acme", orgTestNow)
	if err != nil {
		t.Fatal(err)
	}
	if snapshot.IgnoredRules != 2 || len(snapshot.Deny) != 2 || snapshot.Deny[0].RuleID != "rule-003" {
		t.Fatalf("snapshot = %+v", snapshot)
	}
}

func TestLoadFailsClosed(t *testing.T) {
	valid := storedPayload(t, validPayload("acme",
		controlplane.PolicyRule{Resource: "network:203.0.113.0/24:443", Action: "deny", RuleID: "rule-001"},
	))
	expired := storedPayload(t, controlplane.PolicyPayload{
		SchemaVersion: 1, OrgID: "acme", Revision: 3,
		IssuedAt: orgTestNow.Add(-2 * time.Hour), ExpiresAt: orgTestNow.Add(-time.Hour),
	})
	crossOrg := storedPayload(t, validPayload("other",
		controlplane.PolicyRule{Resource: "network:203.0.113.0/24:443", Action: "deny", RuleID: "rule-001"},
	))
	revisionMismatch := valid
	revisionMismatch.Revision = 4
	malformed := storedPayload(t, validPayload("acme",
		controlplane.PolicyRule{Resource: "network:203.0.113.0/24", Action: "deny", RuleID: "rule-001"},
	))

	for name, test := range map[string]struct {
		reader staticReader
		org    string
		want   error
	}{
		"not configured":     {reader: staticReader{}, org: "", want: ErrNotConfigured},
		"missing":            {reader: staticReader{}, org: "acme", want: ErrBundleMissing},
		"expired":            {reader: staticReader{bundle: expired, found: true}, org: "acme", want: ErrBundleExpired},
		"cross org":          {reader: staticReader{bundle: crossOrg, found: true}, org: "acme", want: ErrBundleOrgMismatch},
		"revision":           {reader: staticReader{bundle: revisionMismatch, found: true}, org: "acme", want: ErrBundleInvalid},
		"malformed deny":     {reader: staticReader{bundle: malformed, found: true}, org: "acme", want: ErrMalformedDeny},
		"invalid store read": {reader: staticReader{err: errors.New("synthetic store failure")}, org: "acme", want: ErrBundleInvalid},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := Load(context.Background(), test.reader, test.org, orgTestNow); !errors.Is(err, test.want) {
				t.Fatalf("error = %v; want %v", err, test.want)
			}
		})
	}
}

func TestInspectReturnsNetworkRulesAndMetadata(t *testing.T) {
	bundle := storedPayload(t, validPayload("acme",
		controlplane.PolicyRule{Resource: "network:api.example.test:443", Action: "allow", RuleID: "rule-001"},
		controlplane.PolicyRule{Resource: "network:203.0.113.7:8443", Action: "deny", RuleID: "rule-002"},
		controlplane.PolicyRule{Resource: "filesystem:/work", Action: "deny", RuleID: "rule-003"},
	))
	bundle.Signature = "SECRET-SIGNATURE-CANARY"
	view, err := Inspect(context.Background(), staticReader{bundle: bundle, found: true}, "acme", orgTestNow)
	if err != nil {
		t.Fatal(err)
	}
	if view.OrgID != "acme" || view.SchemaVersion != 1 || view.Revision != 3 {
		t.Fatalf("view metadata = %+v", view)
	}
	if !strings.HasPrefix(view.BundleID, "sha256:") || len(view.BundleID) != len("sha256:")+64 {
		t.Fatalf("bundle id = %q", view.BundleID)
	}
	if !view.LoadedAt.Equal(orgTestNow) || !view.IssuedAt.Equal(bundle.IssuedAt) || !view.ExpiresAt.Equal(bundle.ExpiresAt) {
		t.Fatalf("view times = loaded %s issued %s expires %s", view.LoadedAt, view.IssuedAt, view.ExpiresAt)
	}
	if view.IgnoredRules != 1 || len(view.Rules) != 3 {
		t.Fatalf("ignored=%d rules=%+v", view.IgnoredRules, view.Rules)
	}
	denyProtocols := map[string]bool{}
	for _, rule := range view.Rules {
		if rule.Source != "org" || rule.ResourceType != "network" {
			t.Fatalf("unexpected rule provenance: %+v", rule)
		}
		switch rule.RuleID {
		case "rule-001":
			if rule.Action != "allow" || rule.Enforceable || rule.AdvisoryReason == "" || rule.Domain != "api.example.test" || rule.Port != 443 {
				t.Fatalf("allow rule = %+v", rule)
			}
		case "rule-002":
			if rule.Action != "deny" || !rule.Enforceable || rule.CIDR != "203.0.113.7/32" || rule.Port != 8443 {
				t.Fatalf("deny rule = %+v", rule)
			}
			denyProtocols[rule.Protocol] = true
		}
	}
	if !denyProtocols["tcp"] || !denyProtocols["udp"] {
		t.Fatalf("deny protocols = %+v", denyProtocols)
	}
	if strings.Contains(fmt.Sprintf("%+v", view), "SECRET-SIGNATURE-CANARY") {
		t.Fatal("stored signature leaked into the view")
	}
}

func TestInspectFailsClosed(t *testing.T) {
	valid := storedPayload(t, validPayload("acme",
		controlplane.PolicyRule{Resource: "network:203.0.113.0/24:443", Action: "deny", RuleID: "rule-001"},
	))
	expired := storedPayload(t, controlplane.PolicyPayload{
		SchemaVersion: 1, OrgID: "acme", Revision: 3,
		IssuedAt: orgTestNow.Add(-2 * time.Hour), ExpiresAt: orgTestNow.Add(-time.Hour),
	})
	corrupt := valid
	corrupt.Payload = []byte(`{"schemaVersion":1,"orgId":"acme",`)
	malformed := storedPayload(t, validPayload("acme",
		controlplane.PolicyRule{Resource: "network:203.0.113.0/24", Action: "deny", RuleID: "rule-001"},
	))
	for name, test := range map[string]struct {
		reader staticReader
		org    string
		want   error
	}{
		"no reader":         {reader: staticReader{}, org: "acme", want: ErrNotConfigured},
		"no org":            {reader: staticReader{}, org: "", want: ErrNotConfigured},
		"missing":           {reader: staticReader{}, org: "acme", want: ErrBundleMissing},
		"corrupt":           {reader: staticReader{bundle: corrupt, found: true}, org: "acme", want: ErrBundleInvalid},
		"expired":           {reader: staticReader{bundle: expired, found: true}, org: "acme", want: ErrBundleExpired},
		"malformed deny":    {reader: staticReader{bundle: malformed, found: true}, org: "acme", want: ErrMalformedDeny},
		"store read failed": {reader: staticReader{err: errors.New("synthetic store failure")}, org: "acme", want: ErrBundleInvalid},
	} {
		t.Run(name, func(t *testing.T) {
			var reader Reader = test.reader
			if name == "no reader" {
				reader = nil
			}
			if _, err := Inspect(context.Background(), reader, test.org, orgTestNow); !errors.Is(err, test.want) {
				t.Fatalf("error = %v; want %v", err, test.want)
			}
		})
	}
}

func TestParseNetworkResource(t *testing.T) {
	for name, test := range map[string]struct {
		resource string
		port     uint16
		ok       bool
	}{
		"domain":       {resource: "network:api.example.test:443", port: 443, ok: true},
		"ipv4 cidr":    {resource: "network:10.0.0.0/8:8443", port: 8443, ok: true},
		"ipv6 cidr":    {resource: "network:2001:db8::/32:443", port: 443, ok: true},
		"ipv6 literal": {resource: "network:2001:db8::1:443", port: 443, ok: true},
		"missing port": {resource: "network:api.example.test", ok: false},
		"zero port":    {resource: "network:api.example.test:0", ok: false},
		"empty host":   {resource: "network::443", ok: false},
		"whitespace":   {resource: "network:api example.test:443", ok: false},
	} {
		t.Run(name, func(t *testing.T) {
			_, port, err := parseNetworkResource(test.resource)
			if test.ok && err != nil {
				t.Fatalf("parse error = %v", err)
			}
			if !test.ok && err == nil {
				t.Fatal("malformed resource accepted")
			}
			if test.ok && port != test.port {
				t.Fatalf("port = %d, want %d", port, test.port)
			}
		})
	}
}

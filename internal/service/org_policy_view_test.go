package service

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/rheic/sandboxes-daemon/internal/controlplane"
	"github.com/rheic/sandboxes-daemon/internal/orgpolicy"
)

func TestGetOrgPolicyReturnsEffectiveView(t *testing.T) {
	ctx := context.Background()
	svc, st := openOrgPolicyService(t, &fakeRuntime{})
	bundle := signedBundle(t, testPolicyPayload("acme",
		controlplane.PolicyRule{Resource: "network:api.example.test:443", Action: "allow", RuleID: "rule-001"},
		controlplane.PolicyRule{Resource: "network:203.0.113.7:8443", Action: "deny", RuleID: "rule-002"},
		controlplane.PolicyRule{Resource: "filesystem:/work", Action: "deny", RuleID: "rule-003"},
	))
	bundle.Signature = "SECRET-BUNDLE-SIGNATURE-CANARY"
	saveBundle(t, st, bundle)
	enableOrgPolicy(svc, "acme")

	view, err := svc.GetOrgPolicy(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if view.OrgID != "acme" || view.SchemaVersion != 1 || view.Revision != 7 || !view.EnforcementEnabled {
		t.Fatalf("view metadata = %+v", view)
	}
	if !strings.HasPrefix(view.BundleID, "sha256:") || !view.LoadedAt.Equal(orgPolicyTestNow) {
		t.Fatalf("bundle id=%q loaded=%s", view.BundleID, view.LoadedAt)
	}
	if view.IgnoredRules != 1 || len(view.Rules) != 3 {
		t.Fatalf("ignored=%d rules=%+v", view.IgnoredRules, view.Rules)
	}
	for _, rule := range view.Rules {
		if rule.Source != "org" || rule.ResourceType != "network" {
			t.Fatalf("rule provenance = %+v", rule)
		}
		switch rule.RuleID {
		case "rule-001":
			if rule.Action != "allow" || rule.Enforced || rule.AdvisoryReason == "" {
				t.Fatalf("advisory allow = %+v", rule)
			}
		case "rule-002":
			if rule.Action != "deny" || !rule.Enforced || rule.AdvisoryReason != "" {
				t.Fatalf("enforced deny = %+v", rule)
			}
		}
	}
	if strings.Contains(fmt.Sprintf("%+v", view), "SECRET-BUNDLE-SIGNATURE-CANARY") {
		t.Fatal("stored signature leaked into the service view")
	}
}

func TestGetOrgPolicyMarksEverythingAdvisoryWhenEnforcementOff(t *testing.T) {
	ctx := context.Background()
	svc, st := openOrgPolicyService(t, &fakeRuntime{})
	saveBundle(t, st, signedBundle(t, testPolicyPayload("acme",
		controlplane.PolicyRule{Resource: "network:203.0.113.7:8443", Action: "deny", RuleID: "rule-001"},
	)))
	svc.OrgPolicyEnforce = false
	svc.OrgPolicyOrg = "acme"

	view, err := svc.GetOrgPolicy(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if view.EnforcementEnabled || len(view.Rules) != 2 {
		t.Fatalf("view = %+v", view)
	}
	for _, rule := range view.Rules {
		if rule.Enforced || rule.AdvisoryReason != "org_policy.enforce is disabled" {
			t.Fatalf("rule with enforcement off = %+v", rule)
		}
	}
}

func TestGetOrgPolicyFailsClosedAndDoesNotWrite(t *testing.T) {
	ctx := context.Background()
	svc, st := openOrgPolicyService(t, &fakeRuntime{})
	svc.OrgPolicyOrg = "acme"

	if _, err := svc.GetOrgPolicy(ctx); !errors.Is(err, orgpolicy.ErrBundleMissing) {
		t.Fatalf("missing bundle error = %v", err)
	}

	corrupt := signedBundle(t, testPolicyPayload("acme"))
	corrupt.Payload = []byte(`{"schemaVersion":1,"orgId":"acme",`)
	saveBundle(t, st, corrupt)
	if _, err := svc.GetOrgPolicy(ctx); !errors.Is(err, orgpolicy.ErrBundleInvalid) {
		t.Fatalf("corrupt bundle error = %v", err)
	}

	before, found, err := st.GetPolicyBundle(ctx, "acme")
	if err != nil || !found {
		t.Fatalf("stored bundle after failed reads: found=%t err=%v", found, err)
	}
	if !before.IssuedAt.Equal(corrupt.IssuedAt) || before.Revision != corrupt.Revision || string(before.Payload) != string(corrupt.Payload) {
		t.Fatal("read-only org policy view mutated the stored bundle")
	}

	svc.OrgPolicyOrg = ""
	if _, err := svc.GetOrgPolicy(ctx); !errors.Is(err, orgpolicy.ErrNotConfigured) {
		t.Fatalf("unconfigured org error = %v", err)
	}
}

func TestGetOrgPolicyExpiredBundleIsTyped(t *testing.T) {
	ctx := context.Background()
	svc, st := openOrgPolicyService(t, &fakeRuntime{})
	payload := testPolicyPayload("acme")
	payload.IssuedAt = orgPolicyTestNow.Add(-2 * time.Hour)
	payload.ExpiresAt = orgPolicyTestNow.Add(-time.Hour)
	saveBundle(t, st, signedBundle(t, payload))
	svc.OrgPolicyOrg = "acme"

	if _, err := svc.GetOrgPolicy(ctx); !errors.Is(err, orgpolicy.ErrBundleExpired) {
		t.Fatalf("expired bundle error = %v", err)
	}
}

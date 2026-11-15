package server

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"path/filepath"
	"strings"
	"testing"
	"time"

	localv1 "github.com/rheic/sandboxes-api/gen/go/sandboxes/local/v1"
	"github.com/rheic/sandboxes-core/sandbox"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/rheic/sandboxes-daemon/internal/controlplane"
	"github.com/rheic/sandboxes-daemon/internal/service"
	"github.com/rheic/sandboxes-daemon/internal/store"
)

var serverOrgPolicyNow = time.Now().UTC().Truncate(time.Second)

func serverOrgPolicyService(t *testing.T) (*service.Service, *store.Store) {
	t.Helper()
	ctx := context.Background()
	st, err := store.Open(ctx, filepath.Join(t.TempDir(), "org-policy.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	svc := service.New(st, nil)
	return svc, st
}

func saveServerOrgPolicyBundle(t *testing.T, st *store.Store, payload controlplane.PolicyPayload) {
	t.Helper()
	encoded, err := json.Marshal(payload)
	if err != nil {
		t.Fatal(err)
	}
	err = st.SavePolicyBundle(context.Background(), store.StoredPolicyBundle{
		OrgID: payload.OrgID, Revision: payload.Revision, Payload: encoded,
		Signature: "SECRET-ORG-POLICY-SIGNATURE-CANARY",
		IssuedAt:  payload.IssuedAt.UTC(), ExpiresAt: payload.ExpiresAt.UTC(), SyncedAt: serverOrgPolicyNow,
	})
	if err != nil {
		t.Fatal(err)
	}
}

func serverOrgPolicyPayload(org string, rules ...controlplane.PolicyRule) controlplane.PolicyPayload {
	return controlplane.PolicyPayload{
		SchemaVersion: 1, OrgID: org, Revision: 9,
		IssuedAt: serverOrgPolicyNow.Add(-time.Hour), ExpiresAt: serverOrgPolicyNow.Add(time.Hour), Rules: rules,
	}
}

func TestGetOrgPolicyReturnsRulesAndEnforcement(t *testing.T) {
	svc, st := serverOrgPolicyService(t)
	svc.OrgPolicyOrg = "acme"
	svc.OrgPolicyEnforce = true
	saveServerOrgPolicyBundle(t, st, serverOrgPolicyPayload("acme",
		controlplane.PolicyRule{Resource: "network:api.example.test:443", Action: "allow", RuleID: "rule-001"},
		controlplane.PolicyRule{Resource: "network:203.0.113.7:8443", Action: "deny", RuleID: "rule-002"},
	))

	response, err := NewSandbox(svc).GetOrgPolicy(context.Background(), &localv1.GetOrgPolicyRequest{})
	if err != nil {
		t.Fatal(err)
	}
	if response.GetOrg() != "acme" || response.GetSchemaVersion() != 1 || response.GetRevision() != 9 || !response.GetEnforcementEnabled() {
		t.Fatalf("response metadata = %+v", response)
	}
	if !strings.HasPrefix(response.GetBundleId(), "sha256:") || response.GetLoadedAtUnix() != serverOrgPolicyNow.Unix() {
		t.Fatalf("bundle id=%q loaded=%d", response.GetBundleId(), response.GetLoadedAtUnix())
	}
	if len(response.GetRules()) != 3 {
		t.Fatalf("rules = %+v", response.GetRules())
	}
	for _, rule := range response.GetRules() {
		if rule.GetSource() != "org" || rule.GetResourceType() != "network" {
			t.Fatalf("rule provenance = %+v", rule)
		}
		switch rule.GetRuleId() {
		case "rule-001":
			if rule.GetAction() != "allow" || rule.GetEnforced() || rule.GetAdvisoryReason() == "" {
				t.Fatalf("advisory allow = %+v", rule)
			}
		case "rule-002":
			if rule.GetAction() != "deny" || !rule.GetEnforced() || rule.GetAdvisoryReason() != "" {
				t.Fatalf("enforced deny = %+v", rule)
			}
		}
	}
	if strings.Contains(response.String(), "SECRET-ORG-POLICY-SIGNATURE-CANARY") {
		t.Fatal("stored signature leaked into the RPC response")
	}

	global, err := NewSandbox(svc).GetGlobalPolicy(context.Background(), &localv1.GetGlobalPolicyRequest{})
	if err != nil {
		t.Fatal(err)
	}
	if len(global.GetAllow())+len(global.GetDeny()) != 0 {
		t.Fatalf("unexpected global rules: %+v", global)
	}
}

func TestGetOrgPolicyFailsClosedWithTypedStatus(t *testing.T) {
	ctx := context.Background()
	svc, st := serverOrgPolicyService(t)
	var logs bytes.Buffer
	previous := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&logs, nil)))
	t.Cleanup(func() { slog.SetDefault(previous) })

	svc.OrgPolicyOrg = "acme"
	_, err := NewSandbox(svc).GetOrgPolicy(ctx, &localv1.GetOrgPolicyRequest{})
	if status.Code(err) != codes.NotFound {
		t.Fatalf("missing bundle status = %v", err)
	}
	if strings.Contains(err.Error(), "SECRET-ORG-POLICY-SIGNATURE-CANARY") || strings.Contains(logs.String(), "SECRET-ORG-POLICY-SIGNATURE-CANARY") {
		t.Fatal("secret canary leaked through the missing-bundle error or logs")
	}

	corrupt := serverOrgPolicyPayload("acme")
	encoded, marshalErr := json.Marshal(corrupt)
	if marshalErr != nil {
		t.Fatal(marshalErr)
	}
	encoded = append(encoded[:len(encoded)-1], []byte(`,"leak":"SECRET-ORG-POLICY-SIGNATURE-CANARY"}`)...)
	if saveErr := st.SavePolicyBundle(ctx, store.StoredPolicyBundle{
		OrgID: "acme", Revision: 9, Payload: encoded, Signature: "SECRET-ORG-POLICY-SIGNATURE-CANARY",
		IssuedAt: corrupt.IssuedAt.UTC(), ExpiresAt: corrupt.ExpiresAt.UTC(), SyncedAt: serverOrgPolicyNow,
	}); saveErr != nil {
		t.Fatal(saveErr)
	}
	_, err = NewSandbox(svc).GetOrgPolicy(ctx, &localv1.GetOrgPolicyRequest{})
	if status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("corrupt bundle status = %v", err)
	}
	if strings.Contains(err.Error(), "SECRET-ORG-POLICY-SIGNATURE-CANARY") || strings.Contains(logs.String(), "SECRET-ORG-POLICY-SIGNATURE-CANARY") {
		t.Fatal("secret canary leaked through the corrupt-bundle error or logs")
	}

	svc.OrgPolicyOrg = ""
	if _, err := NewSandbox(svc).GetOrgPolicy(ctx, &localv1.GetOrgPolicyRequest{}); status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("unconfigured org status = %v", err)
	}
}

func TestGetOrgPolicyEnforcementOffIsVisibleAndAdvisory(t *testing.T) {
	svc, st := serverOrgPolicyService(t)
	svc.OrgPolicyOrg = "acme"
	svc.OrgPolicyEnforce = false
	saveServerOrgPolicyBundle(t, st, serverOrgPolicyPayload("acme",
		controlplane.PolicyRule{Resource: "network:203.0.113.7:8443", Action: "deny", RuleID: "rule-001"},
	))

	response, err := NewSandbox(svc).GetOrgPolicy(context.Background(), &localv1.GetOrgPolicyRequest{})
	if err != nil {
		t.Fatal(err)
	}
	if response.GetEnforcementEnabled() || len(response.GetRules()) != 2 {
		t.Fatalf("response = %+v", response)
	}
	for _, rule := range response.GetRules() {
		if rule.GetEnforced() || rule.GetAdvisoryReason() != "org_policy.enforce is disabled" {
			t.Fatalf("advisory rule = %+v", rule)
		}
	}
}

func TestNetworkRuleOriginIsLocal(t *testing.T) {
	rules := toProtoRules([]sandbox.NetworkRule{{Protocol: "tcp", CIDR: "203.0.113.0/24", Port: 443}})
	if len(rules) != 1 || rules[0].GetOrigin() != "local" {
		t.Fatalf("proto rule origin = %+v", rules)
	}
}

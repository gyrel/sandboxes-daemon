package service

import (
	"context"
	"errors"
	"strings"
	"testing"

	localv1 "github.com/gyrel/sandboxes-api/gen/go/sandboxes/local/v1"
	"github.com/gyrel/sandboxes-core/ids"
	"github.com/gyrel/slogx/events"

	"github.com/gyrel/sandboxes-daemon/internal/approvals"
	"github.com/gyrel/sandboxes-daemon/internal/servicesecrets"
)

func correlationContext() context.Context {
	return ids.WithReqID(ids.WithOpID(context.Background(), ids.NewOpID()), ids.NewReqID())
}

func TestApprovalRequestedEventTable(t *testing.T) {
	output := captureLogs(t)
	ctx := correlationContext()
	for _, tc := range []struct {
		name    string
		kind    localv1.ApprovalKind
		headers []*localv1.ApprovalHeader
		provide events.ApprovalRequestedProvider
		want    []string
	}{
		{"host command", localv1.ApprovalKind_APPROVAL_KIND_HOST_COMMAND, nil, events.ApprovalRequestedProviderOs,
			[]string{`"kind":"host_command"`, `"provider":"os"`, `"disclosure_boundary":"headers"`}},
		{"mcp register", localv1.ApprovalKind_APPROVAL_KIND_MCP_REGISTRATION, nil, events.ApprovalRequestedProviderOs,
			[]string{`"kind":"mcp_register"`}},
		{"other without provider", localv1.ApprovalKind_APPROVAL_KIND_OTHER, nil, events.ApprovalRequestedProviderNone,
			[]string{`"kind":"other"`, `"provider":"none"`}},
		{"vault ref boundary", localv1.ApprovalKind_APPROVAL_KIND_OTHER,
			[]*localv1.ApprovalHeader{{Name: "authorization", VaultReferenceIds: []string{"ref-1"}}}, events.ApprovalRequestedProviderOs,
			[]string{`"disclosure_boundary":"vault_refs"`}},
	} {
		output.Reset()
		entry := approvals.Entry{
			ID:            "0123456789abcdef0123456789abcdef",
			Kind:          tc.kind,
			Headers:       tc.headers,
			ActionSummary: "synthetic-summary-canary-" + tc.name,
		}
		emitApprovalRequested(ctx, entry, tc.provide)
		got := output.String()
		for _, want := range append(tc.want, `"event":"gyrel.approval.requested"`, `"outcome":"ok"`) {
			if !strings.Contains(got, want) {
				t.Fatalf("%s: missing %s in %s", tc.name, want, got)
			}
		}
		if strings.Contains(got, "synthetic-summary-canary") {
			t.Fatalf("%s: entry summary leaked: %s", tc.name, got)
		}
	}
	output.Reset()
	emitApprovalRequested(ctx, approvals.Entry{Kind: localv1.ApprovalKind_APPROVAL_KIND_UNSPECIFIED}, events.ApprovalRequestedProviderOs)
	if output.Len() > 0 {
		t.Fatalf("unspecified class emitted an event: %s", output.String())
	}
}

func TestApprovalRespondedProviderMissingStillEmits(t *testing.T) {
	svc := newApprovalTestService(t)
	entry := createTestApproval(t, svc, "sb-1")
	output := captureLogs(t)
	ctx := correlationContext()
	for _, tc := range []struct {
		decision localv1.ApprovalDecision
		persist  localv1.ApprovalPersistScope
		want     string
	}{
		{localv1.ApprovalDecision_APPROVAL_DECISION_APPROVE, localv1.ApprovalPersistScope_APPROVAL_PERSIST_SCOPE_ONCE, `"decision":"APPROVE"`},
		{localv1.ApprovalDecision_APPROVAL_DECISION_DENY, localv1.ApprovalPersistScope_APPROVAL_PERSIST_SCOPE_EXACT, `"decision":"DENY"`},
	} {
		output.Reset()
		if _, _, err := svc.RespondApproval(ctx, entry.ID, tc.decision, tc.persist); !errors.Is(err, ErrApprovalProviderUnavailable) {
			t.Fatalf("err = %v", err)
		}
		got := output.String()
		for _, want := range []string{`"event":"gyrel.approval.responded"`, tc.want, `"result":"FAILED_PRECONDITION"`, `"outcome":"denied"`} {
			if !strings.Contains(got, want) {
				t.Fatalf("provider-missing path missing %s in %s", want, got)
			}
		}
	}
}

func TestApprovalRespondedDecisionTable(t *testing.T) {
	svc := newApprovalTestService(t)
	provider := &testApprovalProvider{}
	svc.SetApprovalProvider(provider)
	ctx := correlationContext()
	output := captureLogs(t)
	for _, tc := range []struct {
		decision localv1.ApprovalDecision
		persist  localv1.ApprovalPersistScope
		want     []string
	}{
		{localv1.ApprovalDecision_APPROVAL_DECISION_APPROVE, localv1.ApprovalPersistScope_APPROVAL_PERSIST_SCOPE_ONCE,
			[]string{`"decision":"APPROVE"`, `"outcome":"ok"`, `"result":"ok"`}},
		{localv1.ApprovalDecision_APPROVAL_DECISION_APPROVE, localv1.ApprovalPersistScope_APPROVAL_PERSIST_SCOPE_EXACT,
			[]string{`"decision":"EXACT"`, `"outcome":"ok"`}},
		{localv1.ApprovalDecision_APPROVAL_DECISION_DENY, localv1.ApprovalPersistScope_APPROVAL_PERSIST_SCOPE_ONCE,
			[]string{`"decision":"DENY"`, `"outcome":"denied"`}},
	} {
		entry, err := svc.approvals.Create(approvals.CreateRequest{
			Kind:          localv1.ApprovalKind_APPROVAL_KIND_OTHER,
			SandboxID:     "sb-canary",
			ActionSummary: "synthetic-action-summary-canary",
			EnvNames:      []string{"SYNTHETIC_ENV_NAME_CANARY"},
		})
		if err != nil {
			t.Fatal(err)
		}
		output.Reset()
		if _, _, err := svc.RespondApproval(ctx, entry.ID, tc.decision, tc.persist); err != nil {
			t.Fatal(err)
		}
		got := output.String()
		for _, want := range append(tc.want, `"event":"gyrel.approval.responded"`) {
			if !strings.Contains(got, want) {
				t.Fatalf("%v: missing %s in %s", tc.decision, want, got)
			}
		}
		for _, canary := range []string{"synthetic-action-summary-canary", "SYNTHETIC_ENV_NAME_CANARY"} {
			if strings.Contains(got, canary) {
				t.Fatalf("event leaked %q: %s", canary, got)
			}
		}
	}
}

func TestApprovalProviderRefusalRespondsDenied(t *testing.T) {
	svc := newApprovalTestService(t)
	svc.SetApprovalProvider(&testApprovalProvider{err: errors.New("user refused the synthetic canary")})
	entry := createTestApproval(t, svc, "sb-1")
	output := captureLogs(t)
	ctx := correlationContext()
	if _, _, err := svc.RespondApproval(ctx, entry.ID,
		localv1.ApprovalDecision_APPROVAL_DECISION_APPROVE, localv1.ApprovalPersistScope_APPROVAL_PERSIST_SCOPE_ONCE); !errors.Is(err, ErrApprovalDenied) {
		t.Fatalf("err = %v", err)
	}
	got := output.String()
	for _, want := range []string{`"event":"gyrel.approval.responded"`, `"decision":"DENY"`, `"outcome":"denied"`, `"result":"ok"`} {
		if !strings.Contains(got, want) {
			t.Fatalf("missing %s in %s", want, got)
		}
	}
	if strings.Contains(got, "user refused") {
		t.Fatalf("provider error text leaked: %s", got)
	}
}

func TestApprovalRequestedHostCommandFlow(t *testing.T) {
	svc, _ := newSecretService(t)
	svc.SetHostCommandApprovalProvider(&allowHostCommands{})
	marker := t.TempDir() + "/marker"
	ctx := correlationContext()
	output := captureLogs(t)
	if _, err := svc.SetServiceSecretSource(ctx, "openai", servicesecrets.ScopeGlobal, "", servicesecrets.Source{
		Command: commandForMarker(marker), NoVerify: true,
	}); err != nil {
		t.Fatal(err)
	}
	got := output.String()
	for _, want := range []string{
		`"event":"gyrel.approval.requested"`, `"kind":"host_command"`, `"provider":"os"`,
		`"event":"gyrel.approval.responded"`, `"decision":"APPROVE"`, `"result":"ok"`,
	} {
		if !strings.Contains(got, want) {
			t.Fatalf("missing %s in %s", want, got)
		}
	}
	if strings.Contains(got, marker) {
		t.Fatalf("command path leaked: %s", got)
	}
}

func TestApprovalRequestedCustomSecretSourceFlow(t *testing.T) {
	svc, _, _ := newCustomSecretTestService(t)
	ctx := correlationContext()
	output := captureLogs(t)
	if _, _, _, err := svc.SetCustomSecret(ctx, CustomSecretSetRequest{
		Service: "flow-test", Hosts: []string{"api.flow-test.example"}, Env: "KEY",
		Source: &servicesecrets.Source{Reference: "op://vault/synthetic-reference-canary/field"},
	}); err != nil {
		t.Fatal(err)
	}
	got := output.String()
	for _, want := range []string{`"event":"gyrel.approval.requested"`, `"kind":"other"`, `"provider":"none"`} {
		if !strings.Contains(got, want) {
			t.Fatalf("missing %s in %s", want, got)
		}
	}
	if strings.Contains(got, "synthetic-reference-canary") {
		t.Fatalf("source reference leaked: %s", got)
	}
}

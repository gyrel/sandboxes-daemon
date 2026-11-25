package service

import (
	"context"
	"errors"
	"testing"

	core "github.com/gyrel/sandboxes-core"

	localv1 "github.com/gyrel/sandboxes-api/gen/go/sandboxes/local/v1"

	"github.com/gyrel/sandboxes-daemon/internal/approvals"
	"github.com/gyrel/sandboxes-daemon/internal/servicesecrets"
)

type testApprovalProvider struct {
	err   error
	calls []approvals.Entry
}

func (p *testApprovalProvider) Approve(_ context.Context, entry approvals.Entry) error {
	p.calls = append(p.calls, entry)
	return p.err
}

func newApprovalTestService(t *testing.T) *Service {
	t.Helper()
	svc, _, _ := newCustomSecretTestService(t)
	return svc
}

func createTestApproval(t *testing.T, svc *Service, sandbox string) approvals.Entry {
	t.Helper()
	entry, err := svc.approvals.Create(approvals.CreateRequest{
		Kind:      localv1.ApprovalKind_APPROVAL_KIND_OTHER,
		SandboxID: sandbox,
	})
	if err != nil {
		t.Fatal(err)
	}
	return entry
}

func TestRespondApprovalWithoutProviderFailsClosed(t *testing.T) {
	svc := newApprovalTestService(t)
	entry := createTestApproval(t, svc, "sb-1")
	ctx := context.Background()

	if _, _, err := svc.RespondApproval(ctx, entry.ID, localv1.ApprovalDecision_APPROVAL_DECISION_UNSPECIFIED, localv1.ApprovalPersistScope_APPROVAL_PERSIST_SCOPE_ONCE); !errors.Is(err, ErrApprovalInvalidDecision) {
		t.Fatalf("unspecified err = %v", err)
	}
	if _, _, err := svc.RespondApproval(ctx, entry.ID, localv1.ApprovalDecision_APPROVAL_DECISION_APPROVE, localv1.ApprovalPersistScope_APPROVAL_PERSIST_SCOPE_ONCE); !errors.Is(err, ErrApprovalProviderUnavailable) {
		t.Fatalf("approve without provider err = %v", err)
	}
	if _, _, err := svc.RespondApproval(ctx, entry.ID, localv1.ApprovalDecision_APPROVAL_DECISION_DENY, localv1.ApprovalPersistScope_APPROVAL_PERSIST_SCOPE_EXACT); !errors.Is(err, ErrApprovalProviderUnavailable) {
		t.Fatalf("exact without provider err = %v", err)
	}
	if listed, err := svc.ListApprovals(ctx, ""); err != nil || len(listed) != 1 {
		t.Fatalf("failed-closed responses must not consume the approval: %v %+v", err, listed)
	}
}

func TestRespondDenyWithoutProviderSucceeds(t *testing.T) {
	svc := newApprovalTestService(t)
	entry := createTestApproval(t, svc, "sb-1")
	updated, ruleID, err := svc.RespondApproval(context.Background(), entry.ID,
		localv1.ApprovalDecision_APPROVAL_DECISION_DENY, localv1.ApprovalPersistScope_APPROVAL_PERSIST_SCOPE_UNSPECIFIED)
	if err != nil {
		t.Fatal(err)
	}
	if ruleID != "" {
		t.Fatalf("unexpected rule id %q", ruleID)
	}
	if updated.State != localv1.ApprovalState_APPROVAL_STATE_DENIED {
		t.Fatalf("state = %v", updated.State)
	}
	if _, _, err := svc.RespondApproval(context.Background(), entry.ID, localv1.ApprovalDecision_APPROVAL_DECISION_DENY, localv1.ApprovalPersistScope_APPROVAL_PERSIST_SCOPE_ONCE); !errors.Is(err, ErrApprovalNotPending) {
		t.Fatalf("second respond err = %v", err)
	}
}

func TestRespondApproveWithProvider(t *testing.T) {
	svc := newApprovalTestService(t)
	provider := &testApprovalProvider{}
	svc.SetApprovalProvider(provider)
	entry := createTestApproval(t, svc, "sb-1")
	updated, _, err := svc.RespondApproval(context.Background(), entry.ID,
		localv1.ApprovalDecision_APPROVAL_DECISION_APPROVE, localv1.ApprovalPersistScope_APPROVAL_PERSIST_SCOPE_ONCE)
	if err != nil {
		t.Fatal(err)
	}
	if updated.State != localv1.ApprovalState_APPROVAL_STATE_APPROVED {
		t.Fatalf("state = %v", updated.State)
	}
	if len(provider.calls) != 1 || provider.calls[0].ID != entry.ID {
		t.Fatalf("provider calls = %+v", provider.calls)
	}
}

func TestRespondApproveProviderRefusalMarksDenied(t *testing.T) {
	svc := newApprovalTestService(t)
	svc.SetApprovalProvider(&testApprovalProvider{err: errors.New("user refused")})
	entry := createTestApproval(t, svc, "sb-1")
	_, _, err := svc.RespondApproval(context.Background(), entry.ID,
		localv1.ApprovalDecision_APPROVAL_DECISION_APPROVE, localv1.ApprovalPersistScope_APPROVAL_PERSIST_SCOPE_ONCE)
	if !errors.Is(err, ErrApprovalDenied) {
		t.Fatalf("refusal err = %v", err)
	}
	if got, _ := svc.approvals.Get(entry.ID); got.State != localv1.ApprovalState_APPROVAL_STATE_DENIED {
		t.Fatalf("provider refusal must deny the approval, state = %v", got.State)
	}
}

func TestInspectAndListSemantics(t *testing.T) {
	svc := newApprovalTestService(t)
	ctx := context.Background()
	a := createTestApproval(t, svc, "sb-a")
	createTestApproval(t, svc, "sb-b")
	if _, _, err := svc.RespondApproval(ctx, a.ID, localv1.ApprovalDecision_APPROVAL_DECISION_DENY, localv1.ApprovalPersistScope_APPROVAL_PERSIST_SCOPE_ONCE); err != nil {
		t.Fatal(err)
	}
	listed, err := svc.ListApprovals(ctx, "")
	if err != nil || len(listed) != 1 || listed[0].SandboxID != "sb-b" {
		t.Fatalf("pending-only contract violated: %v %+v", err, listed)
	}
	if _, err := svc.InspectApproval(ctx, a.ID, "sb-b"); !errors.Is(err, core.ErrNotFound) {
		t.Fatalf("cross-sandbox inspect err = %v", err)
	}
	if entry, err := svc.InspectApproval(ctx, a.ID, "sb-a"); err != nil || entry.State != localv1.ApprovalState_APPROVAL_STATE_DENIED {
		t.Fatalf("resolved inspect: %+v err=%v", entry, err)
	}
	if _, err := svc.InspectApproval(ctx, "nope", ""); !errors.Is(err, core.ErrNotFound) {
		t.Fatalf("missing id err = %v", err)
	}
}

func TestSetCustomSourceCreatesApprovalAndStoresNothing(t *testing.T) {
	svc, vault, _ := newCustomSecretTestService(t)
	ctx := context.Background()
	_, placeholder, approvalID, err := svc.SetCustomSecret(ctx, CustomSecretSetRequest{
		Service: "approval-test", Hosts: []string{"api.approval-test.example"}, Env: "KEY",
		Source: &servicesecrets.Source{Reference: "op://vault/item/field"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if placeholder != "" {
		t.Fatal("pending approval must not echo a placeholder")
	}
	if approvalID == "" {
		t.Fatal("approval id missing")
	}
	if len(vault.items) != 0 {
		t.Fatalf("secret material stored before approval: %v", vault.items)
	}
	listed, err := svc.ListApprovals(ctx, "")
	if err != nil || len(listed) != 1 {
		t.Fatalf("approval listed: %v %+v", err, listed)
	}
	if listed[0].ID != approvalID || listed[0].Kind != localv1.ApprovalKind_APPROVAL_KIND_OTHER {
		t.Fatalf("approval mismatch: %+v", listed[0])
	}
}

func TestSetCustomCommandSourceKindHostCommand(t *testing.T) {
	svc, _, _ := newCustomSecretTestService(t)
	_, _, approvalID, err := svc.SetCustomSecret(context.Background(), CustomSecretSetRequest{
		Hosts: []string{"api.approval-test.example"}, Env: "KEY",
		Source: &servicesecrets.Source{Command: "/usr/local/bin/token-helper"},
	})
	if err != nil {
		t.Fatal(err)
	}
	entry, ok := svc.approvals.Get(approvalID)
	if !ok || entry.Kind != localv1.ApprovalKind_APPROVAL_KIND_HOST_COMMAND {
		t.Fatalf("command challenge kind = %v ok=%t", entry.Kind, ok)
	}
}

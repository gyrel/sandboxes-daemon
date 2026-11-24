package service

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"

	core "github.com/rheic/sandboxes-core"

	localv1 "github.com/rheic/sandboxes-api/gen/go/sandboxes/local/v1"

	"github.com/rheic/sandboxes-daemon/internal/approvals"
)

var (
	ErrApprovalInvalidDecision     = errors.New("approval decision is unspecified")
	ErrApprovalProviderUnavailable = errors.New("trusted approval provider is unavailable")
	ErrApprovalDenied              = errors.New("approval was denied or trusted approval failed")
	ErrApprovalNotPending          = errors.New("approval is not pending")
)

// ListApprovals returns approvals, optionally filtered by sandbox ID.
func (s *Service) ListApprovals(ctx context.Context, sandboxID string) ([]approvals.Entry, error) {
	if s.approvals == nil {
		return nil, errors.New("approval store is unavailable")
	}
	return s.approvals.List(sandboxID), nil
}

// Aliases.
func (s *Service) ListPendingApprovals(ctx context.Context, sandboxID string) ([]approvals.Entry, error) {
	return s.ListApprovals(ctx, sandboxID)
}

// InspectApproval returns one approval, including recently resolved ones.
func (s *Service) InspectApproval(ctx context.Context, approvalID, sandboxID string) (approvals.Entry, error) {
	if s.approvals == nil {
		return approvals.Entry{}, errors.New("approval store is unavailable")
	}
	entry, ok := s.approvals.Get(approvalID)
	if !ok {
		return approvals.Entry{}, core.ErrNotFound
	}
	if sandboxID != "" && firstApprovalSandbox(entry) != sandboxID {
		return approvals.Entry{}, core.ErrNotFound
	}
	return entry, nil
}

func (s *Service) GetApproval(ctx context.Context, approvalID, sandboxID string) (approvals.Entry, error) {
	return s.InspectApproval(ctx, approvalID, sandboxID)
}

// RespondApproval records a host-side decision.
func (s *Service) RespondApproval(ctx context.Context, approvalID string, decision localv1.ApprovalDecision, persist localv1.ApprovalPersistScope) (approvals.Entry, string, error) {
	if s.approvals == nil {
		return approvals.Entry{}, "", errors.New("approval store is unavailable")
	}
	if decision == localv1.ApprovalDecision_APPROVAL_DECISION_UNSPECIFIED {
		return approvals.Entry{}, "", ErrApprovalInvalidDecision
	}
	if persist == localv1.ApprovalPersistScope_APPROVAL_PERSIST_SCOPE_UNSPECIFIED {
		persist = localv1.ApprovalPersistScope_APPROVAL_PERSIST_SCOPE_ONCE
	}
	entry, ok := s.approvals.Get(approvalID)
	if !ok {
		return approvals.Entry{}, "", core.ErrNotFound
	}
	if entry.State != localv1.ApprovalState_APPROVAL_STATE_PENDING {
		return approvals.Entry{}, "", ErrApprovalNotPending
	}
	// EXACT persistence and approval both require a trusted provider.
	if persist == localv1.ApprovalPersistScope_APPROVAL_PERSIST_SCOPE_EXACT || decision == localv1.ApprovalDecision_APPROVAL_DECISION_APPROVE {
		if s.approvalProvider == nil {
			return approvals.Entry{}, "", ErrApprovalProviderUnavailable
		}
	}
	if decision == localv1.ApprovalDecision_APPROVAL_DECISION_APPROVE {
		if err := s.callApprovalProvider(ctx, entry); err != nil {
			_, _ = s.approvals.Resolve(approvalID, localv1.ApprovalDecision_APPROVAL_DECISION_DENY, persist)
			return approvals.Entry{}, "", err
		}
	}
	state := localv1.ApprovalDecision_APPROVAL_DECISION_DENY
	if decision == localv1.ApprovalDecision_APPROVAL_DECISION_APPROVE {
		state = localv1.ApprovalDecision_APPROVAL_DECISION_APPROVE
	}
	updated, err := s.approvals.Resolve(approvalID, decision, persist)
	if err != nil {
		return approvals.Entry{}, "", err
	}
	_ = state
	slog.Info("approval resolved", "approval_id", approvalID, "kind", entry.Kind, "decision", decision)
	persistedRuleID := ""
	return updated, persistedRuleID, nil
}

//nolint:gocritic // entry-sized disclosure parameter
func (s *Service) callApprovalProvider(ctx context.Context, entry approvals.Entry) error {
	provider := s.approvalProvider
	if provider == nil {
		return ErrApprovalProviderUnavailable
	}
	// Support several plausible method names without treating caller identity
	// or the challenge ID as consent: only the stored entry is presented.
	if fn, ok := provider.(interface {
		Approve(context.Context, approvals.Entry) error
	}); ok {
		if err := fn.Approve(ctx, entry); err != nil {
			return fmt.Errorf("%w: %w", ErrApprovalDenied, err)
		}
		return nil
	}
	if fn, ok := provider.(interface {
		ApproveApproval(context.Context, approvals.Entry) error
	}); ok {
		if err := fn.ApproveApproval(ctx, entry); err != nil {
			return fmt.Errorf("%w: %w", ErrApprovalDenied, err)
		}
		return nil
	}
	if fn, ok := provider.(interface {
		ApprovePending(context.Context, approvals.Entry) error
	}); ok {
		if err := fn.ApprovePending(ctx, entry); err != nil {
			return fmt.Errorf("%w: %w", ErrApprovalDenied, err)
		}
		return nil
	}
	// If provider does not implement a known method, fail closed.
	return ErrApprovalProviderUnavailable
}

//nolint:gocritic // entry-sized disclosure parameter
func firstApprovalSandbox(entry approvals.Entry) string {
	for _, v := range []string{entry.SandboxID, entry.SandboxId, entry.Sandbox} {
		if strings.TrimSpace(v) != "" {
			return strings.TrimSpace(v)
		}
	}
	return ""
}

package service

import (
	"context"
	"errors"
	"fmt"
	"log/slog"

	core "github.com/rheic/sandboxes-core"

	localv1 "github.com/rheic/sandboxes-api/gen/go/sandboxes/local/v1"

	"github.com/rheic/slogx/events"

	"github.com/rheic/sandboxes-daemon/internal/approvals"
)

var (
	// ErrApprovalInvalidDecision reports an UNSPECIFIED decision.
	ErrApprovalInvalidDecision = errors.New("approval decision is unspecified")
	// ErrApprovalProviderUnavailable reports that the daemon has no trusted
	// OS-backed consent mechanism; APPROVE and EXACT persist fail closed.
	ErrApprovalProviderUnavailable = errors.New("trusted approval provider is unavailable")
	// ErrApprovalDenied reports a provider refusal after an approve attempt.
	ErrApprovalDenied = errors.New("approval was denied or trusted approval failed")
	// ErrApprovalNotPending reports responding to an already resolved ID.
	ErrApprovalNotPending = errors.New("approval is not pending")
)

// ApprovalProvider is the trusted host-side consent mechanism invoked before
// an APPROVE decision becomes visible. Implementations must obtain real human
// consent (OS prompt, biometric, hardware key); a challenge ID or caller
// identity is never consent. The provider only ever sees the disclosure-safe
// entry.
type ApprovalProvider interface {
	Approve(ctx context.Context, entry approvals.Entry) error
}

// ListApprovals returns pending approvals per the contract (pending only).
func (s *Service) ListApprovals(ctx context.Context, sandboxID string) ([]approvals.Entry, error) {
	if s.approvals == nil {
		return nil, errors.New("approval store is unavailable")
	}
	return s.approvals.ListPending(sandboxID), nil
}

// InspectApproval returns one approval, including recently resolved ones. A
// non-empty sandboxID that does not match the entry returns ErrNotFound.
func (s *Service) InspectApproval(ctx context.Context, approvalID, sandboxID string) (approvals.Entry, error) {
	if s.approvals == nil {
		return approvals.Entry{}, errors.New("approval store is unavailable")
	}
	entry, ok := s.approvals.Get(approvalID)
	if !ok {
		return approvals.Entry{}, core.ErrNotFound
	}
	if sandboxID != "" && entry.SandboxID != sandboxID {
		return approvals.Entry{}, core.ErrNotFound
	}
	return entry, nil
}

// RespondApproval records a host-side decision. DENY is always allowed for a
// pending approval. APPROVE and EXACT persist require the trusted provider;
// without one they fail closed with ErrApprovalProviderUnavailable and never
// downgrade to ONCE or a silent DENY.
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
	if decision == localv1.ApprovalDecision_APPROVAL_DECISION_APPROVE ||
		persist == localv1.ApprovalPersistScope_APPROVAL_PERSIST_SCOPE_EXACT {
		if s.approvalProvider == nil {
			emitPlatformUnsupported(ctx, events.PlatformUnsupportedCapabilityApprovalprovidermissing)
			emitApprovalResponded(ctx, approvalID, decision, persist,
				events.ApprovalRespondedResultFailedPrecondition, events.OutcomeDenied)
			return approvals.Entry{}, "", ErrApprovalProviderUnavailable
		}
	}
	if decision == localv1.ApprovalDecision_APPROVAL_DECISION_APPROVE {
		if err := s.approvalProvider.Approve(ctx, entry); err != nil {
			denied, _ := s.approvals.Resolve(approvalID, localv1.ApprovalDecision_APPROVAL_DECISION_DENY,
				localv1.ApprovalPersistScope_APPROVAL_PERSIST_SCOPE_ONCE)
			_ = denied
			emitApprovalResponded(ctx, approvalID, localv1.ApprovalDecision_APPROVAL_DECISION_DENY,
				localv1.ApprovalPersistScope_APPROVAL_PERSIST_SCOPE_ONCE,
				events.ApprovalRespondedResultOk, events.OutcomeDenied)
			return approvals.Entry{}, "", fmt.Errorf("%w: %w", ErrApprovalDenied, err)
		}
	}
	updated, err := s.approvals.Resolve(approvalID, decision, persist)
	if err != nil {
		return approvals.Entry{}, "", err
	}
	emitApprovalResponded(ctx, approvalID, decision, persist, events.ApprovalRespondedResultOk, respondedOutcome(decision))
	// EXACT rule storage lands with the governance provider slice; until then
	// the decision is recorded but no rule ID is returned.
	slog.Info("approval decision recorded", "approval_id", approvalID, "kind", entry.Kind, "decision", decision, "persist_scope", persist)
	return updated, "", nil
}

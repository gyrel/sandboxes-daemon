package service

import (
	"context"
	"log/slog"

	localv1 "github.com/gyrel/sandboxes-api/gen/go/sandboxes/local/v1"
	"github.com/gyrel/sandboxes-core/ids"
	"github.com/gyrel/slogx/events"

	"github.com/gyrel/sandboxes-daemon/internal/approvals"
)

// emitApprovalRequested records one pending approval after creation. Entries
// carry no secret material by construction; only the store ID, the request
// class, the disclosure surface and the provider availability reach the
// catalog. Unrecognized classes are not emitted.
func emitApprovalRequested(ctx context.Context, entry approvals.Entry, provider events.ApprovalRequestedProvider) {
	var kind events.ApprovalRequestedKind
	switch entry.Kind {
	case localv1.ApprovalKind_APPROVAL_KIND_MCP_REGISTRATION:
		kind = events.ApprovalRequestedKindMCPRegister
	case localv1.ApprovalKind_APPROVAL_KIND_HOST_COMMAND:
		kind = events.ApprovalRequestedKindHostCommand
	case localv1.ApprovalKind_APPROVAL_KIND_OTHER:
		kind = events.ApprovalRequestedKindOther
	default:
		return
	}
	// The boundary names what the consent view discloses: a vault-reference
	// header list is a vault_refs disclosure, every other entry discloses at
	// most names and summaries (headers).
	boundary := events.ApprovalRequestedDisclosureBoundaryHeaders
	for _, header := range entry.Headers {
		if header != nil && len(header.VaultReferenceIds) > 0 {
			boundary = events.ApprovalRequestedDisclosureBoundaryVaultRefs
			break
		}
	}
	event, err := events.ApprovalRequested(events.OutcomeOK, events.ApprovalRequestedParams{
		ApprovalID: events.ID(entry.ID), Kind: kind, DisclosureBoundary: boundary, Provider: provider,
	})
	if err != nil {
		return
	}
	op, req := ids.FromContext(ctx)
	standard := events.Standard{}
	if ids.Validate(op) == nil {
		id := events.ID(op)
		standard.OpID = &id
	}
	if ids.Validate(req) == nil {
		id := events.ID(req)
		standard.ReqID = &id
	}
	event.Emit(ctx, slog.Default(), standard)
}

// emitApprovalResponded records one decision outcome for an approval. A
// missing trusted provider is still a response: the requested decision is
// emitted with result FAILED_PRECONDITION and the fail-closed error.
func emitApprovalResponded(ctx context.Context, approvalID string, decision localv1.ApprovalDecision,
	persist localv1.ApprovalPersistScope, result events.ApprovalRespondedResult, outcome events.Outcome) {
	catalog, ok := respondedDecision(decision, persist)
	if !ok {
		return
	}
	event, err := events.ApprovalResponded(outcome, events.ApprovalRespondedParams{
		ApprovalID: events.ID(approvalID), Decision: catalog, Result: result,
	})
	if err != nil {
		return
	}
	op, req := ids.FromContext(ctx)
	standard := events.Standard{}
	if ids.Validate(op) == nil {
		id := events.ID(op)
		standard.OpID = &id
	}
	if ids.Validate(req) == nil {
		id := events.ID(req)
		standard.ReqID = &id
	}
	event.Emit(ctx, slog.Default(), standard)
}

// respondedDecision maps the contract pair (decision, persist scope) onto the
// catalog decision: an APPROVE with EXACT persist is the EXACT rule decision.
func respondedDecision(decision localv1.ApprovalDecision, persist localv1.ApprovalPersistScope) (events.ApprovalRespondedDecision, bool) {
	switch decision {
	case localv1.ApprovalDecision_APPROVAL_DECISION_DENY:
		return events.ApprovalRespondedDecisionDeny, true
	case localv1.ApprovalDecision_APPROVAL_DECISION_APPROVE:
		if persist == localv1.ApprovalPersistScope_APPROVAL_PERSIST_SCOPE_EXACT {
			return events.ApprovalRespondedDecisionExact, true
		}
		return events.ApprovalRespondedDecisionApprove, true
	default:
		return "", false
	}
}

// respondedOutcome denies the outcome label for DENY responses and reports ok
// otherwise; the result field carries provider availability separately.
func respondedOutcome(decision localv1.ApprovalDecision) events.Outcome {
	if decision == localv1.ApprovalDecision_APPROVAL_DECISION_DENY {
		return events.OutcomeDenied
	}
	return events.OutcomeOK
}

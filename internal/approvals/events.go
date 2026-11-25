package approvals

import (
	"context"
	"log/slog"

	"github.com/gyrel/slogx/events"
)

// emitApprovalExpired records one resolved approval leaving the retention
// window. The sweep is store-internal and has no request context, so
// correlation IDs are omitted; the entry ID and its age at eviction are the
// only fields, and neither can carry secret material.
func emitApprovalExpired(id string, ttlMS uint64) {
	event, err := events.ApprovalExpired(events.OutcomeOK, events.ApprovalExpiredParams{
		ApprovalID: events.ID(id), TTLMs: ttlMS,
	})
	if err != nil {
		return
	}
	event.Emit(context.Background(), slog.Default(), events.Standard{})
}

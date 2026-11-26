package service

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"log/slog"

	"github.com/gyrel/sandboxes-core/ids"
	"github.com/gyrel/sandboxes-runtime/ctr"
	"github.com/gyrel/slogx/events"
)

// emitJournalFinding only emits recognized recovery reasons; raw journal IDs,
// resources and unknown reason strings must never become event fields.
func emitJournalFinding(ctx context.Context, f ctr.JournalFinding) {
	reasons := map[string]events.JournalRecoverFinding{
		"markerMissing":        events.JournalRecoverFindingMarkermissing,
		"markerMismatch":       events.JournalRecoverFindingMarkermismatch,
		"symlinkRefused":       events.JournalRecoverFindingSymlinkrefused,
		"outsideRoot":          events.JournalRecoverFindingOutsideroot,
		"parseFailed":          events.JournalRecoverFindingParsefailed,
		"tempOrphan":           events.JournalRecoverFindingTemporphan,
		"foreign":              events.JournalRecoverFindingForeignresource,
		"unsupportedOwnership": events.JournalRecoverFindingUnsupportedownership,
	}
	reason, ok := reasons[string(f.Reason)]
	if !ok {
		return
	}
	sum := sha256.Sum256([]byte(f.Resource))
	event, err := events.JournalRecover(events.OutcomeDenied, events.JournalRecoverParams{
		Finding: reason, Action: events.JournalRecoverActionLeave, ResourceKind: "unknown", PathHash: events.Hash(hex.EncodeToString(sum[:])),
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

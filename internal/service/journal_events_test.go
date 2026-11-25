package service

import (
	"bytes"
	"context"
	"log/slog"
	"strings"
	"testing"

	"github.com/rheic/sandboxes-core/ids"
	"github.com/rheic/sandboxes-runtime/ctr"
)

func TestJournalFindingEventsRedactInputs(t *testing.T) {
	var output bytes.Buffer
	previous := slog.Default()
	slog.SetDefault(slog.New(slog.NewJSONHandler(&output, nil)))
	t.Cleanup(func() { slog.SetDefault(previous) })
	ctx := ids.WithReqID(ids.WithOpID(context.Background(), ids.NewOpID()), ids.NewReqID())
	reasons := []ctr.JournalFinding{{Reason: "markerMissing"}, {Reason: "markerMismatch"}, {Reason: "symlinkRefused"}, {Reason: "outsideRoot"}, {Reason: "parseFailed"}, {Reason: "tempOrphan"}, {Reason: "foreign"}, {Reason: "unsupportedOwnership"}}
	for _, reason := range reasons {
		reason.ID = "synthetic-secret-id"
		reason.Resource = "synthetic-secret-path"
		emitJournalFinding(ctx, reason)
	}
	emitJournalFinding(ctx, ctr.JournalFinding{Reason: "synthetic-secret-reason"})
	got := output.String()
	if strings.Count(got, "rheic.journal.recover") != len(reasons)*2 {
		t.Fatalf("unexpected events: %s", got)
	}
	for _, secret := range []string{"synthetic-secret-id", "synthetic-secret-path", "synthetic-secret-reason"} {
		if strings.Contains(got, secret) {
			t.Fatalf("leaked %q", secret)
		}
	}
	op, req := ids.FromContext(ctx)
	if !strings.Contains(got, op) || !strings.Contains(got, req) {
		t.Fatal("missing correlation IDs")
	}
}

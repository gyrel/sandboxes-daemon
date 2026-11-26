package service

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/gyrel/sandboxes-core/ids"
	"github.com/gyrel/sandboxes-core/sandbox"
	"github.com/gyrel/sandboxes-runtime/ctr"

	"github.com/gyrel/sandboxes-daemon/internal/store"
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
	if strings.Count(got, "gyrel.journal.recover") != len(reasons)*2 {
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

func TestReconcileEventCountsAndRedactsSandboxNames(t *testing.T) {
	var output bytes.Buffer
	previous := slog.Default()
	slog.SetDefault(slog.New(slog.NewJSONHandler(&output, nil)))
	t.Cleanup(func() { slog.SetDefault(previous) })
	ctx := context.Background()
	st, err := store.Open(ctx, filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = st.Close() }()
	now := time.Unix(100, 0).UTC()
	for i, name := range []string{"canary-secret-sandbox-one", "canary-secret-sandbox-two"} {
		sb := sandbox.Sandbox{ID: []string{"sb-1", "sb-2"}[i], Name: name, State: sandbox.Running, Generation: 1, CreatedAt: now, UpdatedAt: now}
		if err := st.Create(ctx, sb); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := New(st, nil).Reconcile(ctx); err != nil {
		t.Fatal(err)
	}
	got := output.String()
	for _, name := range []string{"canary-secret-sandbox-one", "canary-secret-sandbox-two"} {
		if strings.Contains(got, name) {
			t.Errorf("sandbox name leaked: %s", got)
		}
	}
	count := 0
	for _, line := range strings.Split(strings.TrimSpace(got), "\n") {
		var record map[string]any
		if err := json.Unmarshal([]byte(line), &record); err != nil {
			t.Fatal(err)
		}
		if record["event"] != "gyrel.daemon.reconcile" {
			continue
		}
		count++
		for field, want := range map[string]float64{"scanned": 2, "adopted": 0, "left_alone": 0, "generation_mismatch": 0} {
			if record[field] != want {
				t.Errorf("%s = %v, want %v", field, record[field], want)
			}
		}
	}
	if count != 1 {
		t.Errorf("reconcile event count = %d, want 1", count)
	}
}

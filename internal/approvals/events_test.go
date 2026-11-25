package approvals

import (
	"bytes"
	"log/slog"
	"strings"
	"testing"
	"time"

	localv1 "github.com/rheic/sandboxes-api/gen/go/sandboxes/local/v1"
)

func TestApprovalExpiredEventOnRetentionSweep(t *testing.T) {
	var output bytes.Buffer
	previous := slog.Default()
	slog.SetDefault(slog.New(slog.NewJSONHandler(&output, nil)))
	t.Cleanup(func() { slog.SetDefault(previous) })
	now, clock := fixedClock(time.Date(2026, 11, 24, 0, 0, 0, 0, time.UTC))
	store := New(Config{Now: clock, Window: time.Minute})
	entry, err := store.Create(CreateRequest{
		Kind:          localv1.ApprovalKind_APPROVAL_KIND_OTHER,
		ActionSummary: "synthetic-action-summary-canary",
		EnvNames:      []string{"SYNTHETIC_ENV_NAME_CANARY"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.Resolve(entry.ID, localv1.ApprovalDecision_APPROVAL_DECISION_DENY,
		localv1.ApprovalPersistScope_APPROVAL_PERSIST_SCOPE_ONCE); err != nil {
		t.Fatal(err)
	}
	output.Reset()
	*now = now.Add(2 * time.Minute)
	if _, ok := store.Get(entry.ID); ok {
		t.Fatal("entry survived the retention window")
	}
	got := output.String()
	for _, want := range []string{
		`"event":"rheic.approval.expired"`, `"outcome":"ok"`,
		`"approval_id":"` + entry.ID + `"`, `"ttl_ms":120000`,
	} {
		if !strings.Contains(got, want) {
			t.Fatalf("missing %s in %s", want, got)
		}
	}
	for _, canary := range []string{"synthetic-action-summary-canary", "SYNTHETIC_ENV_NAME_CANARY"} {
		if strings.Contains(got, canary) {
			t.Fatalf("expiry event leaked %q: %s", canary, got)
		}
	}
}

func TestApprovalExpiredSkipsPendingEntries(t *testing.T) {
	var output bytes.Buffer
	previous := slog.Default()
	slog.SetDefault(slog.New(slog.NewJSONHandler(&output, nil)))
	t.Cleanup(func() { slog.SetDefault(previous) })
	now, clock := fixedClock(time.Date(2026, 11, 24, 0, 0, 0, 0, time.UTC))
	store := New(Config{Now: clock, Window: time.Minute})
	entry, err := store.Create(CreateRequest{Kind: localv1.ApprovalKind_APPROVAL_KIND_OTHER})
	if err != nil {
		t.Fatal(err)
	}
	*now = now.Add(time.Hour)
	output.Reset()
	if _, ok := store.Get(entry.ID); !ok {
		t.Fatal("pending entry was swept")
	}
	if strings.Contains(output.String(), "rheic.approval.expired") {
		t.Fatalf("pending entry expired: %s", output.String())
	}
}

package service

import (
	"context"
	"errors"
	"path/filepath"
	"strings"
	"testing"

	"github.com/rheic/sandboxes-core/sandbox"
	runtime "github.com/rheic/sandboxes-runtime"
	"github.com/rheic/slogx/events"

	"github.com/rheic/sandboxes-daemon/internal/store"
)

func TestTemplateSaveEventsReportComputedFields(t *testing.T) {
	svc, fake := templateFixture(t)
	sb := seedSandbox(t, svc, "tpl-evt", "alpine:3.22", sandbox.Stopped, nil)
	output := captureLogs(t)
	ctx := correlationContext()
	if _, err := svc.TemplateSave(ctx, sb.ID, "evt:v1", filepath.Join(t.TempDir(), "synthetic-export-path-canary")); err != nil {
		t.Fatal(err)
	}
	if len(fake.saved) != 1 {
		t.Fatalf("saved=%d", len(fake.saved))
	}
	got := output.String()
	for _, want := range []string{
		`"event":"rheic.template.save"`, `"outcome":"ok"`,
		`"template_id":"docker.io/library/evt:v1"`, `"layers":3`, `"bytes":4096`, `"digest":"sha256:aa"`,
	} {
		if !strings.Contains(got, want) {
			t.Fatalf("missing %s in %s", want, got)
		}
	}
	if strings.Contains(got, "synthetic-export-path-canary") {
		t.Fatalf("output path leaked: %s", got)
	}
}

func TestTemplateSaveEventOutcomes(t *testing.T) {
	svc, fake := templateFixture(t)
	sb := seedSandbox(t, svc, "tpl-evt-fail", "alpine:3.22", sandbox.Running, nil)
	output := captureLogs(t)
	ctx := correlationContext()
	fake.failSave = errors.New("synthetic save explosion")
	if _, err := svc.TemplateSave(ctx, sb.ID, "t:v1", ""); err == nil {
		t.Fatal("failing save accepted")
	}
	got := output.String()
	if !strings.Contains(got, `"event":"rheic.template.save"`) || !strings.Contains(got, `"outcome":"failed"`) {
		t.Fatalf("failed save not recorded: %s", got)
	}
	if strings.Contains(got, "synthetic save explosion") {
		t.Fatalf("backend error text leaked: %s", got)
	}
}

func TestTemplateSaveUnsupportedEvent(t *testing.T) {
	output := captureLogs(t)
	st, err := store.Open(context.Background(), filepath.Join(t.TempDir(), "unsupported.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = st.Close() }()
	svc := New(st, &fakeRuntime{})
	if _, err := svc.TemplateSave(correlationContext(), "missing", "t:v1", ""); err == nil {
		t.Fatal("unsupported backend accepted")
	}
	got := output.String()
	if !strings.Contains(got, `"event":"rheic.template.save"`) || !strings.Contains(got, `"outcome":"unsupported"`) {
		t.Fatalf("unsupported save not recorded: %s", got)
	}
}

func TestTemplateLoadEventReportsComputedFields(t *testing.T) {
	svc, _ := templateFixture(t)
	output := captureLogs(t)
	ctx := correlationContext()
	if _, err := svc.TemplateLoad(ctx, filepath.Join(t.TempDir(), "synthetic-tar-canary.tar"), ""); err != nil {
		t.Fatal(err)
	}
	got := output.String()
	for _, want := range []string{
		`"event":"rheic.template.load"`, `"outcome":"ok"`,
		`"template_id":"docker.io/library/from-archive:v1"`, `"layers":2`, `"bytes":100`, `"digest":"sha256:beef"`,
	} {
		if !strings.Contains(got, want) {
			t.Fatalf("missing %s in %s", want, got)
		}
	}
	if strings.Contains(got, "synthetic-tar-canary") {
		t.Fatalf("archive path leaked: %s", got)
	}
}

func TestTemplateEventZeroFieldsAreOmittedValues(t *testing.T) {
	// Whiteouts, opaque dirs and warning flags are not computed by the save
	// flow; the catalog records them at their zero values, never re-derived.
	output := captureLogs(t)
	ctx := correlationContext()
	emitTemplateSaved(ctx, events.OutcomeOK, runtime.TemplateInfo{Name: "t:v1", Layers: 1})
	got := output.String()
	if !strings.Contains(got, `"whiteouts":0`) || !strings.Contains(got, `"opaque_dirs":0`) ||
		!strings.Contains(got, `"host_workspace_included":false`) || !strings.Contains(got, `"guest_secrets_warning":false`) {
		t.Fatalf("zero fields missing: %s", got)
	}
}

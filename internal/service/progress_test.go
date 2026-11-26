package service

import (
	"context"
	"errors"
	"path/filepath"
	"testing"

	"github.com/gyrel/sandboxes-core/sandbox"
	runtimeapi "github.com/gyrel/sandboxes-runtime"

	"github.com/gyrel/sandboxes-daemon/internal/store"
)

func TestCreateProgressStoreRoundTrip(t *testing.T) {
	st, err := store.Open(context.Background(), filepath.Join(t.TempDir(), "progress.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	svc := New(st, nil)
	if _, ok := svc.CreateProgress("sb_missing"); ok {
		t.Fatal("unknown id must report no progress")
	}
	svc.setCreateProgress("sb_x", CreateProgressSnapshot{Phase: "pulling", Completed: 2, Total: 9})
	snapshot, ok := svc.CreateProgress("sb_x")
	if !ok || snapshot.Phase != "pulling" || snapshot.Completed != 2 || snapshot.Total != 9 {
		t.Fatalf("round trip=%+v ok=%v", snapshot, ok)
	}
	svc.clearCreateProgress("sb_x")
	if _, ok := svc.CreateProgress("sb_x"); ok {
		t.Fatal("cleared id must report no progress")
	}
}

// TestCreateReportsTransientProgress walks the whole lifecycle: the durable
// creating row exists before the runtime call, OnProgress becomes observable
// through CreateProgress while Create blocks, and the snapshot is gone once
// Create returns.
func TestCreateReportsTransientProgress(t *testing.T) {
	st, err := store.Open(context.Background(), filepath.Join(t.TempDir(), "progress.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	backend := &fakeRuntime{}
	svc := New(st, backend)
	ctx := context.Background()

	type observation struct {
		found    bool
		snapshot CreateProgressSnapshot
	}
	observed := make(chan observation, 1)
	backend.afterCreate = func() {
		backend.lastConfig.OnProgress(runtimeapi.ProgressUpdate{Phase: "pulling", Completed: 5, Total: 7})
		items, _, err := svc.List(ctx, sandbox.ListOptions{PageSize: 10})
		if err != nil || len(items) != 1 {
			observed <- observation{}
			return
		}
		snapshot, ok := svc.CreateProgress(items[0].ID)
		observed <- observation{found: ok, snapshot: snapshot}
	}

	op, err := svc.Create(ctx, CreateRequest{Name: "progress-demo", Image: "img", Workspace: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	got := <-observed
	if !got.found || got.snapshot.Phase != "pulling" || got.snapshot.Completed != 5 || got.snapshot.Total != 7 {
		t.Fatalf("mid-create observation=%+v", got)
	}
	if _, ok := svc.CreateProgress(op.SandboxID); ok {
		t.Fatal("progress must be cleared after create returns")
	}
}

// failingProgressRuntime reports progress and then fails Create, exercising
// the abort path's progress cleanup.
type failingProgressRuntime struct{ fakeRuntime }

func (f *failingProgressRuntime) Create(_ context.Context, cfg runtimeapi.Config) (runtimeapi.Handle, error) {
	if cfg.OnProgress != nil {
		cfg.OnProgress(runtimeapi.ProgressUpdate{Phase: "pulling", Completed: 1, Total: 4})
	}
	return runtimeapi.Handle{}, errors.New("simulated pull failure")
}

func TestCreateAbortClearsProgress(t *testing.T) {
	st, err := store.Open(context.Background(), filepath.Join(t.TempDir(), "progress-abort.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	svc := New(st, &failingProgressRuntime{})
	ctx := context.Background()
	if _, err := svc.Create(ctx, CreateRequest{Name: "abort-demo", Image: "img", Workspace: t.TempDir()}); err == nil {
		t.Fatal("expected create failure")
	}
	items, _, err := svc.List(ctx, sandbox.ListOptions{PageSize: 10})
	if err != nil {
		t.Fatal(err)
	}
	for _, item := range items {
		if _, ok := svc.CreateProgress(item.ID); ok {
			t.Fatalf("aborted sandbox %s still reports progress", item.ID)
		}
	}
}

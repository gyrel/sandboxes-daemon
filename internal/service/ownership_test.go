package service

import (
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/gyrel/sandboxes-core/operation"
	"github.com/gyrel/sandboxes-core/sandbox"

	"github.com/gyrel/sandboxes-daemon/internal/machinecode"
	"github.com/gyrel/sandboxes-daemon/internal/store"
)

func checkOwnershipReason(t *testing.T, err error, want machinecode.Code) {
	t.Helper()
	got, _ := machinecode.Of(err)
	if got != want || (want == "") != (err == nil) {
		t.Fatalf("reason %q, error %v; want %q", got, err, want)
	}
}

func TestOwnershipCorpus(t *testing.T) {
	for i := range 40 {
		kind := i % 10
		t.Run(fmt.Sprintf("row-%02d", i), func(t *testing.T) {
			ctx := t.Context()
			root := t.TempDir()
			path := filepath.Join(root, "sandboxes.db")
			st, err := store.Open(ctx, path)
			if err != nil {
				t.Fatal(err)
			}
			defer st.Close()
			svc := New(st, nil)
			defer svc.Close()
			id := fmt.Sprintf("sb-%02d", i)
			if kind == 5 {
				id = "../" + id
			}
			sb := sandbox.Sandbox{ID: id, Name: "inventory", State: sandbox.Running, Generation: 1}
			op := operation.Operation{ID: "interrupted", SandboxID: id, Kind: operation.KindStop, State: operation.Pending}
			if err := st.CreateSandboxWithOperation(ctx, sb, op); err != nil {
				t.Fatal(err)
			}
			db, err := sql.Open("sqlite", "file:"+path)
			if err != nil {
				t.Fatal(err)
			}
			defer db.Close()
			var want machinecode.Code
			var stmt string
			switch kind {
			case 0, 1:
			case 2:
				stmt = "UPDATE sandboxes SET owner_uid=owner_uid+1"
				want = machinecode.NotOwned
			case 3:
				stmt = "UPDATE sandboxes SET install_id='aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'"
				want = machinecode.NotOwned
			case 4:
				stmt = "UPDATE sandboxes SET ports='[{\"bogus\":true}]'"
				want = machinecode.UnknownState
			case 5:
				want = machinecode.PathEscape
			case 6:
				if err := os.Mkdir(filepath.Join(root, "sandboxes"), 0700); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(t.TempDir(), filepath.Join(root, "sandboxes", id)); err != nil {
					t.Fatal(err)
				}
				want = machinecode.PathEscape
			case 7:
				stmt = "UPDATE sandboxes SET state='invalid'"
				want = machinecode.UnknownState
			case 8:
				stmt = "UPDATE sandboxes SET owner_uid='broken'"
				want = machinecode.UnknownState
			case 9:
				stmt = "UPDATE sandboxes SET install_id=''"
				want = machinecode.UnknownState
			}
			if stmt != "" {
				if _, err = db.ExecContext(ctx, stmt); err != nil {
					t.Fatal(err)
				}
			}
			_, err = st.Get(ctx, id)
			checkOwnershipReason(t, err, want)
			rows, _, hidden, err := svc.ListWithHiddenCount(ctx, sandbox.ListOptions{})
			if err != nil || (len(rows) == 1) != (want == "") || hidden+len(rows) != 1 {
				t.Fatalf("list count %d, err %v", len(rows), err)
			}
			svc.backend = recoveringBackend{}
			_, err = svc.RecoverRuntimeJournal(ctx)
			checkOwnershipReason(t, err, want)
			svc.backend = nil
			changed, err := svc.Reconcile(ctx)
			if err != nil || (changed == 2) != (want == "") || (want != "" && changed != 0) {
				t.Fatalf("reconcile changed %d, err %v", changed, err)
			}
			recovered, err := st.Operations().Get(ctx, op.ID)
			if err != nil || (recovered.State == operation.Failed) != (want == "") {
				t.Fatalf("recovered operation %v, err %v", recovered.State, err)
			}
			_, err = svc.Stop(ctx, id)
			checkOwnershipReason(t, err, want)
			_, err = svc.UpdatePorts(ctx, id, nil)
			checkOwnershipReason(t, err, want)
			_, err = svc.Delete(ctx, id, true)
			checkOwnershipReason(t, err, want)
		})
	}
}

func TestOwnershipCopiedDatabase(t *testing.T) {
	ctx := t.Context()
	path := filepath.Join(t.TempDir(), "sandboxes.db")
	st, err := store.Open(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	ids := []string{"sb-first", "sb-second", "sb-third"}
	for _, id := range ids {
		if err := st.Create(ctx, sandbox.Sandbox{ID: id, Name: id, State: sandbox.Stopped, Labels: map[string]string{"team": "platform"}}); err != nil {
			t.Fatal(err)
		}
	}
	if err := st.Close(); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	destination := filepath.Join(t.TempDir(), "sandboxes.db")
	if err := os.WriteFile(destination, data, 0600); err != nil {
		t.Fatal(err)
	}
	copied, err := store.Open(ctx, destination)
	if err != nil {
		t.Fatal(err)
	}
	defer copied.Close()
	svc := New(copied, nil)
	defer svc.Close()
	for _, id := range ids {
		_, err := svc.Stop(ctx, id)
		checkOwnershipReason(t, err, machinecode.NotOwned)
		_, err = svc.Delete(ctx, id, true)
		checkOwnershipReason(t, err, machinecode.NotOwned)
	}
}

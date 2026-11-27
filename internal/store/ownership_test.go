package store

import (
	"database/sql"
	"os"
	"path/filepath"
	"testing"

	"github.com/gyrel/sandboxes-core/sandbox"

	"github.com/gyrel/sandboxes-daemon/internal/lifecycle"
)

func TestOwnershipMigration(t *testing.T) {
	ctx := t.Context()
	root := t.TempDir()
	path := filepath.Join(root, "sandboxes.db")
	st, err := Open(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	if userVersion(t, path) != schemaVersion {
		t.Fatal("fresh schema version")
	}
	for _, id := range []string{"first", "second"} {
		if err := st.Create(ctx, sandbox.Sandbox{ID: id, Name: id, State: sandbox.Stopped}); err != nil {
			t.Fatal(err)
		}
	}
	_, err = st.db.ExecContext(ctx, `ALTER TABLE sandboxes DROP COLUMN owner_uid;
 ALTER TABLE sandboxes DROP COLUMN install_id;
 ALTER TABLE sandboxes DROP COLUMN labels;
 PRAGMA user_version=7;
 CREATE TRIGGER fail_backfill BEFORE UPDATE ON sandboxes BEGIN SELECT RAISE(ABORT,'fixture'); END`)
	if err != nil {
		t.Fatal(err)
	}
	if err := st.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(ctx, path); err == nil {
		t.Fatal("expected migration failure")
	}
	raw, err := sql.Open("sqlite", "file:"+path)
	if err != nil {
		t.Fatal(err)
	}
	defer raw.Close()
	var n int
	if err := raw.QueryRowContext(ctx, "SELECT COUNT(*) FROM pragma_table_info('sandboxes') WHERE name IN ('owner_uid','install_id')").Scan(&n); err != nil || n != 0 || userVersion(t, path) != 7 {
		t.Fatalf("rollback columns %d, err %v", n, err)
	}
	if _, err := raw.ExecContext(ctx, "DROP TRIGGER fail_backfill"); err != nil {
		t.Fatal(err)
	}
	upgraded, err := Open(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	defer upgraded.Close()
	install, err := lifecycle.EnsureInstallationID(root)
	if err != nil {
		t.Fatal(err)
	}
	if err := raw.QueryRowContext(ctx, "SELECT COUNT(*) FROM sandboxes WHERE owner_uid=? AND install_id=?", os.Geteuid(), install).Scan(&n); err != nil || n != 2 {
		t.Fatalf("backfilled %d, err %v", n, err)
	}
	rows, _, err := upgraded.List(ctx, sandbox.ListOptions{})
	if err != nil || len(rows) != 2 {
		t.Fatalf("owned rows %d, err %v", len(rows), err)
	}
	backups, err := filepath.Glob(path + ".pre-v7-*.bak")
	if err != nil || len(backups) == 0 || userVersion(t, backups[0]) != 7 {
		t.Fatalf("backups %v, err %v", backups, err)
	}
}

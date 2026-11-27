package store

import (
	"errors"
	"path/filepath"
	"testing"

	"github.com/gyrel/sandboxes-core/sandbox"
	"modernc.org/sqlite"

	"github.com/gyrel/sandboxes-daemon/internal/machinecode"
)

func TestLabelsMigration(t *testing.T) {
	ctx := t.Context()
	path := filepath.Join(t.TempDir(), "sandboxes.db")
	st, err := Open(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = st.Close() }()
	if err := st.Create(ctx, sandbox.Sandbox{ID: "legacy", Name: "legacy", State: sandbox.Stopped}); err != nil {
		t.Fatal(err)
	}
	if _, err := st.db.ExecContext(ctx, "ALTER TABLE sandboxes DROP COLUMN labels; PRAGMA user_version = 8"); err != nil {
		t.Fatal(err)
	}
	if err := st.prepareSchema(ctx, path); err != nil {
		t.Fatal(err)
	}

	// Let the ALTER succeed, then reject the schema marker on the same connection.
	conn, err := st.db.Conn(ctx)
	if err != nil {
		t.Fatal(err)
	}
	deniedVersionUpdate := false
	err = conn.Raw(func(driverConn any) error {
		return driverConn.(sqlite.AuthorizerRegisterer).RegisterAuthorizer(func(action sqlite.AuthorizerActionCode, arg1, arg2, _, _ string) sqlite.AuthorizerReturnCode {
			if action == sqlite.AuthPragma && arg1 == "user_version" && arg2 == "9" {
				deniedVersionUpdate = true
				return sqlite.AuthorizerDeny
			}
			return sqlite.AuthorizerOK
		})
	})
	if closeErr := conn.Close(); closeErr != nil || err != nil {
		t.Fatal(errors.Join(err, closeErr))
	}
	if err := st.migrate(ctx); err == nil || !deniedVersionUpdate {
		t.Fatalf("migration error = %v, reached version update = %t", err, deniedVersionUpdate)
	}
	var columns int
	if err := st.db.QueryRowContext(ctx, "SELECT count(*) FROM pragma_table_info('sandboxes') WHERE name = 'labels'").Scan(&columns); err != nil || columns != 0 {
		t.Fatalf("labels column count after rollback = %d, err = %v", columns, err)
	}
	backups, err := filepath.Glob(path + ".pre-v8-*.bak")
	if err != nil || len(backups) != 1 || userVersion(t, backups[0]) != 8 || userVersion(t, path) != 8 {
		t.Fatalf("failed migration backups = %v, err = %v", backups, err)
	}
	if err := st.Close(); err != nil {
		t.Fatal(err)
	}

	upgraded, err := Open(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = upgraded.Close() }()
	sb, err := upgraded.Get(ctx, "legacy")
	if err != nil || sb.Labels != nil || userVersion(t, path) != 9 {
		t.Fatalf("upgraded row labels = %v, err = %v", sb.Labels, err)
	}
}

func TestCorruptStoredLabelsFailClosed(t *testing.T) {
	ctx := t.Context()
	st, err := Open(ctx, filepath.Join(t.TempDir(), "sandboxes.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = st.Close() }()
	if err := st.Create(ctx, sandbox.Sandbox{ID: "fixture", Name: "fixture", State: sandbox.Stopped}); err != nil {
		t.Fatal(err)
	}

	for _, value := range []any{`{"team":`, `{"team":"dev"} {}`, `{"team":{"unknown":"dev"}}`,
		`{"team":null}`, `null`, `{"github_token":"dev"}`, []byte(`{"team":"dev"}`)} {
		if _, err := st.db.ExecContext(ctx, "UPDATE sandboxes SET labels=?, install_id='foreign'", value); err != nil {
			t.Fatal(err)
		}
		_, getErr := st.Get(ctx, "fixture")
		for _, decodeErr := range []error{getErr, st.CheckRecoveryInventory(ctx)} {
			if reason, _ := machinecode.Of(decodeErr); reason != machinecode.UnknownState {
				t.Fatalf("corruption %q: expected UNKNOWN_STATE before ownership, got %v", value, decodeErr)
			}
		}
		items, _, hidden, err := st.ListWithHiddenCount(ctx, sandbox.ListOptions{})
		if err != nil || len(items) != 0 || hidden != 1 {
			t.Fatalf("corruption %q: items = %d, hidden = %d, err = %v", value, len(items), hidden, err)
		}
	}
}

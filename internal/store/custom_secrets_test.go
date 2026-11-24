package store

import (
	"context"
	"database/sql"
	"errors"
	"path/filepath"
	"testing"

	core "github.com/rheic/sandboxes-core"
)

func userVersion(t *testing.T, path string) int {
	t.Helper()
	db, err := sql.Open("sqlite", "file:"+path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()
	var version int
	if err := db.QueryRowContext(context.Background(), `PRAGMA user_version`).Scan(&version); err != nil {
		t.Fatal(err)
	}
	return version
}

func tableExists(t *testing.T, path, name string) bool {
	t.Helper()
	db, err := sql.Open("sqlite", "file:"+path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()
	var count int
	if err := db.QueryRowContext(context.Background(), `SELECT count(*) FROM sqlite_master WHERE type='table' AND name=?`, name).Scan(&count); err != nil {
		t.Fatal(err)
	}
	return count == 1
}

func TestCustomSecretMigrationUpgradesV6WithBackup(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "sandboxes.db")
	st, err := Open(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.db.ExecContext(ctx, `DROP TABLE custom_secret_index`); err != nil {
		t.Fatal(err)
	}
	if _, err := st.db.ExecContext(ctx, `PRAGMA user_version = 6`); err != nil {
		t.Fatal(err)
	}
	if err := st.Close(); err != nil {
		t.Fatal(err)
	}

	upgraded, err := Open(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = upgraded.Close() }()
	if got := userVersion(t, path); got != 7 {
		t.Fatalf("schema version = %d, want 7", got)
	}
	if !tableExists(t, path, "custom_secret_index") {
		t.Fatal("custom_secret_index was not created")
	}
	backups, err := filepath.Glob(path + ".pre-v6-*.bak")
	if err != nil || len(backups) != 1 {
		t.Fatalf("pre-upgrade backups = %v, %v", backups, err)
	}
}

func TestCustomSecretMigrationRollsBackPartialFailureAndRetries(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "sandboxes.db")
	blocker, err := sql.Open("sqlite", "file:"+path)
	if err != nil {
		t.Fatal(err)
	}
	// The index name below collides with this table, so CREATE INDEX fails
	// after CREATE TABLE custom_secret_index has already run inside the migration.
	if _, err := blocker.ExecContext(ctx, `CREATE TABLE custom_secret_index_sandbox (x INTEGER)`); err != nil {
		t.Fatal(err)
	}
	if err := blocker.Close(); err != nil {
		t.Fatal(err)
	}

	if _, err := Open(ctx, path); err == nil {
		t.Fatal("migration succeeded despite a conflicting index name")
	}
	if tableExists(t, path, "custom_secret_index") {
		t.Fatal("partial migration left custom_secret_index behind")
	}
	if got := userVersion(t, path); got == schemaVersion {
		t.Fatalf("failed migration recorded schema version %d", got)
	}

	cleanup, err := sql.Open("sqlite", "file:"+path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := cleanup.ExecContext(ctx, `DROP TABLE custom_secret_index_sandbox`); err != nil {
		t.Fatal(err)
	}
	if err := cleanup.Close(); err != nil {
		t.Fatal(err)
	}
	retried, err := Open(ctx, path)
	if err != nil {
		t.Fatalf("retry after removing the conflict failed: %v", err)
	}
	defer func() { _ = retried.Close() }()
	if !tableExists(t, path, "custom_secret_index") || userVersion(t, path) != schemaVersion {
		t.Fatal("retry did not complete the migration")
	}
}

func TestCustomSecretIndexIsolatesSandboxesAndKeepsCreatedAt(t *testing.T) {
	ctx := context.Background()
	st, err := Open(ctx, filepath.Join(t.TempDir(), "sandboxes.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = st.Close() }()

	base := CustomSecretIndex{Service: "api.example.test", Scope: "global", EnvName: "EXAMPLE_KEY",
		Hosts: []string{"api.example.test", "*.example.test"}, PlaceholderMasked: "************wxyz", Origin: "local"}
	if err := st.UpsertCustomSecretIndex(ctx, base); err != nil {
		t.Fatal(err)
	}
	first, err := st.GetCustomSecretIndex(ctx, base.Service, "global", "")
	if err != nil {
		t.Fatal(err)
	}
	sandbox := base
	sandbox.Scope, sandbox.SandboxName, sandbox.Service = "sandbox", "dev", "other.example.test"
	if err := st.UpsertCustomSecretIndex(ctx, sandbox); err != nil {
		t.Fatal(err)
	}
	other := sandbox
	other.SandboxName = "prod"
	if err := st.UpsertCustomSecretIndex(ctx, other); err != nil {
		t.Fatal(err)
	}

	visible, err := st.ListCustomSecretIndexForSandbox(ctx, "dev")
	if err != nil || len(visible) != 2 {
		t.Fatalf("dev visible = %+v, %v", visible, err)
	}
	for _, entry := range visible {
		if entry.Scope == "sandbox" && entry.SandboxName != "dev" {
			t.Fatalf("sandbox row for another sandbox visible: %+v", entry)
		}
	}
	if len(visible[0].Hosts) != 2 || visible[0].Hosts[1] != "*.example.test" {
		t.Fatalf("hosts did not round-trip: %+v", visible[0].Hosts)
	}

	base.EnvName = "ROTATED_KEY"
	if err := st.UpsertCustomSecretIndex(ctx, base); err != nil {
		t.Fatal(err)
	}
	updated, err := st.GetCustomSecretIndex(ctx, base.Service, "global", "")
	if err != nil || updated.EnvName != "ROTATED_KEY" || !updated.CreatedAt.Equal(first.CreatedAt) {
		t.Fatalf("update changed created_at or env: %+v, %v", updated, err)
	}

	if _, err := st.GetCustomSecretIndex(ctx, "missing.example.test", "global", ""); !errors.Is(err, core.ErrNotFound) {
		t.Fatalf("missing row err = %v", err)
	}
	if err := st.DeleteCustomSecretIndex(ctx, base.Service, "global", ""); err != nil {
		t.Fatal(err)
	}
	if err := st.DeleteCustomSecretIndex(ctx, base.Service, "global", ""); err != nil {
		t.Fatalf("second delete not idempotent: %v", err)
	}
	all, err := st.ListCustomSecretIndex(ctx)
	if err != nil || len(all) != 2 {
		t.Fatalf("list after delete = %d, %v", len(all), err)
	}
}

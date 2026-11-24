package store

import (
	"context"
	"database/sql"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestOpenMigratesLegacySchemaWithBackup(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "sandboxes.db")
	legacy, err := sql.Open("sqlite", "file:"+path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := legacy.ExecContext(ctx, `CREATE TABLE legacy_marker (value TEXT NOT NULL)`); err != nil {
		t.Fatal(err)
	}
	if _, err := legacy.ExecContext(ctx, `INSERT INTO legacy_marker(value) VALUES ('pre-upgrade')`); err != nil {
		t.Fatal(err)
	}
	if _, err := legacy.ExecContext(ctx, `PRAGMA user_version = 0`); err != nil {
		t.Fatal(err)
	}
	if err := legacy.Close(); err != nil {
		t.Fatal(err)
	}

	st, err := Open(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	if err := st.Close(); err != nil {
		t.Fatal(err)
	}

	matches, err := filepath.Glob(path + ".pre-v0-*.bak")
	if err != nil || len(matches) != 1 {
		t.Fatalf("backups = %v, %v", matches, err)
	}
	info, err := os.Stat(matches[0])
	if err != nil {
		t.Fatal(err)
	}
	if runtime.GOOS != "windows" && info.Mode().Perm() != 0o600 {
		t.Fatalf("backup mode = %v", info.Mode().Perm())
	}

	db, err := sql.Open("sqlite", "file:"+path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()
	var version int
	if err := db.QueryRowContext(ctx, `PRAGMA user_version`).Scan(&version); err != nil {
		t.Fatal(err)
	}
	if version != schemaVersion {
		t.Fatalf("schema version = %d", version)
	}

	backup, err := sql.Open("sqlite", "file:"+matches[0])
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = backup.Close() }()
	var value string
	if err := backup.QueryRowContext(ctx, `SELECT value FROM legacy_marker`).Scan(&value); err != nil {
		t.Fatal(err)
	}
	if value != "pre-upgrade" {
		t.Fatalf("backup value = %q", value)
	}
	var backupVersion int
	if err := backup.QueryRowContext(ctx, `PRAGMA user_version`).Scan(&backupVersion); err != nil {
		t.Fatal(err)
	}
	if backupVersion != 0 {
		t.Fatalf("backup schema version = %d", backupVersion)
	}
}

func TestSchemaUpgradeAddsSecretMetadataColumns(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "sandboxes.db")
	db, err := sql.Open("sqlite", "file:"+path)
	if err != nil {
		t.Fatal(err)
	}
	for _, statement := range []string{
		`CREATE TABLE service_secret_index (
			service TEXT NOT NULL,
			scope TEXT NOT NULL,
			sandbox_name TEXT NOT NULL DEFAULT '',
			updated_at INTEGER NOT NULL,
			PRIMARY KEY (service, scope, sandbox_name)
		)`,
		`CREATE TABLE registry_credential_index (
			registry TEXT NOT NULL,
			scope TEXT NOT NULL,
			sandbox_name TEXT NOT NULL DEFAULT '',
			username TEXT NOT NULL,
			PRIMARY KEY (registry, scope, sandbox_name)
		)`,
		`INSERT INTO service_secret_index(service, scope, sandbox_name, updated_at) VALUES ('github','global','',1700000000)`,
		`PRAGMA user_version = 4`,
	} {
		if _, err := db.ExecContext(ctx, statement); err != nil {
			t.Fatal(err)
		}
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}

	st, err := Open(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = st.Close() }()
	items, err := st.ListServiceSecretIndex(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(items) != 1 || items[0].CreatedAt.Unix() != 1700000000 || items[0].UpdatedAt.Unix() != 1700000000 ||
		items[0].SourceKind != "" || items[0].Origin != "" {
		t.Fatalf("migrated service secret index=%+v", items)
	}
	credentials, err := st.ListRegistryCredentialIndex(ctx)
	if err != nil || len(credentials) != 0 {
		t.Fatalf("migrated registry credential index=%+v err=%v", credentials, err)
	}
}

func TestOpenRefusesNewerSchema(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "sandboxes.db")
	db, err := sql.Open("sqlite", "file:"+path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(ctx, `PRAGMA user_version = 99`); err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(ctx, path); !errors.Is(err, ErrSchemaNewer) {
		t.Fatalf("Open error = %v, want ErrSchemaNewer", err)
	}
}

func TestCloneSchemaUpgradeRejectsOlderDaemon(t *testing.T) {
	if schemaVersion != 7 {
		t.Fatalf("schema version = %d, want 7 for custom secret index", schemaVersion)
	}
	if err := schemaVersionCompatibilityError(schemaVersion, 4); !errors.Is(err, ErrSchemaNewer) {
		t.Fatalf("older daemon compatibility error = %v, want ErrSchemaNewer", err)
	}

	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "sandboxes.db")
	db, err := sql.Open("sqlite", "file:"+path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(ctx, `CREATE TABLE legacy_marker (value TEXT NOT NULL)`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(ctx, `PRAGMA user_version = 3`); err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	st, err := Open(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	if err := st.Close(); err != nil {
		t.Fatal(err)
	}
	matches, err := filepath.Glob(path + ".pre-v3-*.bak")
	if err != nil || len(matches) != 1 {
		t.Fatalf("version 3 backups = %v, %v", matches, err)
	}
}

func TestBackupRestoresPreUpgradeDatabase(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "sandboxes.db")
	legacy, err := sql.Open("sqlite", "file:"+path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := legacy.ExecContext(ctx, `CREATE TABLE legacy_marker (value TEXT NOT NULL)`); err != nil {
		t.Fatal(err)
	}
	if _, err := legacy.ExecContext(ctx, `INSERT INTO legacy_marker(value) VALUES ('rollback')`); err != nil {
		t.Fatal(err)
	}
	if err := legacy.Close(); err != nil {
		t.Fatal(err)
	}

	st, err := Open(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	if err := st.Close(); err != nil {
		t.Fatal(err)
	}
	matches, err := filepath.Glob(path + ".pre-v0-*.bak")
	if err != nil || len(matches) != 1 {
		t.Fatalf("backups = %v, %v", matches, err)
	}
	data, err := os.ReadFile(matches[0])
	if err != nil {
		t.Fatal(err)
	}
	if len(data) == 0 || !strings.HasPrefix(string(data), "SQLite format 3") {
		t.Fatal("backup is not a SQLite database")
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	rolledBack, err := sql.Open("sqlite", "file:"+path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = rolledBack.Close() }()
	var value string
	if err := rolledBack.QueryRowContext(ctx, `SELECT value FROM legacy_marker`).Scan(&value); err != nil {
		t.Fatal(err)
	}
	if value != "rollback" {
		t.Fatalf("restored value = %q", value)
	}
}

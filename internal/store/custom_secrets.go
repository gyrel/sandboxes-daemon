package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	core "github.com/gyrel/sandboxes-core"
)

// CustomSecretIndex is the non-secret inventory row of one custom secret. It
// stores host patterns, the environment name and a masked placeholder only. The
// value and the full placeholder live in the host keychain.
type CustomSecretIndex struct {
	Service           string
	Scope             string
	SandboxName       string
	EnvName           string
	Hosts             []string
	PlaceholderMasked string
	Refresh           string
	Origin            string
	CreatedAt         time.Time
	UpdatedAt         time.Time
}

// customSecretSchemaStatements is applied in one transaction. A failure rolls
// the whole table back, so a daemon that stops mid-migration retries cleanly
// on the next start instead of seeing a half-built index.
func customSecretSchemaStatements() []string {
	return []string{
		`CREATE TABLE IF NOT EXISTS custom_secret_index (
			service TEXT NOT NULL,
			scope TEXT NOT NULL,
			sandbox_name TEXT NOT NULL DEFAULT '',
			env_name TEXT NOT NULL DEFAULT '',
			hosts TEXT NOT NULL DEFAULT '[]',
			placeholder_masked TEXT NOT NULL DEFAULT '',
			refresh TEXT NOT NULL DEFAULT '',
			origin TEXT NOT NULL DEFAULT '',
			created_at INTEGER NOT NULL DEFAULT 0,
			updated_at INTEGER NOT NULL DEFAULT 0,
			PRIMARY KEY (service, scope, sandbox_name)
		)`,
		`CREATE INDEX IF NOT EXISTS custom_secret_index_sandbox
			ON custom_secret_index(sandbox_name)`,
	}
}

// migrateCustomSecrets creates the custom secret index atomically.
func (s *Store) migrateCustomSecrets(ctx context.Context) (err error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin custom secret migration: %w", err)
	}
	defer func() {
		if err != nil {
			_ = tx.Rollback()
		}
	}()
	for _, stmt := range customSecretSchemaStatements() {
		if _, err = tx.ExecContext(ctx, stmt); err != nil {
			return fmt.Errorf("migrate custom secrets: %w", err)
		}
	}
	if err = tx.Commit(); err != nil {
		return fmt.Errorf("commit custom secret migration: %w", err)
	}
	return nil
}

// UpsertCustomSecretIndex records or updates one custom secret row. CreatedAt is
// kept from the first write, matching service secret inventory semantics.
func (s *Store) UpsertCustomSecretIndex(ctx context.Context, entry CustomSecretIndex) error {
	now := time.Now().UTC()
	if entry.CreatedAt.IsZero() {
		entry.CreatedAt = now
	}
	if entry.UpdatedAt.IsZero() {
		entry.UpdatedAt = now
	}
	hosts, err := json.Marshal(entry.Hosts)
	if err != nil {
		return fmt.Errorf("encode custom secret hosts: %w", err)
	}
	_, err = s.db.ExecContext(ctx, `INSERT INTO custom_secret_index
		(service, scope, sandbox_name, env_name, hosts, placeholder_masked, refresh, origin, created_at, updated_at)
		VALUES (?,?,?,?,?,?,?,?,?,?)
		ON CONFLICT(service, scope, sandbox_name) DO UPDATE SET
			env_name=excluded.env_name, hosts=excluded.hosts, placeholder_masked=excluded.placeholder_masked,
			refresh=excluded.refresh, origin=excluded.origin, updated_at=excluded.updated_at`,
		entry.Service, entry.Scope, entry.SandboxName, entry.EnvName, string(hosts), entry.PlaceholderMasked,
		entry.Refresh, entry.Origin, toUnix(entry.CreatedAt), toUnix(entry.UpdatedAt))
	if err != nil {
		return fmt.Errorf("record custom secret index: %w", err)
	}
	return nil
}

// GetCustomSecretIndex returns one row or core.ErrNotFound.
func (s *Store) GetCustomSecretIndex(ctx context.Context, service, scope, sandboxName string) (CustomSecretIndex, error) {
	row := s.db.QueryRowContext(ctx, `SELECT service, scope, sandbox_name, env_name, hosts, placeholder_masked,
		refresh, origin, created_at, updated_at
		FROM custom_secret_index WHERE service=? AND scope=? AND sandbox_name=?`, service, scope, sandboxName)
	entry, err := scanCustomSecretIndex(row)
	if errors.Is(err, sql.ErrNoRows) {
		return CustomSecretIndex{}, core.ErrNotFound
	}
	return entry, err
}

// DeleteCustomSecretIndex removes one row. Missing rows are not an error.
func (s *Store) DeleteCustomSecretIndex(ctx context.Context, service, scope, sandboxName string) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM custom_secret_index WHERE service=? AND scope=? AND sandbox_name=?`,
		service, scope, sandboxName)
	if err != nil {
		return fmt.Errorf("delete custom secret index: %w", err)
	}
	return nil
}

// ListCustomSecretIndex lists every custom secret row in stable order.
func (s *Store) ListCustomSecretIndex(ctx context.Context) ([]CustomSecretIndex, error) {
	return s.queryCustomSecretIndex(ctx, `SELECT service, scope, sandbox_name, env_name, hosts, placeholder_masked,
		refresh, origin, created_at, updated_at
		FROM custom_secret_index ORDER BY service, scope, sandbox_name`)
}

// ListCustomSecretIndexForSandbox lists global rows and the rows scoped to one
// sandbox. It never returns another sandbox's rows.
func (s *Store) ListCustomSecretIndexForSandbox(ctx context.Context, sandboxName string) ([]CustomSecretIndex, error) {
	return s.queryCustomSecretIndex(ctx, `SELECT service, scope, sandbox_name, env_name, hosts, placeholder_masked,
		refresh, origin, created_at, updated_at
		FROM custom_secret_index
		WHERE scope='global' OR (scope='sandbox' AND sandbox_name=?)
		ORDER BY service, scope, sandbox_name`, sandboxName)
}

func (s *Store) queryCustomSecretIndex(ctx context.Context, query string, args ...any) ([]CustomSecretIndex, error) {
	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("list custom secret index: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var out []CustomSecretIndex
	for rows.Next() {
		entry, err := scanCustomSecretIndex(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, entry)
	}
	return out, rows.Err()
}

type rowScanner interface {
	Scan(dest ...any) error
}

func scanCustomSecretIndex(row rowScanner) (CustomSecretIndex, error) {
	var entry CustomSecretIndex
	var hosts string
	var createdAt, updatedAt int64
	if err := row.Scan(&entry.Service, &entry.Scope, &entry.SandboxName, &entry.EnvName, &hosts,
		&entry.PlaceholderMasked, &entry.Refresh, &entry.Origin, &createdAt, &updatedAt); err != nil {
		return CustomSecretIndex{}, err
	}
	if err := json.Unmarshal([]byte(hosts), &entry.Hosts); err != nil {
		return CustomSecretIndex{}, errors.New("decode custom secret hosts")
	}
	entry.CreatedAt = fromUnix(createdAt)
	entry.UpdatedAt = fromUnix(updatedAt)
	return entry, nil
}

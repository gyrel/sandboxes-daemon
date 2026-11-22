package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"
)

// TemplateRecord is one recorded local template. Values are display
// metadata; template records never carry secret material.
type TemplateRecord struct {
	Name      string
	Digest    string
	SizeBytes int64
	BaseImage string
	Flavor    string
	Layers    int
	CreatedAt int64
}

// PutTemplate inserts or replaces a template record. The name must already
// be normalized (docker.io/... grammar) by the caller.
func (s *Store) PutTemplate(ctx context.Context, t TemplateRecord) error {
	if strings.TrimSpace(t.Name) == "" || strings.TrimSpace(t.Digest) == "" {
		return errors.New("store: template name and digest are required")
	}
	created := t.CreatedAt
	if created == 0 {
		created = time.Now().UTC().Unix()
	}
	_, err := s.db.ExecContext(ctx, `INSERT INTO templates (name, digest, size_bytes, base_image, flavor, layers, created_at)
		VALUES (?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(name) DO UPDATE SET digest = excluded.digest, size_bytes = excluded.size_bytes,
			base_image = excluded.base_image, flavor = excluded.flavor, layers = excluded.layers`,
		t.Name, t.Digest, t.SizeBytes, t.BaseImage, t.Flavor, t.Layers, created)
	if err != nil {
		return fmt.Errorf("record template: %w", err)
	}
	return nil
}

// GetTemplate returns one record; absence is reported as ErrTemplateNotFound.
func (s *Store) GetTemplate(ctx context.Context, name string) (TemplateRecord, error) {
	var t TemplateRecord
	err := s.db.QueryRowContext(ctx, `SELECT name, digest, size_bytes, base_image, flavor, layers, created_at FROM templates WHERE name = ?`, name).
		Scan(&t.Name, &t.Digest, &t.SizeBytes, &t.BaseImage, &t.Flavor, &t.Layers, &t.CreatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return TemplateRecord{}, ErrTemplateNotFound
	}
	if err != nil {
		return TemplateRecord{}, err
	}
	return t, nil
}

// ListTemplates returns all records ordered by creation time.
func (s *Store) ListTemplates(ctx context.Context) ([]TemplateRecord, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT name, digest, size_bytes, base_image, flavor, layers, created_at FROM templates ORDER BY created_at, name`)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	var out []TemplateRecord
	for rows.Next() {
		var t TemplateRecord
		if err := rows.Scan(&t.Name, &t.Digest, &t.SizeBytes, &t.BaseImage, &t.Flavor, &t.Layers, &t.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, t)
	}
	return out, rows.Err()
}

// DeleteTemplate removes the record.
func (s *Store) DeleteTemplate(ctx context.Context, name string) error {
	res, err := s.db.ExecContext(ctx, `DELETE FROM templates WHERE name = ?`, name)
	if err != nil {
		return err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("delete template: %w", err)
	}
	if n == 0 {
		return ErrTemplateNotFound
	}
	return nil
}

// TemplateReferences counts sandboxes that boot from the given image
// reference; template removal is refused while the count is non-zero.
func (s *Store) TemplateReferences(ctx context.Context, name string) (int, error) {
	var count int
	if err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM sandboxes WHERE image = ?`, name).Scan(&count); err != nil {
		return 0, err
	}
	return count, nil
}

// ErrTemplateNotFound reports an unknown template name.
var ErrTemplateNotFound = errors.New("store: template not found")

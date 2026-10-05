package store

import (
	"context"
	"database/sql"
	"errors"
	"time"
)

// BrandingRow is the applied branding (JSON of branding.Branding).
type BrandingRow struct {
	Version   int64
	Data      string
	UpdatedAt time.Time
	UpdatedBy string
}

// BrandingAsset is a stored image.
type BrandingAsset struct {
	SHA256      string
	ContentType string
	Data        []byte
}

// GetBranding returns the applied branding, or ErrNotFound when conductor
// never pushed one (the product look).
func (s *Store) GetBranding(ctx context.Context) (*BrandingRow, error) {
	var r BrandingRow
	var at int64
	err := s.db.QueryRowContext(ctx, `SELECT version, data, updated_at, updated_by FROM branding WHERE id = 1`).
		Scan(&r.Version, &r.Data, &at, &r.UpdatedBy)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	r.UpdatedAt = fromNanos(at)
	return &r, nil
}

// BrandingAssets returns every stored image.
func (s *Store) BrandingAssets(ctx context.Context) ([]BrandingAsset, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT sha256, content_type, data FROM branding_assets ORDER BY sha256`)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	var out []BrandingAsset
	for rows.Next() {
		var a BrandingAsset
		if err := rows.Scan(&a.SHA256, &a.ContentType, &a.Data); err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

// PutBranding replaces the branding and its images in one transaction.
func (s *Store) PutBranding(ctx context.Context, version int64, data, by string, assets []BrandingAsset) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := tx.ExecContext(ctx, `INSERT INTO branding(id, version, data, updated_at, updated_by) VALUES (1, ?, ?, ?, ?)
		ON CONFLICT(id) DO UPDATE SET version = excluded.version, data = excluded.data, updated_at = excluded.updated_at,
		updated_by = excluded.updated_by`, version, data, nanos(s.now()), by); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM branding_assets`); err != nil {
		return err
	}
	for _, a := range assets {
		if _, err := tx.ExecContext(ctx, `INSERT INTO branding_assets(sha256, content_type, data) VALUES (?, ?, ?)`,
			a.SHA256, a.ContentType, a.Data); err != nil {
			return err
		}
	}
	return tx.Commit()
}

package store

import (
	"context"
	"database/sql"
	"errors"
	"time"
)

// SettingsRow is the settings edited from conductor's panel (the JSON of
// idpapi.Settings), versioned for optimistic concurrency.
type SettingsRow struct {
	Version   int64
	Data      string
	UpdatedAt time.Time
	UpdatedBy string
}

// GetSettings returns the saved settings, or ErrNotFound when they were
// never edited (the configuration file's values apply).
func (s *Store) GetSettings(ctx context.Context) (*SettingsRow, error) {
	var r SettingsRow
	var at int64
	err := s.db.QueryRowContext(ctx, `SELECT version, data, updated_at, updated_by FROM settings WHERE id = 1`).
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

// ErrStale is returned when the settings changed since the editor read
// them.
var ErrStale = errors.New("store: settings changed since they were read")

// SaveSettings stores new settings if the current version is base, and
// returns the new version.
func (s *Store) SaveSettings(ctx context.Context, base int64, data, by string) (int64, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, err
	}
	defer func() { _ = tx.Rollback() }()
	var cur int64
	err = tx.QueryRowContext(ctx, `SELECT version FROM settings WHERE id = 1`).Scan(&cur)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return 0, err
	}
	if cur != base {
		return 0, ErrStale
	}
	next := cur + 1
	if _, err := tx.ExecContext(ctx, `INSERT INTO settings(id, version, data, updated_at, updated_by) VALUES (1, ?, ?, ?, ?)
		ON CONFLICT(id) DO UPDATE SET version = excluded.version, data = excluded.data, updated_at = excluded.updated_at,
		updated_by = excluded.updated_by`, next, data, nanos(s.now()), by); err != nil {
		return 0, err
	}
	return next, tx.Commit()
}

package store

import (
	"context"
	"database/sql"
	"errors"
	"time"
)

// TOTPRecord is a user's sealed TOTP secret.
type TOTPRecord struct {
	UserKey   string
	Secret    []byte // sealed, bound to UserKey
	LastStep  int64
	CreatedAt time.Time
}

// GetTOTP reads a user's TOTP enrollment.
func (s *Store) GetTOTP(ctx context.Context, userKey string) (*TOTPRecord, error) {
	var r TOTPRecord
	var created int64
	err := s.db.QueryRowContext(ctx, `SELECT user_key, secret, last_step, created_at FROM totp WHERE user_key = ?`, userKey).
		Scan(&r.UserKey, &r.Secret, &r.LastStep, &created)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	r.CreatedAt = fromNanos(created)
	return &r, nil
}

// SaveTOTP stores a new enrollment and its recovery codes (hashes),
// replacing any previous one, in one transaction.
func (s *Store) SaveTOTP(ctx context.Context, userKey string, sealed []byte, step int64, recoveryHashes []string) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := tx.ExecContext(ctx, `DELETE FROM totp WHERE user_key = ?`, userKey); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM recovery_codes WHERE user_key = ?`, userKey); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO totp(user_key, secret, last_step, created_at) VALUES (?, ?, ?, ?)`,
		userKey, sealed, step, nanos(s.now())); err != nil {
		return err
	}
	for _, h := range recoveryHashes {
		if _, err := tx.ExecContext(ctx, `INSERT INTO recovery_codes(user_key, code_hash) VALUES (?, ?)`, userKey, h); err != nil {
			return err
		}
	}
	return tx.Commit()
}

// AdvanceTOTPStep records an accepted step; false when the step is not
// newer than the last accepted one (a replayed code).
func (s *Store) AdvanceTOTPStep(ctx context.Context, userKey string, step int64) (bool, error) {
	res, err := s.db.ExecContext(ctx, `UPDATE totp SET last_step = ? WHERE user_key = ? AND last_step < ?`, step, userKey, step)
	if err != nil {
		return false, err
	}
	n, err := res.RowsAffected()
	return n == 1, err
}

// UseRecoveryCode consumes a recovery code; false when unknown or used.
func (s *Store) UseRecoveryCode(ctx context.Context, userKey, hash string) (bool, error) {
	res, err := s.db.ExecContext(ctx, `UPDATE recovery_codes SET used_at = ? WHERE user_key = ? AND code_hash = ? AND used_at = 0`,
		nanos(s.now()), userKey, hash)
	if err != nil {
		return false, err
	}
	n, err := res.RowsAffected()
	return n == 1, err
}

// RecoveryCodesLeft counts unused recovery codes.
func (s *Store) RecoveryCodesLeft(ctx context.Context, userKey string) (int, error) {
	var n int
	err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM recovery_codes WHERE user_key = ? AND used_at = 0`, userKey).Scan(&n)
	return n, err
}

// DeleteTOTP removes a user's 2FA enrollment (admin reset).
func (s *Store) DeleteTOTP(ctx context.Context, userKey string) (bool, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return false, err
	}
	defer func() { _ = tx.Rollback() }()
	res, err := tx.ExecContext(ctx, `DELETE FROM totp WHERE user_key = ?`, userKey)
	if err != nil {
		return false, err
	}
	n, _ := res.RowsAffected()
	if _, err := tx.ExecContext(ctx, `DELETE FROM recovery_codes WHERE user_key = ?`, userKey); err != nil {
		return false, err
	}
	return n == 1, tx.Commit()
}

// CreateEnrollLink stores the hash of a one-time administrator enrollment
// link for one username.
func (s *Store) CreateEnrollLink(ctx context.Context, hash, username, createdBy string, ttl time.Duration) error {
	now := s.now()
	_, err := s.db.ExecContext(ctx, `INSERT INTO enroll_links(token_hash, username, created_by, created_at, expires_at) VALUES (?, ?, ?, ?, ?)`,
		hash, username, createdBy, nanos(now), nanos(now.Add(ttl)))
	return err
}

// ValidEnrollLink reports whether a link is unused, unexpired and for
// this username.
func (s *Store) ValidEnrollLink(ctx context.Context, hash, username string) (bool, error) {
	var n int
	err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM enroll_links WHERE token_hash = ? AND username = ? AND used_at = 0 AND expires_at > ?`,
		hash, username, nanos(s.now())).Scan(&n)
	return n == 1, err
}

// UseEnrollLink consumes a link; false when it was not valid.
func (s *Store) UseEnrollLink(ctx context.Context, hash, username string) (bool, error) {
	res, err := s.db.ExecContext(ctx, `UPDATE enroll_links SET used_at = ? WHERE token_hash = ? AND username = ? AND used_at = 0 AND expires_at > ?`,
		nanos(s.now()), hash, username, nanos(s.now()))
	if err != nil {
		return false, err
	}
	n, err := res.RowsAffected()
	return n == 1, err
}

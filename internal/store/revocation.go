package store

import (
	"context"
	"database/sql"
	"errors"
	"time"
)

// UserRevocation is what RevokeUser ended.
type UserRevocation struct {
	// RefreshTokens is the number of live refresh tokens revoked.
	RefreshTokens int64
	// Consents is the number of consents (grants to clients) forgotten.
	Consents int64
	// RevokedAt is the instant every earlier session and token stops.
	RevokedAt time.Time
}

// RevokeUser ends what an account holds at the provider, in one
// transaction: its refresh and access tokens (every client), its consents,
// the authorization requests completed for it and not redeemed yet, and it
// records the revocation time. Browser sessions are in the memory of the
// running server; they check UserRevokedAt and end themselves when they
// started before it, so a revocation made by the CLI or the management API
// reaches them too.
func (s *Store) RevokeUser(ctx context.Context, subject, reason string) (UserRevocation, error) {
	now := s.now()
	out := UserRevocation{RevokedAt: now}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return out, err
	}
	defer func() { _ = tx.Rollback() }()
	at := nanos(now)
	res, err := tx.ExecContext(ctx, `UPDATE refresh_tokens SET revoked_at = ? WHERE subject = ? AND revoked_at = 0`, at, subject)
	if err != nil {
		return out, err
	}
	out.RefreshTokens, _ = res.RowsAffected()
	if _, err := tx.ExecContext(ctx, `UPDATE access_tokens SET revoked_at = ? WHERE subject = ? AND revoked_at = 0`, at, subject); err != nil {
		return out, err
	}
	res, err = tx.ExecContext(ctx, `DELETE FROM consents WHERE subject = ?`, subject)
	if err != nil {
		return out, err
	}
	out.Consents, _ = res.RowsAffected()
	if _, err := tx.ExecContext(ctx, `DELETE FROM auth_requests WHERE subject = ?`, subject); err != nil {
		return out, err
	}
	if len(reason) > 200 {
		reason = reason[:200]
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO user_revocations(subject, revoked_at, reason) VALUES (?, ?, ?)
		ON CONFLICT(subject) DO UPDATE SET revoked_at = excluded.revoked_at, reason = excluded.reason`, subject, at, reason); err != nil {
		return out, err
	}
	return out, tx.Commit()
}

// UserRevokedAt returns the last revocation of an account (zero when it was
// never revoked).
func (s *Store) UserRevokedAt(ctx context.Context, subject string) (time.Time, error) {
	var at int64
	err := s.db.QueryRowContext(ctx, `SELECT revoked_at FROM user_revocations WHERE subject = ?`, subject).Scan(&at)
	if errors.Is(err, sql.ErrNoRows) {
		return time.Time{}, nil
	}
	if err != nil {
		return time.Time{}, err
	}
	return fromNanos(at), nil
}

// maxKnownDevices bounds the browsers remembered per account (the oldest
// are forgotten first).
const maxKnownDevices = 20

// RememberDevice records that a browser completed a password sign-in for
// an account, for ttl.
func (s *Store) RememberDevice(ctx context.Context, username, browserHash string, ttl time.Duration) error {
	now := s.now()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := tx.ExecContext(ctx, `INSERT INTO known_devices(username, browser_hash, last_seen, expires_at) VALUES (?, ?, ?, ?)
		ON CONFLICT(username, browser_hash) DO UPDATE SET last_seen = excluded.last_seen, expires_at = excluded.expires_at`,
		username, browserHash, nanos(now), nanos(now.Add(ttl))); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM known_devices WHERE username = ? AND browser_hash NOT IN
		(SELECT browser_hash FROM known_devices WHERE username = ? ORDER BY last_seen DESC LIMIT ?)`,
		username, username, maxKnownDevices); err != nil {
		return err
	}
	return tx.Commit()
}

// KnownDevice reports whether a browser signed in to an account before and
// is still remembered.
func (s *Store) KnownDevice(ctx context.Context, username, browserHash string) (bool, error) {
	if browserHash == "" {
		return false, nil
	}
	var n int
	err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM known_devices WHERE username = ? AND browser_hash = ? AND expires_at > ?`,
		username, browserHash, nanos(s.now())).Scan(&n)
	return n > 0, err
}

// ForgetDevices forgets every browser of an account (after a revocation).
func (s *Store) ForgetDevices(ctx context.Context, username string) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM known_devices WHERE username = ?`, username)
	return err
}

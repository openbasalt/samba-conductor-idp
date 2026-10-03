package store

import (
	"context"
	"database/sql"
	"errors"
	"time"
)

// AuthRequest is a pending OIDC authorization request.
type AuthRequest struct {
	ID                  string
	ClientID            string
	RedirectURI         string
	State               string
	Nonce               string
	Scopes              []string
	ResponseType        string
	ResponseMode        string
	CodeChallenge       string
	CodeChallengeMethod string
	Prompt              []string
	MaxAge              *int64
	LoginHint           string
	UILocales           string
	BrowserHash         string
	Subject             string
	AuthTime            time.Time
	AMR                 []string
	CreatedAt           time.Time
	ExpiresAt           time.Time
}

const authReqCols = `id, client_id, redirect_uri, state, nonce, scopes, response_type, response_mode, code_challenge,
	code_challenge_method, prompt, max_age, login_hint, ui_locales, browser_hash, subject, auth_time, amr, created_at, expires_at`

// CreateAuthRequest stores a validated request.
func (s *Store) CreateAuthRequest(ctx context.Context, r *AuthRequest) error {
	var maxAge any
	if r.MaxAge != nil {
		maxAge = *r.MaxAge
	}
	_, err := s.db.ExecContext(ctx, `INSERT INTO auth_requests(`+authReqCols+`) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		r.ID, r.ClientID, r.RedirectURI, r.State, r.Nonce, toJSON(nz(r.Scopes)), r.ResponseType, r.ResponseMode, r.CodeChallenge,
		r.CodeChallengeMethod, toJSON(nz(r.Prompt)), maxAge, r.LoginHint, r.UILocales, r.BrowserHash, r.Subject, nanos(r.AuthTime),
		toJSON(nz(r.AMR)), nanos(r.CreatedAt), nanos(r.ExpiresAt))
	return err
}

// GetAuthRequest reads a request (expired ones included; callers check).
func (s *Store) GetAuthRequest(ctx context.Context, id string) (*AuthRequest, error) {
	var r AuthRequest
	var scopes, prompt, amr string
	var maxAge sql.NullInt64
	var authTime, created, expires int64
	err := s.db.QueryRowContext(ctx, `SELECT `+authReqCols+` FROM auth_requests WHERE id = ?`, id).Scan(
		&r.ID, &r.ClientID, &r.RedirectURI, &r.State, &r.Nonce, &scopes, &r.ResponseType, &r.ResponseMode, &r.CodeChallenge,
		&r.CodeChallengeMethod, &prompt, &maxAge, &r.LoginHint, &r.UILocales, &r.BrowserHash, &r.Subject, &authTime, &amr, &created, &expires)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	r.Scopes, r.Prompt, r.AMR = strs(scopes), strs(prompt), strs(amr)
	if maxAge.Valid {
		v := maxAge.Int64
		r.MaxAge = &v
	}
	r.AuthTime, r.CreatedAt, r.ExpiresAt = fromNanos(authTime), fromNanos(created), fromNanos(expires)
	return &r, nil
}

// BindAuthRequest ties a request to the browser that first continued it.
// A request already bound to another browser is refused.
func (s *Store) BindAuthRequest(ctx context.Context, id, browserHash string) error {
	res, err := s.db.ExecContext(ctx, `UPDATE auth_requests SET browser_hash = ? WHERE id = ? AND (browser_hash = '' OR browser_hash = ?) AND subject = ''`,
		browserHash, id, browserHash)
	return oneRow(res, err)
}

// CompleteAuthRequest records the authenticated user (once).
func (s *Store) CompleteAuthRequest(ctx context.Context, id, subject string, authTime time.Time, amr []string) error {
	res, err := s.db.ExecContext(ctx, `UPDATE auth_requests SET subject = ?, auth_time = ?, amr = ? WHERE id = ? AND subject = '' AND expires_at > ?`,
		subject, nanos(authTime), toJSON(nz(amr)), id, nanos(s.now()))
	return oneRow(res, err)
}

// DeleteAuthRequest removes a request.
func (s *Store) DeleteAuthRequest(ctx context.Context, id string) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM auth_requests WHERE id = ?`, id)
	return err
}

// SaveAuthCode stores the hash of an authorization code.
func (s *Store) SaveAuthCode(ctx context.Context, codeHash, requestID string, expires time.Time) error {
	_, err := s.db.ExecContext(ctx, `INSERT INTO auth_codes(code_hash, auth_request_id, expires_at) VALUES (?, ?, ?)`,
		codeHash, requestID, nanos(expires))
	return err
}

// ErrCodeReused is returned when an authorization code is presented a
// second time; the request ID is returned so its tokens can be revoked
// (RFC 6749 §4.1.2).
var ErrCodeReused = errors.New("store: authorization code reused")

// ConsumeAuthCode marks a code used and returns its request ID. A code
// works once: a second use returns the request ID with ErrCodeReused.
func (s *Store) ConsumeAuthCode(ctx context.Context, codeHash string) (string, error) {
	now := nanos(s.now())
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return "", err
	}
	defer func() { _ = tx.Rollback() }()
	var reqID string
	var expires, used int64
	err = tx.QueryRowContext(ctx, `SELECT auth_request_id, expires_at, used_at FROM auth_codes WHERE code_hash = ?`, codeHash).Scan(&reqID, &expires, &used)
	if errors.Is(err, sql.ErrNoRows) {
		return "", ErrNotFound
	}
	if err != nil {
		return "", err
	}
	if used != 0 {
		return reqID, ErrCodeReused
	}
	if expires <= now {
		return "", ErrNotFound
	}
	if _, err := tx.ExecContext(ctx, `UPDATE auth_codes SET used_at = ? WHERE code_hash = ?`, now, codeHash); err != nil {
		return "", err
	}
	return reqID, tx.Commit()
}

// AccessToken is an opaque access token's server-side row.
type AccessToken struct {
	ID        string
	ChainID   string
	ClientID  string
	Subject   string
	Scopes    []string
	Audience  []string
	CreatedAt time.Time
	ExpiresAt time.Time
	RevokedAt time.Time
}

// CreateAccessToken stores an access token.
func (s *Store) CreateAccessToken(ctx context.Context, t *AccessToken) error {
	_, err := s.db.ExecContext(ctx, `INSERT INTO access_tokens(id, chain_id, client_id, subject, scopes, audience, created_at, expires_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?)`, t.ID, t.ChainID, t.ClientID, t.Subject, toJSON(nz(t.Scopes)), toJSON(nz(t.Audience)),
		nanos(t.CreatedAt), nanos(t.ExpiresAt))
	return err
}

// GetAccessToken reads an access token row.
func (s *Store) GetAccessToken(ctx context.Context, id string) (*AccessToken, error) {
	var t AccessToken
	var scopes, aud string
	var created, expires, revoked int64
	err := s.db.QueryRowContext(ctx, `SELECT id, chain_id, client_id, subject, scopes, audience, created_at, expires_at, revoked_at
		FROM access_tokens WHERE id = ?`, id).Scan(&t.ID, &t.ChainID, &t.ClientID, &t.Subject, &scopes, &aud, &created, &expires, &revoked)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	t.Scopes, t.Audience = strs(scopes), strs(aud)
	t.CreatedAt, t.ExpiresAt, t.RevokedAt = fromNanos(created), fromNanos(expires), fromNanos(revoked)
	return &t, nil
}

// RevokeAccessToken revokes one access token.
func (s *Store) RevokeAccessToken(ctx context.Context, id string) error {
	_, err := s.db.ExecContext(ctx, `UPDATE access_tokens SET revoked_at = ? WHERE id = ? AND revoked_at = 0`, nanos(s.now()), id)
	return err
}

// RefreshToken is a stored (hashed) refresh token.
type RefreshToken struct {
	ID             string
	ChainID        string
	TokenHash      string
	ClientID       string
	Subject        string
	Scopes         []string
	Audience       []string
	AMR            []string
	AuthTime       time.Time
	CreatedAt      time.Time
	ExpiresAt      time.Time
	ChainExpiresAt time.Time
	RotatedAt      time.Time
	RevokedAt      time.Time
}

// CreateRefreshToken stores a refresh token.
func (s *Store) CreateRefreshToken(ctx context.Context, t *RefreshToken) error {
	_, err := s.db.ExecContext(ctx, `INSERT INTO refresh_tokens(id, chain_id, token_hash, client_id, subject, scopes, audience, amr,
		auth_time, created_at, expires_at, chain_expires_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		t.ID, t.ChainID, t.TokenHash, t.ClientID, t.Subject, toJSON(nz(t.Scopes)), toJSON(nz(t.Audience)), toJSON(nz(t.AMR)),
		nanos(t.AuthTime), nanos(t.CreatedAt), nanos(t.ExpiresAt), nanos(t.ChainExpiresAt))
	return err
}

// GetRefreshTokenByHash reads a refresh token by the hash of its value.
func (s *Store) GetRefreshTokenByHash(ctx context.Context, hash string) (*RefreshToken, error) {
	var t RefreshToken
	var scopes, aud, amr string
	var authTime, created, expires, chainExp, rotated, revoked int64
	err := s.db.QueryRowContext(ctx, `SELECT id, chain_id, token_hash, client_id, subject, scopes, audience, amr, auth_time, created_at,
		expires_at, chain_expires_at, rotated_at, revoked_at FROM refresh_tokens WHERE token_hash = ?`, hash).Scan(
		&t.ID, &t.ChainID, &t.TokenHash, &t.ClientID, &t.Subject, &scopes, &aud, &amr, &authTime, &created, &expires, &chainExp, &rotated, &revoked)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	t.Scopes, t.Audience, t.AMR = strs(scopes), strs(aud), strs(amr)
	t.AuthTime, t.CreatedAt, t.ExpiresAt = fromNanos(authTime), fromNanos(created), fromNanos(expires)
	t.ChainExpiresAt, t.RotatedAt, t.RevokedAt = fromNanos(chainExp), fromNanos(rotated), fromNanos(revoked)
	return &t, nil
}

// RotateRefreshToken marks a token rotated. It returns false when the
// token was already rotated or revoked (a concurrent or repeated use).
func (s *Store) RotateRefreshToken(ctx context.Context, id string) (bool, error) {
	res, err := s.db.ExecContext(ctx, `UPDATE refresh_tokens SET rotated_at = ? WHERE id = ? AND rotated_at = 0 AND revoked_at = 0`, nanos(s.now()), id)
	if err != nil {
		return false, err
	}
	n, err := res.RowsAffected()
	return n == 1, err
}

// RevokeChain revokes every refresh and access token of a chain (a
// refresh chain, or the tokens issued from one authorization request).
func (s *Store) RevokeChain(ctx context.Context, chainID string) error {
	now := nanos(s.now())
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := tx.ExecContext(ctx, `UPDATE refresh_tokens SET revoked_at = ? WHERE chain_id = ? AND revoked_at = 0`, now, chainID); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `UPDATE access_tokens SET revoked_at = ? WHERE chain_id = ? AND revoked_at = 0`, now, chainID); err != nil {
		return err
	}
	return tx.Commit()
}

// RevokeSubjectTokens revokes a user's tokens for one client, or for every
// client when clientID is empty. It returns the number of refresh tokens
// revoked.
func (s *Store) RevokeSubjectTokens(ctx context.Context, subject, clientID string) (int64, error) {
	now := nanos(s.now())
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, err
	}
	defer func() { _ = tx.Rollback() }()
	cond, args := `subject = ? AND revoked_at = 0`, []any{now, subject}
	if clientID != "" {
		cond += ` AND client_id = ?`
		args = append(args, clientID)
	}
	res, err := tx.ExecContext(ctx, `UPDATE refresh_tokens SET revoked_at = ? WHERE `+cond, args...)
	if err != nil {
		return 0, err
	}
	n, _ := res.RowsAffected()
	if _, err := tx.ExecContext(ctx, `UPDATE access_tokens SET revoked_at = ? WHERE `+cond, args...); err != nil {
		return 0, err
	}
	return n, tx.Commit()
}

// ---- signing keys ----

// Key purposes.
const (
	KeyOIDC = "oidc"
	KeySAML = "saml"
)

// SigningKey is a stored signing key; Private is sealed.
type SigningKey struct {
	ID        string
	Purpose   string
	Alg       string
	Private   []byte
	Cert      []byte
	CreatedAt time.Time
	RetireAt  time.Time
}

// CreateSigningKey stores a key.
func (s *Store) CreateSigningKey(ctx context.Context, k *SigningKey) error {
	_, err := s.db.ExecContext(ctx, `INSERT INTO signing_keys(id, purpose, alg, private, cert, created_at, retire_at) VALUES (?, ?, ?, ?, ?, ?, ?)`,
		k.ID, k.Purpose, k.Alg, k.Private, k.Cert, nanos(k.CreatedAt), nanos(k.RetireAt))
	return err
}

// ListSigningKeys returns the keys of a purpose still published at now,
// newest first.
func (s *Store) ListSigningKeys(ctx context.Context, purpose string, now time.Time) ([]*SigningKey, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT id, purpose, alg, private, cert, created_at, retire_at FROM signing_keys
		WHERE purpose = ? AND (retire_at = 0 OR retire_at > ?) ORDER BY created_at DESC, rowid DESC`, purpose, nanos(now))
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	var out []*SigningKey
	for rows.Next() {
		var k SigningKey
		var created, retire int64
		if err := rows.Scan(&k.ID, &k.Purpose, &k.Alg, &k.Private, &k.Cert, &created, &retire); err != nil {
			return nil, err
		}
		k.CreatedAt, k.RetireAt = fromNanos(created), fromNanos(retire)
		out = append(out, &k)
	}
	return out, rows.Err()
}

// RetireSigningKey schedules a key's removal from the published set
// (only if it is not already scheduled earlier).
func (s *Store) RetireSigningKey(ctx context.Context, id string, at time.Time) error {
	_, err := s.db.ExecContext(ctx, `UPDATE signing_keys SET retire_at = ? WHERE id = ? AND (retire_at = 0 OR retire_at > ?)`,
		nanos(at), id, nanos(at))
	return err
}

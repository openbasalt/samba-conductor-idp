package store

import (
	"context"
	"database/sql"
	"errors"
	"time"
)

// Client kinds.
const (
	ClientConfidential = "confidential"
	ClientPublic       = "public"
)

// Groups claim styles.
const (
	GroupsNone  = "none"
	GroupsNames = "names"
	GroupsSIDs  = "sids"
)

// Client is a registered OIDC relying party.
type Client struct {
	ID             string
	Name           string
	Kind           string
	SecretHash     string
	RedirectURIs   []string
	PostLogoutURIs []string
	Scopes         []string
	// AllowedGroups are group SIDs; a user must be a (nested) member of
	// one, unless AllowAllUsers.
	AllowedGroups []string
	AllowAllUsers bool
	// FirstParty skips the consent screen.
	FirstParty bool
	// GroupsClaim is none, names or sids; GroupsFilter (SIDs) limits the
	// groups put in the claim (empty = every group of the user).
	GroupsClaim     string
	GroupsFilter    []string
	RequireMFA      bool
	Enabled         bool
	CreatedAt       time.Time
	UpdatedAt       time.Time
	SecretRotatedAt time.Time
}

// Public reports whether the client has no secret (native/SPA apps).
func (c *Client) Public() bool { return c.Kind == ClientPublic }

const clientCols = `id, name, kind, secret_hash, redirect_uris, post_logout_uris, scopes, allowed_groups, allow_all_users,
	first_party, groups_claim, groups_filter, require_mfa, enabled, created_at, updated_at, secret_rotated_at`

func scanClient(row interface{ Scan(...any) error }) (*Client, error) {
	var c Client
	var redirect, postLogout, scopes, groups, filter string
	var allowAll, firstParty, mfa, enabled int
	var created, updated, rotated int64
	if err := row.Scan(&c.ID, &c.Name, &c.Kind, &c.SecretHash, &redirect, &postLogout, &scopes, &groups, &allowAll,
		&firstParty, &c.GroupsClaim, &filter, &mfa, &enabled, &created, &updated, &rotated); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	c.RedirectURIs, c.PostLogoutURIs, c.Scopes = strs(redirect), strs(postLogout), strs(scopes)
	c.AllowedGroups, c.GroupsFilter = strs(groups), strs(filter)
	c.AllowAllUsers, c.FirstParty, c.RequireMFA, c.Enabled = allowAll == 1, firstParty == 1, mfa == 1, enabled == 1
	c.CreatedAt, c.UpdatedAt, c.SecretRotatedAt = fromNanos(created), fromNanos(updated), fromNanos(rotated)
	return &c, nil
}

// CreateClient registers a client.
func (s *Store) CreateClient(ctx context.Context, c *Client) error {
	now := s.now()
	c.CreatedAt, c.UpdatedAt = now, now
	if c.SecretHash != "" {
		c.SecretRotatedAt = now
	}
	_, err := s.db.ExecContext(ctx, `INSERT INTO clients(`+clientCols+`) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		c.ID, c.Name, c.Kind, c.SecretHash, toJSON(nz(c.RedirectURIs)), toJSON(nz(c.PostLogoutURIs)), toJSON(nz(c.Scopes)),
		toJSON(nz(c.AllowedGroups)), boolInt(c.AllowAllUsers), boolInt(c.FirstParty), c.GroupsClaim, toJSON(nz(c.GroupsFilter)),
		boolInt(c.RequireMFA), boolInt(c.Enabled), nanos(c.CreatedAt), nanos(c.UpdatedAt), nanos(c.SecretRotatedAt))
	if isUnique(err) {
		return ErrConflict
	}
	return err
}

// nz turns nil into an empty slice, so JSON stores [] rather than null.
func nz(v []string) []string {
	if v == nil {
		return []string{}
	}
	return v
}

// GetClient reads a client by client_id.
func (s *Store) GetClient(ctx context.Context, id string) (*Client, error) {
	return scanClient(s.db.QueryRowContext(ctx, `SELECT `+clientCols+` FROM clients WHERE id = ?`, id))
}

// ListClients returns every client, by name.
func (s *Store) ListClients(ctx context.Context) ([]*Client, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT `+clientCols+` FROM clients ORDER BY name, id`)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	var out []*Client
	for rows.Next() {
		c, err := scanClient(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

// UpdateClient writes every mutable field (not the secret).
func (s *Store) UpdateClient(ctx context.Context, c *Client) error {
	c.UpdatedAt = s.now()
	res, err := s.db.ExecContext(ctx, `UPDATE clients SET name = ?, redirect_uris = ?, post_logout_uris = ?, scopes = ?,
		allowed_groups = ?, allow_all_users = ?, first_party = ?, groups_claim = ?, groups_filter = ?, require_mfa = ?,
		enabled = ?, updated_at = ? WHERE id = ?`,
		c.Name, toJSON(nz(c.RedirectURIs)), toJSON(nz(c.PostLogoutURIs)), toJSON(nz(c.Scopes)), toJSON(nz(c.AllowedGroups)),
		boolInt(c.AllowAllUsers), boolInt(c.FirstParty), c.GroupsClaim, toJSON(nz(c.GroupsFilter)), boolInt(c.RequireMFA),
		boolInt(c.Enabled), nanos(c.UpdatedAt), c.ID)
	return oneRow(res, err)
}

// SetClientSecret replaces a confidential client's secret hash.
func (s *Store) SetClientSecret(ctx context.Context, id, hash string) error {
	now := nanos(s.now())
	res, err := s.db.ExecContext(ctx, `UPDATE clients SET secret_hash = ?, secret_rotated_at = ?, updated_at = ? WHERE id = ? AND kind = 'confidential'`,
		hash, now, now, id)
	return oneRow(res, err)
}

// DeleteClient removes a client with its requests, tokens and consents.
func (s *Store) DeleteClient(ctx context.Context, id string) error {
	res, err := s.db.ExecContext(ctx, `DELETE FROM clients WHERE id = ?`, id)
	return oneRow(res, err)
}

func oneRow(res sql.Result, err error) error {
	if err != nil {
		return err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if n == 0 {
		return ErrNotFound
	}
	return nil
}

// ---- consents ----

// GetConsent returns the scopes a user granted a client (nil when none).
func (s *Store) GetConsent(ctx context.Context, subject, clientID string) ([]string, error) {
	var scopes string
	err := s.db.QueryRowContext(ctx, `SELECT scopes FROM consents WHERE subject = ? AND client_id = ?`, subject, clientID).Scan(&scopes)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return strs(scopes), nil
}

// SaveConsent records the scopes a user granted a client.
func (s *Store) SaveConsent(ctx context.Context, subject, clientID string, scopes []string) error {
	_, err := s.db.ExecContext(ctx, `INSERT INTO consents(subject, client_id, scopes, granted_at) VALUES (?, ?, ?, ?)
		ON CONFLICT(subject, client_id) DO UPDATE SET scopes = excluded.scopes, granted_at = excluded.granted_at`,
		subject, clientID, toJSON(nz(scopes)), nanos(s.now()))
	return err
}

// DeleteConsents forgets every consent given to a client (after its
// scopes changed, for example).
func (s *Store) DeleteConsents(ctx context.Context, clientID string) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM consents WHERE client_id = ?`, clientID)
	return err
}

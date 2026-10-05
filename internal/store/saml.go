package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"time"
)

// SAMLAttribute maps an AD-derived value to a SAML attribute name.
type SAMLAttribute struct {
	Name string `json:"name"`
	// Source is one of the samlidp sources (email, upn, username, name,
	// given_name, surname, groups, group_sids, guid).
	Source string `json:"source"`
}

// SAMLSP is a registered SAML service provider.
type SAMLSP struct {
	EntityID         string
	Name             string
	ACSURLs          []string
	NameIDFormat     string
	NameIDSource     string
	Attributes       []SAMLAttribute
	AllowedGroups    []string
	AllowAllUsers    bool
	EncryptAssertion bool
	EncryptionCert   []byte // DER
	IdPInitiated     bool
	DefaultRelay     string
	RequireMFA       bool
	Enabled          bool
	CreatedAt        time.Time
	UpdatedAt        time.Time
	// SLOURL and SLOBinding are the SP's single logout endpoint (empty:
	// not part of single logout); SigningCert (DER) verifies its
	// HTTP-Redirect LogoutRequests.
	SLOURL      string
	SLOBinding  string
	SigningCert []byte
}

const spCols = `entity_id, name, acs_urls, nameid_format, nameid_source, attributes, allowed_groups, allow_all_users,
	encrypt_assertion, encryption_cert, idp_initiated, default_relay, require_mfa, enabled, created_at, updated_at,
	slo_url, slo_binding, signing_cert`

func scanSP(row interface{ Scan(...any) error }) (*SAMLSP, error) {
	var sp SAMLSP
	var acs, attrs, groups string
	var allowAll, encrypt, idpInit, mfa, enabled int
	var created, updated int64
	if err := row.Scan(&sp.EntityID, &sp.Name, &acs, &sp.NameIDFormat, &sp.NameIDSource, &attrs, &groups, &allowAll,
		&encrypt, &sp.EncryptionCert, &idpInit, &sp.DefaultRelay, &mfa, &enabled, &created, &updated,
		&sp.SLOURL, &sp.SLOBinding, &sp.SigningCert); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	sp.ACSURLs, sp.AllowedGroups = strs(acs), strs(groups)
	_ = json.Unmarshal([]byte(attrs), &sp.Attributes)
	sp.AllowAllUsers, sp.EncryptAssertion, sp.IdPInitiated = allowAll == 1, encrypt == 1, idpInit == 1
	sp.RequireMFA, sp.Enabled = mfa == 1, enabled == 1
	sp.CreatedAt, sp.UpdatedAt = fromNanos(created), fromNanos(updated)
	return &sp, nil
}

func attrsJSON(a []SAMLAttribute) string {
	if a == nil {
		a = []SAMLAttribute{}
	}
	return toJSON(a)
}

// CreateSP registers a service provider.
func (s *Store) CreateSP(ctx context.Context, sp *SAMLSP) error {
	now := s.now()
	sp.CreatedAt, sp.UpdatedAt = now, now
	_, err := s.db.ExecContext(ctx, `INSERT INTO saml_sps(`+spCols+`) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		sp.EntityID, sp.Name, toJSON(nz(sp.ACSURLs)), sp.NameIDFormat, sp.NameIDSource, attrsJSON(sp.Attributes),
		toJSON(nz(sp.AllowedGroups)), boolInt(sp.AllowAllUsers), boolInt(sp.EncryptAssertion), sp.EncryptionCert,
		boolInt(sp.IdPInitiated), sp.DefaultRelay, boolInt(sp.RequireMFA), boolInt(sp.Enabled), nanos(now), nanos(now),
		sp.SLOURL, sp.SLOBinding, sp.SigningCert)
	if isUnique(err) {
		return ErrConflict
	}
	return err
}

// GetSP reads a service provider by entity ID.
func (s *Store) GetSP(ctx context.Context, entityID string) (*SAMLSP, error) {
	return scanSP(s.db.QueryRowContext(ctx, `SELECT `+spCols+` FROM saml_sps WHERE entity_id = ?`, entityID))
}

// ListSPs returns every service provider, by name.
func (s *Store) ListSPs(ctx context.Context) ([]*SAMLSP, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT `+spCols+` FROM saml_sps ORDER BY name, entity_id`)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	var out []*SAMLSP
	for rows.Next() {
		sp, err := scanSP(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, sp)
	}
	return out, rows.Err()
}

// UpdateSP writes every mutable field.
func (s *Store) UpdateSP(ctx context.Context, sp *SAMLSP) error {
	sp.UpdatedAt = s.now()
	res, err := s.db.ExecContext(ctx, `UPDATE saml_sps SET name = ?, acs_urls = ?, nameid_format = ?, nameid_source = ?,
		attributes = ?, allowed_groups = ?, allow_all_users = ?, encrypt_assertion = ?, encryption_cert = ?, idp_initiated = ?,
		default_relay = ?, require_mfa = ?, enabled = ?, updated_at = ?, slo_url = ?, slo_binding = ?, signing_cert = ? WHERE entity_id = ?`,
		sp.Name, toJSON(nz(sp.ACSURLs)), sp.NameIDFormat, sp.NameIDSource, attrsJSON(sp.Attributes), toJSON(nz(sp.AllowedGroups)),
		boolInt(sp.AllowAllUsers), boolInt(sp.EncryptAssertion), sp.EncryptionCert, boolInt(sp.IdPInitiated), sp.DefaultRelay,
		boolInt(sp.RequireMFA), boolInt(sp.Enabled), nanos(sp.UpdatedAt), sp.SLOURL, sp.SLOBinding, sp.SigningCert, sp.EntityID)
	return oneRow(res, err)
}

// DeleteSP removes a service provider.
func (s *Store) DeleteSP(ctx context.Context, entityID string) error {
	res, err := s.db.ExecContext(ctx, `DELETE FROM saml_sps WHERE entity_id = ?`, entityID)
	return oneRow(res, err)
}

// SAMLPending is an AuthnRequest waiting for the user to sign in.
type SAMLPending struct {
	ID          string
	EntityID    string
	RequestID   string
	Payload     []byte
	RelayState  string
	BrowserHash string
	ReceivedAt  time.Time
	ExpiresAt   time.Time
}

// CreateSAMLPending stores a request; ErrConflict when the same SP sent
// the same request ID before (a replay).
func (s *Store) CreateSAMLPending(ctx context.Context, p *SAMLPending) error {
	_, err := s.db.ExecContext(ctx, `INSERT INTO saml_pending(id, entity_id, request_id, payload, relay_state, browser_hash, received_at, expires_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?)`, p.ID, p.EntityID, p.RequestID, p.Payload, p.RelayState, p.BrowserHash, nanos(p.ReceivedAt), nanos(p.ExpiresAt))
	if isUnique(err) {
		return ErrConflict
	}
	return err
}

// GetSAMLPending reads a pending request that has not expired.
func (s *Store) GetSAMLPending(ctx context.Context, id string) (*SAMLPending, error) {
	var p SAMLPending
	var received, expires int64
	err := s.db.QueryRowContext(ctx, `SELECT id, entity_id, request_id, payload, relay_state, browser_hash, received_at, expires_at
		FROM saml_pending WHERE id = ? AND expires_at > ?`, id, nanos(s.now())).
		Scan(&p.ID, &p.EntityID, &p.RequestID, &p.Payload, &p.RelayState, &p.BrowserHash, &received, &expires)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	p.ReceivedAt, p.ExpiresAt = fromNanos(received), fromNanos(expires)
	return &p, nil
}

// FinishSAMLPending marks a request answered: the row stays until it
// expires (so the request ID cannot be replayed) but can no longer be
// continued.
func (s *Store) FinishSAMLPending(ctx context.Context, id string) (bool, error) {
	res, err := s.db.ExecContext(ctx, `UPDATE saml_pending SET browser_hash = '' WHERE id = ? AND browser_hash <> ''`, id)
	if err != nil {
		return false, err
	}
	n, err := res.RowsAffected()
	return n == 1, err
}

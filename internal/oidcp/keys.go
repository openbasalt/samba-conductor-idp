package oidcp

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"errors"
	"fmt"
	"sync"
	"time"

	jose "github.com/go-jose/go-jose/v4"
	"github.com/google/uuid"
	"github.com/zitadel/oidc/v3/pkg/op"

	"github.com/samba-conductor/conductor-idp/internal/secret"
	"github.com/samba-conductor/conductor-idp/internal/store"
)

// keyAlg signs ID tokens. ES256 is supported by every current RP library
// and keeps tokens small; RS256 is not offered (no RP here needs it).
const keyAlg = jose.ES256

const keyCacheTTL = time.Minute

// sealAAD binds a sealed private key to its row.
func sealAAD(id string) []byte { return []byte("oidc-signing-key\x00" + id) }

type signingKey struct {
	id   string
	priv *ecdsa.PrivateKey
}

func (k *signingKey) SignatureAlgorithm() jose.SignatureAlgorithm { return keyAlg }
func (k *signingKey) ID() string                                  { return k.id }
func (k *signingKey) Key() any                                    { return k.priv }

type publicKey struct{ k *signingKey }

func (p publicKey) ID() string                         { return p.k.id }
func (p publicKey) Algorithm() jose.SignatureAlgorithm { return keyAlg }
func (p publicKey) Use() string                        { return "sig" }
func (p publicKey) Key() any                           { return &p.k.priv.PublicKey }

// KeyManager keeps the OIDC signing keys in the store, private halves
// sealed with the master key. A new key is created when the newest is
// older than RotateAfter; replaced keys stay in the JWKS for Overlap so
// tokens they signed and relying parties' JWKS caches outlive the switch.
type KeyManager struct {
	Store       *store.Store
	Box         *secret.Box
	RotateAfter time.Duration
	Overlap     time.Duration
	Now         func() time.Time

	mu       sync.Mutex
	loadedAt time.Time
	active   []*signingKey // newest first
}

func (m *KeyManager) now() time.Time {
	if m.Now != nil {
		return m.Now().UTC()
	}
	return time.Now().UTC()
}

// Ensure creates the first key, or rotates when the newest is too old.
// Safe to call on every start and periodically.
func (m *KeyManager) Ensure(ctx context.Context) (bool, error) {
	keys, err := m.Store.ListSigningKeys(ctx, store.KeyOIDC, m.now())
	if err != nil {
		return false, err
	}
	if len(keys) > 0 && keys[0].RetireAt.IsZero() && m.now().Sub(keys[0].CreatedAt) < m.RotateAfter {
		return false, nil
	}
	_, err = m.Rotate(ctx)
	return err == nil, err
}

// Rotate creates a new signing key and schedules the retirement of the
// previous ones after the overlap. It returns the new key's ID.
func (m *KeyManager) Rotate(ctx context.Context) (string, error) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return "", err
	}
	der, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		return "", err
	}
	defer clear(der)
	id := uuid.NewString()
	sealed, err := m.Box.Seal(der, sealAAD(id))
	if err != nil {
		return "", err
	}
	old, err := m.Store.ListSigningKeys(ctx, store.KeyOIDC, m.now())
	if err != nil {
		return "", err
	}
	now := m.now()
	if err := m.Store.CreateSigningKey(ctx, &store.SigningKey{ID: id, Purpose: store.KeyOIDC, Alg: string(keyAlg), Private: sealed, CreatedAt: now}); err != nil {
		return "", err
	}
	for _, k := range old {
		if err := m.Store.RetireSigningKey(ctx, k.ID, now.Add(m.Overlap)); err != nil {
			return "", err
		}
	}
	m.mu.Lock()
	m.loadedAt = time.Time{}
	m.mu.Unlock()
	return id, nil
}

func (m *KeyManager) load(ctx context.Context) ([]*signingKey, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if len(m.active) > 0 && m.now().Sub(m.loadedAt) < keyCacheTTL {
		return m.active, nil
	}
	rows, err := m.Store.ListSigningKeys(ctx, store.KeyOIDC, m.now())
	if err != nil {
		return nil, err
	}
	var out []*signingKey
	for _, r := range rows {
		der, err := m.Box.Open(r.Private, sealAAD(r.ID))
		if err != nil {
			return nil, fmt.Errorf("oidcp: signing key %s cannot be opened (wrong master key?)", r.ID)
		}
		priv, err := x509.ParseECPrivateKey(der)
		clear(der)
		if err != nil {
			return nil, err
		}
		out = append(out, &signingKey{id: r.ID, priv: priv})
	}
	if len(out) == 0 {
		return nil, errors.New("oidcp: no signing key")
	}
	m.active, m.loadedAt = out, m.now()
	return out, nil
}

// SigningKey returns the newest key (the one that is not retiring).
func (m *KeyManager) SigningKey(ctx context.Context) (op.SigningKey, error) {
	keys, err := m.load(ctx)
	if err != nil {
		return nil, err
	}
	return keys[0], nil
}

// KeySet returns every published public key (the JWKS).
func (m *KeyManager) KeySet(ctx context.Context) ([]op.Key, error) {
	keys, err := m.load(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]op.Key, 0, len(keys))
	for _, k := range keys {
		out = append(out, publicKey{k})
	}
	return out, nil
}

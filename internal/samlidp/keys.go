package samlidp

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"fmt"
	"math/big"
	"sync"
	"time"

	"github.com/google/uuid"

	"github.com/openbasalt/samba-conductor-idp/internal/secret"
	"github.com/openbasalt/samba-conductor-idp/internal/store"
)

// keyBits of the RSA signing key. RSA because every SAML service provider
// supports RSA-SHA256 (Google Workspace accepts RSA keys only).
const keyBits = 3072

// certValidity of the self-signed signing certificate. SAML SPs pin the
// certificate itself (no chain, no expiry check by most), so it lives long
// and is replaced by rotation, not by expiry.
const certValidity = 10 * 365 * 24 * time.Hour

func sealAAD(id string) []byte { return []byte("saml-signing-key\x00" + id) }

// KeyPair is a loaded signing key with its certificate.
type KeyPair struct {
	ID   string
	Key  *rsa.PrivateKey
	Cert *x509.Certificate
}

// KeyManager keeps the SAML signing keys in the store, sealed with the
// master key. Rotation is manual and staged, because service providers pin
// the certificate: a rotation publishes the new certificate in the
// metadata next to the current one, the current key keeps signing until
// the overlap ends (time to import the new certificate in every SP), then
// the new key takes over. An emergency rotation (immediate) switches at
// once.
type KeyManager struct {
	Store   *store.Store
	Box     *secret.Box
	Subject string // certificate common name (the issuer host)
	Overlap time.Duration
	Now     func() time.Time

	mu       sync.Mutex
	loadedAt time.Time
	keys     []*KeyPair // newest first
}

func (m *KeyManager) now() time.Time {
	if m.Now != nil {
		return m.Now().UTC()
	}
	return time.Now().UTC()
}

// Ensure creates the first key when there is none.
func (m *KeyManager) Ensure(ctx context.Context) (bool, error) {
	keys, err := m.Store.ListSigningKeys(ctx, store.KeySAML, m.now())
	if err != nil {
		return false, err
	}
	for _, k := range keys {
		if k.RetireAt.IsZero() {
			return false, nil
		}
	}
	_, err = m.Rotate(ctx, true)
	return err == nil, err
}

// Rotate creates a new key and certificate and schedules the retirement of
// the previous ones after the overlap (or now, when immediate).
func (m *KeyManager) Rotate(ctx context.Context, immediate bool) (string, error) {
	priv, err := rsa.GenerateKey(rand.Reader, keyBits)
	if err != nil {
		return "", err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 126))
	if err != nil {
		return "", err
	}
	now := m.now()
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: m.Subject, Organization: []string{"Samba Conductor IdP"}},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(certValidity),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}
	certDER, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
	if err != nil {
		return "", err
	}
	der := x509.MarshalPKCS1PrivateKey(priv)
	defer clear(der)
	id := uuid.NewString()
	sealed, err := m.Box.Seal(der, sealAAD(id))
	if err != nil {
		return "", err
	}
	old, err := m.Store.ListSigningKeys(ctx, store.KeySAML, now)
	if err != nil {
		return "", err
	}
	if err := m.Store.CreateSigningKey(ctx, &store.SigningKey{ID: id, Purpose: store.KeySAML, Alg: "RS256",
		Private: sealed, Cert: certDER, CreatedAt: now}); err != nil {
		return "", err
	}
	retire := now.Add(m.Overlap)
	if immediate {
		retire = now
	}
	for _, k := range old {
		if err := m.Store.RetireSigningKey(ctx, k.ID, retire); err != nil {
			return "", err
		}
	}
	m.mu.Lock()
	m.loadedAt = time.Time{}
	m.mu.Unlock()
	return id, nil
}

// Keys returns the published keys, newest first. The signing key is the
// oldest one (see Signer).
func (m *KeyManager) Keys(ctx context.Context) ([]*KeyPair, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if len(m.keys) > 0 && m.now().Sub(m.loadedAt) < time.Minute {
		return m.keys, nil
	}
	rows, err := m.Store.ListSigningKeys(ctx, store.KeySAML, m.now())
	if err != nil {
		return nil, err
	}
	var out []*KeyPair
	for _, r := range rows {
		der, err := m.Box.Open(r.Private, sealAAD(r.ID))
		if err != nil {
			return nil, fmt.Errorf("samlidp: signing key %s cannot be opened (wrong master key?)", r.ID)
		}
		priv, err := x509.ParsePKCS1PrivateKey(der)
		clear(der)
		if err != nil {
			return nil, err
		}
		cert, err := x509.ParseCertificate(r.Cert)
		if err != nil {
			return nil, err
		}
		out = append(out, &KeyPair{ID: r.ID, Key: priv, Cert: cert})
	}
	if len(out) == 0 {
		return nil, errors.New("samlidp: no signing key")
	}
	m.keys, m.loadedAt = out, m.now()
	return out, nil
}

// Signer returns the key that signs now: the oldest published key, so a
// staged rotation keeps the current certificate until the overlap ends.
func (m *KeyManager) Signer(ctx context.Context) (*KeyPair, error) {
	keys, err := m.Keys(ctx)
	if err != nil {
		return nil, err
	}
	return keys[len(keys)-1], nil
}

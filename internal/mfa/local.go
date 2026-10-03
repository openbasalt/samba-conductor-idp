package mfa

import (
	"context"
	"errors"
	"time"

	"github.com/openbasalt/samba-conductor-idp/internal/directory"
	"github.com/openbasalt/samba-conductor-idp/internal/secret"
	"github.com/openbasalt/samba-conductor-idp/internal/store"
	"github.com/openbasalt/samba-conductor-idp/internal/totp"
)

// Local keeps second factors in the idp's own database.
type Local struct {
	Store *store.Store
	Box   *secret.Box
	Now   func() time.Time
}

func (l *Local) now() time.Time {
	if l.Now != nil {
		return l.Now()
	}
	return time.Now()
}

// Name implements Backend.
func (l *Local) Name() string { return "local" }

// CanEnroll implements Backend.
func (l *Local) CanEnroll() bool { return true }

// Enrolled implements Backend.
func (l *Local) Enrolled(ctx context.Context, u *directory.User) (bool, error) {
	_, err := l.Store.GetTOTP(ctx, u.GUID)
	if errors.Is(err, store.ErrNotFound) {
		return false, nil
	}
	return err == nil, err
}

// Verify implements Backend: a TOTP code (each step accepted once) or an
// unused recovery code.
func (l *Local) Verify(ctx context.Context, u *directory.User, code string) (Result, error) {
	if totp.LooksLikeRecoveryCode(code) {
		ok, err := l.Store.UseRecoveryCode(ctx, u.GUID, totp.HashRecoveryCode(u.GUID, code))
		return Result{OK: ok, Recovery: ok}, err
	}
	rec, err := l.Store.GetTOTP(ctx, u.GUID)
	if errors.Is(err, store.ErrNotFound) {
		return Result{}, nil
	}
	if err != nil {
		return Result{}, err
	}
	sec, err := l.Box.Open(rec.Secret, []byte(u.GUID))
	if err != nil {
		return Result{}, err
	}
	defer clear(sec)
	step, ok := totp.Verify(sec, code, l.now())
	if !ok {
		return Result{}, nil
	}
	fresh, err := l.Store.AdvanceTOTPStep(ctx, u.GUID, step)
	return Result{OK: fresh}, err
}

// Enroll stores a verified new secret and returns fresh recovery codes to
// show once. code must match the secret (proves the authenticator works).
func (l *Local) Enroll(ctx context.Context, u *directory.User, sec []byte, code string) ([]string, bool, error) {
	step, ok := totp.Verify(sec, code, l.now())
	if !ok {
		return nil, false, nil
	}
	sealed, err := l.Box.Seal(sec, []byte(u.GUID))
	if err != nil {
		return nil, false, err
	}
	codes, err := totp.NewRecoveryCodes()
	if err != nil {
		return nil, false, err
	}
	hashes := make([]string, len(codes))
	for i, c := range codes {
		hashes[i] = totp.HashRecoveryCode(u.GUID, c)
	}
	if err := l.Store.SaveTOTP(ctx, u.GUID, sealed, step, hashes); err != nil {
		return nil, false, err
	}
	return codes, true, nil
}

// Reset removes a user's enrollment (admin action).
func (l *Local) Reset(ctx context.Context, userGUID string) (bool, error) {
	return l.Store.DeleteTOTP(ctx, userGUID)
}

// Seal and Open protect an enrollment secret kept in a browser session
// between the QR page and the confirmation.
func (l *Local) Seal(u *directory.User, sec []byte) ([]byte, error) {
	return l.Box.Seal(sec, []byte("enroll\x00"+u.GUID))
}

// OpenPending reverses Seal.
func (l *Local) OpenPending(u *directory.User, sealed []byte) ([]byte, error) {
	return l.Box.Open(sealed, []byte("enroll\x00"+u.GUID))
}

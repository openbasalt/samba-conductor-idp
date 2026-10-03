// Package mfa is the second factor of conductor-idp: TOTP with recovery
// codes. Two backends implement Backend:
//
//   - Local keeps the TOTP secret (sealed with the master key, bound to the
//     user's objectGUID) and hashed recovery codes in the idp's database,
//     with its own enrollment pages. It is the backend for an idp that does
//     not run next to conductor.
//   - Conductor asks conductor's 2FA store through a local Unix socket, so
//     users have one enrollment for both (the single source of truth the
//     architecture prefers). Enrollment then happens in conductor only.
//
// See docs/decisions.md (D4) for the choice and the socket protocol.
package mfa

import (
	"context"
	"errors"

	"github.com/openbasalt/samba-conductor-idp/internal/directory"
)

// Result of a verification.
type Result struct {
	OK bool
	// Recovery is set when a recovery code (single use) was accepted.
	Recovery bool
}

// Backend verifies second factors.
type Backend interface {
	// Name is "local" or "conductor" (logs, audit).
	Name() string
	// Enrolled reports whether the user has a second factor.
	Enrolled(ctx context.Context, u *directory.User) (bool, error)
	// Verify checks a TOTP or recovery code, with replay protection.
	Verify(ctx context.Context, u *directory.User, code string) (Result, error)
	// CanEnroll reports whether users enroll through the idp's pages.
	CanEnroll() bool
}

// ErrUnavailable is returned when the backend cannot answer (conductor's
// socket down): sign-in must stop, never skip the second factor.
var ErrUnavailable = errors.New("mfa: second-factor backend unavailable")

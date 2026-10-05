// Package mfa is the second factor of conductor-idp. Two backends
// implement Backend:
//
//   - Local keeps the TOTP secret (sealed with the master key, bound to the
//     user's objectGUID) and hashed recovery codes in the idp's database,
//     with its own enrollment pages. It is the backend for an idp that does
//     not run next to conductor.
//   - Conductor asks conductor's 2FA store through conductor's local Unix
//     socket (protocol in idpapi), so users have one enrollment (TOTP,
//     recovery codes and security keys) and one policy for both. Enrollment
//     then happens in conductor only. It also implements KeyBackend:
//     security keys (passkeys) registered in conductor work here when the
//     idp's origin is one of conductor's WebAuthn origins.
//
// See docs/decisions.md (D4, D10) for the choice and the socket protocol.
package mfa

import (
	"context"
	"encoding/json"
	"errors"

	"github.com/openbasalt/samba-conductor-idp/internal/directory"
)

// Result of a verification.
type Result struct {
	OK bool
	// Recovery is set when a recovery code (single use) was accepted.
	Recovery bool
}

// State is a user's second factor as the backend sees it.
type State struct {
	Enrolled bool
	// TOTP: an authenticator app is enrolled (else only security keys and
	// recovery codes).
	TOTP bool
	// Keys is the number of security keys (conductor backend only).
	Keys int
	// Shared: the policy comes from conductor (Required and Policy are
	// conductor's decision); otherwise the idp applies its own.
	Shared   bool
	Required bool
	Policy   string
	// KeyRequired: TOTP codes are refused for this user (a security key
	// or a recovery code is needed).
	KeyRequired bool
}

// Backend verifies second factors.
type Backend interface {
	// Name is "local" or "conductor" (logs, audit).
	Name() string
	// State reports the user's enrollment (and, for a shared policy,
	// whether a second factor is required).
	State(ctx context.Context, u *directory.User) (State, error)
	// Verify checks a TOTP or recovery code, with replay protection.
	Verify(ctx context.Context, u *directory.User, code string) (Result, error)
	// CanEnroll reports whether users enroll through the idp's pages.
	CanEnroll() bool
}

// Ceremony is a started WebAuthn assertion.
type Ceremony struct {
	ID      string
	Options json.RawMessage
}

// KeyBackend verifies security keys (WebAuthn assertions).
type KeyBackend interface {
	BeginKey(ctx context.Context, u *directory.User) (Ceremony, error)
	FinishKey(ctx context.Context, u *directory.User, ceremony, response string) (bool, error)
}

// ErrUnavailable is returned when the backend cannot answer (conductor's
// socket down): sign-in must stop, never skip the second factor.
var ErrUnavailable = errors.New("mfa: second-factor backend unavailable")

// ErrKeyRequired is returned when a TOTP code is refused because the user
// must use a security key.
var ErrKeyRequired = errors.New("mfa: a security key is required")

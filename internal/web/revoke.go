package web

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/openbasalt/samba-conductor-idp/internal/directory"
	"github.com/openbasalt/samba-conductor-idp/internal/store"
)

// errSessionRevoked ends a browser session whose account changed under it:
// its password was changed or reset in AD, or the account was revoked
// (second factor reset or enrolled, explicit revocation).
var errSessionRevoked = errors.New("web: the session's account changed since the sign-in")

// knownDeviceTTL is how long a browser stays known to an account after a
// password sign-in (the browser cookie lives as long).
const knownDeviceTTL = 30 * 24 * time.Hour

// sessionRevoked reports whether a session started before the last
// revocation of its account. Sessions that are not bound to an account yet
// (password change page) are never revoked here.
func (s *Server) sessionRevoked(ctx context.Context, sess *Session) (bool, error) {
	sess.mu.Lock()
	guid, from := sess.guid, sess.validFrom
	sess.mu.Unlock()
	if guid == "" {
		return false, nil
	}
	at, err := s.store.UserRevokedAt(ctx, guid)
	if err != nil {
		return false, err
	}
	return !at.IsZero() && at.After(from), nil
}

// endRevoked ends the request's session after errSessionRevoked and sends
// the browser to the sign-in page (keeping the flow it was in).
func (s *Server) endRevoked(rc *reqCtx, c cont) {
	if rc.sess != nil {
		s.audit(rc.ctx(), rc, "signout", "", "session ended: password or second factor changed, or account revoked", store.ResultOK)
		s.sess.destroy(rc.sess)
		rc.sess = nil
	}
	s.clearSessionCookie(rc.w)
	rc.redirect(c.with("/login?m=revoked"))
}

// userError answers a failed sessionUser: a revoked session goes back to
// the sign-in page, anything else is a directory error.
func (s *Server) userError(rc *reqCtx, c cont, err error) {
	if errors.Is(err, errSessionRevoked) {
		s.endRevoked(rc, c)
		return
	}
	rc.errorPage(http.StatusBadGateway, "err.directory")
}

// revokeUser ends what an account holds at the provider: every browser
// session on every listener, its tokens for every client, its consents and
// the browsers known to it. Sessions of other processes or started later by
// the CLI end through the stored revocation (sessionRevoked).
func (s *Server) revokeUser(ctx context.Context, u *directory.User, reason string) (store.UserRevocation, int, error) {
	rev, err := s.store.RevokeUser(ctx, u.GUID, reason)
	if err != nil {
		return rev, 0, err
	}
	if err := s.store.ForgetDevices(ctx, strings.ToLower(u.SAM)); err != nil {
		return rev, 0, err
	}
	n := 0
	for _, t := range s.allSessions {
		n += t.destroyUser(u.GUID)
	}
	return rev, n, nil
}

// ---- per-account sign-in failures (known browsers) ----

// deviceKey is the deviceFails key of an account and a browser.
func deviceKey(sam, browser string) string { return sam + "\x00" + browser }

// knownBrowser returns the browser hash when this browser completed a
// password sign-in for sam before, else "". A store error counts as
// unknown (the account-wide limit applies: fail closed).
func (s *Server) knownBrowser(ctx context.Context, rc *reqCtx, sam string) string {
	bh := rc.existingBrowserHash()
	if bh == "" {
		return ""
	}
	known, err := s.store.KnownDevice(ctx, sam, bh)
	if err != nil {
		s.log.Warn("known browser lookup failed", "err", err)
		return ""
	}
	if !known {
		return ""
	}
	return bh
}

// signInBlocked applies the per-account failure limit. A browser that
// signed in to the account before is judged by its own counter only, so
// failures from other browsers (an attacker typing the user's name) never
// lock the owner out of their usual browser; any other browser is judged
// by the account-wide counter.
func (s *Server) signInBlocked(sam, known string) bool {
	if known != "" {
		return s.deviceFails.Blocked(deviceKey(sam, known))
	}
	return s.accountFails.Blocked(sam)
}

// signInFailed counts a wrong password for an account (and for the known
// browser it came from, if any).
func (s *Server) signInFailed(sam, known string) {
	s.accountFails.Fail(sam)
	if known != "" {
		s.deviceFails.Fail(deviceKey(sam, known))
	}
}

// signInSucceeded forgets the account's failures and remembers this
// browser for the account.
func (s *Server) signInSucceeded(ctx context.Context, rc *reqCtx, sam string) {
	s.accountFails.Reset(sam)
	bh := rc.refreshBrowserCookie()
	s.deviceFails.Reset(deviceKey(sam, bh))
	if err := s.store.RememberDevice(ctx, sam, bh, knownDeviceTTL); err != nil {
		s.log.Warn("remembering the browser failed", "err", err)
	}
}

// refreshBrowserCookie (re)sets the browser cookie for its full lifetime
// and returns its hash.
func (rc *reqCtx) refreshBrowserCookie() string {
	if rc.existingBrowserHash() != "" {
		c, _ := rc.r.Cookie(browserCookie)
		setCookie(rc.w, browserCookie, c.Value, int(knownDeviceTTL/time.Second), http.SameSiteLaxMode)
		return rc.existingBrowserHash()
	}
	return rc.browserHash()
}

// ---- per-account second-factor failures ----

// mfaLocked reports whether the account's second factor is locked by too
// many wrong codes or keys (any session, any address).
func (s *Server) mfaLocked(guid string) bool { return s.mfaFails.Blocked(guid) }

// mfaFailed counts a wrong second factor for the account and reports
// whether that locked it.
func (s *Server) mfaFailed(ctx context.Context, rc *reqCtx, guid, sam string) bool {
	s.mfaFails.Fail(guid)
	if !s.mfaFails.Blocked(guid) {
		return false
	}
	s.log.Warn("second factor locked: too many wrong codes for the account", "user", sam,
		"failures", s.cfg.RateLimit.MFAFailures, "window_minutes", s.cfg.RateLimit.MFAWindowMinutes)
	s.audit(ctx, rc, "mfa.locked", sam, "too many wrong second factors for the account", store.ResultDenied)
	return true
}

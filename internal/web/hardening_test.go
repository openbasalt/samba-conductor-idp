package web

import (
	"context"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/openbasalt/samba-conductor-idp/internal/config"
	"github.com/openbasalt/samba-conductor-idp/internal/registry"
	"github.com/openbasalt/samba-conductor-idp/internal/store"
	"github.com/openbasalt/samba-conductor-idp/internal/totp"
)

// enrollWithLink enrolls a user's TOTP through a one-time link and leaves
// the browser fully signed in; it returns the secret.
func (h *harness) enrollWithLink(b *browser, sam string) []byte {
	h.t.Helper()
	tok := "Tok3n-enroll-" + sam + "-abcdefghijklmnopqrstuvwxyz0123"
	if err := h.store.CreateEnrollLink(context.Background(), LinkHash(tok), sam, "test", time.Hour); err != nil {
		h.t.Fatal(err)
	}
	b.get("/login?enroll=" + tok)
	b.mustContain(`data-e2e="signin-text-enroll"`)
	b.submit("/login", url.Values{"username": {sam}, "password": {"Passw0rd!" + sam}, "enroll": {tok}})
	sec := b.enroll()
	b.submit("/login/continue", url.Values{})
	return sec
}

func auditHas(t *testing.T, h *harness, action, detailPart string) bool {
	t.Helper()
	events, _, err := h.store.ListAudit(context.Background(), store.AuditFilter{Action: action}, 0, 50)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range events {
		if strings.Contains(e.Detail, detailPart) {
			return true
		}
	}
	return false
}

// IDP-3: email_verified is a per-client opt-in, and an address that another
// directory object also holds is never asserted.
func TestEmailClaimVerifiedOptInAndUnique(t *testing.T) {
	h := newHarness(t, harnessOpts{})
	plain := h.client(registry.ClientInput{FirstParty: true, Name: "Plain", Scopes: []string{"email"}})
	yes := true
	vouched := h.client(registry.ClientInput{FirstParty: true, Name: "Vouched", Scopes: []string{"email"}, EmailVerified: &yes})
	b := h.browser()
	v := b.authorize(plain, "openid email")
	b.login("alice")
	claims := h.idClaims(h.exchange(plain, b.code(), v).IDToken)
	if claims["email"] != "alice@lab.test" || claims["email_verified"] == true {
		t.Fatalf("default client: email=%v email_verified=%v", claims["email"], claims["email_verified"])
	}
	v = b.authorize(vouched, "openid email")
	claims = h.idClaims(h.exchange(vouched, b.code(), v).IDToken)
	if claims["email_verified"] != true {
		t.Fatalf("opted-in client: email_verified=%v", claims["email_verified"])
	}

	// Another object (a contact, a user someone gave a copy of the mail)
	// holds the address: the claim is withheld and audited.
	h.dir.mu.Lock()
	h.dir.contacts["99999999-9999-4999-8999-999999999999"] = "ALICE@lab.test"
	h.dir.mu.Unlock()
	v = b.authorize(vouched, "openid email")
	tr := h.exchange(vouched, b.code(), v)
	claims = h.idClaims(tr.IDToken)
	if _, ok := claims["email"]; ok {
		t.Fatalf("ambiguous address asserted: %v", claims["email"])
	}
	if _, ok := claims["email_verified"]; ok {
		t.Fatal("email_verified without an email")
	}
	if st, ui := h.userinfo(tr.AccessToken); st != 200 || ui["email"] != nil {
		t.Fatalf("userinfo %d %v", st, ui)
	}
	if !auditHas(t, h, "oidc.email_withheld", "not unique") {
		t.Fatal("withheld claim not audited")
	}
}

// IDP-3: an e-mail NameID is refused when the address is not unique.
func TestSAMLAmbiguousMailRefused(t *testing.T) {
	h := newHarness(t, harnessOpts{})
	sp := h.testSP(t, false, false)
	h.dir.mu.Lock()
	h.dir.contacts["99999999-9999-4999-8999-999999999999"] = "alice@lab.test"
	h.dir.mu.Unlock()
	b := h.browser()
	u, _ := mustRedirect(t, sp, h)
	b.get(u.String())
	b.login("alice")
	b.mustStatus(http.StatusBadRequest)
	b.mustContain("also set on another directory account")
	if strings.Contains(b.body, "SAMLResponse") {
		t.Fatal("a response was built")
	}
}

// IDP-5: a password changed or reset in AD ends the browser session, the
// refresh chain and userinfo of sign-ins made before it.
func TestPasswordChangeInADEndsSessionAndTokens(t *testing.T) {
	h := newHarness(t, harnessOpts{})
	c := h.client(registry.ClientInput{FirstParty: true, Scopes: []string{"offline_access", "profile"}})
	b := h.browser()
	v := b.authorize(c, "openid offline_access profile")
	b.login("alice")
	tr := h.exchange(c, b.code(), v)
	tr = h.refresh(c, tr.RefreshToken)
	if tr.Status != 200 {
		t.Fatalf("refresh before the change: %+v", tr)
	}

	// Helpdesk resets the password: pwdLastSet changes.
	h.dir.set("alice", func(u *fakeUser) { u.PwdLastSet += 10_000_000 })
	if st, _ := h.userinfo(tr.AccessToken); st == 200 {
		t.Fatal("userinfo works after a password reset")
	}
	if r := h.refresh(c, tr.RefreshToken); r.Status == 200 {
		t.Fatal("refresh works after a password reset")
	}
	if !auditHas(t, h, "oidc.refresh", "password changed") {
		t.Fatal("refusal not audited")
	}
	// The SSO session no longer mints codes: back to the sign-in page.
	b.authorize(c, "openid")
	if u := b.last.Request.URL; u.Path != "/login" || u.Query().Get("m") != "revoked" {
		t.Fatalf("session survived the reset: %s", u)
	}
	// "Must change at next logon" (pwdLastSet = 0) is a reset as well.
	b2 := h.browser()
	v = b2.authorize(c, "openid offline_access")
	b2.login("alice")
	tr = h.exchange(c, b2.code(), v)
	h.dir.set("alice", func(u *fakeUser) { u.PwdLastSet = 0 })
	if r := h.refresh(c, tr.RefreshToken); r.Status == 200 {
		t.Fatal("refresh works after must-change was set")
	}
}

// IDP-5: a second-factor reset by an administrator, and an explicit
// revocation, end the user's sessions, tokens and consents.
func TestMFAResetAndRevokeEndEverything(t *testing.T) {
	h := newHarness(t, harnessOpts{})
	c := h.client(registry.ClientInput{Scopes: []string{"offline_access"}})
	alice := h.browser()
	h.enrollWithLink(alice, "alice")
	v := alice.authorize(c, "openid offline_access")
	alice.submit("/consent", url.Values{"decision": {"allow"}})
	tr := h.exchange(c, alice.code(), v)
	if tr.RefreshToken == "" {
		t.Fatalf("%+v", tr)
	}

	adm := h.adminBrowser()
	adm.get("/admin/users")
	adm.submit("/admin/users/mfa-reset", url.Values{"username": {"alice"}})
	adm.mustContain("was reset")
	if r := h.refresh(c, tr.RefreshToken); r.Status == 200 {
		t.Fatal("refresh token survived the 2FA reset")
	}
	if g, _ := h.store.GetConsent(context.Background(), "11111111-1111-4111-8111-111111111111", c.id); g != nil {
		t.Fatal("consent survived the 2FA reset")
	}
	alice.get("/")
	if u := alice.last.Request.URL; u.Path != "/login" {
		t.Fatalf("session survived the 2FA reset: %s", u)
	}
	if !auditHas(t, h, "admin.mfa_reset", "refresh_tokens_revoked=1") {
		t.Fatal("reset audit detail")
	}

	// Explicit revocation from the admin page.
	bob := h.browser()
	bob.get("/login")
	bob.login("bob")
	bob.get("/")
	bob.mustStatus(http.StatusOK)
	adm.get("/admin/users")
	adm.submit("/admin/users/revoke", url.Values{"username": {"bob"}})
	adm.mustContain("were revoked")
	bob.get("/")
	if u := bob.last.Request.URL; u.Path != "/login" {
		t.Fatalf("session survived the revocation: %s", u)
	}
}

// IDP-5: a revocation stored by another process (CLI, management API)
// ends the running server's sessions on their next request; sessions
// started after it are not affected.
func TestStoredRevocationEndsOlderSessions(t *testing.T) {
	h := newHarness(t, harnessOpts{})
	b := h.browser()
	b.get("/login")
	b.login("bob")
	b.get("/")
	b.mustStatus(http.StatusOK)
	h.clock.Advance(time.Second)
	if _, err := h.store.RevokeUser(context.Background(), "22222222-2222-4222-8222-222222222222", "test"); err != nil {
		t.Fatal(err)
	}
	b.get("/")
	if u := b.last.Request.URL; u.Path != "/login" {
		t.Fatalf("session survived: %s", u)
	}
	h.clock.Advance(time.Second)
	b2 := h.browser()
	b2.get("/login")
	b2.login("bob")
	b2.get("/")
	b2.mustStatus(http.StatusOK)
}

// IDP-5 and IDP-7: enrolling a second factor ends the account's other
// sessions (signed in without it) but keeps the enrolling one.
func TestEnrollmentRevokesOtherSessions(t *testing.T) {
	h := newHarness(t, harnessOpts{enrollment: config.EnrollSelf})
	other := h.browser()
	other.get("/login")
	other.login("alice")
	other.get("/")
	other.mustStatus(http.StatusOK)
	h.clock.Advance(time.Second)
	b := h.browser()
	b.get("/login")
	b.login("alice")
	b.get("/login/enroll")
	b.enroll()
	b.submit("/login/continue", url.Values{})
	b.get("/")
	b.mustStatus(http.StatusOK)
	other.get("/")
	if u := other.last.Request.URL; u.Path != "/login" {
		t.Fatalf("the other session survived the enrollment: %s", u)
	}
}

// IDP-6: wrong second factors are counted per account across sessions;
// the lock refuses even a right code until the window passes, and does not
// touch the password sign-in.
func TestMFAFailuresCountedPerAccount(t *testing.T) {
	h := newHarness(t, harnessOpts{})
	sec := h.enrollWithLink(h.browser(), "alice")
	limit := h.srv.cfg.RateLimit.MFAFailures
	failures := 0
	for failures < limit {
		b := h.browser()
		b.get("/login")
		b.login("alice")
		b.mustContain(`data-e2e="mfa-input-code"`)
		// At most maxMFAFailures per session, then a new session.
		for i := 0; i < maxMFAFailures-1 && failures < limit; i++ {
			b.submit("/login/2fa", url.Values{"code": {"000000"}})
			failures++
		}
	}
	h.clock.Advance(31 * time.Second)
	h.srv.SetLimiterClock(h.clock.Now)
	b := h.browser()
	b.get("/login")
	b.login("alice")
	b.mustContain(`data-e2e="mfa-input-code"`) // the password still works
	b.submit("/login/2fa", url.Values{"code": {totp.Code(sec, totp.Step(h.clock.Now()))}})
	b.mustStatus(http.StatusTooManyRequests)
	b.mustContain("Too many wrong codes")
	if !auditHas(t, h, "mfa.locked", "too many") {
		t.Fatal("lock not audited")
	}
	// The lock ends by itself.
	h.clock.Advance(time.Duration(h.srv.cfg.RateLimit.MFAWindowMinutes)*time.Minute + time.Second)
	b = h.browser()
	b.get("/login")
	b.login("alice")
	b.submit("/login/2fa", url.Values{"code": {totp.Code(sec, totp.Step(h.clock.Now()))}})
	b.get("/")
	b.mustStatus(http.StatusOK)
	b.mustContain(`data-e2e="home-text-mfa"`)
}

// IDP-9: failures typed from other browsers cannot lock the owner out of a
// browser that signed in to the account before; new browsers stay limited.
func TestKnownBrowserNotLockedOutByOthers(t *testing.T) {
	h := newHarness(t, harnessOpts{})
	owner := h.browser()
	owner.get("/login")
	owner.login("alice")
	owner.get("/")
	owner.mustStatus(http.StatusOK)
	owner.submit("/logout", url.Values{})

	attacker := h.browser()
	attacker.get("/login")
	for i := 0; i < 5; i++ {
		attacker.submit("/login", url.Values{"username": {"alice"}, "password": {"guess"}})
	}
	attacker.submit("/login", url.Values{"username": {"alice"}, "password": {"Passw0rd!alice"}})
	attacker.mustStatus(http.StatusTooManyRequests)
	stranger := h.browser()
	stranger.get("/login")
	stranger.login("alice")
	stranger.mustStatus(http.StatusTooManyRequests)

	owner.get("/login")
	owner.login("alice")
	owner.get("/")
	owner.mustStatus(http.StatusOK)

	// The known browser has a limit of its own.
	owner.submit("/logout", url.Values{})
	owner.get("/login")
	for i := 0; i < 5; i++ {
		owner.submit("/login", url.Values{"username": {"alice"}, "password": {"typo"}})
	}
	owner.login("alice")
	owner.mustStatus(http.StatusTooManyRequests)
}

// IDP-9: a disabled (or locked, expired, restricted) account gets the
// wrong-password message; the audit log keeps the reason.
func TestAccountStateNotRevealed(t *testing.T) {
	h := newHarness(t, harnessOpts{})
	h.dir.set("bob", func(u *fakeUser) { u.Enabled = false })
	b := h.browser()
	b.get("/login")
	b.login("bob")
	b.mustStatus(http.StatusUnauthorized)
	b.mustContain("Wrong username or password")
	if strings.Contains(b.body, "disabled") {
		t.Fatal("account state revealed")
	}
	if !auditHas(t, h, "signin.failure", "account disabled") && !auditHas(t, h, "signin.failure", "reason=") {
		t.Fatal("reason not audited")
	}
}

// IDP-7: by default nobody binds an authenticator with a password alone.
func TestEnrollmentNeedsLinkByDefault(t *testing.T) {
	h := newHarness(t, harnessOpts{policy: config.MFARequired})
	b := h.browser()
	b.get("/login")
	b.login("alice")
	b.mustStatus(http.StatusForbidden)
	b.mustContain("enrollment link")
	if !auditHas(t, h, "signin.failure", "without a valid enrollment link") {
		t.Fatal("refusal not audited")
	}
	// A wrong code keeps the link; the right one consumes it.
	tok := "Tok3n-enroll-alice-wrong-code-first-0123456789"
	if err := h.store.CreateEnrollLink(context.Background(), LinkHash(tok), "alice", "test", time.Hour); err != nil {
		t.Fatal(err)
	}
	b.get("/login?enroll=" + tok)
	b.submit("/login", url.Values{"username": {"alice"}, "password": {"Passw0rd!alice"}, "enroll": {tok}})
	b.submit("/login/enroll", url.Values{"code": {"000000"}})
	b.mustStatus(http.StatusBadRequest)
	if ok, _ := h.store.ValidEnrollLink(context.Background(), LinkHash(tok), "alice"); !ok {
		t.Fatal("a wrong code consumed the link")
	}
	b.enroll()
	b.mustContain(`data-e2e="recovery-list-codes"`)
	if ok, _ := h.store.ValidEnrollLink(context.Background(), LinkHash(tok), "alice"); ok {
		t.Fatal("link still valid after the enrollment")
	}

	// Voluntary enrollment from the home page is not offered either.
	h2 := newHarness(t, harnessOpts{})
	b2 := h2.browser()
	b2.get("/login")
	b2.login("bob")
	b2.get("/")
	if strings.Contains(b2.body, `data-e2e="home-link-enroll"`) {
		t.Fatal("self-enrollment offered under the link policy")
	}
	b2.get("/login/enroll")
	b2.mustStatus(http.StatusForbidden)
}

// IDP-7: with mfa.enrollment = "self", enrollment needs a recent password.
func TestSelfEnrollmentNeedsRecentPassword(t *testing.T) {
	h := newHarness(t, harnessOpts{enrollment: config.EnrollSelf})
	b := h.browser()
	b.get("/login")
	b.login("bob")
	b.get("/")
	b.mustContain(`data-e2e="home-link-enroll"`)
	h.clock.Advance(config.EnrollSelfMaxAge + time.Minute)
	b.get("/login/enroll")
	if u := b.last.Request.URL; u.Path != "/login" || u.Query().Get("m") != "reauth" {
		t.Fatalf("stale password admitted to enrollment: %s", u)
	}
	b.get("/login?m=reauth")
	b.login("bob")
	b.get("/login/enroll")
	b.mustStatus(http.StatusOK)
	b.mustContain(`data-e2e="enroll-text-secret"`)
}

// IDP-8: CORS only on the endpoints browser clients fetch, never with
// credentials.
func TestCORSLimitedToAPIEndpoints(t *testing.T) {
	h := newHarness(t, harnessOpts{})
	c := h.client(registry.ClientInput{FirstParty: true})
	get := func(path string) http.Header {
		req, _ := http.NewRequest(http.MethodGet, h.ts.URL+path, nil)
		req.Header.Set("Origin", "https://evil.example")
		resp, err := h.ts.Client().Do(req)
		if err != nil {
			t.Fatal(err)
		}
		_ = resp.Body.Close()
		return resp.Header
	}
	hd := get("/keys")
	if hd.Get("Access-Control-Allow-Origin") == "" {
		t.Fatal("no CORS on /keys")
	}
	if hd.Get("Access-Control-Allow-Credentials") != "" {
		t.Fatal("credentials allowed on /keys")
	}
	_, challenge := pkce()
	hd = get("/authorize?" + fmtQuery("client_id", c.id, "redirect_uri", rpRedirect, "response_type", "code", "scope", "openid",
		"code_challenge", challenge, "code_challenge_method", "S256"))
	if hd.Get("Access-Control-Allow-Origin") != "" || hd.Get("Access-Control-Allow-Credentials") != "" {
		t.Fatalf("CORS on /authorize: %v", hd)
	}
	hd = get("/end_session")
	if hd.Get("Access-Control-Allow-Origin") != "" {
		t.Fatal("CORS on /end_session")
	}
	// A preflight for the token endpoint is answered without credentials.
	req, _ := http.NewRequest(http.MethodOptions, h.ts.URL+"/oauth/token", nil)
	req.Header.Set("Origin", "https://spa.example")
	req.Header.Set("Access-Control-Request-Method", "POST")
	resp, err := h.ts.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.Header.Get("Access-Control-Allow-Origin") == "" || resp.Header.Get("Access-Control-Allow-Credentials") != "" {
		t.Fatalf("token preflight: %v", resp.Header)
	}
}

// IDP-10: an ID token hint of another user (anyone's own old token) does
// not sign this browser out without confirmation.
func TestEndSessionForeignHintNeedsConfirmation(t *testing.T) {
	h := newHarness(t, harnessOpts{})
	c := h.client(registry.ClientInput{FirstParty: true, PostLogoutURIs: []string{"https://rp.example.test/bye"}})
	other := h.client(registry.ClientInput{FirstParty: true, Name: "Other", Groups: []string{sidSales.String()}})
	// The attacker's own ID token.
	mallory := h.browser()
	v := mallory.authorize(other, "openid")
	mallory.login("bob")
	hint := h.exchange(other, mallory.code(), v).IDToken

	victim := h.browser()
	v = victim.authorize(c, "openid")
	victim.login("alice")
	h.exchange(c, victim.code(), v)
	victim.get("/end_session?" + fmtQuery("id_token_hint", hint))
	for victim.last.StatusCode/100 == 3 {
		victim.get(victim.location().String())
	}
	victim.mustContain(`data-e2e="logout-btn-confirm"`)
	victim.authorize(c, "openid", "prompt", "none")
	if loc := victim.location(); loc.Query().Get("code") == "" {
		t.Fatalf("victim's session ended by a foreign hint: %s", loc)
	}
}

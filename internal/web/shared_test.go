package web

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/openbasalt/samba-conductor-idp/idpapi"
	"github.com/openbasalt/samba-conductor-idp/internal/directory"
	"github.com/openbasalt/samba-conductor-idp/internal/mfa"
	"github.com/openbasalt/samba-conductor-idp/internal/registry"
)

// sharedMFA stands for conductor's 2FA socket: conductor's policy and
// enrollment, security keys included.
type sharedMFA struct {
	mu       sync.Mutex
	state    map[string]mfa.State
	ceremony string
	finished int
}

func (f *sharedMFA) Name() string    { return "conductor" }
func (f *sharedMFA) CanEnroll() bool { return false }
func (f *sharedMFA) State(_ context.Context, u *directory.User) (mfa.State, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	st := f.state[u.SAM]
	st.Shared = true
	return st, nil
}
func (f *sharedMFA) Verify(_ context.Context, u *directory.User, code string) (mfa.Result, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.state[u.SAM].KeyRequired && len(code) == 6 {
		return mfa.Result{}, mfa.ErrKeyRequired
	}
	return mfa.Result{OK: code == "246810"}, nil
}
func (f *sharedMFA) BeginKey(context.Context, *directory.User) (mfa.Ceremony, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.ceremony = "cer-" + time.Now().Format("150405.000000")
	return mfa.Ceremony{ID: f.ceremony, Options: json.RawMessage(`{"publicKey":{"challenge":"AAAA","rpId":"lab.test"}}`)}, nil
}
func (f *sharedMFA) FinishKey(_ context.Context, _ *directory.User, ceremony, response string) (bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.finished++
	return ceremony == f.ceremony && response == `{"ok":true}`, nil
}

func TestSharedPolicyFromConductor(t *testing.T) {
	f := &sharedMFA{state: map[string]mfa.State{
		"alice": {Enrolled: true, Required: true, Policy: "optional"},
		"bob":   {Enrolled: true, Required: false, Policy: "off"},
	}}
	h := newHarness(t, harnessOpts{backend: f})
	// Conductor requires a second factor for alice: asked, verified.
	b := h.browser()
	b.get("/login")
	b.login("alice")
	b.mustContain(`data-e2e="mfa-input-code"`)
	if strings.Contains(b.body, "<script") {
		t.Fatal("script on a page without security keys")
	}
	b.submit("/login/2fa", url.Values{"code": {"246810"}})
	b.get("/")
	b.mustContain(`data-e2e="nav-btn-signout"`)
	// Conductor's policy is "off" for bob: not asked although enrolled.
	b2 := h.browser()
	b2.get("/login")
	b2.login("bob")
	b2.get("/")
	b2.mustContain(`data-e2e="nav-btn-signout"`)
}

func TestSecurityKeyThroughConductor(t *testing.T) {
	f := &sharedMFA{state: map[string]mfa.State{"alice": {Enrolled: true, Keys: 1, Required: true, Policy: "optional", KeyRequired: true}}}
	h := newHarness(t, harnessOpts{backend: f})
	b := h.browser()
	b.get("/login")
	b.login("alice")
	b.mustContain(`data-e2e="key-form-assert"`)
	b.mustContain(`/static/webauthn.js`)
	csp := b.last.Header.Get("Content-Security-Policy")
	if !strings.Contains(csp, "script-src 'nonce-") || strings.Contains(csp, "unsafe") {
		t.Fatalf("CSP: %s", csp)
	}
	// A TOTP code is refused for a user who must use a key.
	b.submit("/login/2fa", url.Values{"code": {"246810"}})
	b.mustStatus(http.StatusUnauthorized)
	b.mustContain("security key or a recovery code")
	// The script would fill "response"; a wrong one fails, a right one
	// signs in.
	b.get("/login/2fa")
	b.submit("/login/2fa/key", url.Values{"response": {`{"ok":false}`}})
	b.mustStatus(http.StatusUnauthorized)
	b.submit("/login/2fa/key", url.Values{"response": {`{"ok":true}`}})
	b.get("/")
	b.mustContain(`data-e2e="nav-btn-signout"`)
	// Each attempt went to conductor with its own ceremony.
	if f.finished != 2 {
		t.Fatalf("finished %d", f.finished)
	}
	// The static script is served with its integrity hash.
	b.get("/static/webauthn.js")
	b.mustStatus(http.StatusOK)
}

func TestRequiredButNotEnrolledInConductor(t *testing.T) {
	f := &sharedMFA{state: map[string]mfa.State{"alice": {Required: true, Policy: "required"}}}
	h := newHarness(t, harnessOpts{backend: f})
	b := h.browser()
	b.get("/login")
	b.login("alice")
	b.mustStatus(http.StatusForbidden)
}

func TestSettingsApplied(t *testing.T) {
	h := newHarness(t, harnessOpts{})
	h.srv.ApplySettings(idpapi.Settings{SessionIdleMinutes: 5, SessionAbsoluteHours: 1, MFAPolicy: "off",
		ConsentText: map[string]string{"en": "Data stays in the company.", "pt-BR": "Os dados ficam na empresa."}})
	c := h.client(registry.ClientInput{Scopes: []string{"profile"}})
	b := h.browser()
	b.authorize(c, "openid profile")
	b.login("alice")
	b.mustContain(`data-e2e="consent-text-note"`)
	b.mustContain("Data stays in the company.")
	// The idle limit applies to the running session.
	h.clock.Advance(6 * time.Minute)
	b.get("/")
	b.mustContain(`data-e2e="signin-input-username"`)
}

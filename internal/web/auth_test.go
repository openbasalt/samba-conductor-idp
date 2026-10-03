package web

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/openbasalt/samba-conductor-idp/internal/config"
	"github.com/openbasalt/samba-conductor-idp/internal/directory"
	"github.com/openbasalt/samba-conductor-idp/internal/mfa"
	"github.com/openbasalt/samba-conductor-idp/internal/registry"
	"github.com/openbasalt/samba-conductor-idp/internal/store"
	"github.com/openbasalt/samba-conductor-idp/internal/totp"
)

func TestWrongPasswordAndAccountLimit(t *testing.T) {
	h := newHarness(t, harnessOpts{})
	b := h.browser()
	b.get("/login")
	for i := 0; i < 5; i++ {
		b.submit("/login", url.Values{"username": {"alice"}, "password": {"nope"}})
		b.mustStatus(http.StatusUnauthorized)
		b.mustContain("Wrong username or password")
	}
	// The per-account limit stops before AD would lock the account.
	b.submit("/login", url.Values{"username": {"alice"}, "password": {"Passw0rd!alice"}})
	b.mustStatus(http.StatusTooManyRequests)
	h.clock.Advance(16 * time.Minute)
	h.srv.SetLimiterClock(h.clock.Now)
}

func TestCSRFRequired(t *testing.T) {
	h := newHarness(t, harnessOpts{})
	b := h.browser()
	b.get("/login")
	b.post("/login", url.Values{"username": {"alice"}, "password": {"Passw0rd!alice"}})
	b.mustStatus(http.StatusForbidden)
	// Cross-site form posts are refused even with a token.
	b.get("/login")
	req, _ := http.NewRequest(http.MethodPost, h.ts.URL+"/login", strings.NewReader(url.Values{"csrf": {b.csrf()},
		"username": {"alice"}, "password": {"Passw0rd!alice"}}.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Sec-Fetch-Site", "cross-site")
	b.do(req)
	b.mustStatus(http.StatusForbidden)
}

func TestSecurityHeaders(t *testing.T) {
	h := newHarness(t, harnessOpts{})
	b := h.browser()
	b.get("/login")
	hd := b.last.Header
	for k, want := range map[string]string{
		"X-Frame-Options": "DENY", "X-Content-Type-Options": "nosniff", "Referrer-Policy": "no-referrer",
		"Cache-Control": "no-store",
	} {
		if hd.Get(k) != want {
			t.Errorf("%s = %q", k, hd.Get(k))
		}
	}
	csp := hd.Get("Content-Security-Policy")
	for _, want := range []string{"default-src 'none'", "script-src 'none'", "frame-ancestors 'none'", "form-action 'self'"} {
		if !strings.Contains(csp, want) {
			t.Errorf("CSP lacks %q: %s", want, csp)
		}
	}
	if strings.Contains(b.body, "<script") {
		t.Error("page has a script")
	}
	for _, c := range b.last.Cookies() {
		if !strings.HasPrefix(c.Name, "__Host-") && c.Name != "lang" && c.Name != "theme" {
			t.Errorf("cookie %s without __Host- prefix", c.Name)
		}
		if !c.Secure || !c.HttpOnly {
			t.Errorf("cookie %s not Secure+HttpOnly", c.Name)
		}
	}
}

// TestRouteGuards enumerates every page route and checks what an
// anonymous browser and a non-admin user get.
func TestRouteGuards(t *testing.T) {
	h := newHarness(t, harnessOpts{})
	anon := h.browser()
	user := h.browser()
	user.get("/login")
	user.login("alice")
	for _, rt := range h.srv.pages() {
		path := regexp.MustCompile(`\{[a-z]+\}`).ReplaceAllString(strings.TrimSuffix(rt.pattern, "{$}"), "x")
		if rt.method != http.MethodGet {
			continue
		}
		anon.get(path)
		switch rt.perm {
		case PermPublic:
		case PermPreAuth, PermUser, PermAdmin:
			if anon.last.StatusCode != http.StatusOK || !strings.Contains(anon.body, `data-e2e="signin-input-username"`) {
				t.Errorf("anonymous %s: status %d, not the sign-in page", path, anon.last.StatusCode)
			}
		}
		if rt.perm == PermAdmin {
			user.get(path)
			if user.last.StatusCode != http.StatusForbidden {
				t.Errorf("non-admin %s: status %d", path, user.last.StatusCode)
			}
		}
	}
	// POSTs to admin routes are refused for a non-admin too (with CSRF).
	user.get("/")
	user.submit("/admin/clients", url.Values{"name": {"x"}})
	user.mustStatus(http.StatusForbidden)
}

func TestExpiredPasswordChange(t *testing.T) {
	h := newHarness(t, harnessOpts{})
	b := h.browser()
	b.get("/login")
	b.submit("/login", url.Values{"username": {"mustchange"}, "password": {"Passw0rd!mustchange"}})
	b.mustStatus(http.StatusOK)
	b.mustContain(`data-e2e="password-input-current"`)
	// The old password is required again.
	b.submit("/login/password", url.Values{"current": {"wrong"}, "new": {"N3w-Passw0rd"}, "confirm": {"N3w-Passw0rd"}})
	b.mustContain("current password is wrong")
	b.submit("/login/password", url.Values{"current": {"Passw0rd!mustchange"}, "new": {"N3w-Passw0rd"}, "confirm": {"N3w-Passw0rd"}})
	b.mustStatus(http.StatusOK)
	b.mustContain("Password changed")
	if h.dir.changed["mustchange"] != "N3w-Passw0rd" {
		t.Fatal("password not changed")
	}
	// A wrong password never reaches the change page.
	b.submit("/login", url.Values{"username": {"bob"}, "password": {"nope"}})
	if strings.Contains(b.body, "password-input-current") {
		t.Fatal("wrong password led to the change page")
	}
}

func TestAdminNeedsEnrollmentLinkThen2FA(t *testing.T) {
	h := newHarness(t, harnessOpts{})
	ctx := context.Background()
	b := h.browser()
	b.get("/login")
	b.login("admin")
	b.mustStatus(http.StatusForbidden)
	b.mustContain("one-time link")

	tok := "Tok3n-for-the-admin-enrollment-link-0123456789"
	if err := h.store.CreateEnrollLink(ctx, LinkHash(tok), "admin", "test", time.Hour); err != nil {
		t.Fatal(err)
	}
	b.get("/login?enroll=" + tok)
	b.mustContain(`data-e2e="signin-text-enroll"`)
	b.submit("/login", url.Values{"username": {"admin"}, "password": {"Passw0rd!admin"}, "enroll": {tok}})
	sec := b.enroll()
	b.mustContain(`data-e2e="recovery-list-codes"`)
	codes := codesRE.FindAllStringSubmatch(b.body, -1)
	if len(codes) != totp.RecoveryCodeCount {
		t.Fatalf("%d recovery codes", len(codes))
	}
	b.submit("/login/continue", url.Values{})
	b.get("/admin/clients")
	b.mustStatus(http.StatusOK)
	b.mustContain(`data-e2e="clients-link-new"`)
	// The link is single use.
	if ok, _ := h.store.ValidEnrollLink(ctx, LinkHash(tok), "admin"); ok {
		t.Fatal("enrollment link still valid")
	}

	// Next sign-in: the code is required, a replayed code is refused, a
	// recovery code works once.
	b2 := h.browser()
	b2.get("/login")
	b2.login("admin")
	b2.mustContain(`data-e2e="mfa-input-code"`)
	b2.submit("/login/2fa", url.Values{"code": {totp.Code(sec, totp.Step(h.clock.Now()))}})
	b2.mustContain(`data-e2e="mfa-input-code"`) // same step as the enrollment: replay
	b2.submit("/login/2fa", url.Values{"code": {codes[0][1]}})
	b2.get("/admin/keys")
	b2.mustStatus(http.StatusOK)
	b3 := h.browser()
	b3.get("/login")
	b3.login("admin")
	b3.submit("/login/2fa", url.Values{"code": {codes[0][1]}})
	b3.mustStatus(http.StatusUnauthorized)
	h.clock.Advance(31 * time.Second)
	b3.submit("/login/2fa", url.Values{"code": {totp.Code(sec, totp.Step(h.clock.Now()))}})
	b3.get("/admin/audit")
	b3.mustStatus(http.StatusOK)
	b3.mustContain(`data-e2e="audit-text-chain-ok"`)
}

func TestAdminCreatesClientAndRotates(t *testing.T) {
	h := newHarness(t, harnessOpts{})
	b := h.adminBrowser()
	b.get("/admin/clients/new")
	b.submit("/admin/clients", url.Values{"name": {"Grafana"}, "kind": {"confidential"}, "redirect_uris": {"https://grafana.test/login/generic_oauth"},
		"scopes": {"profile", "email"}, "groups": {"Engineering"}, "groups_claim": {"names"}})
	b.mustStatus(http.StatusOK)
	secret := regexp.MustCompile(`data-e2e="secret-text-secret">([^<]+)<`).FindStringSubmatch(b.body)
	id := regexp.MustCompile(`data-e2e="secret-text-client-id">([^<]+)<`).FindStringSubmatch(b.body)
	if secret == nil || id == nil {
		t.Fatalf("no secret shown: %.500s", b.body)
	}
	c, err := h.store.GetClient(context.Background(), id[1])
	if err != nil || c.AllowedGroups[0] != sidEngineering.String() || c.GroupsClaim != "names" {
		t.Fatalf("stored %+v %v", c, err)
	}
	// Invalid redirect URIs are refused with a message.
	b.get("/admin/clients/new")
	b.submit("/admin/clients", url.Values{"name": {"Bad"}, "kind": {"confidential"}, "redirect_uris": {"http://evil.test/cb"}, "allow_all": {"1"}})
	b.mustStatus(http.StatusBadRequest)
	b.mustContain("plain http")
	// Rotate and delete.
	b.get("/admin/clients/" + id[1])
	b.submit("/admin/clients/"+id[1]+"/rotate", url.Values{})
	b.mustContain(`data-e2e="secret-text-secret"`)
	b.get("/admin/clients/" + id[1])
	b.submit("/admin/clients/"+id[1]+"/delete", url.Values{"confirm": {id[1]}})
	if _, err := h.store.GetClient(context.Background(), id[1]); !errors.Is(err, store.ErrNotFound) {
		t.Fatal("client not deleted")
	}
	events, _, _ := h.store.ListAudit(context.Background(), store.AuditFilter{Action: "admin.client"}, 0, 10)
	if len(events) < 3 || events[0].ActorName != "admin" {
		t.Fatalf("admin actions not audited: %+v", events)
	}
}

// adminBrowser signs in the test administrator with 2FA.
func (h *harness) adminBrowser() *browser {
	h.t.Helper()
	tok := "Tok3n-for-the-admin-enrollment-link-abcdefghij"
	if err := h.store.CreateEnrollLink(context.Background(), LinkHash(tok), "admin", "test", time.Hour); err != nil {
		h.t.Fatal(err)
	}
	b := h.browser()
	b.get("/login?enroll=" + tok)
	b.submit("/login", url.Values{"username": {"admin"}, "password": {"Passw0rd!admin"}, "enroll": {tok}})
	b.enroll()
	b.submit("/login/continue", url.Values{})
	return b
}

func TestPolicyRequiredEnrollsUsers(t *testing.T) {
	h := newHarness(t, harnessOpts{policy: config.MFARequired})
	c := h.client(registry.ClientInput{FirstParty: true})
	b := h.browser()
	b.authorize(c, "openid")
	b.login("alice")
	b.enroll()
	b.mustContain(`data-e2e="recovery-btn-continue"`)
	b.submit("/login/continue", url.Values{})
	if b.code() == "" {
		t.Fatal("no code after enrollment")
	}
}

func TestClientRequiresMFAStepUp(t *testing.T) {
	h := newHarness(t, harnessOpts{policy: config.MFAOptional})
	plain := h.client(registry.ClientInput{FirstParty: true, Name: "Plain"})
	strict := h.client(registry.ClientInput{FirstParty: true, Name: "Strict", RequireMFA: true})
	b := h.browser()
	b.authorize(plain, "openid")
	b.login("alice")
	b.code()
	// The strict client sends the signed-in user through enrollment.
	b.authorize(strict, "openid")
	if p := b.last.Request.URL.Path; p != "/login/enroll" {
		t.Fatalf("step-up went to %s", p)
	}
	b.enroll()
	b.submit("/login/continue", url.Values{})
	if b.code() == "" {
		t.Fatal("no code after step-up")
	}
}

// failingMFA simulates conductor's socket being down.
type failingMFA struct{}

func (failingMFA) Name() string { return "conductor" }
func (failingMFA) Enrolled(context.Context, *directory.User) (bool, error) {
	return false, mfa.ErrUnavailable
}
func (failingMFA) Verify(context.Context, *directory.User, string) (mfa.Result, error) {
	return mfa.Result{}, mfa.ErrUnavailable
}
func (failingMFA) CanEnroll() bool { return false }

func TestMFABackendDownFailsClosed(t *testing.T) {
	h := newHarness(t, harnessOpts{backend: failingMFA{}})
	b := h.browser()
	b.get("/login")
	b.login("alice")
	b.mustStatus(http.StatusServiceUnavailable)
	b.get("/")
	if !strings.Contains(b.body, `data-e2e="signin-input-username"`) {
		t.Fatal("signed in while the 2FA backend was down")
	}
}

func TestLanguageAndTheme(t *testing.T) {
	h := newHarness(t, harnessOpts{})
	b := h.browser()
	b.get("/login?lang=pt-BR")
	b.mustContain("Entrar")
	b.mustContain(`lang="pt-BR"`)
	b.get("/login")
	b.mustContain("Usuário")
	b.get("/login?theme=dark&lang=en")
	b.mustContain(`data-theme="dark"`)
	b.mustContain("Username")
}

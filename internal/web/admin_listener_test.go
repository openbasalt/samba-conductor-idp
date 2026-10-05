package web

import (
	"context"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/openbasalt/samba-conductor-idp/internal/totp"
)

// TestAdminRoutesOnlyOnAdminSurface keeps every admin page off the public
// surface: a new admin route without on: surfaceAdmin would be served on
// the internet-facing listener.
func TestAdminRoutesOnlyOnAdminSurface(t *testing.T) {
	h := newHarness(t, harnessOpts{})
	for _, rt := range h.srv.pages() {
		isAdmin := rt.perm == PermAdmin || rt.pattern == "/admin" || strings.HasPrefix(rt.pattern, "/admin/")
		if isAdmin && rt.on != surfaceAdmin {
			t.Errorf("%s %s: admin route not limited to the admin surface", rt.method, rt.pattern)
		}
		if !isAdmin && rt.on == surfaceAdmin {
			t.Errorf("%s %s: non-admin route only on the admin surface", rt.method, rt.pattern)
		}
	}
}

// adminPaths are GET admin pages (with placeholders filled in).
func adminPaths(h *harness) []string {
	var out []string
	for _, rt := range h.srv.pages() {
		if rt.on == surfaceAdmin && rt.method == http.MethodGet {
			out = append(out, regexp.MustCompile(`\{[a-z]+\}`).ReplaceAllString(rt.pattern, "x"))
		}
	}
	return out
}

// mustNotFound checks a plain 404 that says nothing about the admin
// listener.
func mustNotFound(t *testing.T, h *harness, b *browser, what string) {
	t.Helper()
	if b.last.StatusCode != http.StatusNotFound {
		t.Fatalf("%s: status %d, want 404", what, b.last.StatusCode)
	}
	if loc := b.last.Header.Get("Location"); loc != "" {
		t.Fatalf("%s: redirect to %q", what, loc)
	}
	if h.adminTS != nil && strings.Contains(b.body, strings.TrimPrefix(h.adminTS.URL, "https://")) {
		t.Fatalf("%s: the answer names the admin listener", what)
	}
}

func TestSeparateAdminListener(t *testing.T) {
	h := newHarness(t, harnessOpts{admin: "split"})
	ctx := context.Background()

	// The public listener answers every admin path like an unknown path,
	// for anonymous visitors and signed-in administrators alike.
	anon := h.browser()
	for _, p := range adminPaths(h) {
		anon.get(p)
		mustNotFound(t, h, anon, "anonymous GET "+p)
	}
	anon.get("/login")
	anon.submit("/admin/clients", url.Values{"name": {"x"}})
	mustNotFound(t, h, anon, "anonymous POST /admin/clients")

	// An enrollment link is not accepted on the public listener: the form
	// does not carry it and the administrator is refused.
	tok := "Tok3n-for-the-public-listener-link-0123456789"
	if err := h.store.CreateEnrollLink(ctx, LinkHash(tok), "admin", "test", time.Hour); err != nil {
		t.Fatal(err)
	}
	pub := h.browser()
	pub.get("/login?enroll=" + tok)
	if strings.Contains(pub.body, `data-e2e="signin-text-enroll"`) {
		t.Fatal("the public listener offers an enrollment link")
	}
	pub.submit("/login", url.Values{"username": {"admin"}, "password": {"Passw0rd!admin"}, "enroll": {tok}})
	pub.mustStatus(http.StatusForbidden)
	pub.mustContain("one-time link")
	if ok, _ := h.store.ValidEnrollLink(ctx, LinkHash(tok), "admin"); !ok {
		t.Fatal("the public listener consumed the enrollment link")
	}

	// The administrator enrolls and signs in on the admin listener.
	jar, _ := cookiejar.New(nil)
	adm := h.browserOn(h.adminTS, jar)
	sec := h.signInAdmin(adm)
	adm.get("/")
	adm.mustStatus(http.StatusOK)
	adm.mustContain(`data-e2e="clients-link-new"`)
	adm.get("/admin/keys")
	adm.mustStatus(http.StatusOK)

	// Enrollment links made there point at the admin listener.
	adm.get("/admin/users")
	adm.submit("/admin/users/enroll-link", url.Values{"username": {"alice"}})
	adm.mustStatus(http.StatusOK)
	adm.mustContain(h.adminTS.URL + "/login?enroll=")

	// The admin listener serves no OpenID Connect or SAML endpoint and no
	// consent page.
	for _, p := range []string{"/.well-known/openid-configuration", "/authorize", "/oauth/token", "/keys", "/saml/metadata", "/saml/sso", "/consent", "/logout/rp"} {
		adm.get(p)
		if adm.last.StatusCode != http.StatusNotFound {
			t.Errorf("admin listener GET %s: status %d, want 404", p, adm.last.StatusCode)
		}
	}

	// The same administrator, with 2FA, on the public listener: no admin
	// page and no link to one.
	pubAdm := h.browser()
	pubAdm.get("/login")
	pubAdm.login("admin")
	pubAdm.mustContain(`data-e2e="mfa-input-code"`)
	h.clock.Advance(31 * time.Second) // not the enrollment's time step
	pubAdm.submit("/login/2fa", url.Values{"code": {totp.Code(sec, totp.Step(h.clock.Now()))}})
	pubAdm.get("/")
	pubAdm.mustStatus(http.StatusOK)
	if strings.Contains(pubAdm.body, "home-link-admin") {
		t.Fatal("the public home page links to the admin pages")
	}
	pubAdm.get("/admin/clients")
	mustNotFound(t, h, pubAdm, "administrator GET /admin/clients on the public listener")

	// A user who is not an administrator cannot sign in on the admin
	// listener.
	user := h.browserOn(h.adminTS, nil)
	user.get("/login")
	user.login("alice")
	user.mustStatus(http.StatusForbidden)
	user.mustContain("administrators only")
	if c := cookieNamed(user.last, adminSessionCookie); c != nil && c.MaxAge >= 0 {
		t.Fatal("a session was created for a non-administrator")
	}

	// CSRF is enforced on the admin listener.
	adm.get("/admin/clients/new")
	adm.post("/admin/clients", url.Values{"name": {"x"}, "csrf": {"wrong"}})
	adm.mustStatus(http.StatusForbidden)
}

func cookieNamed(resp *http.Response, name string) *http.Cookie {
	for _, c := range resp.Cookies() {
		if c.Name == name {
			return c
		}
	}
	return nil
}

// TestAdminSessionNotValidOnPublicListener presents each listener's
// session cookie to the other one, under both cookie names.
func TestAdminSessionNotValidOnPublicListener(t *testing.T) {
	h := newHarness(t, harnessOpts{admin: "split"})
	jar, _ := cookiejar.New(nil)
	adm := h.browserOn(h.adminTS, jar)
	tokCapture := &cookieCapture{}
	adm.c.Transport = tokCapture.wrap(adm.c.Transport)
	h.signInAdmin(adm)
	adminTok := tokCapture.last[adminSessionCookie]
	if adminTok == nil {
		t.Fatal("no admin session cookie")
	}
	if !adminTok.Secure || !adminTok.HttpOnly || adminTok.SameSite != http.SameSiteStrictMode || adminTok.Path != "/" || adminTok.Domain != "" {
		t.Fatalf("admin session cookie flags: %+v", adminTok)
	}
	if tokCapture.last[sessionCookie] != nil {
		t.Fatal("the admin listener set the public session cookie")
	}

	pub := h.browser()
	pubCapture := &cookieCapture{}
	pub.c.Transport = pubCapture.wrap(pub.c.Transport)
	pub.get("/login")
	pub.login("alice")
	pub.get("/")
	pub.mustStatus(http.StatusOK)
	userTok := pubCapture.last[sessionCookie]
	if userTok == nil || pubCapture.last[adminSessionCookie] != nil {
		t.Fatal("public listener cookies wrong")
	}

	raw := func(base, path string, cookies ...*http.Cookie) *http.Response {
		t.Helper()
		req, _ := http.NewRequest(http.MethodGet, base+path, nil)
		for _, c := range cookies {
			req.AddCookie(c)
		}
		tr := h.ts.Client().Transport
		if base == h.adminTS.URL {
			tr = h.adminTS.Client().Transport
		}
		resp, err := (&http.Client{Transport: tr, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}).Do(req)
		if err != nil {
			t.Fatal(err)
		}
		_ = resp.Body.Close()
		return resp
	}
	// The admin session works on the admin listener...
	if r := raw(h.adminTS.URL, "/admin/clients", &http.Cookie{Name: adminSessionCookie, Value: adminTok.Value}); r.StatusCode != http.StatusOK {
		t.Fatalf("admin session on the admin listener: %d", r.StatusCode)
	}
	// ...and is nobody on the public listener, under either name.
	for _, name := range []string{sessionCookie, adminSessionCookie} {
		r := raw(h.ts.URL, "/", &http.Cookie{Name: name, Value: adminTok.Value})
		if loc, _ := r.Location(); r.StatusCode != http.StatusSeeOther || loc == nil || loc.Path != "/login" {
			t.Fatalf("admin session as %s on the public listener: %d", name, r.StatusCode)
		}
	}
	// A public session is nobody on the admin listener, under either name.
	for _, name := range []string{sessionCookie, adminSessionCookie} {
		r := raw(h.adminTS.URL, "/admin/clients", &http.Cookie{Name: name, Value: userTok.Value})
		if loc, _ := r.Location(); r.StatusCode != http.StatusSeeOther || loc == nil || loc.Path != "/login" {
			t.Fatalf("public session as %s on the admin listener: %d", name, r.StatusCode)
		}
	}
	// The admin listener answers only for the admin_url host name.
	req, _ := http.NewRequest(http.MethodGet, h.adminTS.URL+"/login", nil)
	req.Host = "idp.example.com"
	resp, err := h.adminTS.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusMisdirectedRequest {
		t.Fatalf("foreign Host on the admin listener: %d", resp.StatusCode)
	}
}

// cookieCapture records the last Set-Cookie of each name.
type cookieCapture struct {
	last map[string]*http.Cookie
}

func (c *cookieCapture) wrap(rt http.RoundTripper) http.RoundTripper {
	c.last = map[string]*http.Cookie{}
	return roundTripFunc(func(req *http.Request) (*http.Response, error) {
		resp, err := rt.RoundTrip(req)
		if err == nil {
			for _, k := range resp.Cookies() {
				if k.MaxAge >= 0 && k.Value != "" {
					c.last[k.Name] = k
				}
			}
		}
		return resp, err
	})
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestAdminPagesOff(t *testing.T) {
	h := newHarness(t, harnessOpts{admin: "off"})
	if h.srv.AdminHandler() != nil {
		t.Fatal("an admin handler with the admin pages off")
	}
	anon := h.browser()
	for _, p := range adminPaths(h) {
		anon.get(p)
		mustNotFound(t, h, anon, "GET "+p)
	}
	// With nowhere else to enroll, the public listener still accepts an
	// administrator's one-time enrollment link.
	b := h.browser()
	h.signInAdmin(b)
	b.get("/")
	b.mustStatus(http.StatusOK)
	if strings.Contains(b.body, "home-link-admin") {
		t.Fatal("home links to the admin pages while they are off")
	}
	b.get("/admin/clients")
	mustNotFound(t, h, b, "administrator GET /admin/clients")
}

// TestAdminPagesSharedByDefault: without server.admin_listen everything
// stays on the main listener.
func TestAdminPagesSharedByDefault(t *testing.T) {
	h := newHarness(t, harnessOpts{})
	if h.srv.AdminHandler() != nil {
		t.Fatal("a separate admin handler without server.admin_listen")
	}
	b := h.adminBrowser()
	b.get("/")
	b.mustContain("home-link-admin")
	b.get("/admin/users")
	b.submit("/admin/users/enroll-link", url.Values{"username": {"alice"}})
	b.mustContain(h.ts.URL + "/login?enroll=")
}

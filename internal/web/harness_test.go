package web

import (
	"context"
	"crypto/sha256"
	"encoding/base32"
	"encoding/base64"
	"errors"
	"html"
	"io"
	"log/slog"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/go-ldap/ldap/v3"
	ad "github.com/openbasalt/samba-conductor-ad"
	"github.com/openbasalt/samba-conductor-ad/sid"

	"github.com/openbasalt/samba-conductor-idp/internal/config"
	"github.com/openbasalt/samba-conductor-idp/internal/directory"
	"github.com/openbasalt/samba-conductor-idp/internal/mfa"
	"github.com/openbasalt/samba-conductor-idp/internal/oidcp"
	"github.com/openbasalt/samba-conductor-idp/internal/samlidp"
	"github.com/openbasalt/samba-conductor-idp/internal/secret"
	"github.com/openbasalt/samba-conductor-idp/internal/store"
	"github.com/openbasalt/samba-conductor-idp/internal/totp"
)

// ---- fake directory ----

const domainSID = "S-1-5-21-1111-2222-3333"

func dsid(rid uint32) sid.SID {
	d := sid.MustParse(domainSID)
	s, _ := d.WithRID(rid)
	return s
}

var (
	sidDomainAdmins = dsid(512)
	sidDomainUsers  = dsid(513)
	sidEngineering  = dsid(1101)
	sidSales        = dsid(1102)
)

type fakeUser struct {
	directory.User
	password string
	// refuse makes Authenticate fail with this AD sub-code (e.g. "773").
	refuse string
}

type fakeDir struct {
	mu    sync.Mutex
	users map[string]*fakeUser // by sam
	names map[string]string    // SID -> group name
	// changed records expired-password changes.
	changed map[string]string
}

func newFakeDir() *fakeDir {
	d := &fakeDir{users: map[string]*fakeUser{}, changed: map[string]string{}, names: map[string]string{
		sidDomainAdmins.String(): "Domain Admins", sidDomainUsers.String(): "Domain Users",
		sidEngineering.String(): "Engineering", sidSales.String(): "Sales",
	}}
	add := func(sam, guid string, rid uint32, mail string, groups ...sid.SID) *fakeUser {
		u := &fakeUser{password: "Passw0rd!" + sam, User: directory.User{GUID: guid, SID: dsid(rid), SAM: sam, UPN: sam + "@lab.test",
			Mail: mail, DisplayName: strings.ToUpper(sam[:1]) + sam[1:], GivenName: sam, Surname: "Tester", Enabled: true,
			GroupSIDs: append([]sid.SID{sidDomainUsers}, groups...)}}
		d.users[sam] = u
		return u
	}
	add("alice", "11111111-1111-4111-8111-111111111111", 2001, "alice@lab.test", sidEngineering)
	add("bob", "22222222-2222-4222-8222-222222222222", 2002, "bob@lab.test", sidSales)
	add("admin", "33333333-3333-4333-8333-333333333333", 2003, "admin@lab.test", sidDomainAdmins, sidEngineering)
	mc := add("mustchange", "44444444-4444-4444-8444-444444444444", 2004, "", sidEngineering)
	mc.refuse = "773"
	add("nomail", "55555555-5555-4555-8555-555555555555", 2005, "", sidEngineering)
	return d
}

func (d *fakeDir) Realm() string { return "LAB.TEST" }

func (d *fakeDir) Authenticate(_ context.Context, sam, password string) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	u, ok := d.users[sam]
	if !ok || u.password != password {
		return ad.ClassifyBindError(ldap.NewError(ldap.LDAPResultInvalidCredentials, errors.New("80090308: LdapErr: DSID-0C09041C, comment: AcceptSecurityContext error, data 52e, v4563")))
	}
	if u.refuse != "" {
		return ad.ClassifyBindError(ldap.NewError(ldap.LDAPResultInvalidCredentials, errors.New("80090308: LdapErr: DSID-0C09041C, comment: AcceptSecurityContext error, data "+u.refuse+", v4563")))
	}
	if !u.Enabled {
		return ad.ClassifyBindError(ldap.NewError(ldap.LDAPResultInvalidCredentials, errors.New("AcceptSecurityContext error, data 533, v4563")))
	}
	return nil
}

func (d *fakeDir) ChangeExpiredPassword(_ context.Context, sam, oldPassword, newPassword string) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	u, ok := d.users[sam]
	if !ok || u.password != oldPassword {
		return ad.ErrWrongPassword
	}
	if len(newPassword) < 8 {
		return ad.ErrPasswordPolicy
	}
	u.password, u.refuse = newPassword, ""
	d.changed[sam] = newPassword
	return nil
}

func (d *fakeDir) copyUser(u *fakeUser) *directory.User {
	c := u.User
	c.GroupSIDs = append([]sid.SID(nil), u.GroupSIDs...)
	return &c
}

func (d *fakeDir) UserBySAM(_ context.Context, sam string) (*directory.User, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	u, ok := d.users[strings.ToLower(sam)]
	if !ok {
		return nil, directory.ErrNotFound
	}
	return d.copyUser(u), nil
}

func (d *fakeDir) UserByGUID(_ context.Context, guid string) (*directory.User, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	for _, u := range d.users {
		if u.GUID == guid {
			return d.copyUser(u), nil
		}
	}
	return nil, directory.ErrNotFound
}

func (d *fakeDir) GroupNames(_ context.Context, sids []sid.SID) (map[string]string, error) {
	out := map[string]string{}
	for _, s := range sids {
		if n, ok := d.names[s.String()]; ok {
			out[s.String()] = n
		}
	}
	return out, nil
}

func (d *fakeDir) DomainAdminsSID(context.Context) (sid.SID, error) { return sidDomainAdmins, nil }

func (d *fakeDir) GroupByName(_ context.Context, name string) (sid.SID, error) {
	for s, n := range d.names {
		if strings.EqualFold(n, name) {
			return sid.Parse(s)
		}
	}
	return sid.SID{}, directory.ErrGroupNotFound
}

func (d *fakeDir) set(sam string, f func(u *fakeUser)) {
	d.mu.Lock()
	defer d.mu.Unlock()
	f(d.users[sam])
}

// ---- harness ----

type harness struct {
	t  *testing.T
	ts *httptest.Server
	// adminTS is the separate admin listener (harnessOpts.admin "split").
	adminTS *httptest.Server
	srv     *Server
	store   *store.Store
	dir     *fakeDir
	local   *mfa.Local
	oidc    *oidcp.KeyManager
	saml    *samlidp.IdP
	clock   *fakeClock
}

type fakeClock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *fakeClock) Advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(d)
}

type harnessOpts struct {
	policy  string
	backend mfa.Backend
	// admin: "" (admin pages on the main listener), "split" (a separate
	// admin listener, h.adminTS) or "off".
	admin string
}

func newHarness(t *testing.T, o harnessOpts) *harness {
	t.Helper()
	ctx := context.Background()
	h := &harness{t: t, dir: newFakeDir(), clock: &fakeClock{t: time.Now().UTC()}}
	var handler http.Handler = http.NotFoundHandler()
	h.ts = httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { handler.ServeHTTP(w, r) }))
	h.ts.StartTLS()
	t.Cleanup(h.ts.Close)
	var adminHandler http.Handler = http.NotFoundHandler()
	if o.admin == "split" {
		h.adminTS = httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { adminHandler.ServeHTTP(w, r) }))
		h.adminTS.StartTLS()
		t.Cleanup(h.adminTS.Close)
	}

	st, err := store.Open(ctx, ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	st.SetClock(h.clock.Now)
	h.store = st
	cfg := config.Default()
	cfg.Server.Issuer = h.ts.URL
	cfg.Server.TLSCert, cfg.Server.TLSKey = "/x/cert.pem", "/x/key.pem"
	cfg.Domain.Realm, cfg.Domain.CAFile = "LAB.TEST", "/x/ca.pem"
	cfg.ServiceAccount.Username = "svc-idp"
	cfg.SAML.Enabled = true
	if o.policy != "" {
		cfg.MFA.Policy = o.policy
	}
	switch o.admin {
	case "split":
		cfg.Server.AdminListen = "127.0.0.1:9444"
		cfg.Server.AdminURL = h.adminTS.URL
	case "off":
		cfg.Server.AdminListen = config.AdminOff
	}
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i)
	}
	box, _ := secret.New(key)
	h.oidc = &oidcp.KeyManager{Store: st, Box: box, RotateAfter: cfg.KeyRotateAfter(), Overlap: cfg.KeyOverlap(), Now: h.clock.Now}
	if _, err := h.oidc.Ensure(ctx); err != nil {
		t.Fatal(err)
	}
	samlKeys := &samlidp.KeyManager{Store: st, Box: box, Subject: "idp.test", Overlap: cfg.KeyOverlap(), Now: h.clock.Now}
	if _, err := samlKeys.Ensure(ctx); err != nil {
		t.Fatal(err)
	}
	h.saml = &samlidp.IdP{Store: st, Dir: h.dir, Keys: samlKeys, BaseURL: cfg.Issuer(), AssertionTTL: 5 * time.Minute, Now: h.clock.Now}
	h.local = &mfa.Local{Store: st, Box: box, Now: h.clock.Now}
	backend := o.backend
	if backend == nil {
		backend = h.local
	}
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	storage := &oidcp.Storage{Store: st, Keys: h.oidc, Dir: h.dir, Logger: log, Audit: AuditProvider(st, log), Now: h.clock.Now,
		Lifetimes: oidcp.Lifetimes{IDToken: 5 * time.Minute, AccessToken: 10 * time.Minute, Refresh: 24 * time.Hour, RefreshIdle: 12 * time.Hour}}
	atKey, _ := oidcp.AccessTokenKey(key)
	provider, err := oidcp.NewProvider(cfg.Issuer(), storage, atKey, log)
	if err != nil {
		t.Fatal(err)
	}
	h.srv, err = New(Options{Config: cfg, Store: st, Dir: h.dir, MFA: backend, OIDC: storage, Provider: provider, SAML: h.saml,
		Keys: testRotator{h.oidc, samlKeys}, Logger: log, Version: "test", Now: h.clock.Now})
	if err != nil {
		t.Fatal(err)
	}
	handler = h.srv
	if a := h.srv.AdminHandler(); a != nil {
		adminHandler = a
	}
	return h
}

type testRotator struct {
	o *oidcp.KeyManager
	s *samlidp.KeyManager
}

func (r testRotator) RotateOIDC(ctx context.Context) (string, error) { return r.o.Rotate(ctx) }
func (r testRotator) RotateSAML(ctx context.Context, immediate bool) (string, error) {
	return r.s.Rotate(ctx, immediate)
}

// browser is a cookie-keeping client that does not follow redirects off
// the idp (the relying party's redirect URI is not reachable).
type browser struct {
	h *harness
	// base is the listener this browser talks to.
	base string
	c    *http.Client
	last *http.Response
	body string
}

func (h *harness) browser() *browser { return h.browserOn(h.ts, nil) }

// browserOn is a browser for one listener; browsers given the same jar
// share cookies as a real browser does (cookies are not isolated by port).
func (h *harness) browserOn(ts *httptest.Server, jar http.CookieJar) *browser {
	if jar == nil {
		jar, _ = cookiejar.New(nil)
	}
	c := &http.Client{Transport: ts.Client().Transport, Jar: jar, CheckRedirect: func(req *http.Request, via []*http.Request) error {
		if req.URL.Host != strings.TrimPrefix(ts.URL, "https://") {
			return http.ErrUseLastResponse
		}
		return nil
	}}
	return &browser{h: h, base: ts.URL, c: c}
}

func (b *browser) do(req *http.Request) *http.Response {
	b.h.t.Helper()
	resp, err := b.c.Do(req)
	if err != nil {
		b.h.t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	b.last, b.body = resp, string(body)
	return resp
}

func (b *browser) get(path string) *http.Response {
	b.h.t.Helper()
	u := path
	if strings.HasPrefix(path, "/") {
		u = b.base + path
	}
	req, _ := http.NewRequest(http.MethodGet, u, nil)
	return b.do(req)
}

func (b *browser) post(path string, form url.Values) *http.Response {
	b.h.t.Helper()
	req, _ := http.NewRequest(http.MethodPost, b.base+path, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	return b.do(req)
}

var (
	csrfRE   = regexp.MustCompile(`name="csrf" value="([^"]+)"`)
	contRE2  = regexp.MustCompile(`name="c" value="([^"]+)"`)
	secretRE = regexp.MustCompile(`data-e2e="enroll-text-secret">([A-Z2-7]+)<`)
	codesRE  = regexp.MustCompile(`data-e2e="recovery-text-code">([a-z0-9-]+)<`)
)

func (b *browser) csrf() string {
	m := csrfRE.FindStringSubmatch(b.body)
	if m == nil {
		b.h.t.Fatalf("no csrf token on page (status %d): %.400s", b.last.StatusCode, b.body)
	}
	return html.UnescapeString(m[1])
}

func (b *browser) cont() string {
	if m := contRE2.FindStringSubmatch(b.body); m != nil {
		return html.UnescapeString(m[1])
	}
	return ""
}

// submit posts a form of the current page with its CSRF token and
// continuation.
func (b *browser) submit(path string, form url.Values) *http.Response {
	b.h.t.Helper()
	form.Set("csrf", b.csrf())
	if c := b.cont(); c != "" && form.Get("c") == "" {
		form.Set("c", c)
	}
	return b.post(path, form)
}

func (b *browser) login(user string) *http.Response {
	b.h.t.Helper()
	return b.submit("/login", url.Values{"username": {user}, "password": {"Passw0rd!" + user}})
}

// enroll completes a TOTP enrollment page and returns the secret.
func (b *browser) enroll() []byte {
	b.h.t.Helper()
	m := secretRE.FindStringSubmatch(b.body)
	if m == nil {
		b.h.t.Fatalf("not on the enrollment page: %.300s", b.body)
	}
	sec, err := base32NoPad(m[1])
	if err != nil {
		b.h.t.Fatal(err)
	}
	b.submit("/login/enroll", url.Values{"code": {totp.Code(sec, totp.Step(b.h.clock.Now()))}})
	return sec
}

func (b *browser) mustStatus(want int) {
	b.h.t.Helper()
	if b.last.StatusCode != want {
		b.h.t.Fatalf("status %d, want %d: %s %.500s", b.last.StatusCode, want, b.last.Request.URL, b.body)
	}
}

func (b *browser) mustContain(s string) {
	b.h.t.Helper()
	if !strings.Contains(b.body, s) {
		b.h.t.Fatalf("page %s does not contain %q: %.600s", b.last.Request.URL, s, b.body)
	}
}

// location returns the redirect target of the last response.
func (b *browser) location() *url.URL {
	b.h.t.Helper()
	loc, err := b.last.Location()
	if err != nil {
		b.h.t.Fatalf("no redirect (status %d): %.400s", b.last.StatusCode, b.body)
	}
	return loc
}

func pkce() (verifier, challenge string) {
	verifier = secret.Token("") + "-pkce"
	sum := sha256.Sum256([]byte(verifier))
	return verifier, base64.RawURLEncoding.EncodeToString(sum[:])
}

func base32NoPad(s string) ([]byte, error) {
	return base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(s)
}

func fmtQuery(kv ...string) string {
	v := url.Values{}
	for i := 0; i+1 < len(kv); i += 2 {
		v.Set(kv[i], kv[i+1])
	}
	return v.Encode()
}

package web

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"testing"
	"time"

	jose "github.com/go-jose/go-jose/v4"

	"github.com/openbasalt/samba-conductor-idp/internal/registry"
	"github.com/openbasalt/samba-conductor-idp/internal/store"
)

const rpRedirect = "https://rp.example.test/callback"

type testClient struct {
	id, secret string
}

func (h *harness) client(in registry.ClientInput) testClient {
	h.t.Helper()
	if in.Name == "" {
		in.Name = "Test RP"
	}
	if in.Kind == "" {
		in.Kind = store.ClientConfidential
	}
	if len(in.RedirectURIs) == 0 {
		in.RedirectURIs = []string{rpRedirect}
	}
	if len(in.Groups) == 0 && !in.AllowAllUsers {
		in.Groups = []string{sidEngineering.String()}
	}
	c, sec, err := registry.CreateClient(context.Background(), h.store, h.dir, in)
	if err != nil {
		h.t.Fatal(err)
	}
	return testClient{id: c.ID, secret: sec}
}

// authorize starts an authorization request in the browser and returns
// the PKCE verifier.
func (b *browser) authorize(c testClient, scope string, extra ...string) string {
	b.h.t.Helper()
	verifier, challenge := pkce()
	kv := append([]string{"client_id", c.id, "redirect_uri", rpRedirect, "response_type", "code", "scope", scope,
		"state", "st-123", "nonce", "nn-456", "code_challenge", challenge, "code_challenge_method", "S256"}, extra...)
	b.get("/authorize?" + fmtQuery(kv...))
	return verifier
}

// code returns the code from the redirect to the RP, checking state.
func (b *browser) code() string {
	b.h.t.Helper()
	loc := b.location()
	if !strings.HasPrefix(loc.String(), rpRedirect) {
		b.h.t.Fatalf("redirect to %s, want the RP: %.300s", loc, b.body)
	}
	if loc.Query().Get("state") != "st-123" {
		b.h.t.Fatalf("state = %q", loc.Query().Get("state"))
	}
	if e := loc.Query().Get("error"); e != "" {
		b.h.t.Fatalf("RP got error %s: %s", e, loc.Query().Get("error_description"))
	}
	return loc.Query().Get("code")
}

type tokenResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	IDToken      string `json:"id_token"`
	TokenType    string `json:"token_type"`
	Error        string `json:"error"`
	Status       int    `json:"-"`
}

func (h *harness) token(c testClient, form url.Values) tokenResponse {
	h.t.Helper()
	req, _ := http.NewRequest(http.MethodPost, h.ts.URL+"/oauth/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if c.secret != "" {
		req.SetBasicAuth(url.QueryEscape(c.id), url.QueryEscape(c.secret))
	} else {
		form.Set("client_id", c.id)
		req.Body = io.NopCloser(strings.NewReader(form.Encode()))
		req.ContentLength = int64(len(form.Encode()))
	}
	resp, err := h.ts.Client().Do(req)
	if err != nil {
		h.t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	var tr tokenResponse
	_ = json.NewDecoder(resp.Body).Decode(&tr)
	tr.Status = resp.StatusCode
	return tr
}

func (h *harness) exchange(c testClient, code, verifier string) tokenResponse {
	return h.token(c, url.Values{"grant_type": {"authorization_code"}, "code": {code}, "redirect_uri": {rpRedirect}, "code_verifier": {verifier}})
}

func (h *harness) refresh(c testClient, rt string) tokenResponse {
	return h.token(c, url.Values{"grant_type": {"refresh_token"}, "refresh_token": {rt}})
}

func (h *harness) userinfo(at string) (int, map[string]any) {
	h.t.Helper()
	req, _ := http.NewRequest(http.MethodGet, h.ts.URL+"/userinfo", nil)
	req.Header.Set("Authorization", "Bearer "+at)
	resp, err := h.ts.Client().Do(req)
	if err != nil {
		h.t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	var m map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&m)
	return resp.StatusCode, m
}

// idClaims verifies an ID token against the JWKS and returns its claims.
func (h *harness) idClaims(tok string) map[string]any {
	h.t.Helper()
	resp, err := h.ts.Client().Get(h.ts.URL + "/keys")
	if err != nil {
		h.t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	var set jose.JSONWebKeySet
	if err := json.NewDecoder(resp.Body).Decode(&set); err != nil {
		h.t.Fatal(err)
	}
	jws, err := jose.ParseSigned(tok, []jose.SignatureAlgorithm{jose.ES256})
	if err != nil {
		h.t.Fatal(err)
	}
	keys := set.Key(jws.Signatures[0].Header.KeyID)
	if len(keys) != 1 {
		h.t.Fatalf("signing key %s not in the JWKS", jws.Signatures[0].Header.KeyID)
	}
	payload, err := jws.Verify(keys[0])
	if err != nil {
		h.t.Fatal("ID token signature:", err)
	}
	var claims map[string]any
	_ = json.Unmarshal(payload, &claims)
	if claims["iss"] != h.ts.URL {
		h.t.Fatalf("iss = %v", claims["iss"])
	}
	return claims
}

func TestDiscoveryNarrowed(t *testing.T) {
	h := newHarness(t, harnessOpts{})
	resp, err := h.ts.Client().Get(h.ts.URL + "/.well-known/openid-configuration")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	var doc map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&doc)
	if doc["issuer"] != h.ts.URL {
		t.Fatalf("issuer %v", doc["issuer"])
	}
	for k, want := range map[string]string{"response_types_supported": "code", "grant_types_supported": "authorization_code,refresh_token",
		"code_challenge_methods_supported": "S256", "response_modes_supported": "query"} {
		got := []string{}
		for _, v := range doc[k].([]any) {
			got = append(got, v.(string))
		}
		if strings.Join(got, ",") != want {
			t.Errorf("%s = %v, want %s", k, got, want)
		}
	}
	if _, ok := doc["introspection_endpoint"]; ok {
		t.Error("introspection advertised")
	}
	for _, k := range []string{"authorization_endpoint", "token_endpoint", "userinfo_endpoint", "revocation_endpoint", "end_session_endpoint", "jwks_uri"} {
		if !strings.HasPrefix(doc[k].(string), h.ts.URL+"/") {
			t.Errorf("%s = %v", k, doc[k])
		}
	}
}

func TestCodeFlowConsentRefreshAndReuse(t *testing.T) {
	h := newHarness(t, harnessOpts{})
	c := h.client(registry.ClientInput{Scopes: []string{"profile", "email", "groups", "offline_access"}, GroupsClaim: store.GroupsNames})
	b := h.browser()
	verifier := b.authorize(c, "openid profile email groups offline_access")
	b.mustStatus(http.StatusOK)
	b.mustContain(`data-e2e="signin-input-username"`)
	b.mustContain("Test RP")
	b.login("alice")
	b.mustStatus(http.StatusOK)
	b.mustContain(`data-e2e="consent-btn-allow"`)
	b.mustContain("rp.example.test")
	// The consent page may submit to the RP (CSP form-action includes it).
	if csp := b.last.Header.Get("Content-Security-Policy"); !strings.Contains(csp, "form-action 'self' https://rp.example.test") ||
		!strings.Contains(csp, "script-src 'none'") {
		t.Fatalf("CSP: %s", csp)
	}
	b.submit("/consent", url.Values{"decision": {"allow"}})
	code := b.code()

	tr := h.exchange(c, code, verifier)
	if tr.Status != 200 || tr.IDToken == "" || tr.AccessToken == "" || !strings.HasPrefix(tr.RefreshToken, "cidp_rt_") {
		t.Fatalf("token response %+v", tr)
	}
	claims := h.idClaims(tr.IDToken)
	if claims["sub"] != "11111111-1111-4111-8111-111111111111" || claims["nonce"] != "nn-456" || claims["aud"] != c.id && !audHas(claims["aud"], c.id) {
		t.Fatalf("claims %v", claims)
	}
	if claims["email"] != "alice@lab.test" || claims["preferred_username"] != "alice" {
		t.Fatalf("claims %v", claims)
	}
	groups := toStrings(claims["groups"])
	if !slices.Equal(groups, []string{"Domain Users", "Engineering"}) {
		t.Fatalf("groups %v", groups)
	}
	if amr := toStrings(claims["amr"]); !slices.Contains(amr, "pwd") {
		t.Fatalf("amr %v", amr)
	}
	status, info := h.userinfo(tr.AccessToken)
	if status != 200 || info["sub"] != claims["sub"] || info["email"] != "alice@lab.test" {
		t.Fatalf("userinfo %d %v", status, info)
	}

	// A code works once; the second use revokes what the first issued.
	if again := h.exchange(c, code, verifier); again.Status != 400 || again.Error != "invalid_grant" {
		t.Fatalf("code reuse: %+v", again)
	}
	if status, _ := h.userinfo(tr.AccessToken); status == 200 {
		t.Fatal("access token still valid after code reuse")
	}
	if r := h.refresh(c, tr.RefreshToken); r.Status == 200 {
		t.Fatal("refresh token still valid after code reuse")
	}

	// A new sign-in in the same browser: single sign-on, consent remembered.
	verifier = b.authorize(c, "openid profile email groups offline_access")
	code = b.code()
	tr = h.exchange(c, code, verifier)
	if tr.Status != 200 {
		t.Fatalf("second flow: %+v", tr)
	}
	// Refresh rotates; the old token is then a reuse that kills the chain.
	r1 := h.refresh(c, tr.RefreshToken)
	if r1.Status != 200 || r1.RefreshToken == tr.RefreshToken || r1.RefreshToken == "" {
		t.Fatalf("refresh: %+v", r1)
	}
	if r := h.refresh(c, tr.RefreshToken); r.Status != 400 || r.Error != "invalid_grant" {
		t.Fatalf("rotated token reuse: %+v", r)
	}
	if r := h.refresh(c, r1.RefreshToken); r.Status == 200 {
		t.Fatal("chain not revoked after reuse")
	}
	if status, _ := h.userinfo(r1.AccessToken); status == 200 {
		t.Fatal("access token of a revoked chain still valid")
	}

	// The audit log recorded it and its chain verifies.
	v, err := h.store.VerifyAudit(context.Background())
	if err != nil || v.BrokenAt != 0 || v.Rows < 5 {
		t.Fatalf("audit %+v %v", v, err)
	}
	events, _, _ := h.store.ListAudit(context.Background(), store.AuditFilter{Action: "oidc.refresh_reuse"}, 0, 10)
	if len(events) == 0 {
		t.Fatal("reuse not audited")
	}
}

func audHas(aud any, id string) bool { return slices.Contains(toStrings(aud), id) }

func toStrings(v any) []string {
	var out []string
	if arr, ok := v.([]any); ok {
		for _, x := range arr {
			out = append(out, x.(string))
		}
	}
	if s, ok := v.(string); ok {
		out = append(out, s)
	}
	return out
}

func TestPKCERequired(t *testing.T) {
	h := newHarness(t, harnessOpts{})
	c := h.client(registry.ClientInput{FirstParty: true})
	b := h.browser()
	// No code_challenge: refused before any sign-in, back to the RP.
	b.get("/authorize?" + fmtQuery("client_id", c.id, "redirect_uri", rpRedirect, "response_type", "code", "scope", "openid", "state", "s"))
	loc := b.location()
	if !strings.HasPrefix(loc.String(), rpRedirect) || loc.Query().Get("error") != "invalid_request" {
		t.Fatalf("no PKCE: %s", loc)
	}
	// plain method: refused too.
	b.get("/authorize?" + fmtQuery("client_id", c.id, "redirect_uri", rpRedirect, "response_type", "code", "scope", "openid",
		"code_challenge", "abcdefghijabcdefghijabcdefghijabcdefghij123", "code_challenge_method", "plain"))
	if loc := b.location(); loc.Query().Get("error") == "" {
		t.Fatalf("plain PKCE accepted: %s", loc)
	}
	// Wrong verifier at the token endpoint.
	b.authorize(c, "openid")
	b.login("alice")
	code := b.code()
	if tr := h.exchange(c, code, "wrong-verifier-wrong-verifier-wrong-verifier-123"); tr.Status != 400 {
		t.Fatalf("wrong verifier: %+v", tr)
	}
}

func TestRedirectURIExactAndImplicitRefused(t *testing.T) {
	h := newHarness(t, harnessOpts{})
	c := h.client(registry.ClientInput{FirstParty: true})
	b := h.browser()
	_, ch := pkce()
	b.get("/authorize?" + fmtQuery("client_id", c.id, "redirect_uri", rpRedirect+"/evil", "response_type", "code", "scope", "openid",
		"code_challenge", ch, "code_challenge_method", "S256"))
	if b.last.StatusCode != http.StatusBadRequest {
		t.Fatalf("unregistered redirect URI: status %d", b.last.StatusCode)
	}
	b.get("/authorize?" + fmtQuery("client_id", c.id, "redirect_uri", rpRedirect, "response_type", "id_token token", "scope", "openid",
		"nonce", "n", "code_challenge", ch, "code_challenge_method", "S256"))
	if loc, err := b.last.Location(); err == nil && loc.Query().Get("code") != "" || b.last.StatusCode == 200 {
		t.Fatalf("implicit flow not refused: %d %v", b.last.StatusCode, err)
	}
}

func TestGroupPolicyDenied(t *testing.T) {
	h := newHarness(t, harnessOpts{})
	c := h.client(registry.ClientInput{FirstParty: true}) // Engineering only
	b := h.browser()
	b.authorize(c, "openid")
	b.login("bob") // Sales
	b.mustStatus(http.StatusForbidden)
	b.mustContain(`data-e2e="denied-card"`)
	// prompt=none for a signed-in but not allowed user: access_denied.
	b.authorize(c, "openid", "prompt", "none")
	if loc := b.location(); loc.Query().Get("error") != "access_denied" {
		t.Fatalf("prompt=none denied: %s", loc)
	}
}

func TestPromptNoneAndLogin(t *testing.T) {
	h := newHarness(t, harnessOpts{})
	c := h.client(registry.ClientInput{FirstParty: true})
	b := h.browser()
	b.authorize(c, "openid", "prompt", "none")
	if loc := b.location(); loc.Query().Get("error") != "login_required" || loc.Query().Get("state") != "st-123" {
		t.Fatalf("prompt=none without session: %s", loc)
	}
	b.authorize(c, "openid")
	b.login("alice")
	b.code()
	b.authorize(c, "openid", "prompt", "none")
	if b.code() == "" {
		t.Fatal("prompt=none with a session gave no code")
	}
	// prompt=login shows the form again even with a session.
	b.authorize(c, "openid", "prompt", "login")
	b.mustStatus(http.StatusOK)
	b.mustContain(`value="alice"`)
	// max_age exceeded forces a sign-in too.
	h.clock.Advance(2 * time.Minute)
	b.authorize(c, "openid", "max_age", "60")
	b.mustContain(`data-e2e="signin-input-password"`)
}

func TestConsentRequiredForPromptNone(t *testing.T) {
	h := newHarness(t, harnessOpts{})
	c := h.client(registry.ClientInput{}) // third party
	b := h.browser()
	b.authorize(c, "openid")
	b.login("alice")
	b.mustContain(`data-e2e="consent-btn-deny"`)
	b.submit("/consent", url.Values{"decision": {"deny"}})
	if loc := b.location(); loc.Query().Get("error") != "access_denied" {
		t.Fatalf("denied consent: %s", loc)
	}
	b.authorize(c, "openid", "prompt", "none")
	if loc := b.location(); loc.Query().Get("error") != "consent_required" {
		t.Fatalf("prompt=none without consent: %s", loc)
	}
}

func TestCallbackBoundToBrowser(t *testing.T) {
	h := newHarness(t, harnessOpts{})
	c := h.client(registry.ClientInput{FirstParty: true})
	b := h.browser()
	b.authorize(c, "openid")
	login := b.last.Request.URL
	// Another browser cannot continue this request.
	other := h.browser()
	other.get(login.String())
	other.mustStatus(http.StatusForbidden)
	b.login("alice")
	loc := b.location()
	if !strings.HasPrefix(loc.String(), rpRedirect) {
		t.Fatalf("flow: %s", loc)
	}
	// The callback replayed from another browser releases nothing.
	ar := h.browser()
	ar.get("/authorize/callback?id=" + strings.TrimPrefix(login.Query().Get("ar"), ""))
	if ar.last.StatusCode != http.StatusForbidden {
		t.Fatalf("callback from another browser: %d", ar.last.StatusCode)
	}
}

func TestRevocation(t *testing.T) {
	h := newHarness(t, harnessOpts{})
	c := h.client(registry.ClientInput{FirstParty: true, Scopes: []string{"offline_access"}})
	other := h.client(registry.ClientInput{FirstParty: true, Name: "Other"})
	b := h.browser()
	v := b.authorize(c, "openid offline_access")
	b.login("alice")
	tr := h.exchange(c, b.code(), v)
	if tr.RefreshToken == "" {
		t.Fatalf("%+v", tr)
	}
	revoke := func(cl testClient, tok string) int {
		req, _ := http.NewRequest(http.MethodPost, h.ts.URL+"/oauth/revoke", strings.NewReader(url.Values{"token": {tok}}.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.SetBasicAuth(cl.id, cl.secret)
		resp, err := h.ts.Client().Do(req)
		if err != nil {
			t.Fatal(err)
		}
		_ = resp.Body.Close()
		return resp.StatusCode
	}
	// Another client may not revoke it.
	if st := revoke(other, tr.RefreshToken); st == 200 {
		if r := h.refresh(c, tr.RefreshToken); r.Status != 200 {
			t.Fatal("another client revoked the token")
		}
	}
	if st := revoke(c, tr.RefreshToken); st != 200 {
		t.Fatalf("revoke: %d", st)
	}
	if r := h.refresh(c, tr.RefreshToken); r.Status == 200 {
		t.Fatal("revoked refresh token still works")
	}
	if st, _ := h.userinfo(tr.AccessToken); st == 200 {
		t.Fatal("access token of a revoked chain still works")
	}
}

func TestRefreshRechecksAccount(t *testing.T) {
	h := newHarness(t, harnessOpts{})
	c := h.client(registry.ClientInput{FirstParty: true, Scopes: []string{"offline_access"}})
	b := h.browser()
	v := b.authorize(c, "openid offline_access")
	b.login("alice")
	tr := h.exchange(c, b.code(), v)
	h.dir.set("alice", func(u *fakeUser) { u.Enabled = false })
	if r := h.refresh(c, tr.RefreshToken); r.Status != 400 {
		t.Fatalf("refresh of a disabled account: %+v", r)
	}
	h.dir.set("alice", func(u *fakeUser) { u.Enabled = true })
	if r := h.refresh(c, tr.RefreshToken); r.Status == 200 {
		t.Fatal("chain survived the denied refresh")
	}
}

func TestPublicClient(t *testing.T) {
	h := newHarness(t, harnessOpts{})
	c := h.client(registry.ClientInput{Kind: store.ClientPublic, FirstParty: true})
	if c.secret != "" {
		t.Fatal("public client got a secret")
	}
	b := h.browser()
	v := b.authorize(c, "openid")
	b.login("alice")
	tr := h.exchange(c, b.code(), v)
	if tr.Status != 200 || tr.IDToken == "" {
		t.Fatalf("public client exchange: %+v", tr)
	}
}

func TestConfidentialClientNeedsSecret(t *testing.T) {
	h := newHarness(t, harnessOpts{})
	c := h.client(registry.ClientInput{FirstParty: true})
	b := h.browser()
	v := b.authorize(c, "openid")
	b.login("alice")
	code := b.code()
	if tr := h.exchange(testClient{id: c.id, secret: "cidp_cs_wrong"}, code, v); tr.Status != 401 && tr.Error != "invalid_client" {
		t.Fatalf("wrong secret: %+v", tr)
	}
}

func TestEndSession(t *testing.T) {
	h := newHarness(t, harnessOpts{})
	c := h.client(registry.ClientInput{FirstParty: true, PostLogoutURIs: []string{"https://rp.example.test/bye"}})
	b := h.browser()
	v := b.authorize(c, "openid")
	b.login("alice")
	tr := h.exchange(c, b.code(), v)
	b.get("/end_session?" + fmtQuery("id_token_hint", tr.IDToken, "post_logout_redirect_uri", "https://rp.example.test/bye", "state", "x"))
	// end_session → /logout/rp → the RP.
	for b.last.StatusCode/100 == 3 {
		loc := b.location()
		if strings.HasPrefix(loc.String(), "https://rp.example.test/bye") {
			break
		}
		b.get(loc.String())
	}
	if loc := b.location(); !strings.HasPrefix(loc.String(), "https://rp.example.test/bye") {
		t.Fatalf("end_session landed at %s", loc)
	}
	// The browser session is gone: prompt=none now needs a login.
	b.authorize(c, "openid", "prompt", "none")
	if loc := b.location(); loc.Query().Get("error") != "login_required" {
		t.Fatalf("session survived logout: %s", loc)
	}
}

// TestTokenResponsesNotCacheable: every token endpoint answer (also a
// refresh and an error) carries Cache-Control: no-store (RFC 6749 5.1).
func TestTokenResponsesNotCacheable(t *testing.T) {
	h := newHarness(t, harnessOpts{})
	c := h.client(registry.ClientInput{Scopes: []string{"offline_access"}})
	for _, form := range []url.Values{
		{"grant_type": {"refresh_token"}, "refresh_token": {"cidp_rt_unknown"}},
		{"grant_type": {"authorization_code"}, "code": {"nope"}, "redirect_uri": {rpRedirect}, "code_verifier": {"x"}},
	} {
		req, _ := http.NewRequest(http.MethodPost, h.ts.URL+"/oauth/token", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.SetBasicAuth(c.id, c.secret)
		resp, err := h.ts.Client().Do(req)
		if err != nil {
			t.Fatal(err)
		}
		_ = resp.Body.Close()
		if resp.Header.Get("Cache-Control") != "no-store" {
			t.Fatalf("%s: Cache-Control %q", form.Get("grant_type"), resp.Header.Get("Cache-Control"))
		}
	}
}

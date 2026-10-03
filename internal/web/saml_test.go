package web

import (
	"bytes"
	"compress/flate"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/xml"
	"html"
	"io"
	"math/big"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/crewjam/saml"

	"github.com/openbasalt/samba-conductor-idp/internal/registry"
	"github.com/openbasalt/samba-conductor-idp/internal/samlidp"
	"github.com/openbasalt/samba-conductor-idp/internal/store"
)

const (
	spEntity = "https://sp.example.test/saml/metadata"
	spACS    = "https://sp.example.test/saml/acs"
)

func newSPKey(t *testing.T) (*rsa.PrivateKey, *x509.Certificate) {
	t.Helper()
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(7), Subject: pkix.Name{CommonName: "sp.example.test"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &k.PublicKey, k)
	if err != nil {
		t.Fatal(err)
	}
	c, _ := x509.ParseCertificate(der)
	return k, c
}

// testSP is a crewjam ServiceProvider trusting the idp's metadata.
func (h *harness) testSP(t *testing.T, encrypt bool, idpInit bool, groups ...string) *saml.ServiceProvider {
	t.Helper()
	key, cert := newSPKey(t)
	resp, err := h.ts.Client().Get(h.ts.URL + samlidp.MetadataPath)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, _ := io.ReadAll(resp.Body)
	var md saml.EntityDescriptor
	if err := xml.Unmarshal(body, &md); err != nil {
		t.Fatalf("idp metadata: %v\n%s", err, body)
	}
	if len(groups) == 0 {
		groups = []string{"Engineering"}
	}
	in := registry.SPInput{EntityID: spEntity, Name: "Test SP", ACSURLs: []string{spACS}, NameIDFormat: samlidp.NameIDEmail,
		NameIDSource: samlidp.SourceEmail, Groups: groups, IdPInitiated: idpInit, DefaultRelay: "/home",
		Attributes: []store.SAMLAttribute{{Name: "uid", Source: "username"}, {Name: "memberOf", Source: "groups"},
			{Name: "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/givenname", Source: "given_name"}}}
	if encrypt {
		in.EncryptAssertion, in.EncryptionCert = true, cert.Raw
	}
	sp, err := registry.BuildSP(context.Background(), h.dir, in)
	if err != nil {
		t.Fatal(err)
	}
	if err := h.store.CreateSP(context.Background(), sp); err != nil {
		t.Fatal(err)
	}
	return &saml.ServiceProvider{EntityID: spEntity, Key: key, Certificate: cert, AcsURL: mustParse(spACS),
		MetadataURL: mustParse(spEntity), IDPMetadata: &md, AllowIDPInitiated: idpInit,
		SignatureMethod: "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"}
}

func mustParse(s string) url.URL {
	u, _ := url.Parse(s)
	return *u
}

var (
	formActionRE = regexp.MustCompile(`data-e2e="saml-form-post"`)
	actionRE     = regexp.MustCompile(`<form method="post" action="([^"]+)" data-e2e="saml-form-post">`)
	samlRespRE   = regexp.MustCompile(`name="SAMLResponse" value="([^"]+)"`)
	relayRE      = regexp.MustCompile(`name="RelayState" value="([^"]+)"`)
)

// acsPost turns the idp's response page into the POST the SP receives.
func (b *browser) acsPost() (*http.Request, string) {
	b.h.t.Helper()
	if !formActionRE.MatchString(b.body) {
		b.h.t.Fatalf("not the SAML response page (status %d): %.500s", b.last.StatusCode, b.body)
	}
	action := html.UnescapeString(actionRE.FindStringSubmatch(b.body)[1])
	resp := html.UnescapeString(samlRespRE.FindStringSubmatch(b.body)[1])
	relay := ""
	if m := relayRE.FindStringSubmatch(b.body); m != nil {
		relay = html.UnescapeString(m[1])
	}
	form := url.Values{"SAMLResponse": {resp}, "RelayState": {relay}}
	req, _ := http.NewRequest(http.MethodPost, action, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	_ = req.ParseForm()
	return req, relay
}

func attrValues(a *saml.Assertion, name string) []string {
	var out []string
	for _, st := range a.AttributeStatements {
		for _, at := range st.Attributes {
			if at.Name == name {
				for _, v := range at.Values {
					out = append(out, v.Value)
				}
			}
		}
	}
	return out
}

func TestSAMLSPInitiated(t *testing.T) {
	h := newHarness(t, harnessOpts{})
	sp := h.testSP(t, false, false)
	b := h.browser()
	authn, err := sp.MakeAuthenticationRequest(h.ts.URL+samlidp.SSOPath, saml.HTTPRedirectBinding, saml.HTTPPostBinding)
	if err != nil {
		t.Fatal(err)
	}
	redirect, err := authn.Redirect("relay-42", sp)
	if err != nil {
		t.Fatal(err)
	}
	b.get(redirect.String())
	b.mustContain(`data-e2e="signin-input-username"`)
	b.mustContain("Test SP")
	b.login("alice")
	b.mustStatus(http.StatusOK)
	// The page may post to the SP's ACS only (CSP form-action).
	if csp := b.last.Header.Get("Content-Security-Policy"); !strings.Contains(csp, "form-action 'self' https://sp.example.test") {
		t.Fatalf("CSP: %s", csp)
	}
	req, relay := b.acsPost()
	if relay != "relay-42" {
		t.Fatalf("RelayState %q", relay)
	}
	a, err := sp.ParseResponse(req, []string{authn.ID})
	if err != nil {
		t.Fatalf("SP rejected the response: %v", err)
	}
	if a.Subject.NameID.Value != "alice@lab.test" || a.Subject.NameID.Format != samlidp.NameIDEmail {
		t.Fatalf("NameID %+v", a.Subject.NameID)
	}
	if got := attrValues(a, "uid"); len(got) != 1 || got[0] != "alice" {
		t.Fatalf("uid %v", got)
	}
	if got := strings.Join(attrValues(a, "memberOf"), ","); got != "Domain Users,Engineering" {
		t.Fatalf("memberOf %v", got)
	}
	if a.Conditions.AudienceRestrictions[0].Audience.Value != spEntity {
		t.Fatal("audience")
	}

	// The same AuthnRequest replayed is refused.
	b.get(redirect.String())
	b.mustStatus(http.StatusBadRequest)

	// SSO: a second request completes without the password.
	authn2, _ := sp.MakeAuthenticationRequest(h.ts.URL+samlidp.SSOPath, saml.HTTPRedirectBinding, saml.HTTPPostBinding)
	r2, _ := authn2.Redirect("", sp)
	b.get(r2.String())
	req, _ = b.acsPost()
	if _, err := sp.ParseResponse(req, []string{authn2.ID}); err != nil {
		t.Fatalf("SSO response: %v", err)
	}

	// A tampered response does not verify at the SP.
	u, id := mustRedirect(t, sp, h)
	b.get(u.String())
	req, _ = b.acsPost()
	if _, err := sp.ParseResponse(cloneReq(req), []string{id}); err != nil {
		t.Fatalf("untampered response rejected: %v", err)
	}
	raw, _ := base64.StdEncoding.DecodeString(req.PostForm.Get("SAMLResponse"))
	tampered := bytes.Replace(raw, []byte("alice@lab.test"), []byte("admin@lab.test"), 1)
	req.PostForm.Set("SAMLResponse", base64.StdEncoding.EncodeToString(tampered))
	if _, err := sp.ParseResponse(req, []string{id}); err == nil {
		t.Fatal("tampered assertion accepted")
	}
}

func mustRedirect(t *testing.T, sp *saml.ServiceProvider, h *harness) (*url.URL, string) {
	t.Helper()
	authn, err := sp.MakeAuthenticationRequest(h.ts.URL+samlidp.SSOPath, saml.HTTPRedirectBinding, saml.HTTPPostBinding)
	if err != nil {
		t.Fatal(err)
	}
	u, err := authn.Redirect("", sp)
	if err != nil {
		t.Fatal(err)
	}
	return u, authn.ID
}

func TestSAMLEncryptedAssertion(t *testing.T) {
	h := newHarness(t, harnessOpts{})
	sp := h.testSP(t, true, false)
	b := h.browser()
	u, id := mustRedirect(t, sp, h)
	b.get(u.String())
	b.login("alice")
	req, _ := b.acsPost()
	raw, _ := base64.StdEncoding.DecodeString(req.PostForm.Get("SAMLResponse"))
	if !bytes.Contains(raw, []byte("EncryptedAssertion")) || bytes.Contains(raw, []byte("alice@lab.test")) {
		t.Fatal("assertion not encrypted")
	}
	a, err := sp.ParseResponse(req, []string{id})
	if err != nil {
		var ie *saml.InvalidResponseError
		if ok := asInvalid(err, &ie); ok {
			t.Fatalf("SP rejected: %v", ie.PrivateErr)
		}
		t.Fatalf("SP rejected: %v", err)
	}
	if a.Subject.NameID.Value != "alice@lab.test" {
		t.Fatalf("NameID %+v", a.Subject.NameID)
	}
}

func asInvalid(err error, target **saml.InvalidResponseError) bool {
	ie, ok := err.(*saml.InvalidResponseError)
	if ok {
		*target = ie
	}
	return ok
}

func TestSAMLPostBindingAndPolicy(t *testing.T) {
	h := newHarness(t, harnessOpts{})
	sp := h.testSP(t, false, false)
	authn, _ := sp.MakeAuthenticationRequest(h.ts.URL+samlidp.SSOPath, saml.HTTPPostBinding, saml.HTTPPostBinding)
	doc, _ := xml.Marshal(authn)
	b := h.browser()
	// POST binding: no CSRF token (cross-site by design).
	req, _ := http.NewRequest(http.MethodPost, h.ts.URL+samlidp.SSOPath, strings.NewReader(url.Values{
		"SAMLRequest": {base64.StdEncoding.EncodeToString(doc)}, "RelayState": {"r"}}.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Sec-Fetch-Site", "cross-site")
	b.do(req)
	b.mustContain(`data-e2e="signin-input-username"`)
	b.login("bob") // Sales: not allowed
	b.mustStatus(http.StatusForbidden)
	b.mustContain(`data-e2e="denied-card"`)
}

func TestSAMLRefusesUnknownSPAndForeignACS(t *testing.T) {
	h := newHarness(t, harnessOpts{})
	sp := h.testSP(t, false, false)
	b := h.browser()
	// Unknown SP.
	other := *sp
	other.EntityID = "https://unknown.example.test/sp"
	u, _ := mustRedirect(t, &other, h)
	b.get(u.String())
	b.mustStatus(http.StatusBadRequest)
	b.mustContain("not registered")
	// An ACS URL that is not registered for the SP.
	authn, _ := sp.MakeAuthenticationRequest(h.ts.URL+samlidp.SSOPath, saml.HTTPRedirectBinding, saml.HTTPPostBinding)
	authn.AssertionConsumerServiceURL = "https://attacker.example.test/acs"
	b.get(redirectURL(t, h, authn))
	b.mustStatus(http.StatusBadRequest)
	// Wrong Destination.
	authn, _ = sp.MakeAuthenticationRequest("https://elsewhere.example.test/sso", saml.HTTPRedirectBinding, saml.HTTPPostBinding)
	b.get(redirectURL(t, h, authn))
	b.mustStatus(http.StatusBadRequest)
}

// redirectURL encodes an AuthnRequest for the HTTP-Redirect binding
// without signing (the idp does not require signed requests).
func redirectURL(t *testing.T, h *harness, authn *saml.AuthnRequest) string {
	t.Helper()
	doc, err := xml.Marshal(authn)
	if err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	w, _ := flate.NewWriter(&buf, flate.DefaultCompression)
	_, _ = w.Write(doc)
	_ = w.Close()
	return h.ts.URL + samlidp.SSOPath + "?" + url.Values{"SAMLRequest": {base64.StdEncoding.EncodeToString(buf.Bytes())}}.Encode()
}

func TestSAMLIdPInitiatedAndHome(t *testing.T) {
	h := newHarness(t, harnessOpts{})
	sp := h.testSP(t, false, true)
	b := h.browser()
	b.get("/login")
	b.login("alice")
	b.get("/")
	b.mustContain(`data-e2e="home-btn-app-test-sp"`)
	b.submit("/saml/start", url.Values{"sp": {spEntity}})
	req, relay := b.acsPost()
	if relay != "/home" {
		t.Fatalf("relay %q", relay)
	}
	a, err := sp.ParseResponse(req, nil)
	if err != nil {
		t.Fatalf("SP rejected the unsolicited response: %v", err)
	}
	if a.Subject.NameID.Value != "alice@lab.test" {
		t.Fatal("NameID")
	}
}

func TestSAMLNoNameID(t *testing.T) {
	h := newHarness(t, harnessOpts{})
	sp := h.testSP(t, false, false)
	b := h.browser()
	u, _ := mustRedirect(t, sp, h)
	b.get(u.String())
	b.login("nomail")
	b.mustStatus(http.StatusBadRequest)
	b.mustContain("lacks the attribute")
}

func TestSAMLStagedRotation(t *testing.T) {
	h := newHarness(t, harnessOpts{})
	ctx := context.Background()
	before, err := h.saml.Keys.Signer(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := h.saml.Keys.Rotate(ctx, false); err != nil {
		t.Fatal(err)
	}
	h.clock.Advance(2 * time.Minute) // past the key cache
	keys, _ := h.saml.Keys.Keys(ctx)
	if len(keys) != 2 {
		t.Fatalf("%d keys published", len(keys))
	}
	md, _ := h.saml.Metadata(ctx)
	if strings.Count(string(md), "<X509Certificate ") != 2 {
		t.Fatalf("metadata does not publish both certificates:\n%s", md)
	}
	now, _ := h.saml.Keys.Signer(ctx)
	if now.ID != before.ID {
		t.Fatal("staged rotation switched the signing key at once")
	}
	h.clock.Advance(49 * time.Hour)
	after, _ := h.saml.Keys.Signer(ctx)
	if after.ID == before.ID {
		t.Fatal("the new key did not take over after the overlap")
	}
}

func cloneReq(r *http.Request) *http.Request {
	c := r.Clone(context.Background())
	c.PostForm = url.Values{}
	for k, v := range r.PostForm {
		c.PostForm[k] = append([]string(nil), v...)
	}
	return c
}

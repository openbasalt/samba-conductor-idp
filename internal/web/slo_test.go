package web

import (
	"bytes"
	"compress/flate"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/xml"
	"html"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/beevik/etree"
	"github.com/crewjam/saml"
	dsig "github.com/russellhaering/goxmldsig"

	"github.com/openbasalt/samba-conductor-idp/internal/registry"
	"github.com/openbasalt/samba-conductor-idp/internal/samlidp"
	"github.com/openbasalt/samba-conductor-idp/internal/store"
)

const (
	spSLO   = "https://sp.example.test/saml/slo"
	sp2     = "https://sp2.example.test/saml/metadata"
	sp2ACS  = "https://sp2.example.test/saml/acs"
	sp2SLO  = "https://sp2.example.test/saml/slo"
	sigAlg  = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"
	samlNS  = "urn:oasis:names:tc:SAML:2.0:protocol"
	entityF = "urn:oasis:names:tc:SAML:2.0:nameid-format:entity"
)

// sloSP gives the harness's test SP a single logout endpoint (HTTP-Redirect)
// and its signing certificate.
func (h *harness) sloSP(t *testing.T, sp *saml.ServiceProvider) {
	t.Helper()
	ctx := context.Background()
	reg, err := h.store.GetSP(ctx, spEntity)
	if err != nil {
		t.Fatal(err)
	}
	reg.SLOURL, reg.SLOBinding, reg.SigningCert = spSLO, saml.HTTPRedirectBinding, sp.Certificate.Raw
	if err := h.store.UpdateSP(ctx, reg); err != nil {
		t.Fatal(err)
	}
}

// secondSP registers another SP with an HTTP-POST single logout endpoint.
func (h *harness) secondSP(t *testing.T, base *saml.ServiceProvider) *saml.ServiceProvider {
	t.Helper()
	key, cert := newSPKey(t)
	in := registry.SPInput{EntityID: sp2, Name: "Second SP", ACSURLs: []string{sp2ACS}, NameIDFormat: samlidp.NameIDEmail,
		NameIDSource: samlidp.SourceEmail, Groups: []string{"Engineering"}, SLOURL: sp2SLO, SLOBinding: saml.HTTPPostBinding}
	reg, err := registry.BuildSP(context.Background(), h.dir, in)
	if err != nil {
		t.Fatal(err)
	}
	if err := h.store.CreateSP(context.Background(), reg); err != nil {
		t.Fatal(err)
	}
	return &saml.ServiceProvider{EntityID: sp2, Key: key, Certificate: cert, AcsURL: mustParse(sp2ACS), MetadataURL: mustParse(sp2),
		IDPMetadata: base.IDPMetadata, SignatureMethod: sigAlg}
}

// signIn runs an SP-initiated sign-in and returns the assertion.
func (b *browser) signIn(t *testing.T, sp *saml.ServiceProvider, user string) *saml.Assertion {
	t.Helper()
	u, id := mustRedirect(t, sp, b.h)
	b.get(u.String())
	if user != "" {
		b.login(user)
	}
	req, _ := b.acsPost()
	a, err := sp.ParseResponse(req, []string{id})
	if err != nil {
		t.Fatalf("SP rejected the response: %v", err)
	}
	return a
}

// redirectLogout encodes a LogoutRequest for the HTTP-Redirect binding,
// signed with the SP's key when sign is set.
func redirectLogout(t *testing.T, h *harness, sp *saml.ServiceProvider, nameID, sessionIndex string, sign bool) (string, string) {
	t.Helper()
	now := time.Now().UTC()
	req := &saml.LogoutRequest{ID: "id-logout-" + base64.RawURLEncoding.EncodeToString([]byte(nameID + sessionIndex))[:10], Version: "2.0",
		IssueInstant: now, Destination: h.ts.URL + samlidp.SLOPath, Issuer: &saml.Issuer{Format: entityF, Value: sp.EntityID},
		NameID: &saml.NameID{Format: samlidp.NameIDEmail, Value: nameID}, SessionIndex: &saml.SessionIndex{Value: sessionIndex}}
	doc := etree.NewDocument()
	doc.SetRoot(req.Element())
	raw, _ := doc.WriteToBytes()
	var z bytes.Buffer
	w, _ := flate.NewWriter(&z, flate.BestCompression)
	_, _ = w.Write(raw)
	_ = w.Close()
	q := "SAMLRequest=" + url.QueryEscape(base64.StdEncoding.EncodeToString(z.Bytes())) + "&RelayState=" + url.QueryEscape("back-to-a")
	if sign {
		q += "&SigAlg=" + url.QueryEscape(sigAlg)
		d := sha256.Sum256([]byte(q))
		sig, err := rsa.SignPKCS1v15(rand.Reader, sp.Key.(*rsa.PrivateKey), crypto.SHA256, d[:])
		if err != nil {
			t.Fatal(err)
		}
		q += "&Signature=" + url.QueryEscape(base64.StdEncoding.EncodeToString(sig))
	}
	return h.ts.URL + samlidp.SLOPath + "?" + q, req.ID
}

var (
	sloActionRE = regexp.MustCompile(`<form method="post" action="([^"]+)" data-e2e="slo-form-post">`)
	sloFieldRE  = regexp.MustCompile(`<input type="hidden" name="(SAMLRequest|SAMLResponse)" value="([^"]+)">`)
)

// verifyIdPRedirect checks the IdP's query signature and returns the
// inflated message.
func verifyIdPRedirect(t *testing.T, h *harness, loc *url.URL, field string) []byte {
	t.Helper()
	raw := loc.RawQuery
	idx := strings.Index(raw, "&Signature=")
	if idx < 0 {
		t.Fatalf("no query signature: %s", raw)
	}
	signed := raw[:idx]
	sigB64, _ := url.QueryUnescape(raw[idx+len("&Signature="):])
	sig, _ := base64.StdEncoding.DecodeString(sigB64)
	kp, err := h.saml.Keys.Signer(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	d := sha256.Sum256([]byte(signed))
	if err := rsa.VerifyPKCS1v15(kp.Cert.PublicKey.(*rsa.PublicKey), crypto.SHA256, d[:], sig); err != nil {
		t.Fatalf("IdP query signature: %v", err)
	}
	z, _ := base64.StdEncoding.DecodeString(loc.Query().Get(field))
	out, err := io.ReadAll(flate.NewReader(bytes.NewReader(z)))
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func TestSAMLSingleLogoutFromSP(t *testing.T) {
	h := newHarness(t, harnessOpts{})
	spA := h.testSP(t, false, false)
	h.sloSP(t, spA)
	spB := h.secondSP(t, spA)
	b := h.browser()
	a := b.signIn(t, spA, "alice")
	b.signIn(t, spB, "") // single sign-on: no password the second time

	// Metadata advertises the SLO endpoint.
	md, _ := h.saml.Metadata(context.Background())
	if !strings.Contains(string(md), samlidp.SLOPath) {
		t.Fatal("metadata without SingleLogoutService")
	}

	// SP A asks, signed: no confirmation, the session ends and SP B gets
	// a LogoutRequest (HTTP-POST, XML-signed).
	u, reqID := redirectLogout(t, h, spA, a.Subject.NameID.Value, a.AuthnStatements[0].SessionIndex, true)
	b.get(u)
	b.mustStatus(http.StatusOK)
	b.mustContain(`data-e2e="slo-form-post"`)
	if csp := b.last.Header.Get("Content-Security-Policy"); !strings.Contains(csp, "https://sp2.example.test") {
		t.Fatalf("CSP: %s", csp)
	}
	action := html.UnescapeString(sloActionRE.FindStringSubmatch(b.body)[1])
	m := sloFieldRE.FindStringSubmatch(b.body)
	if action != sp2SLO || m == nil || m[1] != "SAMLRequest" {
		t.Fatalf("not a logout request to SP B: %s %v", action, m)
	}
	xmlB, _ := base64.StdEncoding.DecodeString(html.UnescapeString(m[2]))
	doc := etree.NewDocument()
	if err := doc.ReadFromBytes(xmlB); err != nil {
		t.Fatal(err)
	}
	kp, _ := h.saml.Keys.Signer(context.Background())
	vc := dsig.NewDefaultValidationContext(&dsig.MemoryX509CertificateStore{Roots: []*x509.Certificate{kp.Cert}})
	if _, err := vc.Validate(doc.Root()); err != nil {
		t.Fatalf("SP B cannot verify the IdP's LogoutRequest: %v", err)
	}
	var lrB saml.LogoutRequest
	if err := xml.Unmarshal(xmlB, &lrB); err != nil || lrB.NameID.Value != "alice@lab.test" || lrB.Destination != sp2SLO {
		t.Fatalf("logout request to B: %+v %v", lrB, err)
	}
	// The session is already over.
	b.get("/")
	b.mustContain(`data-e2e="signin-input-username"`)

	// SP B answers (HTTP-POST, unsigned); the IdP then answers SP A with a
	// signed HTTP-Redirect LogoutResponse.
	resp := &saml.LogoutResponse{ID: "id-resp-b", InResponseTo: lrB.ID, Version: "2.0", IssueInstant: time.Now().UTC(),
		Destination: h.ts.URL + samlidp.SLOPath, Issuer: &saml.Issuer{Format: entityF, Value: sp2},
		Status: saml.Status{StatusCode: saml.StatusCode{Value: saml.StatusSuccess}}}
	rd := etree.NewDocument()
	rd.SetRoot(resp.Element())
	rraw, _ := rd.WriteToBytes()
	post, _ := http.NewRequest(http.MethodPost, h.ts.URL+samlidp.SLOPath, strings.NewReader(url.Values{
		"SAMLResponse": {base64.StdEncoding.EncodeToString(rraw)}}.Encode()))
	post.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	post.Header.Set("Sec-Fetch-Site", "cross-site")
	b.do(post)
	loc := b.location()
	if !strings.HasPrefix(loc.String(), spSLO+"?SAMLResponse=") || loc.Query().Get("RelayState") != "back-to-a" {
		t.Fatalf("not the answer to SP A: %s", loc)
	}
	var final saml.LogoutResponse
	if err := xml.Unmarshal(verifyIdPRedirect(t, h, loc, "SAMLResponse"), &final); err != nil {
		t.Fatal(err)
	}
	if final.InResponseTo != reqID || final.Status.StatusCode.Value != saml.StatusSuccess {
		t.Fatalf("final response %+v", final)
	}
	evs, _, _ := h.store.ListAudit(context.Background(), store.AuditFilter{Action: "saml.slo"}, 0, 10)
	if len(evs) < 2 {
		t.Fatalf("audit %+v", evs)
	}
}

func TestSAMLSingleLogoutUnsignedNeedsConfirmation(t *testing.T) {
	h := newHarness(t, harnessOpts{})
	spA := h.testSP(t, false, false)
	h.sloSP(t, spA)
	b := h.browser()
	a := b.signIn(t, spA, "alice")
	u, _ := redirectLogout(t, h, spA, a.Subject.NameID.Value, a.AuthnStatements[0].SessionIndex, false)
	b.get(u)
	b.mustContain(`data-e2e="slo-text-confirm"`)
	// "Stay signed in" keeps the session.
	b.submit("/saml/slo/confirm", url.Values{"t": {tokenOnPage(t, b)}, "decision": {"stay"}})
	b.get("/")
	b.mustContain(`data-e2e="nav-btn-signout"`)
	// Confirming ends it and answers the SP.
	b.get(u)
	b.submit("/saml/slo/confirm", url.Values{"t": {tokenOnPage(t, b)}, "decision": {"signout"}})
	loc := b.location()
	if !strings.HasPrefix(loc.String(), spSLO) {
		t.Fatalf("location %s", loc)
	}
	b.get("/")
	b.mustContain(`data-e2e="signin-input-username"`)
	// A forged signature is treated as unsigned.
	other, _ := newSPKey(t)
	forged := *spA
	forged.Key = other
	u2, _ := redirectLogout(t, h, &forged, "alice@lab.test", "x", true)
	b.get(u2)
	b.mustContain(`data-e2e="slo-text-confirm"`)
}

var sloTokenRE = regexp.MustCompile(`name="t" value="([^"]+)"`)

func tokenOnPage(t *testing.T, b *browser) string {
	t.Helper()
	m := sloTokenRE.FindStringSubmatch(b.body)
	if m == nil {
		t.Fatalf("no token: %.400s", b.body)
	}
	return html.UnescapeString(m[1])
}

func TestSAMLLogoutStartedAtIdP(t *testing.T) {
	h := newHarness(t, harnessOpts{})
	spA := h.testSP(t, false, false)
	h.sloSP(t, spA)
	b := h.browser()
	b.signIn(t, spA, "alice")
	b.get("/")
	b.submit("/logout", url.Values{})
	loc := b.location()
	if !strings.HasPrefix(loc.String(), spSLO+"?SAMLRequest=") {
		t.Fatalf("no logout request to the SP: %s", loc)
	}
	var lr saml.LogoutRequest
	if err := xml.Unmarshal(verifyIdPRedirect(t, h, loc, "SAMLRequest"), &lr); err != nil {
		t.Fatal(err)
	}
	if lr.NameID == nil || lr.NameID.Value != "alice@lab.test" || lr.SessionIndex == nil || lr.SessionIndex.Value == "" {
		t.Fatalf("logout request %+v", lr)
	}
	// An answer from another browser does not continue the chain.
	other := h.browser()
	resp := &saml.LogoutResponse{ID: "id-r", InResponseTo: lr.ID, Version: "2.0", IssueInstant: time.Now().UTC(),
		Issuer: &saml.Issuer{Value: spEntity}, Status: saml.Status{StatusCode: saml.StatusCode{Value: saml.StatusSuccess}}}
	rd := etree.NewDocument()
	rd.SetRoot(resp.Element())
	rraw, _ := rd.WriteToBytes()
	q := url.Values{"SAMLResponse": {deflate64(rraw)}}.Encode()
	other.get(samlidp.SLOPath + "?" + q)
	if other.last.Request.URL.Path != "/logged-out" {
		t.Fatal("chain continued in another browser")
	}
	// The SP answers; the chain ends where the logout started.
	b.get(samlidp.SLOPath + "?" + q)
	if l := b.last.Request.URL; l.Path != "/login" || l.Query().Get("m") != "signed_out" {
		t.Fatalf("final location %s", l)
	}
}

func deflate64(raw []byte) string {
	var z bytes.Buffer
	w, _ := flate.NewWriter(&z, flate.BestCompression)
	_, _ = w.Write(raw)
	_ = w.Close()
	return base64.StdEncoding.EncodeToString(z.Bytes())
}

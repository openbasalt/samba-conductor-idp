package samlidp

import (
	"bytes"
	"compress/flate"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/beevik/etree"
	"github.com/crewjam/saml"
	xrv "github.com/mattermost/xml-roundtrip-validator"
	dsig "github.com/russellhaering/goxmldsig"

	"github.com/openbasalt/samba-conductor-idp/internal/store"
)

// Single logout (SAML 2.0 profiles §4.4), the IdP's side:
//
//   - A service provider sends a LogoutRequest to SLOPath (HTTP-Redirect
//     or HTTP-POST). It is size bounded, round-trip validated and parsed
//     without DTDs, like an AuthnRequest. A request signed with the
//     HTTP-Redirect binding's query signature, by the signing certificate
//     registered for that SP, ends the session at once. Any other request
//     (unsigned, or HTTP-POST) only leads to a confirmation page: the IdP
//     verifies no XML signature (docs/decisions.md D7), and an unverified
//     request must not be able to sign a user out behind their back.
//   - The IdP then sends a LogoutRequest to every other SP the browser
//     session signed in to that has a single logout URL, one after the
//     other (each answers to SLOPath with a LogoutResponse), and finally
//     answers the initiating SP with a LogoutResponse.
//   - Messages the IdP sends are signed: the query signature for
//     HTTP-Redirect (RSA-SHA256), an enveloped XML signature for HTTP-POST.
//   - A LogoutResponse only advances the chain of the browser that started
//     it (request IDs are bound to that browser by the caller).

// SLOPath is the single logout endpoint.
const SLOPath = "/saml/slo"

// SLOBindings a service provider's single logout endpoint may use.
var SLOBindings = []string{saml.HTTPRedirectBinding, saml.HTTPPostBinding}

// SLOURL is where service providers send logout messages.
func (i *IdP) SLOURL() string { return i.BaseURL + SLOPath }

// maxLogout bounds a decoded logout message.
const maxLogout = 32 << 10

// logoutSkew bounds the age of an incoming logout message.
const logoutSkew = 5 * time.Minute

// Participant is one service provider a browser session signed in to,
// with what its LogoutRequest must name.
type Participant struct {
	EntityID        string
	NameID          string
	NameIDFormat    string
	SPNameQualifier string
	SessionIndex    string
}

// LogoutMessage is a parsed incoming LogoutRequest or LogoutResponse.
type LogoutMessage struct {
	Response bool
	// Issuer is the SP's entity ID (registered, enabled, with SLO).
	Issuer       string
	ID           string
	InResponseTo string
	NameID       string
	SessionIndex string
	Status       string
	RelayState   string
	// Verified: an HTTP-Redirect request whose query signature matches the
	// SP's registered signing certificate.
	Verified bool
}

// ErrNoSLO is returned for a logout message from an SP that is unknown,
// disabled or has no single logout URL.
var ErrNoSLO = errors.New("samlidp: the service provider has no single logout endpoint")

// rawQueryParam returns a query parameter exactly as it was encoded (the
// redirect binding's signature covers the encoded form).
func rawQueryParam(raw, name string) (string, bool) {
	for _, part := range strings.Split(raw, "&") {
		k, v, _ := strings.Cut(part, "=")
		if k == name {
			return v, true
		}
	}
	return "", false
}

// ParseLogout reads a logout message from the SLO endpoint.
func (i *IdP) ParseLogout(ctx context.Context, r *http.Request) (*LogoutMessage, error) {
	var payload, relay string
	redirect := r.Method == http.MethodGet
	var field string
	if redirect {
		q := r.URL.Query()
		field = "SAMLRequest"
		payload = q.Get(field)
		if payload == "" {
			field = "SAMLResponse"
			payload = q.Get(field)
		}
		relay = q.Get("RelayState")
	} else {
		if err := r.ParseForm(); err != nil {
			return nil, err
		}
		field = "SAMLRequest"
		payload = r.PostForm.Get(field)
		if payload == "" {
			field = "SAMLResponse"
			payload = r.PostForm.Get(field)
		}
		relay = r.PostForm.Get("RelayState")
	}
	if payload == "" || len(payload) > maxLogout*2 {
		return nil, errors.New("samlidp: no logout message")
	}
	if len(relay) > 800 {
		return nil, errors.New("samlidp: RelayState too large")
	}
	raw, err := base64.StdEncoding.DecodeString(payload)
	if err != nil {
		return nil, fmt.Errorf("samlidp: logout message: %w", err)
	}
	if redirect {
		raw, err = io.ReadAll(io.LimitReader(flate.NewReader(bytes.NewReader(raw)), maxLogout+1))
		if err != nil {
			return nil, fmt.Errorf("samlidp: logout message: %w", err)
		}
	}
	if len(raw) > maxLogout {
		return nil, errors.New("samlidp: logout message too large")
	}
	if err := xrv.Validate(bytes.NewReader(raw)); err != nil {
		return nil, fmt.Errorf("samlidp: logout message: %w", err)
	}
	m := &LogoutMessage{RelayState: relay, Response: field == "SAMLResponse"}
	var issuer *saml.Issuer
	var destination string
	var issued time.Time
	if m.Response {
		var resp saml.LogoutResponse
		if err := xml.Unmarshal(raw, &resp); err != nil {
			return nil, fmt.Errorf("samlidp: logout response: %w", err)
		}
		issuer, destination, issued = resp.Issuer, resp.Destination, resp.IssueInstant
		m.ID, m.InResponseTo, m.Status = resp.ID, resp.InResponseTo, resp.Status.StatusCode.Value
	} else {
		var req saml.LogoutRequest
		if err := xml.Unmarshal(raw, &req); err != nil {
			return nil, fmt.Errorf("samlidp: logout request: %w", err)
		}
		issuer, destination, issued = req.Issuer, req.Destination, req.IssueInstant
		m.ID = req.ID
		if req.NameID != nil {
			m.NameID = req.NameID.Value
		}
		if req.SessionIndex != nil {
			m.SessionIndex = req.SessionIndex.Value
		}
		if req.NotOnOrAfter != nil && !i.now().Before(*req.NotOnOrAfter) {
			return nil, errors.New("samlidp: logout request expired")
		}
	}
	if issuer == nil || issuer.Value == "" || m.ID == "" {
		return nil, errors.New("samlidp: logout message without issuer or ID")
	}
	m.Issuer = issuer.Value
	if destination != "" && destination != i.SLOURL() {
		return nil, errors.New("samlidp: logout message for another destination")
	}
	if d := i.now().Sub(issued); d > logoutSkew || d < -logoutSkew {
		return nil, errors.New("samlidp: logout message too old or from the future")
	}
	sp, err := i.Store.GetSP(ctx, m.Issuer)
	if errors.Is(err, store.ErrNotFound) || (err == nil && (!sp.Enabled || sp.SLOURL == "")) {
		return nil, ErrNoSLO
	}
	if err != nil {
		return nil, err
	}
	if redirect && !m.Response && len(sp.SigningCert) > 0 {
		m.Verified = verifyRedirectSignature(r.URL.RawQuery, field, sp.SigningCert) == nil
	}
	return m, nil
}

// verifyRedirectSignature checks the HTTP-Redirect binding's signature
// (bindings §3.4.4.1): over "field=..&RelayState=..&SigAlg=.." as encoded
// in the query, RSA with SHA-256 or stronger.
func verifyRedirectSignature(rawQuery, field string, certDER []byte) error {
	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return err
	}
	pub, ok := cert.PublicKey.(*rsa.PublicKey)
	if !ok {
		return errors.New("samlidp: only RSA signing certificates are supported")
	}
	msg, _ := rawQueryParam(rawQuery, field)
	sigAlgRaw, ok1 := rawQueryParam(rawQuery, "SigAlg")
	sigRaw, ok2 := rawQueryParam(rawQuery, "Signature")
	if msg == "" || !ok1 || !ok2 {
		return errors.New("samlidp: no query signature")
	}
	signed := field + "=" + msg
	if relay, ok := rawQueryParam(rawQuery, "RelayState"); ok {
		signed += "&RelayState=" + relay
	}
	signed += "&SigAlg=" + sigAlgRaw
	sigAlg, err := url.QueryUnescape(sigAlgRaw)
	if err != nil {
		return err
	}
	sigB64, err := url.QueryUnescape(sigRaw)
	if err != nil {
		return err
	}
	sig, err := base64.StdEncoding.DecodeString(sigB64)
	if err != nil {
		return err
	}
	var h crypto.Hash
	switch sigAlg {
	case dsig.RSASHA256SignatureMethod:
		h = crypto.SHA256
	case dsig.RSASHA512SignatureMethod:
		h = crypto.SHA512
	default:
		return fmt.Errorf("samlidp: signature algorithm %q not accepted", sigAlg)
	}
	var digest []byte
	if h == crypto.SHA256 {
		d := sha256.Sum256([]byte(signed))
		digest = d[:]
	} else {
		d := sha512.Sum512([]byte(signed))
		digest = d[:]
	}
	return rsa.VerifyPKCS1v15(pub, h, digest, sig)
}

// Outgoing is a logout message to deliver through the browser: a redirect
// (HTTP-Redirect binding) or a form (HTTP-POST binding).
type Outgoing struct {
	RedirectURL string
	Form        *LogoutForm
	// ID of the message (a request's ID is what the answer refers to).
	ID string
}

// LogoutForm is an HTTP-POST binding logout message.
type LogoutForm struct {
	URL        string
	Field      string // SAMLRequest or SAMLResponse
	Value      string
	RelayState string
}

// LogoutRequestTo builds the IdP's LogoutRequest to a session participant.
func (i *IdP) LogoutRequestTo(ctx context.Context, sp *store.SAMLSP, p Participant, relay string) (*Outgoing, error) {
	if sp.SLOURL == "" {
		return nil, ErrNoSLO
	}
	now := i.now()
	end := now.Add(logoutSkew)
	req := &saml.LogoutRequest{ID: randomID(), Version: "2.0", IssueInstant: now, NotOnOrAfter: &end, Destination: sp.SLOURL,
		Issuer: &saml.Issuer{Format: "urn:oasis:names:tc:SAML:2.0:nameid-format:entity", Value: i.EntityID()},
		NameID: &saml.NameID{Format: p.NameIDFormat, NameQualifier: i.EntityID(), SPNameQualifier: p.SPNameQualifier, Value: p.NameID}}
	if p.SessionIndex != "" {
		req.SessionIndex = &saml.SessionIndex{Value: p.SessionIndex}
	}
	out, err := i.deliver(ctx, sp, "SAMLRequest", req.Element(), relay)
	if err != nil {
		return nil, err
	}
	out.ID = req.ID
	return out, nil
}

// LogoutResponseTo builds the IdP's answer to an SP's LogoutRequest.
func (i *IdP) LogoutResponseTo(ctx context.Context, sp *store.SAMLSP, inResponseTo, status, relay string) (*Outgoing, error) {
	if sp.SLOURL == "" {
		return nil, ErrNoSLO
	}
	resp := &saml.LogoutResponse{ID: randomID(), InResponseTo: inResponseTo, Version: "2.0", IssueInstant: i.now(), Destination: sp.SLOURL,
		Issuer: &saml.Issuer{Format: "urn:oasis:names:tc:SAML:2.0:nameid-format:entity", Value: i.EntityID()},
		Status: saml.Status{StatusCode: saml.StatusCode{Value: status}}}
	out, err := i.deliver(ctx, sp, "SAMLResponse", resp.Element(), relay)
	if err != nil {
		return nil, err
	}
	out.ID = resp.ID
	return out, nil
}

// deliver signs a message for the SP's binding.
func (i *IdP) deliver(ctx context.Context, sp *store.SAMLSP, field string, el *etree.Element, relay string) (*Outgoing, error) {
	kp, err := i.Keys.Signer(ctx)
	if err != nil {
		return nil, err
	}
	if sp.SLOBinding == saml.HTTPPostBinding {
		sc := dsig.NewDefaultSigningContext(dsig.TLSCertKeyStore(tls.Certificate{Certificate: [][]byte{kp.Cert.Raw}, PrivateKey: kp.Key, Leaf: kp.Cert}))
		sc.Canonicalizer = dsig.MakeC14N10ExclusiveCanonicalizerWithPrefixList("")
		if err := sc.SetSignatureMethod(dsig.RSASHA256SignatureMethod); err != nil {
			return nil, err
		}
		signed, err := sc.SignEnveloped(el)
		if err != nil {
			return nil, err
		}
		// The signature goes right after the Issuer (schema order).
		sig := signed.Child[len(signed.Child)-1]
		signed.RemoveChildAt(len(signed.Child) - 1)
		pos := 0
		for n, c := range signed.Child {
			if e, ok := c.(*etree.Element); ok && e.Tag == "Issuer" {
				pos = n + 1
				break
			}
		}
		signed.InsertChildAt(pos, sig)
		doc := etree.NewDocument()
		doc.SetRoot(signed)
		buf, err := doc.WriteToBytes()
		if err != nil {
			return nil, err
		}
		return &Outgoing{Form: &LogoutForm{URL: sp.SLOURL, Field: field, Value: base64.StdEncoding.EncodeToString(buf), RelayState: relay}}, nil
	}
	doc := etree.NewDocument()
	doc.SetRoot(el)
	buf, err := doc.WriteToBytes()
	if err != nil {
		return nil, err
	}
	var z bytes.Buffer
	fw, _ := flate.NewWriter(&z, flate.BestCompression)
	_, _ = fw.Write(buf)
	_ = fw.Close()
	q := field + "=" + url.QueryEscape(base64.StdEncoding.EncodeToString(z.Bytes()))
	if relay != "" {
		q += "&RelayState=" + url.QueryEscape(relay)
	}
	q += "&SigAlg=" + url.QueryEscape(dsig.RSASHA256SignatureMethod)
	digest := sha256.Sum256([]byte(q))
	sig, err := rsa.SignPKCS1v15(rand.Reader, kp.Key, crypto.SHA256, digest[:])
	if err != nil {
		return nil, err
	}
	q += "&Signature=" + url.QueryEscape(base64.StdEncoding.EncodeToString(sig))
	target := sp.SLOURL
	sep := "?"
	if strings.Contains(target, "?") {
		sep = "&"
	}
	return &Outgoing{RedirectURL: target + sep + q}, nil
}

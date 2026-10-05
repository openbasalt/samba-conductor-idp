package main

import (
	"bytes"
	"compress/flate"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/xml"
	"io"
	"log"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/beevik/etree"
	"github.com/crewjam/saml"
	"github.com/crewjam/saml/samlsp"
)

const rsaSHA256 = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"

// sloHandler is the test SP's side of SAML single logout over the
// HTTP-Redirect binding: messages it sends carry the query signature,
// messages it receives must carry the idp's.
type sloHandler struct {
	sp      *samlsp.Middleware
	idpCert *x509.Certificate
}

func idpSigningCert(md *saml.EntityDescriptor) *x509.Certificate {
	for _, d := range md.IDPSSODescriptors {
		for _, kd := range d.KeyDescriptors {
			if kd.Use != "signing" && kd.Use != "" {
				continue
			}
			for _, c := range kd.KeyInfo.X509Data.X509Certificates {
				der, err := base64.StdEncoding.DecodeString(strings.Join(strings.Fields(c.Data), ""))
				if err != nil {
					continue
				}
				if cert, err := x509.ParseCertificate(der); err == nil {
					return cert
				}
			}
		}
	}
	return nil
}

func (h *sloHandler) idpSLO() string {
	return h.sp.ServiceProvider.GetSLOBindingLocation(saml.HTTPRedirectBinding)
}

// signedRedirect builds an HTTP-Redirect binding URL signed with the SP key.
func (h *sloHandler) signedRedirect(dest, field string, el *etree.Element, relay string) string {
	doc := etree.NewDocument()
	doc.SetRoot(el)
	raw, _ := doc.WriteToBytes()
	var z bytes.Buffer
	w, _ := flate.NewWriter(&z, flate.BestCompression)
	_, _ = w.Write(raw)
	_ = w.Close()
	q := field + "=" + url.QueryEscape(base64.StdEncoding.EncodeToString(z.Bytes()))
	if relay != "" {
		q += "&RelayState=" + url.QueryEscape(relay)
	}
	q += "&SigAlg=" + url.QueryEscape(rsaSHA256)
	d := sha256.Sum256([]byte(q))
	sig, err := rsa.SignPKCS1v15(rand.Reader, h.sp.ServiceProvider.Key.(*rsa.PrivateKey), crypto.SHA256, d[:])
	if err != nil {
		log.Fatal(err)
	}
	q += "&Signature=" + url.QueryEscape(base64.StdEncoding.EncodeToString(sig))
	sep := "?"
	if strings.Contains(dest, "?") {
		sep = "&"
	}
	return dest + sep + q
}

// logout starts a single logout for the signed-in user.
func (h *sloHandler) logout(w http.ResponseWriter, r *http.Request) {
	s, err := h.sp.Session.GetSession(r)
	claims, ok := s.(samlsp.JWTSessionClaims)
	if err != nil || !ok {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}
	req, err := h.sp.ServiceProvider.MakeLogoutRequest(h.idpSLO(), claims.Subject)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	req.Signature = nil
	_ = h.sp.Session.DeleteSession(w, r)
	http.Redirect(w, r, h.signedRedirect(h.idpSLO(), "SAMLRequest", req.Element(), "example-sp"), http.StatusSeeOther)
}

// verify checks the idp's query signature and returns the inflated XML.
func (h *sloHandler) verify(r *http.Request, field string) ([]byte, bool) {
	raw := r.URL.RawQuery
	i := strings.Index(raw, "&Signature=")
	if i < 0 || h.idpCert == nil {
		return nil, false
	}
	sigB64, _ := url.QueryUnescape(raw[i+len("&Signature="):])
	sig, _ := base64.StdEncoding.DecodeString(sigB64)
	d := sha256.Sum256([]byte(raw[:i]))
	pub, ok := h.idpCert.PublicKey.(*rsa.PublicKey)
	if !ok || rsa.VerifyPKCS1v15(pub, crypto.SHA256, d[:], sig) != nil {
		return nil, false
	}
	z, err := base64.StdEncoding.DecodeString(r.URL.Query().Get(field))
	if err != nil {
		return nil, false
	}
	out, err := io.ReadAll(io.LimitReader(flate.NewReader(bytes.NewReader(z)), 64<<10))
	return out, err == nil
}

func (h *sloHandler) serveSLO(w http.ResponseWriter, r *http.Request) {
	if r.URL.Query().Get("SAMLResponse") != "" {
		raw, ok := h.verify(r, "SAMLResponse")
		var resp saml.LogoutResponse
		if !ok || xml.Unmarshal(raw, &resp) != nil {
			http.Error(w, "invalid logout response", http.StatusBadRequest)
			return
		}
		log.Printf("logout response from the idp: %s", resp.Status.StatusCode.Value)
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write(signedOut)
		return
	}
	raw, ok := h.verify(r, "SAMLRequest")
	var req saml.LogoutRequest
	if !ok || xml.Unmarshal(raw, &req) != nil {
		http.Error(w, "invalid logout request", http.StatusBadRequest)
		return
	}
	_ = h.sp.Session.DeleteSession(w, r)
	resp := &saml.LogoutResponse{ID: "id-" + randomHex(), InResponseTo: req.ID, Version: "2.0", IssueInstant: time.Now().UTC(),
		Destination: h.idpSLO(), Issuer: &saml.Issuer{Format: "urn:oasis:names:tc:SAML:2.0:nameid-format:entity",
			Value: h.sp.ServiceProvider.EntityID},
		Status: saml.Status{StatusCode: saml.StatusCode{Value: saml.StatusSuccess}}}
	http.Redirect(w, r, h.signedRedirect(h.idpSLO(), "SAMLResponse", resp.Element(), r.URL.Query().Get("RelayState")), http.StatusSeeOther)
}

func randomHex() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	var sb strings.Builder
	for _, c := range b {
		sb.WriteString(strings.ToLower(string("0123456789abcdef"[c>>4]) + string("0123456789abcdef"[c&15])))
	}
	return sb.String()
}

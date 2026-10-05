// Package samlidp is the SAML 2.0 identity provider of conductor-idp,
// built on github.com/crewjam/saml for parsing AuthnRequests and for
// signing (goxmldsig) and encrypting assertions.
//
// Hardening on top of the library (see docs/decisions.md D7):
//   - service providers are registered by administrators; the SP
//     "metadata" the library sees is built from that registration, never
//     fetched or taken from a request, so the ACS URL, the encryption
//     certificate and the entity ID come from the registry only;
//   - only the HTTP-POST binding is answered; AuthnRequests may arrive by
//     HTTP-Redirect or HTTP-POST, are size bounded, round-trip validated
//     and never signature-checked (the IdP trusts nothing signed in a
//     request, so XML signature wrapping has nothing to wrap);
//   - an AuthnRequest ID is answered at most once per SP (replay);
//   - assertions and responses are always signed (RSA-SHA256, exclusive
//     C14N); encryption only when enabled for the SP;
//   - attributes are exactly the per-SP mapping (nothing by default).
package samlidp

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/xml"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"slices"
	"strings"
	"time"

	"github.com/beevik/etree"
	"github.com/crewjam/saml"
	dsig "github.com/russellhaering/goxmldsig"

	"github.com/openbasalt/samba-conductor-idp/internal/directory"
	"github.com/openbasalt/samba-conductor-idp/internal/store"
)

// NameID formats offered to service providers.
const (
	NameIDEmail       = "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress"
	NameIDUnspecified = "urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified"
	NameIDPersistent  = "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent"
)

// NameIDFormats lists the formats a registration may use.
var NameIDFormats = []string{NameIDEmail, NameIDUnspecified, NameIDPersistent}

// Sources of NameID and attribute values.
const (
	SourceEmail     = "email"
	SourceUPN       = "upn"
	SourceUsername  = "username"
	SourceName      = "name"
	SourceGivenName = "given_name"
	SourceSurname   = "surname"
	SourceGroups    = "groups"
	SourceGroupSIDs = "group_sids"
	SourceGUID      = "guid"
)

// Sources lists every value source; NameIDSources the single-valued ones
// that may identify a user.
var (
	Sources       = []string{SourceEmail, SourceUPN, SourceUsername, SourceName, SourceGivenName, SourceSurname, SourceGroups, SourceGroupSIDs, SourceGUID}
	NameIDSources = []string{SourceEmail, SourceUPN, SourceUsername, SourceGUID}
)

// Paths of the SAML endpoints.
const (
	MetadataPath = "/saml/metadata"
	SSOPath      = "/saml/sso"
)

// maxRequest bounds a decoded AuthnRequest.
const maxRequest = 64 << 10

// IdP answers SAML requests for registered service providers.
type IdP struct {
	Store   *store.Store
	Dir     directory.Backend
	Keys    *KeyManager
	BaseURL string // the issuer, https://host[:port]
	// AssertionTTL is how long an assertion may be used.
	AssertionTTL time.Duration
	Now          func() time.Time
}

func (i *IdP) now() time.Time {
	if i.Now != nil {
		return i.Now().UTC()
	}
	return time.Now().UTC()
}

// EntityID is the IdP's entity ID (the metadata URL).
func (i *IdP) EntityID() string { return i.BaseURL + MetadataPath }

// SSOURL is where SPs send AuthnRequests.
func (i *IdP) SSOURL() string { return i.BaseURL + SSOPath }

func mustURL(s string) url.URL {
	u, err := url.Parse(s)
	if err != nil {
		return url.URL{}
	}
	return *u
}

// library builds a crewjam IdentityProvider for one request, signing with
// the current key and resolving SPs from the registry only.
func (i *IdP) library(ctx context.Context) (*saml.IdentityProvider, error) {
	kp, err := i.Keys.Signer(ctx)
	if err != nil {
		return nil, err
	}
	return &saml.IdentityProvider{
		Key:                     kp.Key,
		Certificate:             kp.Cert,
		MetadataURL:             mustURL(i.EntityID()),
		SSOURL:                  mustURL(i.SSOURL()),
		ServiceProviderProvider: registry{i: i, ctx: ctx},
		SignatureMethod:         dsig.RSASHA256SignatureMethod,
	}, nil
}

// registry implements saml.ServiceProviderProvider from the store.
type registry struct {
	i   *IdP
	ctx context.Context
}

func (r registry) GetServiceProvider(_ *http.Request, entityID string) (*saml.EntityDescriptor, error) {
	sp, err := r.i.Store.GetSP(r.ctx, entityID)
	if errors.Is(err, store.ErrNotFound) || (err == nil && !sp.Enabled) {
		return nil, os.ErrNotExist
	}
	if err != nil {
		return nil, err
	}
	return SPDescriptor(sp), nil
}

// SPDescriptor builds the SP's metadata from its registration: the ACS
// URLs (HTTP-POST only) and, when encryption is on, the encryption
// certificate. Nothing else of the SP's own metadata is trusted.
func SPDescriptor(sp *store.SAMLSP) *saml.EntityDescriptor {
	d := saml.SPSSODescriptor{}
	for n, u := range sp.ACSURLs {
		d.AssertionConsumerServices = append(d.AssertionConsumerServices, saml.IndexedEndpoint{
			Binding: saml.HTTPPostBinding, Location: u, Index: n,
		})
	}
	if sp.EncryptAssertion && len(sp.EncryptionCert) > 0 {
		d.KeyDescriptors = []saml.KeyDescriptor{{
			Use: "encryption",
			KeyInfo: saml.KeyInfo{X509Data: saml.X509Data{X509Certificates: []saml.X509Certificate{
				{Data: base64.StdEncoding.EncodeToString(sp.EncryptionCert)},
			}}},
		}}
	}
	return &saml.EntityDescriptor{EntityID: sp.EntityID, SPSSODescriptors: []saml.SPSSODescriptor{d}}
}

// Metadata renders the IdP metadata: every published signing certificate
// (two during a staged rotation), the SSO endpoints and NameID formats.
func (i *IdP) Metadata(ctx context.Context) ([]byte, error) {
	keys, err := i.Keys.Keys(ctx)
	if err != nil {
		return nil, err
	}
	var kds []saml.KeyDescriptor
	for _, k := range keys {
		kds = append(kds, saml.KeyDescriptor{Use: "signing", KeyInfo: saml.KeyInfo{X509Data: saml.X509Data{
			X509Certificates: []saml.X509Certificate{{Data: base64.StdEncoding.EncodeToString(k.Cert.Raw)}}}}})
	}
	valid := 7 * 24 * time.Hour
	wantSigned := false
	formats := make([]saml.NameIDFormat, len(NameIDFormats))
	for n, f := range NameIDFormats {
		formats[n] = saml.NameIDFormat(f)
	}
	ed := saml.EntityDescriptor{
		EntityID:      i.EntityID(),
		ValidUntil:    i.now().Add(valid),
		CacheDuration: 24 * time.Hour,
		IDPSSODescriptors: []saml.IDPSSODescriptor{{
			SSODescriptor: saml.SSODescriptor{
				RoleDescriptor: saml.RoleDescriptor{
					ProtocolSupportEnumeration: "urn:oasis:names:tc:SAML:2.0:protocol",
					KeyDescriptors:             kds,
				},
				NameIDFormats: formats,
				SingleLogoutServices: []saml.Endpoint{
					{Binding: saml.HTTPRedirectBinding, Location: i.SLOURL()},
					{Binding: saml.HTTPPostBinding, Location: i.SLOURL()},
				},
			},
			WantAuthnRequestsSigned: &wantSigned,
			SingleSignOnServices: []saml.Endpoint{
				{Binding: saml.HTTPRedirectBinding, Location: i.SSOURL()},
				{Binding: saml.HTTPPostBinding, Location: i.SSOURL()},
			},
		}},
	}
	out, err := xml.MarshalIndent(ed, "", "  ")
	if err != nil {
		return nil, err
	}
	return append([]byte(xml.Header), out...), nil
}

// Request is a validated AuthnRequest.
type Request struct {
	EntityID   string
	RequestID  string
	Payload    []byte // decoded XML
	RelayState string
	ReceivedAt time.Time
}

// ErrUnknownSP is returned for a request from an unregistered or disabled
// service provider.
var ErrUnknownSP = errors.New("samlidp: unknown service provider")

// Parse reads and validates an AuthnRequest from the SSO endpoint
// (HTTP-Redirect or HTTP-POST binding).
func (i *IdP) Parse(ctx context.Context, r *http.Request) (*Request, error) {
	lib, err := i.library(ctx)
	if err != nil {
		return nil, err
	}
	switch r.Method {
	case http.MethodGet:
		if len(r.URL.Query().Get("SAMLRequest")) > maxRequest*2 {
			return nil, errors.New("samlidp: request too large")
		}
	case http.MethodPost:
		if err := r.ParseForm(); err != nil {
			return nil, err
		}
	}
	req, err := saml.NewIdpAuthnRequest(lib, r)
	if err != nil {
		return nil, fmt.Errorf("samlidp: %w", err)
	}
	if len(req.RequestBuffer) > maxRequest {
		return nil, errors.New("samlidp: request too large")
	}
	if len(req.RelayState) > 80*10 {
		// SAML bindings §3.4.3 limits RelayState to 80 bytes; some SPs send
		// more, but nothing legitimate needs kilobytes.
		return nil, errors.New("samlidp: RelayState too large")
	}
	if err := req.Validate(); err != nil {
		if strings.Contains(err.Error(), "unknown service provider") {
			return nil, ErrUnknownSP
		}
		return nil, fmt.Errorf("samlidp: %w", err)
	}
	if req.Request.ID == "" {
		return nil, errors.New("samlidp: request without ID")
	}
	return &Request{EntityID: req.Request.Issuer.Value, RequestID: req.Request.ID, Payload: req.RequestBuffer,
		RelayState: req.RelayState, ReceivedAt: req.Now}, nil
}

// Session is what the assertion says about the sign-in.
type Session struct {
	AuthTime   time.Time
	Expires    time.Time
	ClientAddr string
}

// Form is an HTTP-POST binding response, rendered by the web server.
type Form struct {
	URL          string
	SAMLResponse string
	RelayState   string
	// Participant is what a later single logout must name.
	Participant Participant
}

// Allowed reports whether a user may sign in to a service provider.
func Allowed(sp *store.SAMLSP, u *directory.User) bool {
	if !u.Active() {
		return false
	}
	return sp.AllowAllUsers || u.InAnyGroup(sp.AllowedGroups)
}

// Respond builds the signed response to a pending SP-initiated request.
func (i *IdP) Respond(ctx context.Context, p *store.SAMLPending, sp *store.SAMLSP, u *directory.User, sess Session) (*Form, error) {
	lib, err := i.library(ctx)
	if err != nil {
		return nil, err
	}
	// Re-validate the stored request as of its arrival (the user may have
	// taken longer to sign in than an AuthnRequest may be old), then build
	// the assertion as of now.
	hr, _ := http.NewRequestWithContext(ctx, http.MethodPost, i.SSOURL(), nil)
	req := &saml.IdpAuthnRequest{IDP: lib, HTTPRequest: hr, RequestBuffer: p.Payload, RelayState: p.RelayState, Now: p.ReceivedAt}
	if err := req.Validate(); err != nil {
		return nil, fmt.Errorf("samlidp: %w", err)
	}
	if req.Request.Issuer.Value != sp.EntityID || req.Request.ID != p.RequestID {
		return nil, errors.New("samlidp: pending request does not match")
	}
	req.Now = i.now()
	return i.finish(ctx, req, sp, u, sess)
}

// RespondIdPInitiated builds an unsolicited response to an SP that allows
// IdP-initiated sign-in, posted to its first ACS URL.
func (i *IdP) RespondIdPInitiated(ctx context.Context, sp *store.SAMLSP, u *directory.User, sess Session) (*Form, error) {
	if !sp.IdPInitiated || !sp.Enabled || len(sp.ACSURLs) == 0 {
		return nil, ErrUnknownSP
	}
	lib, err := i.library(ctx)
	if err != nil {
		return nil, err
	}
	hr, _ := http.NewRequestWithContext(ctx, http.MethodGet, i.SSOURL(), nil)
	md := SPDescriptor(sp)
	req := &saml.IdpAuthnRequest{IDP: lib, HTTPRequest: hr, RelayState: sp.DefaultRelay, Now: i.now(),
		ServiceProviderMetadata: md, SPSSODescriptor: &md.SPSSODescriptors[0],
		ACSEndpoint: &md.SPSSODescriptors[0].AssertionConsumerServices[0]}
	return i.finish(ctx, req, sp, u, sess)
}

func (i *IdP) finish(ctx context.Context, req *saml.IdpAuthnRequest, sp *store.SAMLSP, u *directory.User, sess Session) (*Form, error) {
	if req.ACSEndpoint == nil || req.ACSEndpoint.Binding != saml.HTTPPostBinding || !slices.Contains(sp.ACSURLs, req.ACSEndpoint.Location) {
		return nil, errors.New("samlidp: no registered HTTP-POST ACS URL")
	}
	if err := i.makeAssertion(ctx, req, sp, u, sess); err != nil {
		return nil, err
	}
	if err := req.MakeResponse(); err != nil {
		return nil, err
	}
	doc := etree.NewDocument()
	doc.SetRoot(req.ResponseEl)
	buf, err := doc.WriteToBytes()
	if err != nil {
		return nil, err
	}
	p := Participant{EntityID: sp.EntityID}
	if a := req.Assertion; a != nil && a.Subject != nil && a.Subject.NameID != nil {
		p.NameID, p.NameIDFormat, p.SPNameQualifier = a.Subject.NameID.Value, a.Subject.NameID.Format, a.Subject.NameID.SPNameQualifier
		if len(a.AuthnStatements) > 0 {
			p.SessionIndex = a.AuthnStatements[0].SessionIndex
		}
	}
	return &Form{URL: req.ACSEndpoint.Location, SAMLResponse: base64.StdEncoding.EncodeToString(buf), RelayState: req.RelayState,
		Participant: p}, nil
}

func randomID() string {
	b := make([]byte, 20)
	_, _ = rand.Read(b)
	return "id-" + hex.EncodeToString(b)
}

// Values returns the values of a source for a user (also used by the
// management API's mapping preview).
func (i *IdP) Values(ctx context.Context, source string, u *directory.User) ([]string, error) {
	one := func(v string) []string {
		if v == "" {
			return nil
		}
		return []string{v}
	}
	switch source {
	case SourceEmail:
		return one(u.Mail), nil
	case SourceUPN:
		return one(u.UPN), nil
	case SourceUsername:
		return one(u.SAM), nil
	case SourceName:
		return one(u.Name()), nil
	case SourceGivenName:
		return one(u.GivenName), nil
	case SourceSurname:
		return one(u.Surname), nil
	case SourceGUID:
		return one(u.GUID), nil
	case SourceGroupSIDs:
		out := make([]string, 0, len(u.GroupSIDs))
		for _, g := range u.GroupSIDs {
			out = append(out, g.String())
		}
		slices.Sort(out)
		return out, nil
	case SourceGroups:
		names, err := i.Dir.GroupNames(ctx, u.GroupSIDs)
		if err != nil {
			return nil, err
		}
		out := make([]string, 0, len(names))
		for _, n := range names {
			out = append(out, n)
		}
		slices.Sort(out)
		return out, nil
	}
	return nil, fmt.Errorf("samlidp: unknown source %q", source)
}

// ErrNoNameID is returned when the user has no value for the SP's NameID
// source (e.g. no mail for an e-mail NameID).
var ErrNoNameID = errors.New("samlidp: the user has no value for the NameID")

func (i *IdP) makeAssertion(ctx context.Context, req *saml.IdpAuthnRequest, sp *store.SAMLSP, u *directory.User, sess Session) error {
	nameIDs, err := i.Values(ctx, sp.NameIDSource, u)
	if err != nil {
		return err
	}
	if len(nameIDs) != 1 {
		return ErrNoNameID
	}
	var attrs []saml.Attribute
	for _, a := range sp.Attributes {
		vals, err := i.Values(ctx, a.Source, u)
		if err != nil {
			return err
		}
		if len(vals) == 0 {
			continue
		}
		at := saml.Attribute{Name: a.Name, NameFormat: "urn:oasis:names:tc:SAML:2.0:attrname-format:basic"}
		if strings.HasPrefix(a.Name, "urn:") || strings.HasPrefix(a.Name, "http") {
			at.NameFormat = "urn:oasis:names:tc:SAML:2.0:attrname-format:uri"
		}
		for _, v := range vals {
			at.Values = append(at.Values, saml.AttributeValue{Type: "xs:string", Value: v})
		}
		attrs = append(attrs, at)
	}
	now := req.Now
	notBefore := now.Add(-30 * time.Second)
	notOnOrAfter := now.Add(i.AssertionTTL)
	var inResponseTo string
	if req.Request.ID != "" {
		inResponseTo = req.Request.ID
	}
	authTime := sess.AuthTime
	if authTime.IsZero() {
		authTime = now
	}
	var sessionEnd *time.Time
	if !sess.Expires.IsZero() {
		e := sess.Expires.UTC()
		sessionEnd = &e
	}
	assertion := &saml.Assertion{
		ID:           randomID(),
		IssueInstant: now,
		Version:      "2.0",
		Issuer:       saml.Issuer{Format: "urn:oasis:names:tc:SAML:2.0:nameid-format:entity", Value: i.EntityID()},
		Subject: &saml.Subject{
			NameID: &saml.NameID{Format: sp.NameIDFormat, NameQualifier: i.EntityID(), SPNameQualifier: sp.EntityID, Value: nameIDs[0]},
			SubjectConfirmations: []saml.SubjectConfirmation{{
				Method: "urn:oasis:names:tc:SAML:2.0:cm:bearer",
				SubjectConfirmationData: &saml.SubjectConfirmationData{
					InResponseTo: inResponseTo,
					NotOnOrAfter: notOnOrAfter,
					Recipient:    req.ACSEndpoint.Location,
				},
			}},
		},
		Conditions: &saml.Conditions{
			NotBefore:            notBefore,
			NotOnOrAfter:         notOnOrAfter,
			AudienceRestrictions: []saml.AudienceRestriction{{Audience: saml.Audience{Value: sp.EntityID}}},
		},
		AuthnStatements: []saml.AuthnStatement{{
			AuthnInstant:        authTime.UTC(),
			SessionIndex:        randomID(),
			SessionNotOnOrAfter: sessionEnd,
			AuthnContext: saml.AuthnContext{AuthnContextClassRef: &saml.AuthnContextClassRef{
				Value: "urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport",
			}},
		}},
	}
	if len(attrs) > 0 {
		assertion.AttributeStatements = []saml.AttributeStatement{{Attributes: attrs}}
	}
	req.Assertion = assertion
	return nil
}

// ParseSPMetadata reads an SP's metadata document (as an administrator
// imports it) into a registration draft: entity ID, HTTP-POST ACS URLs,
// a NameID format it asks for and its encryption certificate.
func ParseSPMetadata(data []byte) (*store.SAMLSP, error) {
	if len(data) > 1<<20 {
		return nil, errors.New("samlidp: metadata too large")
	}
	var ed saml.EntityDescriptor
	if err := xml.Unmarshal(data, &ed); err != nil {
		// An EntitiesDescriptor with a single entity is common.
		var eds saml.EntitiesDescriptor
		if err2 := xml.Unmarshal(data, &eds); err2 != nil || len(eds.EntityDescriptors) != 1 {
			return nil, fmt.Errorf("samlidp: metadata: %w", err)
		}
		ed = eds.EntityDescriptors[0]
	}
	if ed.EntityID == "" || len(ed.SPSSODescriptors) == 0 {
		return nil, errors.New("samlidp: metadata has no SP descriptor")
	}
	sp := &store.SAMLSP{EntityID: ed.EntityID, NameIDFormat: NameIDUnspecified, NameIDSource: SourceUsername, Enabled: true}
	for _, d := range ed.SPSSODescriptors {
		for _, acs := range d.AssertionConsumerServices {
			if acs.Binding == saml.HTTPPostBinding && !slices.Contains(sp.ACSURLs, acs.Location) {
				sp.ACSURLs = append(sp.ACSURLs, acs.Location)
			}
		}
		for _, f := range d.NameIDFormats {
			if slices.Contains(NameIDFormats, string(f)) {
				sp.NameIDFormat = string(f)
				if string(f) == NameIDEmail {
					sp.NameIDSource = SourceEmail
				} else if string(f) == NameIDPersistent {
					sp.NameIDSource = SourceGUID
				}
				break
			}
		}
		for _, kd := range d.KeyDescriptors {
			if len(kd.KeyInfo.X509Data.X509Certificates) == 0 {
				continue
			}
			raw := strings.Join(strings.Fields(kd.KeyInfo.X509Data.X509Certificates[0].Data), "")
			der, err := base64.StdEncoding.DecodeString(raw)
			if err != nil {
				continue
			}
			if (kd.Use == "encryption" || kd.Use == "") && sp.EncryptionCert == nil {
				sp.EncryptionCert = der
			}
			if (kd.Use == "signing" || kd.Use == "") && sp.SigningCert == nil {
				sp.SigningCert = der
			}
		}
		// Single logout: HTTP-Redirect preferred (no extra click), else
		// HTTP-POST.
		for _, want := range SLOBindings {
			for _, e := range d.SingleLogoutServices {
				if sp.SLOURL == "" && e.Binding == want && ValidACS(e.Location) {
					sp.SLOURL, sp.SLOBinding = e.Location, e.Binding
				}
			}
		}
	}
	if len(sp.ACSURLs) == 0 {
		return nil, errors.New("samlidp: metadata has no HTTP-POST AssertionConsumerService")
	}
	return sp, nil
}

// ValidACS checks an ACS URL a registration may use: https, or http on a
// loopback host for local testing.
func ValidACS(s string) bool {
	u, err := url.Parse(s)
	if err != nil || u.Host == "" || u.User != nil || u.Fragment != "" {
		return false
	}
	if u.Scheme == "https" {
		return true
	}
	h := u.Hostname()
	return u.Scheme == "http" && (h == "localhost" || h == "127.0.0.1" || h == "::1")
}

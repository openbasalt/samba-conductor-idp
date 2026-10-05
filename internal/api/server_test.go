package api

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"image"
	"image/png"
	"math/big"
	"net"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/openbasalt/samba-conductor-ad/sid"
	"github.com/openbasalt/samba-conductor-idp/branding"
	"github.com/openbasalt/samba-conductor-idp/idpapi"
	"github.com/openbasalt/samba-conductor-idp/internal/config"
	"github.com/openbasalt/samba-conductor-idp/internal/directory"
	"github.com/openbasalt/samba-conductor-idp/internal/oidcp"
	"github.com/openbasalt/samba-conductor-idp/internal/samlidp"
	"github.com/openbasalt/samba-conductor-idp/internal/secret"
	"github.com/openbasalt/samba-conductor-idp/internal/store"
)

const domainSID = "S-1-5-21-1111-2222-3333"

func dsid(rid uint32) sid.SID {
	s, _ := sid.MustParse(domainSID).WithRID(rid)
	return s
}

var (
	sidUsers = dsid(513)
	sidEng   = dsid(1101)
)

type fakeDir struct{ users map[string]*directory.User }

func newFakeDir() *fakeDir {
	return &fakeDir{users: map[string]*directory.User{
		"alice": {GUID: "11111111-1111-4111-8111-111111111111", SID: dsid(2001), SAM: "alice", UPN: "alice@lab.test",
			Mail: "alice@lab.test", DisplayName: "Alice", GivenName: "Alice", Surname: "Tester", Enabled: true,
			GroupSIDs: []sid.SID{sidUsers, sidEng}},
		"bob": {GUID: "22222222-2222-4222-8222-222222222222", SID: dsid(2002), SAM: "bob", Enabled: true,
			GroupSIDs: []sid.SID{sidUsers}},
	}}
}

func (d *fakeDir) Realm() string                                      { return "LAB.TEST" }
func (d *fakeDir) Authenticate(context.Context, string, string) error { return nil }
func (d *fakeDir) ChangeExpiredPassword(context.Context, string, string, string) error {
	return nil
}
func (d *fakeDir) UserBySAM(_ context.Context, sam string) (*directory.User, error) {
	if u, ok := d.users[strings.ToLower(sam)]; ok {
		c := *u
		return &c, nil
	}
	return nil, directory.ErrNotFound
}
func (d *fakeDir) UserByGUID(context.Context, string) (*directory.User, error) {
	return nil, directory.ErrNotFound
}
func (d *fakeDir) GroupNames(_ context.Context, sids []sid.SID) (map[string]string, error) {
	names := map[string]string{sidUsers.String(): "Domain Users", sidEng.String(): "Engineering"}
	out := map[string]string{}
	for _, s := range sids {
		if n := names[s.String()]; n != "" {
			out[s.String()] = n
		}
	}
	return out, nil
}
func (d *fakeDir) DomainAdminsSID(context.Context) (sid.SID, error) { return dsid(512), nil }
func (d *fakeDir) GroupByName(_ context.Context, name string) (sid.SID, error) {
	if strings.EqualFold(name, "Engineering") {
		return sidEng, nil
	}
	return sid.SID{}, directory.ErrGroupNotFound
}

type rot struct {
	oidc *oidcp.KeyManager
	saml *samlidp.KeyManager
}

func (r rot) RotateOIDC(ctx context.Context) (string, error) { return r.oidc.Rotate(ctx) }
func (r rot) RotateSAML(ctx context.Context, immediate bool) (string, error) {
	return r.saml.Rotate(ctx, immediate)
}

type env struct {
	s       *Server
	st      *store.Store
	applied []idpapi.Settings
	// brandings are the versions applied to the web server.
	brandings []int64
	mu        sync.Mutex
}

func newEnv(t *testing.T) *env {
	t.Helper()
	ctx := context.Background()
	st, err := store.Open(ctx, ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	cfg := config.Default()
	cfg.Server.Issuer = "https://idp.lab.test"
	cfg.Server.TLSCert, cfg.Server.TLSKey = "/x/c", "/x/k"
	cfg.Domain.Realm, cfg.Domain.CAFile = "LAB.TEST", "/x/ca"
	cfg.ServiceAccount.Username = "svc"
	cfg.SAML.Enabled = true
	cfg.API.Enabled = true
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
	key := make([]byte, 32)
	box, err := secret.New(key)
	if err != nil {
		t.Fatal(err)
	}
	ok := &oidcp.KeyManager{Store: st, Box: box, RotateAfter: cfg.KeyRotateAfter(), Overlap: cfg.KeyOverlap()}
	sk := &samlidp.KeyManager{Store: st, Box: box, Subject: "idp.lab.test", Overlap: cfg.KeyOverlap()}
	if _, err := ok.Ensure(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := sk.Ensure(ctx); err != nil {
		t.Fatal(err)
	}
	dir := newFakeDir()
	idp := &samlidp.IdP{Store: st, Dir: dir, Keys: sk, BaseURL: cfg.Issuer(), AssertionTTL: 5 * time.Minute}
	e := &env{st: st}
	s, err := New(Options{Config: cfg, Store: st, Dir: dir, SAML: idp, SAMLKeys: sk, Keys: rot{ok, sk}, Version: "test",
		AllowedUIDs: []int{1234}, Apply: func(v idpapi.Settings) { e.mu.Lock(); e.applied = append(e.applied, v); e.mu.Unlock() },
		ApplyBranding: func(v int64, _ branding.Branding, _ time.Time, _ string, _ []store.BrandingAsset) {
			e.mu.Lock()
			e.brandings = append(e.brandings, v)
			e.mu.Unlock()
		}})
	if err != nil {
		t.Fatal(err)
	}
	e.s = s
	return e
}

var actor = idpapi.Actor{User: "admin", SID: dsid(500).String(), Session: "sess-0001", IP: "192.0.2.10"}

// call runs an operation and decodes the result into out.
func (e *env) call(t *testing.T, op idpapi.Op, p idpapi.Params, out any) *idpapi.Error {
	t.Helper()
	req, err := idpapi.NewRequest("req-00000001", op, actor, p)
	if err != nil {
		t.Fatalf("%s: %v", op, err)
	}
	resp := e.s.Handle(context.Background(), req)
	if !resp.OK {
		return resp.Error
	}
	if out != nil {
		if err := idpapi.DecodeResult(resp, out); err != nil {
			t.Fatalf("%s: decode: %v", op, err)
		}
	}
	return nil
}

func (e *env) must(t *testing.T, op idpapi.Op, p idpapi.Params, out any) {
	t.Helper()
	if err := e.call(t, op, p, out); err != nil {
		t.Fatalf("%s: %v %v", op, err, err.Details)
	}
}

func TestClientLifecycle(t *testing.T) {
	e := newEnv(t)
	in := idpapi.ClientInput{Name: "Grafana", Kind: "confidential", RedirectURIs: []string{"https://grafana.lab.test/login/generic_oauth"},
		Scopes: []string{"openid", "profile", "email", "groups"}, Groups: []string{sidEng.String()}, GroupsClaim: "names"}
	var created idpapi.ClientSecret
	e.must(t, idpapi.OpClientCreate, idpapi.ClientCreateParams{Input: in}, &created)
	if !strings.HasPrefix(created.Secret, "cidp_cs_") || created.Client.ID == "" || !created.Client.HasSecret {
		t.Fatalf("created %+v", created)
	}
	var list []idpapi.Client
	e.must(t, idpapi.OpClientList, nil, &list)
	if len(list) != 1 || list[0].Name != "Grafana" {
		t.Fatalf("list %+v", list)
	}
	// The secret is never returned again, by any read.
	var got idpapi.Client
	e.must(t, idpapi.OpClientGet, idpapi.ClientRef{ID: created.Client.ID}, &got)
	var rotated idpapi.ClientSecret
	e.must(t, idpapi.OpClientRotate, idpapi.ClientRef{ID: got.ID}, &rotated)
	if rotated.Secret == "" || rotated.Secret == created.Secret {
		t.Fatal("rotation did not give a new secret")
	}
	// Validation errors come back as details.
	bad := in
	bad.RedirectURIs = []string{"http://evil.example/cb"}
	err := e.call(t, idpapi.OpClientUpdate, idpapi.ClientUpdateParams{ID: got.ID, Input: bad}, nil)
	if err == nil || err.Code != idpapi.CodeInvalid || len(err.Details) == 0 {
		t.Fatalf("invalid update: %+v", err)
	}
	e.must(t, idpapi.OpClientEnable, idpapi.ClientEnableParams{ID: got.ID, Enabled: false}, &got)
	if got.Enabled {
		t.Fatal("still enabled")
	}
	// Claims preview: alice is in Engineering, bob is not.
	var pv idpapi.Preview
	e.must(t, idpapi.OpClientPreview, idpapi.ClientPreviewParams{ID: got.ID, Username: "alice"}, &pv)
	if !pv.Allowed || !hasValue(pv.Values, "groups", "Engineering") || !hasValue(pv.Values, "email", "alice@lab.test") {
		t.Fatalf("alice preview %+v", pv)
	}
	e.must(t, idpapi.OpClientPreview, idpapi.ClientPreviewParams{Input: &in, Username: "LAB\\bob"}, &pv)
	if pv.Allowed || pv.Reason == "" {
		t.Fatalf("bob preview %+v", pv)
	}
	if err := e.call(t, idpapi.OpClientPreview, idpapi.ClientPreviewParams{ID: got.ID, Username: "nobody"}, nil); err == nil || err.Code != idpapi.CodeNotFound {
		t.Fatalf("unknown user: %+v", err)
	}
	e.must(t, idpapi.OpClientDelete, idpapi.ClientRef{ID: got.ID}, nil)
	if err := e.call(t, idpapi.OpClientGet, idpapi.ClientRef{ID: got.ID}, nil); err == nil || err.Code != idpapi.CodeNotFound {
		t.Fatalf("after delete: %+v", err)
	}
	// Every mutation is audited with the conductor actor, never a secret.
	evs, _, err2 := e.st.ListAudit(context.Background(), store.AuditFilter{Action: "api."}, 0, 50)
	if err2 != nil {
		t.Fatal(err2)
	}
	var actions []string
	for _, ev := range evs {
		actions = append(actions, ev.Action+"/"+ev.Result)
		if ev.ActorName != "conductor:admin@192.0.2.10" {
			t.Fatalf("actor %q", ev.ActorName)
		}
		if strings.Contains(ev.Detail, created.Secret) || strings.Contains(ev.Detail, rotated.Secret) {
			t.Fatal("a client secret reached the audit log")
		}
	}
	for _, want := range []string{"api.client.create/ok", "api.client.rotate/ok", "api.client.update/failed", "api.client.set_enabled/ok", "api.client.delete/ok"} {
		if !slices.Contains(actions, want) {
			t.Fatalf("audit %v lacks %s", actions, want)
		}
	}
}

func hasValue(vs []idpapi.Value, name, v string) bool {
	for _, x := range vs {
		if x.Name == name && slices.Contains(x.Values, v) {
			return true
		}
	}
	return false
}

func testCert(t *testing.T) []byte {
	t.Helper()
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "sp.lab.test"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &k.PublicKey, k)
	if err != nil {
		t.Fatal(err)
	}
	return der
}

func TestSPMetadataAndLifecycle(t *testing.T) {
	e := newEnv(t)
	cert := base64.StdEncoding.EncodeToString(testCert(t))
	md := `<EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata" entityID="https://sp.lab.test/saml/metadata">
  <SPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
    <KeyDescriptor use="signing"><KeyInfo xmlns="http://www.w3.org/2000/09/xmldsig#"><X509Data><X509Certificate>` + cert + `</X509Certificate></X509Data></KeyInfo></KeyDescriptor>
    <SingleLogoutService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="https://sp.lab.test/saml/slo"/>
    <SingleLogoutService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="https://sp.lab.test/saml/slo"/>
    <NameIDFormat>urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress</NameIDFormat>
    <AssertionConsumerService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="https://sp.lab.test/saml/acs" index="1"/>
  </SPSSODescriptor>
</EntityDescriptor>`
	var d idpapi.SPDraft
	e.must(t, idpapi.OpSPMetadata, idpapi.SPMetadataParams{XML: md}, &d)
	if d.Input.EntityID != "https://sp.lab.test/saml/metadata" || d.Input.SLOURL != "https://sp.lab.test/saml/slo" ||
		d.Input.SLOBinding != idpapi.SLOBindings[0] || len(d.Input.SigningCert) == 0 || d.Input.NameIDSource != "email" {
		t.Fatalf("draft %+v", d.Input)
	}
	if !slices.Contains(d.Warnings, "no_encryption_cert") {
		t.Fatalf("warnings %v", d.Warnings)
	}
	in := d.Input
	in.Name = "Example SP"
	in.Groups = []string{"Engineering"}
	in.Attributes = []idpapi.Attribute{{Name: "groups", Source: "groups"}, {Name: "mail", Source: "email"}}
	var sp idpapi.SP
	e.must(t, idpapi.OpSPCreate, idpapi.SPCreateParams{Input: in}, &sp)
	if sp.SigningInfo == nil || sp.SigningInfo.SHA256 == "" || sp.Groups[0] != sidEng.String() {
		t.Fatalf("sp %+v", sp)
	}
	if err := e.call(t, idpapi.OpSPCreate, idpapi.SPCreateParams{Input: in}, nil); err == nil || err.Code != idpapi.CodeConflict {
		t.Fatalf("duplicate: %+v", err)
	}
	// An update without certificates keeps them; the clear flag removes.
	up := in
	up.SigningCert = nil
	up.Name = "Example SP 2"
	e.must(t, idpapi.OpSPUpdate, idpapi.SPUpdateParams{EntityID: sp.EntityID, Input: up}, &sp)
	if sp.Name != "Example SP 2" || sp.SigningInfo == nil {
		t.Fatalf("kept cert %+v", sp)
	}
	var cleared idpapi.SP
	e.must(t, idpapi.OpSPUpdate, idpapi.SPUpdateParams{EntityID: sp.EntityID, Input: up, ClearSigningCert: true}, &cleared)
	if cleared.SigningInfo != nil || len(cleared.SigningCert) != 0 {
		t.Fatal("signing certificate not cleared")
	}
	var pv idpapi.Preview
	e.must(t, idpapi.OpSPPreview, idpapi.SPPreviewParams{EntityID: sp.EntityID, Username: "alice"}, &pv)
	if !pv.Allowed || pv.NameID != "alice@lab.test" || !hasValue(pv.Values, "groups", "Engineering") {
		t.Fatalf("preview %+v", pv)
	}
	e.must(t, idpapi.OpSPPreview, idpapi.SPPreviewParams{EntityID: sp.EntityID, Username: "bob"}, &pv)
	if pv.Allowed {
		t.Fatal("bob allowed")
	}
	bad := in
	bad.SLOURL = "ftp://sp.lab.test/slo"
	if err := e.call(t, idpapi.OpSPUpdate, idpapi.SPUpdateParams{EntityID: sp.EntityID, Input: bad}, nil); err == nil || err.Code != idpapi.CodeInvalid {
		t.Fatalf("bad SLO URL: %+v", err)
	}
	e.must(t, idpapi.OpSPDelete, idpapi.SPRef{EntityID: sp.EntityID}, nil)
}

func TestPresetsAreValid(t *testing.T) {
	e := newEnv(t)
	vals := map[string]string{"domain": "example.com", "base_url": "https://app.lab.test", "redirect_uri": "https://app.lab.test/cb"}
	for _, p := range idpapi.Presets {
		switch p.Kind {
		case idpapi.KindOIDC:
			in, err := p.Client(vals)
			if err != nil {
				t.Fatalf("%s: %v", p.ID, err)
			}
			in.AllowAllUsers = true
			if err := e.call(t, idpapi.OpClientCreate, idpapi.ClientCreateParams{Input: in}, nil); err != nil {
				t.Fatalf("%s: %v %v", p.ID, err, err.Details)
			}
		case idpapi.KindSAML:
			in, err := p.SP(vals)
			if err != nil {
				t.Fatalf("%s: %v", p.ID, err)
			}
			if p.ID == "generic-saml" {
				in.EntityID, in.ACSURLs = "https://generic.lab.test", []string{"https://generic.lab.test/acs"}
			}
			in.AllowAllUsers = true
			if err := e.call(t, idpapi.OpSPCreate, idpapi.SPCreateParams{Input: in}, nil); err != nil {
				t.Fatalf("%s: %v %v", p.ID, err, err.Details)
			}
		}
	}
	if _, err := idpapi.Presets[0].SP(map[string]string{"domain": "not a domain"}); err == nil {
		t.Fatal("bad domain accepted")
	}
	if _, err := idpapi.Presets[1].Client(map[string]string{"base_url": "http://grafana.lab.test"}); err == nil {
		t.Fatal("plain http base URL accepted")
	}
}

// TestVocabulary keeps the lists conductor's forms use in sync with what
// the registry accepts.
func TestVocabulary(t *testing.T) {
	if !slices.Equal(idpapi.Scopes, oidcp.SupportedScopes) {
		t.Fatalf("scopes %v vs %v", idpapi.Scopes, oidcp.SupportedScopes)
	}
	if !slices.Equal(idpapi.NameIDFormats, samlidp.NameIDFormats) || !slices.Equal(idpapi.NameIDSources, samlidp.NameIDSources) ||
		!slices.Equal(idpapi.Sources, samlidp.Sources) || !slices.Equal(idpapi.SLOBindings, samlidp.SLOBindings) {
		t.Fatal("SAML vocabulary differs")
	}
	if !slices.Equal(idpapi.ClientKinds, []string{store.ClientConfidential, store.ClientPublic}) ||
		!slices.Equal(idpapi.GroupsClaims, []string{store.GroupsNone, store.GroupsNames, store.GroupsSIDs}) ||
		!slices.Equal(idpapi.MFAPolicies, []string{config.MFAOff, config.MFAOptional, config.MFARequired}) {
		t.Fatal("client vocabulary differs")
	}
}

func TestSettings(t *testing.T) {
	e := newEnv(t)
	var v idpapi.SettingsView
	e.must(t, idpapi.OpSettingsGet, nil, &v)
	if v.Version != 0 || v.Settings.SessionIdleMinutes != 60 || v.MFAPolicyShared {
		t.Fatalf("defaults %+v", v)
	}
	next := v.Settings
	next.SessionIdleMinutes = 30
	next.ConsentText = map[string]string{"en": "Company data stays here.", "pt-BR": "  "}
	e.must(t, idpapi.OpSettingsUpdate, idpapi.SettingsUpdateParams{BaseVersion: 0, Settings: next}, &v)
	if v.Version != 1 || v.Settings.SessionIdleMinutes != 30 || len(v.Settings.ConsentText) != 1 {
		t.Fatalf("saved %+v", v)
	}
	if len(e.applied) != 1 || e.applied[0].SessionIdleMinutes != 30 {
		t.Fatalf("applied %+v", e.applied)
	}
	// A stale editor gets a conflict.
	if err := e.call(t, idpapi.OpSettingsUpdate, idpapi.SettingsUpdateParams{BaseVersion: 0, Settings: next}, nil); err == nil || err.Code != idpapi.CodeConflict {
		t.Fatalf("stale: %+v", err)
	}
	next.SessionAbsoluteHours = 99
	if _, err := idpapi.NewRequest("req-00000003", idpapi.OpSettingsUpdate, actor, idpapi.SettingsUpdateParams{BaseVersion: 1, Settings: next}); err == nil {
		t.Fatal("out of range accepted")
	}
}

func testPNG(w, h int) []byte {
	var buf bytes.Buffer
	_ = png.Encode(&buf, image.NewRGBA(image.Rect(0, 0, w, h)))
	return buf.Bytes()
}

// TestBranding: conductor pushes a branding (document and images); the
// idp stores it, applies it, returns it and audits the change with the
// acting administrator. A later push replaces it, images included.
func TestBranding(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	var v idpapi.BrandingView
	e.must(t, idpapi.OpBrandingGet, nil, &v)
	if v.Version != 0 || !v.Branding.IsZero() {
		t.Fatalf("initial %+v", v)
	}
	logo := testPNG(80, 20)
	meta, err := branding.Inspect(branding.SlotLogoLight, logo)
	if err != nil {
		t.Fatal(err)
	}
	doc := branding.Branding{OrgName: "Example Org", PrimaryColor: "#1d4ed8", Texts: map[string]branding.Texts{"en": {Notice: "Maintenance"}},
		Assets: map[string]branding.Asset{branding.SlotLogoLight: meta}}
	e.must(t, idpapi.OpBrandingUpdate, idpapi.BrandingUpdateParams{Version: 3, Branding: doc,
		Assets: []idpapi.BrandingAsset{{SHA256: meta.SHA256, Data: logo}}}, &v)
	if v.Version != 3 || v.Branding.OrgName != "Example Org" || v.UpdatedBy != "conductor" || len(e.brandings) != 1 {
		t.Fatalf("updated %+v %v", v, e.brandings)
	}
	assets, _ := e.st.BrandingAssets(ctx)
	if len(assets) != 1 || assets[0].ContentType != branding.TypePNG || !bytes.Equal(assets[0].Data, logo) {
		t.Fatalf("assets %+v", assets)
	}
	evs, _, _ := e.st.ListAudit(ctx, store.AuditFilter{Action: "api.branding.update"}, 0, 5)
	if len(evs) != 1 || !strings.Contains(evs[0].Detail, "version=3") || !strings.Contains(evs[0].ActorName, "conductor:admin") {
		t.Fatalf("audit %+v", evs)
	}
	// A revert in conductor is a new version without the image: the idp
	// drops it.
	e.must(t, idpapi.OpBrandingUpdate, idpapi.BrandingUpdateParams{Version: 4, Branding: branding.Branding{OrgName: "Example"}}, &v)
	if assets, _ = e.st.BrandingAssets(ctx); len(assets) != 0 || v.Version != 4 {
		t.Fatalf("after revert %+v %+v", v, assets)
	}
	// Invalid documents never reach the store.
	bad := doc
	bad.Links.Help = "javascript:alert(1)"
	if _, err := idpapi.NewRequest("req-00000005", idpapi.OpBrandingUpdate, actor, idpapi.BrandingUpdateParams{Version: 5, Branding: bad,
		Assets: []idpapi.BrandingAsset{{SHA256: meta.SHA256, Data: logo}}}); err == nil {
		t.Fatal("javascript: link accepted")
	}
	e.must(t, idpapi.OpBrandingGet, nil, &v)
	if v.Version != 4 {
		t.Fatalf("after refused update %+v", v)
	}
}

func TestKeysAndActivity(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	var k idpapi.Keys
	e.must(t, idpapi.OpKeysList, nil, &k)
	if len(k.OIDC) != 1 || !k.OIDC[0].Signing || len(k.SAML) != 1 || k.SAML[0].Cert == nil || k.NextOIDCRotation.IsZero() {
		t.Fatalf("keys %+v", k)
	}
	var rot idpapi.KeyRotated
	e.must(t, idpapi.OpKeysRotate, idpapi.KeysRotateParams{Purpose: idpapi.KeySAML}, &rot)
	e.must(t, idpapi.OpKeysList, nil, &k)
	// Staged: the old key still signs, the new one is published.
	if len(k.SAML) != 2 || k.SAML[0].ID != rot.ID || k.SAML[0].Signing || !k.SAML[1].Signing || k.SAMLSwitchAt.IsZero() {
		t.Fatalf("staged %+v", k.SAML)
	}
	var cert idpapi.CertPEM
	e.must(t, idpapi.OpKeysCert, idpapi.KeysCertParams(rot), &cert)
	if !strings.HasPrefix(cert.PEM, "-----BEGIN CERTIFICATE-----") || cert.ID != rot.ID {
		t.Fatalf("cert %+v", cert)
	}
	if _, err := idpapi.NewRequest("req-00000004", idpapi.OpKeysRotate, actor, idpapi.KeysRotateParams{Purpose: idpapi.KeyOIDC, Immediate: true}); err == nil {
		t.Fatal("immediate OIDC rotation accepted")
	}
	for _, ev := range []store.AuditEvent{
		{ActorName: "alice", Action: "signin.password", Result: store.ResultOK},
		{ActorName: "alice", Action: "oidc.authorize", Target: "cidp_x", Result: store.ResultOK},
		{ActorName: "carol", Action: "oidc.authorize", Target: "cidp_x", Result: store.ResultOK},
		{ActorName: "bob", Action: "oidc.authorize", Target: "cidp_x", Result: store.ResultDenied},
		{ActorName: "alice", Action: "saml.sso", Target: "https://sp", Result: store.ResultOK},
		{ActorName: "dave", Action: "signin.failure", Target: "dave", Detail: "reason=account locked code=775", Result: store.ResultDenied},
		{ActorName: "erin", Action: "signin.failure", Target: "erin", Detail: "reason=invalid credentials code=52e", Result: store.ResultDenied},
		{ActorName: "erin", Action: "mfa.failure", Result: store.ResultDenied},
	} {
		if _, err := e.st.AppendAudit(ctx, ev); err != nil {
			t.Fatal(err)
		}
	}
	var a idpapi.Activity
	e.must(t, idpapi.OpActivity, idpapi.ActivityParams{Days: 7}, &a)
	if a.SignIns != 1 || a.Failures != 2 || a.Lockouts != 1 || a.MFAFailures != 1 || len(a.Apps) != 2 {
		t.Fatalf("activity %+v", a)
	}
	if a.Apps[0].ID != "cidp_x" || a.Apps[0].SignIns != 2 || a.Apps[0].Users != 2 || a.Apps[0].Denied != 1 {
		t.Fatalf("apps %+v", a.Apps)
	}
	if len(a.Recent) == 0 {
		t.Fatal("no recent refusals")
	}
	var page idpapi.AuditPage
	e.must(t, idpapi.OpAuditList, idpapi.AuditListParams{Action: "oidc.", Limit: 2}, &page)
	if len(page.Events) != 2 || !page.More {
		t.Fatalf("page %+v", page)
	}
	var vr idpapi.AuditVerify
	e.must(t, idpapi.OpAuditVerify, nil, &vr)
	if vr.BrokenAt != 0 || vr.Rows == 0 {
		t.Fatalf("verify %+v", vr)
	}
}

func TestSocketAdmitsOnlyAllowedPeers(t *testing.T) {
	e := newEnv(t)
	path := filepath.Join(t.TempDir(), "api.sock")
	ln, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	e.s.ln = ln
	var peer atomic.Int64
	peer.Store(9999)
	e.s.peerCred = func(*net.UnixConn) (int, error) { return int(peer.Load()), nil }
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = e.s.Serve(ctx) }()
	req, _ := idpapi.NewRequest("req-00000002", idpapi.OpStatus, actor, nil)
	if _, err := idpapi.Call(ctx, path, req); err == nil {
		t.Fatal("a peer that is not allowed was served")
	}
	peer.Store(1234)
	resp, err := idpapi.Call(ctx, path, req)
	if err != nil {
		t.Fatal(err)
	}
	var st idpapi.Status
	if err := idpapi.DecodeResult(resp, &st); err != nil || !st.SAMLEnabled || st.Issuer != "https://idp.lab.test" {
		t.Fatalf("status %+v %v", st, err)
	}
	// A malformed request gets a typed error, not a hang.
	c, err := net.Dial("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = c.Write([]byte("{not json\n"))
	var r idpapi.Response
	if err := idpapi.ReadMessage(bufio.NewReader(c), &r); err != nil || r.OK || r.Error.Code != idpapi.CodeBadRequest {
		t.Fatalf("malformed: %+v %v", r, err)
	}
	_ = c.Close()
}

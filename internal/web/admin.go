package web

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/openbasalt/samba-conductor-ad/sid"
	"github.com/openbasalt/samba-conductor-idp/internal/directory"
	"github.com/openbasalt/samba-conductor-idp/internal/oidcp"
	"github.com/openbasalt/samba-conductor-idp/internal/registry"
	"github.com/openbasalt/samba-conductor-idp/internal/samlidp"
	"github.com/openbasalt/samba-conductor-idp/internal/secret"
	"github.com/openbasalt/samba-conductor-idp/internal/store"
)

// Admin pages are deliberately small: register and maintain clients and
// service providers, rotate keys, reset 2FA, read the audit log. Every
// change is audited with the administrator as actor.

// lines splits a textarea into trimmed, non-empty lines.
func lines(v string) []string {
	var out []string
	for _, l := range strings.Split(v, "\n") {
		if l = strings.TrimSpace(l); l != "" {
			out = append(out, l)
		}
	}
	return out
}

func (rc *reqCtx) checked(name string) bool { return rc.r.PostFormValue(name) == "1" }

func parseSIDs(in []string) []sid.SID {
	var out []sid.SID
	for _, v := range in {
		if s, err := sid.Parse(v); err == nil {
			out = append(out, s)
		}
	}
	return out
}

// groupLabels renders SIDs with their names for display.
func (s *Server) groupLabels(ctx context.Context, sids []string) []string {
	parsed := parseSIDs(sids)
	names, _ := s.dir.GroupNames(ctx, parsed)
	out := make([]string, len(sids))
	for i, v := range sids {
		if n := names[v]; n != "" {
			out[i] = n + " (" + v + ")"
		} else {
			out[i] = v
		}
	}
	return out
}

func (s *Server) adminData(rc *reqCtx, tab string, d map[string]any) map[string]any {
	if d == nil {
		d = map[string]any{}
	}
	d["Tab"] = tab
	d["SAML"] = s.saml != nil
	return d
}

// ---- clients ----

func (s *Server) handleAdminClients(rc *reqCtx) {
	clients, err := s.store.ListClients(rc.ctx())
	if err != nil {
		rc.errorPage(http.StatusInternalServerError, "err.internal")
		return
	}
	rc.render(http.StatusOK, "admin_clients", s.adminData(rc, "clients", map[string]any{"Clients": clients}))
}

type clientForm struct {
	Name, Kind, Redirects, PostLogout, Groups, GroupsClaim, GroupsFilter string
	Scopes                                                               []string
	AllowAll, FirstParty, RequireMFA                                     bool
}

func (rc *reqCtx) clientInput() (registry.ClientInput, clientForm) {
	_ = rc.r.ParseForm()
	f := clientForm{Name: rc.form("name"), Kind: rc.form("kind"), Redirects: rc.form("redirect_uris"),
		PostLogout: rc.form("post_logout_uris"), Groups: rc.form("groups"), GroupsClaim: rc.form("groups_claim"),
		GroupsFilter: rc.form("groups_filter"), Scopes: rc.r.PostForm["scopes"], AllowAll: rc.checked("allow_all"),
		FirstParty: rc.checked("first_party"), RequireMFA: rc.checked("require_mfa")}
	return registry.ClientInput{Name: f.Name, Kind: f.Kind, RedirectURIs: lines(f.Redirects), PostLogoutURIs: lines(f.PostLogout),
		Scopes: f.Scopes, Groups: lines(f.Groups), AllowAllUsers: f.AllowAll, FirstParty: f.FirstParty,
		GroupsClaim: f.GroupsClaim, GroupsFilter: lines(f.GroupsFilter), RequireMFA: f.RequireMFA}, f
}

func (s *Server) clientFormData(rc *reqCtx, f clientForm, errMsg string, editing *store.Client) map[string]any {
	return s.adminData(rc, "clients", map[string]any{"F": f, "Error": errMsg, "AllScopes": oidcp.SupportedScopes[1:], "Client": editing})
}

func (s *Server) handleAdminClientNew(rc *reqCtx) {
	f := clientForm{Kind: store.ClientConfidential, GroupsClaim: store.GroupsNone, Scopes: []string{"profile", "email"}}
	rc.render(http.StatusOK, "admin_client_form", s.clientFormData(rc, f, "", nil))
}

func (s *Server) handleAdminClientCreate(rc *reqCtx) {
	ctx, cancel := context.WithTimeout(rc.ctx(), requestTimeout)
	defer cancel()
	in, f := rc.clientInput()
	c, plain, err := registry.CreateClient(ctx, s.store, s.dir, in)
	if err != nil {
		rc.render(http.StatusBadRequest, "admin_client_form", s.clientFormData(rc, f, err.Error(), nil))
		return
	}
	s.audit(ctx, rc, "admin.client_create", c.ID, "name="+c.Name+" kind="+c.Kind+" redirects="+strings.Join(c.RedirectURIs, " "), store.ResultOK)
	rc.render(http.StatusOK, "admin_client_secret", s.adminData(rc, "clients", map[string]any{"Client": c, "Secret": plain, "Created": true}))
}

func (s *Server) clientByPath(rc *reqCtx) (*store.Client, bool) {
	c, err := s.store.GetClient(rc.ctx(), rc.r.PathValue("id"))
	if err != nil {
		rc.errorPage(http.StatusNotFound, "err.not_found")
		return nil, false
	}
	return c, true
}

func (s *Server) handleAdminClient(rc *reqCtx) {
	c, ok := s.clientByPath(rc)
	if !ok {
		return
	}
	ctx := rc.ctx()
	f := clientForm{Name: c.Name, Kind: c.Kind, Redirects: strings.Join(c.RedirectURIs, "\n"), PostLogout: strings.Join(c.PostLogoutURIs, "\n"),
		Groups: strings.Join(c.AllowedGroups, "\n"), GroupsClaim: c.GroupsClaim, GroupsFilter: strings.Join(c.GroupsFilter, "\n"),
		Scopes: c.Scopes, AllowAll: c.AllowAllUsers, FirstParty: c.FirstParty, RequireMFA: c.RequireMFA}
	d := s.clientFormData(rc, f, "", c)
	d["GroupLabels"] = s.groupLabels(ctx, c.AllowedGroups)
	d["Issuer"] = s.cfg.Issuer()
	rc.render(http.StatusOK, "admin_client", d)
}

func (s *Server) handleAdminClientUpdate(rc *reqCtx) {
	ctx, cancel := context.WithTimeout(rc.ctx(), requestTimeout)
	defer cancel()
	c, ok := s.clientByPath(rc)
	if !ok {
		return
	}
	in, f := rc.clientInput()
	f.Kind = c.Kind
	updated, err := registry.UpdateClient(ctx, s.store, s.dir, c.ID, in)
	if err != nil {
		d := s.clientFormData(rc, f, err.Error(), c)
		d["Issuer"] = s.cfg.Issuer()
		rc.render(http.StatusBadRequest, "admin_client", d)
		return
	}
	s.audit(ctx, rc, "admin.client_update", c.ID, "redirects="+strings.Join(updated.RedirectURIs, " ")+" groups="+strings.Join(updated.AllowedGroups, ",")+
		" scopes="+strings.Join(updated.Scopes, ","), store.ResultOK)
	rc.flashOK("admin.saved")
	rc.redirect("/admin/clients/" + url.PathEscape(c.ID))
}

func (s *Server) handleAdminClientRotate(rc *reqCtx) {
	c, ok := s.clientByPath(rc)
	if !ok {
		return
	}
	plain, err := registry.RotateSecret(rc.ctx(), s.store, c.ID)
	if err != nil {
		rc.errorPage(http.StatusBadRequest, "err.forbidden")
		return
	}
	s.audit(rc.ctx(), rc, "admin.client_rotate_secret", c.ID, "", store.ResultOK)
	rc.render(http.StatusOK, "admin_client_secret", s.adminData(rc, "clients", map[string]any{"Client": c, "Secret": plain}))
}

func (s *Server) handleAdminClientToggle(rc *reqCtx) {
	c, ok := s.clientByPath(rc)
	if !ok {
		return
	}
	c.Enabled = !c.Enabled
	if err := s.store.UpdateClient(rc.ctx(), c); err != nil {
		rc.errorPage(http.StatusInternalServerError, "err.internal")
		return
	}
	detail := "enabled"
	if !c.Enabled {
		detail = "disabled"
	}
	s.audit(rc.ctx(), rc, "admin.client_toggle", c.ID, detail, store.ResultOK)
	rc.flashOK("admin.saved")
	rc.redirect("/admin/clients/" + url.PathEscape(c.ID))
}

func (s *Server) handleAdminClientDelete(rc *reqCtx) {
	c, ok := s.clientByPath(rc)
	if !ok {
		return
	}
	if rc.form("confirm") != c.ID {
		rc.flashErr("admin.confirm_mismatch")
		rc.redirect("/admin/clients/" + url.PathEscape(c.ID))
		return
	}
	if err := s.store.DeleteClient(rc.ctx(), c.ID); err != nil {
		rc.errorPage(http.StatusInternalServerError, "err.internal")
		return
	}
	s.audit(rc.ctx(), rc, "admin.client_delete", c.ID, "name="+c.Name, store.ResultOK)
	rc.flashOK("admin.deleted")
	rc.redirect("/admin/clients")
}

func (rc *reqCtx) flashErr(key string, args ...any) {
	if rc.sess != nil {
		rc.sess.addFlash("error", rc.T(key, args...))
	}
}

// ---- SAML service providers ----

type spForm struct {
	EntityID, Name, ACS, NameIDFormat, NameIDSource, Attributes, Groups, DefaultRelay, Metadata string
	AllowAll, Encrypt, IdPInitiated, RequireMFA, HasCert                                        bool
}

func (s *Server) handleAdminSPs(rc *reqCtx) {
	sps, err := s.store.ListSPs(rc.ctx())
	if err != nil {
		rc.errorPage(http.StatusInternalServerError, "err.internal")
		return
	}
	rc.render(http.StatusOK, "admin_sps", s.adminData(rc, "saml", map[string]any{"SPs": sps, "MetadataURL": s.saml.EntityID(),
		"SSOURL": s.saml.SSOURL()}))
}

func (s *Server) spFormData(rc *reqCtx, f spForm, errMsg string, editing *store.SAMLSP) map[string]any {
	return s.adminData(rc, "saml", map[string]any{"F": f, "Error": errMsg, "Formats": samlidp.NameIDFormats,
		"NameIDSources": samlidp.NameIDSources, "Sources": samlidp.Sources, "SP": editing})
}

func (s *Server) handleAdminSPNew(rc *reqCtx) {
	f := spForm{NameIDFormat: samlidp.NameIDEmail, NameIDSource: samlidp.SourceEmail}
	rc.render(http.StatusOK, "admin_sp_form", s.spFormData(rc, f, "", nil))
}

func (rc *reqCtx) spInput(existing *store.SAMLSP) (registry.SPInput, spForm, error) {
	f := spForm{EntityID: rc.form("entity_id"), Name: rc.form("name"), ACS: rc.form("acs_urls"), NameIDFormat: rc.form("nameid_format"),
		NameIDSource: rc.form("nameid_source"), Attributes: rc.form("attributes"), Groups: rc.form("groups"),
		DefaultRelay: rc.form("default_relay"), Metadata: rc.form("metadata"), AllowAll: rc.checked("allow_all"),
		Encrypt: rc.checked("encrypt"), IdPInitiated: rc.checked("idp_initiated"), RequireMFA: rc.checked("require_mfa")}
	var cert []byte
	if existing != nil {
		f.EntityID = existing.EntityID
		cert = existing.EncryptionCert
	}
	if f.Metadata != "" {
		draft, err := samlidp.ParseSPMetadata([]byte(f.Metadata))
		if err != nil {
			return registry.SPInput{}, f, err
		}
		if existing != nil && draft.EntityID != existing.EntityID {
			return registry.SPInput{}, f, errors.New("the metadata is for another entity ID")
		}
		f.EntityID = draft.EntityID
		if f.ACS == "" {
			f.ACS = strings.Join(draft.ACSURLs, "\n")
		}
		cert = draft.EncryptionCert
	}
	f.HasCert = len(cert) > 0
	attrs, err := registry.ParseAttributes(lines(f.Attributes))
	if err != nil {
		return registry.SPInput{}, f, err
	}
	return registry.SPInput{EntityID: f.EntityID, Name: f.Name, ACSURLs: lines(f.ACS), NameIDFormat: f.NameIDFormat,
		NameIDSource: f.NameIDSource, Attributes: attrs, Groups: lines(f.Groups), AllowAllUsers: f.AllowAll,
		EncryptAssertion: f.Encrypt, EncryptionCert: cert, IdPInitiated: f.IdPInitiated, DefaultRelay: f.DefaultRelay,
		RequireMFA: f.RequireMFA}, f, nil
}

func (s *Server) handleAdminSPCreate(rc *reqCtx) {
	ctx, cancel := context.WithTimeout(rc.ctx(), requestTimeout)
	defer cancel()
	in, f, err := rc.spInput(nil)
	if err == nil {
		var sp *store.SAMLSP
		sp, err = registry.BuildSP(ctx, s.dir, in)
		if err == nil {
			err = s.store.CreateSP(ctx, sp)
			if errors.Is(err, store.ErrConflict) {
				err = errors.New("this entity ID is already registered")
			}
		}
	}
	if err != nil {
		f.Metadata = ""
		rc.render(http.StatusBadRequest, "admin_sp_form", s.spFormData(rc, f, err.Error(), nil))
		return
	}
	s.audit(ctx, rc, "admin.sp_create", in.EntityID, "name="+in.Name+" acs="+strings.Join(in.ACSURLs, " "), store.ResultOK)
	rc.flashOK("admin.saved")
	rc.redirect("/admin/saml/sp?id=" + url.QueryEscape(in.EntityID))
}

func (s *Server) spByQuery(rc *reqCtx) (*store.SAMLSP, bool) {
	id := rc.r.URL.Query().Get("id")
	if rc.r.Method == http.MethodPost {
		id = rc.form("id")
	}
	sp, err := s.store.GetSP(rc.ctx(), id)
	if err != nil {
		rc.errorPage(http.StatusNotFound, "err.not_found")
		return nil, false
	}
	return sp, true
}

func spToForm(sp *store.SAMLSP) spForm {
	return spForm{EntityID: sp.EntityID, Name: sp.Name, ACS: strings.Join(sp.ACSURLs, "\n"), NameIDFormat: sp.NameIDFormat,
		NameIDSource: sp.NameIDSource, Attributes: strings.Join(registry.FormatAttributes(sp.Attributes), "\n"),
		Groups: strings.Join(sp.AllowedGroups, "\n"), DefaultRelay: sp.DefaultRelay, AllowAll: sp.AllowAllUsers,
		Encrypt: sp.EncryptAssertion, IdPInitiated: sp.IdPInitiated, RequireMFA: sp.RequireMFA, HasCert: len(sp.EncryptionCert) > 0}
}

func (s *Server) handleAdminSP(rc *reqCtx) {
	sp, ok := s.spByQuery(rc)
	if !ok {
		return
	}
	d := s.spFormData(rc, spToForm(sp), "", sp)
	d["GroupLabels"] = s.groupLabels(rc.ctx(), sp.AllowedGroups)
	rc.render(http.StatusOK, "admin_sp", d)
}

func (s *Server) handleAdminSPUpdate(rc *reqCtx) {
	ctx, cancel := context.WithTimeout(rc.ctx(), requestTimeout)
	defer cancel()
	sp, ok := s.spByQuery(rc)
	if !ok {
		return
	}
	in, f, err := rc.spInput(sp)
	var updated *store.SAMLSP
	if err == nil {
		updated, err = registry.BuildSP(ctx, s.dir, in)
	}
	if err == nil {
		updated.Enabled = sp.Enabled
		err = s.store.UpdateSP(ctx, updated)
	}
	if err != nil {
		f.Metadata = ""
		rc.render(http.StatusBadRequest, "admin_sp", s.spFormData(rc, f, err.Error(), sp))
		return
	}
	s.audit(ctx, rc, "admin.sp_update", sp.EntityID, "acs="+strings.Join(updated.ACSURLs, " ")+" groups="+strings.Join(updated.AllowedGroups, ","), store.ResultOK)
	rc.flashOK("admin.saved")
	rc.redirect("/admin/saml/sp?id=" + url.QueryEscape(sp.EntityID))
}

func (s *Server) handleAdminSPToggle(rc *reqCtx) {
	sp, ok := s.spByQuery(rc)
	if !ok {
		return
	}
	sp.Enabled = !sp.Enabled
	if err := s.store.UpdateSP(rc.ctx(), sp); err != nil {
		rc.errorPage(http.StatusInternalServerError, "err.internal")
		return
	}
	detail := "enabled"
	if !sp.Enabled {
		detail = "disabled"
	}
	s.audit(rc.ctx(), rc, "admin.sp_toggle", sp.EntityID, detail, store.ResultOK)
	rc.flashOK("admin.saved")
	rc.redirect("/admin/saml/sp?id=" + url.QueryEscape(sp.EntityID))
}

func (s *Server) handleAdminSPDelete(rc *reqCtx) {
	sp, ok := s.spByQuery(rc)
	if !ok {
		return
	}
	if rc.form("confirm") != sp.EntityID {
		rc.flashErr("admin.confirm_mismatch")
		rc.redirect("/admin/saml/sp?id=" + url.QueryEscape(sp.EntityID))
		return
	}
	if err := s.store.DeleteSP(rc.ctx(), sp.EntityID); err != nil {
		rc.errorPage(http.StatusInternalServerError, "err.internal")
		return
	}
	s.audit(rc.ctx(), rc, "admin.sp_delete", sp.EntityID, "name="+sp.Name, store.ResultOK)
	rc.flashOK("admin.deleted")
	rc.redirect("/admin/saml")
}

// ---- keys ----

type keyRow struct {
	ID       string
	Purpose  string
	Created  time.Time
	RetireAt time.Time
	Signing  bool
}

func (s *Server) handleAdminKeys(rc *reqCtx) {
	ctx := rc.ctx()
	var rows []keyRow
	for _, p := range []string{store.KeyOIDC, store.KeySAML} {
		if p == store.KeySAML && s.saml == nil {
			continue
		}
		keys, err := s.store.ListSigningKeys(ctx, p, s.now())
		if err != nil {
			rc.errorPage(http.StatusInternalServerError, "err.internal")
			return
		}
		for i, k := range keys {
			signing := i == 0
			if p == store.KeySAML {
				signing = i == len(keys)-1
			}
			rows = append(rows, keyRow{ID: k.ID, Purpose: p, Created: k.CreatedAt, RetireAt: k.RetireAt, Signing: signing})
		}
	}
	rc.render(http.StatusOK, "admin_keys", s.adminData(rc, "keys", map[string]any{"Keys": rows,
		"RotateDays": s.cfg.Keys.RotateDays, "OverlapHours": s.cfg.Keys.OverlapHours}))
}

// KeyRotator rotates keys (the OIDC and SAML key managers).
type KeyRotator interface {
	RotateOIDC(ctx context.Context) (string, error)
	RotateSAML(ctx context.Context, immediate bool) (string, error)
}

func (s *Server) handleAdminKeysRotate(rc *reqCtx) {
	ctx := rc.ctx()
	purpose := rc.form("purpose")
	var id string
	var err error
	switch {
	case purpose == store.KeyOIDC && s.keys != nil:
		id, err = s.keys.RotateOIDC(ctx)
	case purpose == store.KeySAML && s.keys != nil && s.saml != nil:
		id, err = s.keys.RotateSAML(ctx, rc.checked("immediate"))
	default:
		rc.errorPage(http.StatusBadRequest, "err.not_found")
		return
	}
	if err != nil {
		s.log.Error("key rotation failed", "purpose", purpose, "err", err)
		rc.errorPage(http.StatusInternalServerError, "err.internal")
		return
	}
	s.audit(ctx, rc, "admin.key_rotate", purpose, "new key "+id, store.ResultOK)
	rc.flashOK("admin.key_rotated")
	rc.redirect("/admin/keys")
}

// ---- users: 2FA reset and enrollment links ----

func (s *Server) handleAdminUsers(rc *reqCtx) {
	rc.render(http.StatusOK, "admin_users", s.adminData(rc, "users", map[string]any{"Local": s.local != nil}))
}

func (s *Server) adminUser(rc *reqCtx) (*directory.User, bool) {
	sam, ok := directory.NormalizeUsername(rc.form("username"), s.dir.Realm())
	if !ok {
		rc.flashErr("admin.user_not_found")
		rc.redirect("/admin/users")
		return nil, false
	}
	u, err := s.dir.UserBySAM(rc.ctx(), sam)
	if err != nil {
		rc.flashErr("admin.user_not_found")
		rc.redirect("/admin/users")
		return nil, false
	}
	return u, true
}

func (s *Server) handleAdminMFAReset(rc *reqCtx) {
	if s.local == nil {
		rc.errorPage(http.StatusNotFound, "err.not_found")
		return
	}
	u, ok := s.adminUser(rc)
	if !ok {
		return
	}
	removed, err := s.local.Reset(rc.ctx(), u.GUID)
	if err != nil {
		rc.errorPage(http.StatusInternalServerError, "err.internal")
		return
	}
	n := s.sess.destroyUser(u.GUID)
	s.audit(rc.ctx(), rc, "admin.mfa_reset", u.SAM, "removed="+boolStr(removed)+" sessions_ended="+strconv.Itoa(n), store.ResultOK)
	if removed {
		rc.flashOK("admin.mfa_reset_done", u.SAM)
	} else {
		rc.flashOK("admin.mfa_reset_none", u.SAM)
	}
	rc.redirect("/admin/users")
}

// EnrollLinkTTL is how long an administrator enrollment link works.
const EnrollLinkTTL = 24 * time.Hour

func (s *Server) handleAdminEnrollLink(rc *reqCtx) {
	if s.local == nil {
		rc.errorPage(http.StatusNotFound, "err.not_found")
		return
	}
	u, ok := s.adminUser(rc)
	if !ok {
		return
	}
	tok := secret.Token("")
	rc.sess.mu.Lock()
	by := rc.sess.sam
	rc.sess.mu.Unlock()
	if err := s.store.CreateEnrollLink(rc.ctx(), LinkHash(tok), strings.ToLower(u.SAM), by, EnrollLinkTTL); err != nil {
		rc.errorPage(http.StatusInternalServerError, "err.internal")
		return
	}
	s.audit(rc.ctx(), rc, "admin.enroll_link", u.SAM, "valid 24 h", store.ResultOK)
	link := s.cfg.Issuer() + "/login?enroll=" + url.QueryEscape(tok)
	rc.render(http.StatusOK, "admin_users", s.adminData(rc, "users", map[string]any{"Local": true, "Link": link, "LinkUser": u.SAM}))
}

// ---- audit ----

func (s *Server) handleAdminAudit(rc *reqCtx) {
	ctx := rc.ctx()
	q := rc.r.URL.Query()
	f := store.AuditFilter{Actor: q.Get("actor"), Action: q.Get("action"), Result: q.Get("result")}
	events, more, err := s.store.ListAudit(ctx, f, 0, 200)
	if err != nil {
		rc.errorPage(http.StatusInternalServerError, "err.internal")
		return
	}
	v, err := s.store.VerifyAudit(ctx)
	if err != nil {
		rc.errorPage(http.StatusInternalServerError, "err.internal")
		return
	}
	rc.render(http.StatusOK, "admin_audit", s.adminData(rc, "audit", map[string]any{"Events": events, "More": more, "Verify": v, "F": f}))
}

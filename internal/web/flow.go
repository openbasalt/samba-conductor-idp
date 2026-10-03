package web

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"time"

	"github.com/google/uuid"
	"github.com/zitadel/oidc/v3/pkg/oidc"
	"github.com/zitadel/oidc/v3/pkg/op"

	"github.com/samba-conductor/conductor-idp/internal/oidcp"
	"github.com/samba-conductor/conductor-idp/internal/samlidp"
	"github.com/samba-conductor/conductor-idp/internal/store"
)

// finish continues a fully signed-in session to where the sign-in started.
func (s *Server) finish(rc *reqCtx, c cont) {
	switch c.kind {
	case 'o':
		s.finishOIDC(rc, c, false)
	case 's':
		s.finishSAML(rc, c)
	default:
		rc.redirect("/")
	}
}

// ---- OIDC ----

// authRequestFor loads a pending authorization request continued in this
// browser.
func (s *Server) authRequestFor(rc *reqCtx, id string) (*store.AuthRequest, bool) {
	ar, err := s.oidc.GetAuthRequest(rc.ctx(), id)
	if err != nil {
		rc.errorPage(http.StatusBadRequest, "err.flow")
		return nil, false
	}
	bh := rc.existingBrowserHash()
	if ar.BrowserHash == "" || bh == "" || !tokensEqual(bh, ar.BrowserHash) {
		s.audit(rc.ctx(), rc, "oidc.flow_denied", ar.ClientID, "authorization request continued in another browser", store.ResultDenied)
		rc.errorPage(http.StatusForbidden, "err.flow")
		return nil, false
	}
	return ar, true
}

// oidcError sends the browser back to the relying party with an OAuth
// error (the redirect URI was validated when the request was created).
func (s *Server) oidcError(rc *reqCtx, id string, e *oidc.Error) {
	ar, err := s.oidc.AuthRequestByID(rc.ctx(), id)
	if err != nil {
		rc.errorPage(http.StatusBadRequest, "err.flow")
		return
	}
	_ = s.store.DeleteAuthRequest(rc.ctx(), id)
	op.AuthRequestError(rc.w, rc.r, ar, e, s.provider)
}

// startOIDC is the provider's login URL: it binds the request to this
// browser and either completes it from the existing session or asks the
// user to sign in. It returns true when it answered.
func (s *Server) startOIDC(rc *reqCtx, c cont) bool {
	ctx := rc.ctx()
	ar, err := s.oidc.GetAuthRequest(ctx, c.id)
	if err != nil {
		rc.errorPage(http.StatusBadRequest, "err.flow")
		return true
	}
	if err := s.store.BindAuthRequest(ctx, c.id, rc.browserHash()); err != nil {
		s.audit(ctx, rc, "oidc.flow_denied", ar.ClientID, "authorization request already bound to another browser", store.ResultDenied)
		rc.errorPage(http.StatusForbidden, "err.flow")
		return true
	}
	full := rc.sess != nil && rc.sess.snapshotStage() == stageFull
	forceLogin := slices.Contains(ar.Prompt, oidc.PromptLogin) || slices.Contains(ar.Prompt, oidc.PromptSelectAccount)
	if full && ar.MaxAge != nil {
		rc.sess.mu.Lock()
		age := s.now().Sub(rc.sess.authTime)
		rc.sess.mu.Unlock()
		if age > time.Duration(*ar.MaxAge)*time.Second {
			forceLogin = true
		}
	}
	if slices.Contains(ar.Prompt, oidc.PromptNone) {
		if !full || forceLogin {
			s.oidcError(rc, c.id, oidc.ErrLoginRequired())
			return true
		}
		s.finishOIDC(rc, c, true)
		return true
	}
	if full && !forceLogin {
		s.finishOIDC(rc, c, false)
		return true
	}
	if rc.sess != nil && !full {
		// A half-finished sign-in of another flow: start over.
		s.sess.destroy(rc.sess)
		clearCookie(rc.w, sessionCookie)
		rc.sess = nil
	}
	username := ""
	if forceLogin && rc.sess != nil {
		rc.sess.mu.Lock()
		username = rc.sess.sam
		rc.sess.mu.Unlock()
	} else if ar.LoginHint != "" && len(ar.LoginHint) <= 64 {
		username = ar.LoginHint
	}
	s.showLogin(rc, c, username, http.StatusOK)
	return true
}

// finishOIDC completes an authorization request for the signed-in user:
// access policy, step-up 2FA, consent, then the code. noInteraction is
// prompt=none: anything that needs the user becomes an error to the RP.
func (s *Server) finishOIDC(rc *reqCtx, c cont, noInteraction bool) {
	ctx, cancel := context.WithTimeout(rc.ctx(), requestTimeout)
	defer cancel()
	ar, ok := s.authRequestFor(rc, c.id)
	if !ok {
		return
	}
	cl, err := s.store.GetClient(ctx, ar.ClientID)
	if err != nil || !cl.Enabled {
		rc.errorPage(http.StatusBadRequest, "err.flow")
		return
	}
	u, err := s.sessionUser(ctx, rc.sess)
	if err != nil {
		rc.errorPage(http.StatusBadGateway, "err.directory")
		return
	}
	if !oidcp.Allowed(cl, u) {
		s.audit(ctx, rc, "oidc.authorize", cl.ID, "user not in the client's allowed groups", store.ResultDenied)
		if noInteraction {
			s.oidcError(rc, c.id, oidc.ErrAccessDenied().WithDescription("the user may not use this application"))
			return
		}
		rc.render(http.StatusForbidden, "denied", map[string]any{"App": cl.Name, "C": c.String()})
		return
	}
	rc.sess.mu.Lock()
	verified := rc.sess.mfaVerified
	rc.sess.mu.Unlock()
	if cl.RequireMFA && !verified {
		if noInteraction {
			s.oidcError(rc, c.id, oidc.ErrInteractionRequired().WithDescription("a second factor is required"))
			return
		}
		s.stepUp(rc, c, u)
		return
	}
	if !cl.FirstParty {
		granted, err := s.store.GetConsent(ctx, u.GUID, cl.ID)
		if err != nil {
			rc.errorPage(http.StatusInternalServerError, "err.internal")
			return
		}
		need := slices.Contains(ar.Prompt, oidc.PromptConsent) || !covers(granted, ar.Scopes)
		if need {
			if noInteraction {
				s.oidcError(rc, c.id, oidcp.ErrConsentRequired())
				return
			}
			rc.redirect(c.with("/consent"))
			return
		}
	}
	s.completeOIDC(rc, ar, u.GUID)
}

// covers reports whether granted scopes include every requested one.
func covers(granted, requested []string) bool {
	for _, sc := range requested {
		if sc != oidc.ScopeOpenID && !slices.Contains(granted, sc) {
			return false
		}
	}
	return granted != nil
}

func (s *Server) completeOIDC(rc *reqCtx, ar *store.AuthRequest, subject string) {
	ctx := rc.ctx()
	rc.sess.mu.Lock()
	authTime := rc.sess.authTime
	rc.sess.mu.Unlock()
	if err := s.store.CompleteAuthRequest(ctx, ar.ID, subject, authTime, rc.sess.amr()); err != nil {
		rc.errorPage(http.StatusBadRequest, "err.flow")
		return
	}
	s.audit(ctx, rc, "oidc.authorize", ar.ClientID, "scopes="+joinScopes(ar.Scopes), store.ResultOK)
	rc.redirect(oidcp.CallbackPath + "?id=" + url.QueryEscape(ar.ID))
}

func joinScopes(s []string) string {
	out := ""
	for i, v := range s {
		if i > 0 {
			out += " "
		}
		out += v
	}
	return out
}

// handleCallback guards the provider's callback: the code is released
// only to the browser that the request was bound to and only once the
// request was completed by a sign-in.
func (s *Server) handleCallback(w http.ResponseWriter, r *http.Request) {
	rc := &reqCtx{s: s, w: w, r: r, ip: s.clientIP(r)}
	s.prefs(rc)
	s.securityHeaders(w.Header())
	w.Header().Set("Cache-Control", "no-store")
	ar, err := s.store.GetAuthRequest(r.Context(), r.URL.Query().Get("id"))
	bh := rc.existingBrowserHash()
	if err != nil || ar.Subject == "" || bh == "" || !tokensEqual(bh, ar.BrowserHash) {
		rc.errorPage(http.StatusForbidden, "err.flow")
		return
	}
	s.provider.ServeHTTP(w, r)
}

// consent page

var scopeKeys = map[string]string{
	oidc.ScopeOpenID:        "consent.scope.openid",
	oidc.ScopeProfile:       "consent.scope.profile",
	oidc.ScopeEmail:         "consent.scope.email",
	oidcp.ScopeGroups:       "consent.scope.groups",
	oidc.ScopeOfflineAccess: "consent.scope.offline_access",
}

func (s *Server) consentData(rc *reqCtx, ar *store.AuthRequest, cl *store.Client) map[string]any {
	var scopes []map[string]string
	for _, sc := range ar.Scopes {
		if k, ok := scopeKeys[sc]; ok {
			scopes = append(scopes, map[string]string{"Name": sc, "Text": rc.T(k)})
		}
	}
	rc.formTargets = append(rc.formTargets, ar.RedirectURI)
	u, _ := url.Parse(ar.RedirectURI)
	host := ""
	if u != nil {
		host = u.Host
	}
	return map[string]any{"App": cl.Name, "Host": host, "Scopes": scopes, "C": "o." + ar.ID}
}

func (s *Server) handleConsentPage(rc *reqCtx) {
	c := rc.cont()
	if c.kind != 'o' {
		rc.errorPage(http.StatusBadRequest, "err.flow")
		return
	}
	ar, ok := s.authRequestFor(rc, c.id)
	if !ok {
		return
	}
	cl, err := s.store.GetClient(rc.ctx(), ar.ClientID)
	if err != nil {
		rc.errorPage(http.StatusBadRequest, "err.flow")
		return
	}
	rc.render(http.StatusOK, "consent", s.consentData(rc, ar, cl))
}

func (s *Server) handleConsent(rc *reqCtx) {
	ctx := rc.ctx()
	c := rc.cont()
	if c.kind != 'o' {
		rc.errorPage(http.StatusBadRequest, "err.flow")
		return
	}
	ar, ok := s.authRequestFor(rc, c.id)
	if !ok {
		return
	}
	cl, err := s.store.GetClient(ctx, ar.ClientID)
	if err != nil {
		rc.errorPage(http.StatusBadRequest, "err.flow")
		return
	}
	u, err := s.sessionUser(ctx, rc.sess)
	if err != nil {
		rc.errorPage(http.StatusBadGateway, "err.directory")
		return
	}
	if !oidcp.Allowed(cl, u) {
		rc.render(http.StatusForbidden, "denied", map[string]any{"App": cl.Name})
		return
	}
	if rc.form("decision") != "allow" {
		s.audit(ctx, rc, "oidc.consent", cl.ID, "denied by the user", store.ResultDenied)
		s.oidcError(rc, c.id, oidc.ErrAccessDenied().WithDescription("the user denied the request"))
		return
	}
	if err := s.store.SaveConsent(ctx, u.GUID, cl.ID, ar.Scopes); err != nil {
		rc.errorPage(http.StatusInternalServerError, "err.internal")
		return
	}
	s.audit(ctx, rc, "oidc.consent", cl.ID, "scopes="+joinScopes(ar.Scopes), store.ResultOK)
	s.completeOIDC(rc, ar, u.GUID)
}

// ---- RP-initiated logout ----

// endSessionURL is called by the provider's end_session endpoint after it
// validated the request; the returned page ends the browser session.
func (s *Server) endSessionURL(_ context.Context, subject, clientID, target string, hinted bool) string {
	t := s.endSessions.put(endSessionTicket{subject: subject, client: clientID, target: target, hinted: hinted})
	return "/logout/rp?t=" + url.QueryEscape(t)
}

func (s *Server) handleRPLogoutPage(rc *reqCtx) {
	tok := rc.r.URL.Query().Get("t")
	t, ok := s.endSessions.peek(tok)
	if !ok {
		rc.redirect("/logged-out")
		return
	}
	if t.hinted {
		s.endSessions.take(tok)
		s.endBrowserSession(rc, "rp-initiated logout (id_token_hint) client="+t.client)
		s.leaveTo(rc, t.target)
		return
	}
	if rc.sess == nil {
		s.endSessions.take(tok)
		s.leaveTo(rc, t.target)
		return
	}
	// Without an id_token_hint anyone could link here: ask first.
	if t.target != "" {
		rc.formTargets = append(rc.formTargets, t.target)
	}
	rc.render(http.StatusOK, "logout_confirm", map[string]any{"T": tok})
}

func (s *Server) handleRPLogout(rc *reqCtx) {
	t, ok := s.endSessions.take(rc.form("t"))
	if !ok {
		rc.redirect("/logged-out")
		return
	}
	if rc.form("decision") == "signout" {
		s.endBrowserSession(rc, "rp-initiated logout (confirmed) client="+t.client)
		s.leaveTo(rc, t.target)
		return
	}
	rc.redirect("/")
}

func (s *Server) endBrowserSession(rc *reqCtx, detail string) {
	if rc.sess != nil {
		s.audit(rc.ctx(), rc, "signout", "", detail, store.ResultOK)
		s.sess.destroy(rc.sess)
		rc.sess = nil
	}
	clearCookie(rc.w, sessionCookie)
}

// leaveTo redirects to a post-logout URI the provider validated, or to
// the idp's own signed-out page.
func (s *Server) leaveTo(rc *reqCtx, target string) {
	if target == "" || target == "/logged-out" {
		rc.redirect("/logged-out")
		return
	}
	http.Redirect(rc.w, rc.r, target, http.StatusSeeOther)
}

// ---- SAML ----

// handleSAMLSSO receives AuthnRequests (HTTP-Redirect or HTTP-POST).
func (s *Server) handleSAMLSSO(rc *reqCtx) {
	ctx := rc.ctx()
	if !s.ipLimit.Allow("saml:" + rc.ip) {
		rc.errorPage(http.StatusTooManyRequests, "signin.err.rate_ip")
		return
	}
	req, err := s.saml.Parse(ctx, rc.r)
	if err != nil {
		s.log.Info("SAML request refused", "err", err)
		s.audit(ctx, rc, "saml.request", "", truncate(err.Error(), 300), store.ResultDenied)
		key := "err.saml_request"
		if errors.Is(err, samlidp.ErrUnknownSP) {
			key = "err.saml_unknown_sp"
		}
		rc.errorPage(http.StatusBadRequest, key)
		return
	}
	p := &store.SAMLPending{ID: uuid.NewString(), EntityID: req.EntityID, RequestID: req.RequestID, Payload: req.Payload,
		RelayState: req.RelayState, BrowserHash: rc.browserHash(), ReceivedAt: req.ReceivedAt, ExpiresAt: s.now().Add(15 * time.Minute)}
	if err := s.store.CreateSAMLPending(ctx, p); err != nil {
		if errors.Is(err, store.ErrConflict) {
			s.audit(ctx, rc, "saml.request", req.EntityID, "replayed request ID "+truncate(req.RequestID, 100), store.ResultDenied)
			rc.errorPage(http.StatusBadRequest, "err.saml_request")
			return
		}
		rc.errorPage(http.StatusInternalServerError, "err.internal")
		return
	}
	s.audit(ctx, rc, "saml.request", req.EntityID, "", store.ResultPending)
	rc.redirect("/login?c=" + url.QueryEscape(cont{kind: 's', id: p.ID}.String()))
}

func truncate(s string, n int) string {
	if len(s) > n {
		return s[:n]
	}
	return s
}

// startSAML: complete from the existing session or ask for a sign-in.
func (s *Server) startSAML(rc *reqCtx, c cont) bool {
	if rc.sess != nil && rc.sess.snapshotStage() == stageFull {
		s.finishSAML(rc, c)
		return true
	}
	if rc.sess != nil {
		s.sess.destroy(rc.sess)
		clearCookie(rc.w, sessionCookie)
		rc.sess = nil
	}
	return false
}

func (s *Server) samlSession(rc *reqCtx) samlidp.Session {
	rc.sess.mu.Lock()
	defer rc.sess.mu.Unlock()
	return samlidp.Session{AuthTime: rc.sess.authTime, Expires: rc.sess.expires, ClientAddr: rc.ip}
}

func (s *Server) finishSAML(rc *reqCtx, c cont) {
	ctx, cancel := context.WithTimeout(rc.ctx(), requestTimeout)
	defer cancel()
	p, err := s.store.GetSAMLPending(ctx, c.id)
	bh := rc.existingBrowserHash()
	if err != nil || bh == "" || !tokensEqual(bh, p.BrowserHash) {
		rc.errorPage(http.StatusBadRequest, "err.flow")
		return
	}
	sp, err := s.store.GetSP(ctx, p.EntityID)
	if err != nil || !sp.Enabled {
		rc.errorPage(http.StatusBadRequest, "err.saml_unknown_sp")
		return
	}
	u, err := s.sessionUser(ctx, rc.sess)
	if err != nil {
		rc.errorPage(http.StatusBadGateway, "err.directory")
		return
	}
	if !samlidp.Allowed(sp, u) {
		s.audit(ctx, rc, "saml.sso", sp.EntityID, "user not in the SP's allowed groups", store.ResultDenied)
		rc.render(http.StatusForbidden, "denied", map[string]any{"App": sp.Name})
		return
	}
	rc.sess.mu.Lock()
	verified := rc.sess.mfaVerified
	rc.sess.mu.Unlock()
	if sp.RequireMFA && !verified {
		s.stepUp(rc, c, u)
		return
	}
	form, err := s.saml.Respond(ctx, p, sp, u, s.samlSession(rc))
	if err != nil {
		s.log.Error("SAML response failed", "sp", sp.EntityID, "err", err)
		s.audit(ctx, rc, "saml.sso", sp.EntityID, truncate(err.Error(), 300), store.ResultFailed)
		key := "err.saml_request"
		if errors.Is(err, samlidp.ErrNoNameID) {
			key = "err.saml_no_nameid"
		}
		rc.errorPage(http.StatusBadRequest, key)
		return
	}
	if ok, err := s.store.FinishSAMLPending(ctx, p.ID); err != nil || !ok {
		rc.errorPage(http.StatusBadRequest, "err.flow")
		return
	}
	s.audit(ctx, rc, "saml.sso", sp.EntityID, "sp-initiated", store.ResultOK)
	s.renderSAMLPost(rc, sp.Name, form)
}

func (s *Server) renderSAMLPost(rc *reqCtx, app string, form *samlidp.Form) {
	rc.formTargets = append(rc.formTargets, form.URL)
	rc.render(http.StatusOK, "saml_post", map[string]any{"App": app, "Form": form})
}

// handleSAMLStart is IdP-initiated sign-in from the home page.
func (s *Server) handleSAMLStart(rc *reqCtx) {
	ctx, cancel := context.WithTimeout(rc.ctx(), requestTimeout)
	defer cancel()
	sp, err := s.store.GetSP(ctx, rc.form("sp"))
	if err != nil || !sp.Enabled || !sp.IdPInitiated {
		rc.errorPage(http.StatusNotFound, "err.not_found")
		return
	}
	u, err := s.sessionUser(ctx, rc.sess)
	if err != nil {
		rc.errorPage(http.StatusBadGateway, "err.directory")
		return
	}
	if !samlidp.Allowed(sp, u) {
		rc.render(http.StatusForbidden, "denied", map[string]any{"App": sp.Name})
		return
	}
	rc.sess.mu.Lock()
	verified := rc.sess.mfaVerified
	rc.sess.mu.Unlock()
	if sp.RequireMFA && !verified {
		s.stepUp(rc, cont{}, u)
		return
	}
	form, err := s.saml.RespondIdPInitiated(ctx, sp, u, s.samlSession(rc))
	if err != nil {
		s.log.Error("SAML IdP-initiated response failed", "sp", sp.EntityID, "err", err)
		rc.errorPage(http.StatusBadRequest, "err.saml_request")
		return
	}
	s.audit(ctx, rc, "saml.sso", sp.EntityID, "idp-initiated", store.ResultOK)
	s.renderSAMLPost(rc, sp.Name, form)
}

func (s *Server) handleSAMLMetadata(w http.ResponseWriter, r *http.Request) {
	md, err := s.saml.Metadata(r.Context())
	if err != nil {
		s.log.Error("SAML metadata", "err", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	s.securityHeaders(w.Header())
	w.Header().Set("Content-Type", "application/samlmetadata+xml")
	w.Header().Set("Cache-Control", "public, max-age=3600")
	w.Header().Set("Content-Length", strconv.Itoa(len(md)))
	_, _ = w.Write(md)
}

// ---- home ----

func (s *Server) handleHome(rc *reqCtx) {
	ctx := rc.ctx()
	u, err := s.sessionUser(ctx, rc.sess)
	if err != nil {
		rc.errorPage(http.StatusBadGateway, "err.directory")
		return
	}
	var apps []*store.SAMLSP
	if s.saml != nil {
		sps, err := s.store.ListSPs(ctx)
		if err == nil {
			for _, sp := range sps {
				if sp.Enabled && sp.IdPInitiated && samlidp.Allowed(sp, u) {
					apps = append(apps, sp)
				}
			}
		}
	}
	enrolled, _ := s.mfa.Enrolled(ctx, u)
	admin, _ := s.isAdmin(ctx, rc.sess)
	rc.sess.mu.Lock()
	verified := rc.sess.mfaVerified
	rc.sess.mu.Unlock()
	rc.render(http.StatusOK, "home", map[string]any{"Apps": apps, "Enrolled": enrolled, "CanEnroll": s.local != nil && !enrolled,
		"Admin": admin && verified, "UserName": u.Name(), "SAM": u.SAM, "Mail": u.Mail})
}

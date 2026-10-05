package web

import (
	"net/http"

	"github.com/openbasalt/samba-conductor-idp/internal/oidcp"
	"github.com/openbasalt/samba-conductor-idp/internal/samlidp"
)

// pages returns the route table of the HTML pages. Every page goes
// through wrap (security headers, CSRF, guard).
func (s *Server) pages() []route {
	signin := []stage{stageMFA}
	enroll := []stage{stageEnroll, stageFull}
	// The sign-in pages are served on both listeners: administrators sign
	// in (with their second factor) on the admin listener itself.
	both := surfacePublic | surfaceAdmin
	rs := []route{
		{method: "GET", pattern: "/{$}", on: both, perm: PermUser, h: s.handleHome},
		{method: "GET", pattern: "/login", on: both, perm: PermPublic, h: s.handleLoginPage},
		{method: "POST", pattern: "/login", on: both, perm: PermPublic, h: s.handleLogin},
		{method: "GET", pattern: "/login/password", on: both, perm: PermPreAuth, stages: []stage{stageMustChange}, h: s.handlePasswordPage},
		{method: "POST", pattern: "/login/password", on: both, perm: PermPreAuth, stages: []stage{stageMustChange}, h: s.handlePassword},
		// /login/2fa also serves step-up for signed-in users whose
		// application requires a second factor.
		{method: "GET", pattern: "/login/2fa", on: both, perm: PermPreAuth, stages: append(signin, stageFull), h: s.handleMFAPage, script: true},
		{method: "POST", pattern: "/login/2fa", on: both, perm: PermPreAuth, stages: append(signin, stageFull), h: s.handleMFA},
		{method: "POST", pattern: "/login/2fa/key", on: both, perm: PermPreAuth, stages: append(signin, stageFull), h: s.handleMFAKey},
		{method: "GET", pattern: "/login/enroll", on: both, perm: PermPreAuth, stages: enroll, h: s.handleEnrollPage},
		{method: "GET", pattern: "/login/enroll/qr.png", on: both, perm: PermPreAuth, stages: enroll, h: s.handleEnrollQR},
		{method: "POST", pattern: "/login/enroll", on: both, perm: PermPreAuth, stages: enroll, h: s.handleEnroll},
		{method: "GET", pattern: "/login/recovery-codes", on: both, perm: PermUser, h: s.handleRecoveryCodes},
		{method: "POST", pattern: "/login/continue", on: both, perm: PermUser, h: s.handleContinue},
		{method: "GET", pattern: "/consent", perm: PermUser, h: s.handleConsentPage},
		{method: "POST", pattern: "/consent", perm: PermUser, h: s.handleConsent},
		{method: "POST", pattern: "/logout", on: both, perm: PermPublic, h: s.handleLogout},
		{method: "GET", pattern: "/logout/rp", perm: PermPublic, h: s.handleRPLogoutPage},
		{method: "POST", pattern: "/logout/rp", perm: PermPublic, h: s.handleRPLogout},
		{method: "GET", pattern: "/logged-out", on: both, perm: PermPublic, h: s.handleLoggedOut},

		{method: "GET", pattern: "/admin", perm: PermAdmin, on: surfaceAdmin, h: func(rc *reqCtx) { rc.redirect("/admin/clients") }},
		{method: "GET", pattern: "/admin/clients", perm: PermAdmin, on: surfaceAdmin, h: s.handleAdminClients},
		{method: "GET", pattern: "/admin/clients/new", perm: PermAdmin, on: surfaceAdmin, h: s.handleAdminClientNew},
		{method: "POST", pattern: "/admin/clients", perm: PermAdmin, on: surfaceAdmin, h: s.handleAdminClientCreate},
		{method: "GET", pattern: "/admin/clients/{id}", perm: PermAdmin, on: surfaceAdmin, h: s.handleAdminClient},
		{method: "POST", pattern: "/admin/clients/{id}", perm: PermAdmin, on: surfaceAdmin, h: s.handleAdminClientUpdate},
		{method: "POST", pattern: "/admin/clients/{id}/rotate", perm: PermAdmin, on: surfaceAdmin, h: s.handleAdminClientRotate},
		{method: "POST", pattern: "/admin/clients/{id}/toggle", perm: PermAdmin, on: surfaceAdmin, h: s.handleAdminClientToggle},
		{method: "POST", pattern: "/admin/clients/{id}/delete", perm: PermAdmin, on: surfaceAdmin, h: s.handleAdminClientDelete},
		{method: "GET", pattern: "/admin/keys", perm: PermAdmin, on: surfaceAdmin, h: s.handleAdminKeys},
		{method: "POST", pattern: "/admin/keys/rotate", perm: PermAdmin, on: surfaceAdmin, h: s.handleAdminKeysRotate},
		{method: "GET", pattern: "/admin/users", perm: PermAdmin, on: surfaceAdmin, h: s.handleAdminUsers},
		{method: "POST", pattern: "/admin/users/mfa-reset", perm: PermAdmin, on: surfaceAdmin, h: s.handleAdminMFAReset},
		{method: "POST", pattern: "/admin/users/enroll-link", perm: PermAdmin, on: surfaceAdmin, h: s.handleAdminEnrollLink},
		{method: "GET", pattern: "/admin/audit", perm: PermAdmin, on: surfaceAdmin, h: s.handleAdminAudit},
	}
	if s.saml != nil {
		rs = append(rs,
			// The SSO endpoint receives cross-site POSTs from service
			// providers by design: no form CSRF token, no state change for
			// the signed-in user (it only stores the request and redirects).
			route{method: "GET", pattern: samlidp.SSOPath, perm: PermPublic, h: s.handleSAMLSSO},
			route{method: "POST", pattern: samlidp.SSOPath, perm: PermPublic, noCSRF: true, h: s.handleSAMLSSO, maxBody: 256 << 10},
			route{method: "POST", pattern: "/saml/start", perm: PermUser, h: s.handleSAMLStart},
			// Single logout: LogoutRequests and LogoutResponses from service
			// providers (cross-site POSTs by design, like the SSO endpoint).
			route{method: "GET", pattern: samlidp.SLOPath, perm: PermPublic, h: s.handleSAMLSLO},
			route{method: "POST", pattern: samlidp.SLOPath, perm: PermPublic, noCSRF: true, h: s.handleSAMLSLO, maxBody: 128 << 10},
			route{method: "POST", pattern: samlidp.SLOPath + "/confirm", perm: PermPublic, h: s.handleSAMLSLOConfirm},
			route{method: "GET", pattern: "/admin/saml", perm: PermAdmin, on: surfaceAdmin, h: s.handleAdminSPs},
			route{method: "GET", pattern: "/admin/saml/new", perm: PermAdmin, on: surfaceAdmin, h: s.handleAdminSPNew},
			route{method: "POST", pattern: "/admin/saml", perm: PermAdmin, on: surfaceAdmin, h: s.handleAdminSPCreate, maxBody: 1 << 20},
			route{method: "GET", pattern: "/admin/saml/sp", perm: PermAdmin, on: surfaceAdmin, h: s.handleAdminSP},
			route{method: "POST", pattern: "/admin/saml/sp", perm: PermAdmin, on: surfaceAdmin, h: s.handleAdminSPUpdate, maxBody: 1 << 20},
			route{method: "POST", pattern: "/admin/saml/sp/toggle", perm: PermAdmin, on: surfaceAdmin, h: s.handleAdminSPToggle},
			route{method: "POST", pattern: "/admin/saml/sp/delete", perm: PermAdmin, on: surfaceAdmin, h: s.handleAdminSPDelete},
		)
	}
	return rs
}

// routes registers what this listener serves. A route of another surface
// is not registered at all, so it answers like any unknown path (404).
func (s *Server) routes() {
	for _, rt := range s.pages() {
		if rt.servedOn(s.surface) {
			s.mux.Handle(rt.method+" "+rt.pattern, s.wrap(rt))
		}
	}
	s.mux.Handle("GET /static/", s.staticHandler())
	s.mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
		if err := s.store.Ping(r.Context()); err != nil {
			http.Error(w, "unhealthy", http.StatusServiceUnavailable)
			return
		}
		_, _ = w.Write([]byte("ok"))
	})
	if s.surface&surfacePublic == 0 {
		// The admin listener serves no OpenID Connect or SAML endpoint,
		// and no branding (its pages keep the product look).
		return
	}
	s.brandRoutes()
	if s.saml != nil {
		s.mux.HandleFunc("GET "+samlidp.MetadataPath, s.handleSAMLMetadata)
	}
	if s.provider == nil {
		return
	}
	// OpenID provider endpoints: rate limited per address, security
	// headers, and the callback guarded by the browser binding.
	s.mux.Handle("GET "+oidcp.Discovery, s.apiHeaders(oidcp.DiscoveryHandler(s.provider)))
	s.mux.Handle(oidcp.CallbackPath, s.limited(http.HandlerFunc(s.handleCallback)))
	for _, p := range []string{oidcp.AuthorizePath, oidcp.TokenPath, oidcp.UserinfoPath, oidcp.RevokePath, oidcp.EndSession, oidcp.KeysPath} {
		h := s.apiHeaders(s.withRequest(s.provider))
		if p == oidcp.TokenPath || p == oidcp.UserinfoPath {
			h = noStore(h)
		}
		s.mux.Handle(p, s.limited(h))
	}
}

// apiHeaders sets the security headers of the provider's endpoints (JSON
// and redirects; the library sets its own caching headers).
func (s *Server) apiHeaders(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.securityHeaders(w.Header())
		r.Body = http.MaxBytesReader(w, r.Body, maxBody)
		h.ServeHTTP(w, r)
	})
}

// withRequest puts the request and client address in the context, for
// the provider's audit hook.
func (s *Server) withRequest(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		ctx = contextWith(ctx, r, s.clientIP(r))
		h.ServeHTTP(w, r.WithContext(ctx))
	})
}

// limited applies the per-address token-endpoint limit.
func (s *Server) limited(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !s.tokenLimit.Allow("api:" + s.clientIP(r)) {
			w.Header().Set("Retry-After", "60")
			http.Error(w, "too many requests", http.StatusTooManyRequests)
			return
		}
		h.ServeHTTP(w, r)
	})
}

// noStore marks responses that carry tokens or user data as not
// cacheable (RFC 6749 5.1): the library sets it for some grants only (the
// OpenID conformance suite found a refresh response without it).
func noStore(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Pragma", "no-cache")
		h.ServeHTTP(w, r)
	})
}

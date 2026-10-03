package web

import (
	"net/http"

	"github.com/samba-conductor/conductor-idp/internal/oidcp"
	"github.com/samba-conductor/conductor-idp/internal/samlidp"
)

// pages returns the route table of the HTML pages. Every page goes
// through wrap (security headers, CSRF, guard).
func (s *Server) pages() []route {
	signin := []stage{stageMFA}
	enroll := []stage{stageEnroll, stageFull}
	rs := []route{
		{method: "GET", pattern: "/{$}", perm: PermUser, h: s.handleHome},
		{method: "GET", pattern: "/login", perm: PermPublic, h: s.handleLoginPage},
		{method: "POST", pattern: "/login", perm: PermPublic, h: s.handleLogin},
		{method: "GET", pattern: "/login/password", perm: PermPreAuth, stages: []stage{stageMustChange}, h: s.handlePasswordPage},
		{method: "POST", pattern: "/login/password", perm: PermPreAuth, stages: []stage{stageMustChange}, h: s.handlePassword},
		// /login/2fa also serves step-up for signed-in users whose
		// application requires a second factor.
		{method: "GET", pattern: "/login/2fa", perm: PermPreAuth, stages: append(signin, stageFull), h: s.handleMFAPage},
		{method: "POST", pattern: "/login/2fa", perm: PermPreAuth, stages: append(signin, stageFull), h: s.handleMFA},
		{method: "GET", pattern: "/login/enroll", perm: PermPreAuth, stages: enroll, h: s.handleEnrollPage},
		{method: "GET", pattern: "/login/enroll/qr.png", perm: PermPreAuth, stages: enroll, h: s.handleEnrollQR},
		{method: "POST", pattern: "/login/enroll", perm: PermPreAuth, stages: enroll, h: s.handleEnroll},
		{method: "GET", pattern: "/login/recovery-codes", perm: PermUser, h: s.handleRecoveryCodes},
		{method: "POST", pattern: "/login/continue", perm: PermUser, h: s.handleContinue},
		{method: "GET", pattern: "/consent", perm: PermUser, h: s.handleConsentPage},
		{method: "POST", pattern: "/consent", perm: PermUser, h: s.handleConsent},
		{method: "POST", pattern: "/logout", perm: PermPublic, h: s.handleLogout},
		{method: "GET", pattern: "/logout/rp", perm: PermPublic, h: s.handleRPLogoutPage},
		{method: "POST", pattern: "/logout/rp", perm: PermPublic, h: s.handleRPLogout},
		{method: "GET", pattern: "/logged-out", perm: PermPublic, h: s.handleLoggedOut},

		{method: "GET", pattern: "/admin", perm: PermAdmin, h: func(rc *reqCtx) { rc.redirect("/admin/clients") }},
		{method: "GET", pattern: "/admin/clients", perm: PermAdmin, h: s.handleAdminClients},
		{method: "GET", pattern: "/admin/clients/new", perm: PermAdmin, h: s.handleAdminClientNew},
		{method: "POST", pattern: "/admin/clients", perm: PermAdmin, h: s.handleAdminClientCreate},
		{method: "GET", pattern: "/admin/clients/{id}", perm: PermAdmin, h: s.handleAdminClient},
		{method: "POST", pattern: "/admin/clients/{id}", perm: PermAdmin, h: s.handleAdminClientUpdate},
		{method: "POST", pattern: "/admin/clients/{id}/rotate", perm: PermAdmin, h: s.handleAdminClientRotate},
		{method: "POST", pattern: "/admin/clients/{id}/toggle", perm: PermAdmin, h: s.handleAdminClientToggle},
		{method: "POST", pattern: "/admin/clients/{id}/delete", perm: PermAdmin, h: s.handleAdminClientDelete},
		{method: "GET", pattern: "/admin/keys", perm: PermAdmin, h: s.handleAdminKeys},
		{method: "POST", pattern: "/admin/keys/rotate", perm: PermAdmin, h: s.handleAdminKeysRotate},
		{method: "GET", pattern: "/admin/users", perm: PermAdmin, h: s.handleAdminUsers},
		{method: "POST", pattern: "/admin/users/mfa-reset", perm: PermAdmin, h: s.handleAdminMFAReset},
		{method: "POST", pattern: "/admin/users/enroll-link", perm: PermAdmin, h: s.handleAdminEnrollLink},
		{method: "GET", pattern: "/admin/audit", perm: PermAdmin, h: s.handleAdminAudit},
	}
	if s.saml != nil {
		rs = append(rs,
			// The SSO endpoint receives cross-site POSTs from service
			// providers by design: no form CSRF token, no state change for
			// the signed-in user (it only stores the request and redirects).
			route{method: "GET", pattern: samlidp.SSOPath, perm: PermPublic, h: s.handleSAMLSSO},
			route{method: "POST", pattern: samlidp.SSOPath, perm: PermPublic, noCSRF: true, h: s.handleSAMLSSO, maxBody: 256 << 10},
			route{method: "POST", pattern: "/saml/start", perm: PermUser, h: s.handleSAMLStart},
			route{method: "GET", pattern: "/admin/saml", perm: PermAdmin, h: s.handleAdminSPs},
			route{method: "GET", pattern: "/admin/saml/new", perm: PermAdmin, h: s.handleAdminSPNew},
			route{method: "POST", pattern: "/admin/saml", perm: PermAdmin, h: s.handleAdminSPCreate, maxBody: 1 << 20},
			route{method: "GET", pattern: "/admin/saml/sp", perm: PermAdmin, h: s.handleAdminSP},
			route{method: "POST", pattern: "/admin/saml/sp", perm: PermAdmin, h: s.handleAdminSPUpdate, maxBody: 1 << 20},
			route{method: "POST", pattern: "/admin/saml/sp/toggle", perm: PermAdmin, h: s.handleAdminSPToggle},
			route{method: "POST", pattern: "/admin/saml/sp/delete", perm: PermAdmin, h: s.handleAdminSPDelete},
		)
	}
	return rs
}

func (s *Server) routes() {
	for _, rt := range s.pages() {
		s.mux.Handle(rt.method+" "+rt.pattern, s.wrap(rt))
	}
	s.mux.Handle("GET /static/", s.staticHandler())
	s.mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
		if err := s.store.Ping(r.Context()); err != nil {
			http.Error(w, "unhealthy", http.StatusServiceUnavailable)
			return
		}
		_, _ = w.Write([]byte("ok"))
	})
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
		s.mux.Handle(p, s.limited(s.apiHeaders(s.withRequest(s.provider))))
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

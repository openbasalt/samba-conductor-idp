package web

import (
	"context"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/openbasalt/samba-conductor-idp/internal/i18n"
)

// Perm is what a route requires.
type Perm int

const (
	// PermPublic: anyone (sign-in form, metadata, static).
	PermPublic Perm = iota
	// PermPreAuth: a session in one of the route's stages.
	PermPreAuth
	// PermUser: a fully signed-in user.
	PermUser
	// PermAdmin: a fully signed-in administrator with 2FA.
	PermAdmin
)

// route is one entry of the route table: every page handler is reachable
// only through it, so the guard below runs for every request.
type route struct {
	method  string
	pattern string
	perm    Perm
	stages  []stage
	h       func(*reqCtx)
	// noCSRF exempts a POST from the form CSRF check: only the SAML SSO
	// endpoint, which receives cross-site POSTs from service providers by
	// design (it changes no state of the signed-in user).
	noCSRF bool
	// maxBody overrides the request body limit.
	maxBody int64
}

// reqCtx carries one request through a handler.
type reqCtx struct {
	s     *Server
	w     http.ResponseWriter
	r     *http.Request
	sess  *Session
	lang  string
	theme string
	ip    string
	route route
	// actorHint names the actor of anonymous audit events (typed username).
	actorHint string
	// formTargets are extra origins the page's forms may lead to (the
	// relying party's redirect URI or the SP's ACS URL): CSP form-action
	// also applies to the redirects that follow a form submission.
	formTargets []string
}

func (rc *reqCtx) ctx() context.Context { return rc.r.Context() }

// T translates in the request's language.
func (rc *reqCtx) T(key string, args ...any) string { return rc.s.cat.T(rc.lang, key, args...) }

// maxBody bounds request bodies (forms are small).
const maxBody = 64 << 10

// basePolicy: no script, styles and images only from this origin.
const basePolicy = "default-src 'none'; script-src 'none'; style-src 'self'; img-src 'self'; font-src 'self'; " +
	"connect-src 'none'; frame-ancestors 'none'; base-uri 'none'"

// csp builds the page policy: form-action is 'self' plus the origins the
// page's flow may legitimately continue to. There is no script at all.
func csp(formTargets []string) string {
	fa := "'self'"
	for _, t := range formTargets {
		if o := origin(t); o != "" && !strings.Contains(fa, " "+o) {
			fa += " " + o
		}
	}
	return basePolicy + "; form-action " + fa
}

// origin returns scheme://host[:port] of a URL, or "" when unusable in a
// CSP source expression.
func origin(raw string) string {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" || (u.Scheme != "https" && u.Scheme != "http") ||
		strings.ContainsAny(u.Host, " ;,'\"") {
		return ""
	}
	return u.Scheme + "://" + u.Host
}

func (s *Server) securityHeaders(h http.Header) {
	h.Set("Content-Security-Policy", csp(nil))
	h.Set("X-Content-Type-Options", "nosniff")
	h.Set("X-Frame-Options", "DENY")
	h.Set("Referrer-Policy", "no-referrer")
	h.Set("Cross-Origin-Opener-Policy", "same-origin")
	h.Set("Cross-Origin-Resource-Policy", "same-origin")
	h.Set("Permissions-Policy", "camera=(), microphone=(), geolocation=(), payment=(), usb=()")
	h.Set("Strict-Transport-Security", "max-age=63072000; includeSubDomains")
}

// clientIP returns the peer address, or the X-Forwarded-For entry added by
// a trusted proxy.
func (s *Server) clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	peer, err := netip.ParseAddr(host)
	if err != nil {
		return host
	}
	peer = peer.Unmap()
	if !s.cfg.Server.BehindProxy || !s.isTrusted(peer) {
		return peer.String()
	}
	parts := strings.Split(r.Header.Get("X-Forwarded-For"), ",")
	for i := len(parts) - 1; i >= 0; i-- {
		a, err := netip.ParseAddr(strings.TrimSpace(parts[i]))
		if err != nil {
			break
		}
		a = a.Unmap()
		if !s.isTrusted(a) {
			return a.String()
		}
	}
	return peer.String()
}

func (s *Server) isTrusted(a netip.Addr) bool {
	for _, p := range s.trusted {
		if p.Contains(a) {
			return true
		}
	}
	return false
}

// wrap applies the common pipeline and the route's guard.
func (s *Server) wrap(rt route) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.securityHeaders(w.Header())
		w.Header().Set("Cache-Control", "no-store")
		limit := int64(maxBody)
		if rt.maxBody > 0 {
			limit = rt.maxBody
		}
		r.Body = http.MaxBytesReader(w, r.Body, limit)
		rc := &reqCtx{s: s, w: w, r: r, route: rt, ip: s.clientIP(r)}
		rc.r = r.WithContext(context.WithValue(context.WithValue(r.Context(), requestKey{}, r), ipKey{}, rc.ip))
		s.prefs(rc)
		if c, err := r.Cookie(sessionCookie); err == nil {
			rc.sess = s.sess.get(c.Value)
		}
		defer func() {
			if v := recover(); v != nil {
				s.log.Error("handler panic", "path", r.URL.Path, "panic", v)
				rc.errorPage(http.StatusInternalServerError, "err.internal")
			}
		}()
		if r.Method == http.MethodPost && !rt.noCSRF && !s.checkCSRF(rc) {
			s.audit(rc.ctx(), rc, "security.csrf_rejected", r.URL.Path, "", "denied")
			rc.errorPage(http.StatusForbidden, "err.csrf")
			return
		}
		if !s.guard(rc) {
			return
		}
		rt.h(rc)
	})
}

// prefs resolves language and theme; ?lang= and ?theme= on a GET store the
// choice in a cookie (UI preferences only).
func (s *Server) prefs(rc *reqCtx) {
	r := rc.r
	langCookie, themeCookie := "", ""
	if c, err := r.Cookie("lang"); err == nil {
		langCookie = c.Value
	}
	if c, err := r.Cookie("theme"); err == nil {
		themeCookie = c.Value
	}
	if r.Method == http.MethodGet {
		if l := r.URL.Query().Get("lang"); i18n.Valid(l) {
			langCookie = l
			http.SetCookie(rc.w, &http.Cookie{Name: "lang", Value: l, Path: "/", MaxAge: 365 * 24 * 3600, Secure: true, HttpOnly: true, SameSite: http.SameSiteLaxMode})
		}
		if t := r.URL.Query().Get("theme"); slices.Contains([]string{"light", "dark", "system"}, t) {
			themeCookie = t
			http.SetCookie(rc.w, &http.Cookie{Name: "theme", Value: t, Path: "/", MaxAge: 365 * 24 * 3600, Secure: true, HttpOnly: true, SameSite: http.SameSiteLaxMode})
		}
	}
	rc.lang = i18n.Negotiate(r, langCookie, s.cfg.UI.DefaultLanguage)
	if themeCookie == "light" || themeCookie == "dark" {
		rc.theme = themeCookie
	}
}

// checkCSRF verifies a state-changing request: same-origin by Fetch
// metadata / Origin, and the session's token (or, without a session, the
// pre-session cookie: double submit).
func (s *Server) checkCSRF(rc *reqCtx) bool {
	r := rc.r
	if site := r.Header.Get("Sec-Fetch-Site"); site != "" && site != "same-origin" && site != "none" {
		return false
	}
	if o := r.Header.Get("Origin"); o != "" && o != "null" {
		u, err := url.Parse(o)
		if err != nil || !strings.EqualFold(u.Host, r.Host) {
			return false
		}
	}
	if err := r.ParseForm(); err != nil {
		return false
	}
	tok := r.PostForm.Get("csrf")
	if rc.sess != nil {
		rc.sess.mu.Lock()
		want := rc.sess.csrf
		rc.sess.mu.Unlock()
		if tokensEqual(tok, want) {
			return true
		}
	}
	if rc.route.perm == PermPublic {
		if c, err := r.Cookie(preCookie); err == nil && tokensEqual(tok, c.Value) {
			return true
		}
	}
	return false
}

// guard enforces the route's permission before the handler runs.
func (s *Server) guard(rc *reqCtx) bool {
	rt := rc.route
	switch rt.perm {
	case PermPublic:
		return true
	case PermPreAuth:
		if rc.sess == nil || !slices.Contains(rt.stages, rc.sess.snapshotStage()) {
			rc.redirect("/login")
			return false
		}
		return true
	}
	if rc.sess == nil || rc.sess.snapshotStage() != stageFull {
		rc.redirect("/login")
		return false
	}
	if rt.perm == PermAdmin {
		ok, err := s.isAdmin(rc.ctx(), rc.sess)
		if err != nil {
			s.log.Warn("admin re-check failed", "err", err)
			rc.errorPage(http.StatusBadGateway, "err.directory")
			return false
		}
		if !ok {
			s.audit(rc.ctx(), rc, "access.denied", rc.r.Method+" "+rc.r.URL.Path, "requires admin", "denied")
			rc.errorPage(http.StatusForbidden, "err.forbidden")
			return false
		}
		rc.sess.mu.Lock()
		verified := rc.sess.mfaVerified
		rc.sess.mu.Unlock()
		if !verified {
			// Administrators always need 2FA in this session.
			s.audit(rc.ctx(), rc, "access.denied", rc.r.Method+" "+rc.r.URL.Path, "admin without 2FA in this session", "denied")
			s.sess.destroy(rc.sess)
			clearCookie(rc.w, sessionCookie)
			rc.redirect("/login?m=mfa_required")
			return false
		}
	}
	return true
}

// isAdmin re-checks the administrator role against AD (cached at most
// roles.cache_seconds).
func (s *Server) isAdmin(ctx context.Context, sess *Session) (bool, error) {
	sess.mu.Lock()
	guid, admin, at := sess.guid, sess.admin, sess.adminAt
	sess.mu.Unlock()
	if s.now().Sub(at) < s.cfg.RoleCacheTTL() {
		return admin, nil
	}
	u, err := s.dir.UserByGUID(ctx, guid)
	if err != nil {
		return false, err
	}
	admin, err = s.userIsAdmin(ctx, u.GroupSIDs, u.Active())
	if err != nil {
		return false, err
	}
	sess.mu.Lock()
	sess.admin, sess.adminAt = admin, s.now()
	sess.mu.Unlock()
	return admin, nil
}

func (rc *reqCtx) redirect(path string) {
	http.Redirect(rc.w, rc.r, path, http.StatusSeeOther)
}

// requestTimeout bounds directory work per request.
const requestTimeout = 30 * time.Second

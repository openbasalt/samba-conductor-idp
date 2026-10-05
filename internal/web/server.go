// Package web is conductor-idp's HTTP server: the sign-in, second-factor,
// consent and admin pages (server-rendered, no JavaScript), the OIDC
// endpoints of the zitadel provider and the SAML endpoints.
package web

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"html/template"
	"log/slog"
	"net/http"
	"net/netip"
	"sync/atomic"
	"time"

	"github.com/zitadel/oidc/v3/pkg/op"

	"github.com/openbasalt/samba-conductor-ad/sid"
	"github.com/openbasalt/samba-conductor-idp/internal/config"
	"github.com/openbasalt/samba-conductor-idp/internal/directory"
	"github.com/openbasalt/samba-conductor-idp/internal/i18n"
	"github.com/openbasalt/samba-conductor-idp/internal/mfa"
	"github.com/openbasalt/samba-conductor-idp/internal/oidcp"
	"github.com/openbasalt/samba-conductor-idp/internal/ratelimit"
	"github.com/openbasalt/samba-conductor-idp/internal/samlidp"
	"github.com/openbasalt/samba-conductor-idp/internal/settings"
	"github.com/openbasalt/samba-conductor-idp/internal/store"
)

// Options build a Server.
type Options struct {
	Config   *config.Config
	Store    *store.Store
	Dir      directory.Backend
	MFA      mfa.Backend
	OIDC     *oidcp.Storage
	Provider *op.Provider
	SAML     *samlidp.IdP // nil when SAML is off
	Keys     KeyRotator
	Logger   *slog.Logger
	Version  string
	Now      func() time.Time
}

// Server is the HTTP handler.
type Server struct {
	cfg      *config.Config
	store    *store.Store
	dir      directory.Backend
	mfa      mfa.Backend
	local    *mfa.Local // set when users enroll here
	oidc     *oidcp.Storage
	provider *op.Provider
	saml     *samlidp.IdP
	keys     KeyRotator
	log      *slog.Logger
	version  string
	now      func() time.Time

	cat     *i18n.Catalog
	tmpl    map[string]map[string]*template.Template
	sess    *sessions
	trusted []netip.Prefix
	mux     *http.ServeMux

	ipLimit      *ratelimit.Bucket
	tokenLimit   *ratelimit.Bucket
	accountFails *ratelimit.Failures
	endSessions  *endSessionTickets
	adminSIDs    []sid.SID

	// keyBackend is set when the 2FA backend verifies security keys.
	keyBackend mfa.KeyBackend
	// scriptSRI is the Subresource Integrity hash of static/webauthn.js.
	scriptSRI string
	// rt holds the settings edited from conductor's panel (shared with
	// the admin listener's server).
	rt *atomic.Pointer[runtimeSettings]
	// logouts are the single logout chains in progress.
	logouts *logoutChains

	// surface is what this handler serves: the public pages, the admin
	// pages, or both (admin pages on the main listener).
	surface surface
	// admin is the admin listener's handler when the admin pages have a
	// listener of their own (server.admin_listen), else nil.
	admin *Server
	// allSessions are the session tables of every listener (a 2FA reset
	// ends the user's sessions everywhere).
	allSessions []*sessions
	// Cookie names and the session cookie's SameSite mode of this
	// listener: each listener has its own, so a session of one is never
	// valid on the other.
	sessionName string
	preName     string
	sessionSite http.SameSite
	// behindProxy is this listener's server.behind_proxy (or
	// admin_behind_proxy); trusted holds its trusted proxies.
	behindProxy bool
	// host, when set, is the only Host this listener answers for.
	host string
}

// surface is a set of route groups.
type surface uint8

const (
	// surfacePublic: sign-in, consent, OIDC and SAML.
	surfacePublic surface = 1 << iota
	// surfaceAdmin: the admin pages and the sign-in pages they need.
	surfaceAdmin
)

// New builds the server and its routes.
func New(o Options) (*Server, error) {
	now := o.Now
	if now == nil {
		now = time.Now
	}
	s := &Server{cfg: o.Config, store: o.Store, dir: o.Dir, mfa: o.MFA, oidc: o.OIDC, provider: o.Provider, saml: o.SAML, keys: o.Keys,
		log: o.Logger, version: o.Version, now: now}
	if s.log == nil {
		s.log = slog.Default()
	}
	if l, ok := o.MFA.(*mfa.Local); ok {
		s.local = l
	}
	if k, ok := o.MFA.(mfa.KeyBackend); ok {
		s.keyBackend = k
	}
	js, err := staticFS.ReadFile("static/webauthn.js")
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256(js)
	s.scriptSRI = "sha256-" + base64.StdEncoding.EncodeToString(sum[:])
	cat, err := i18n.Load()
	if err != nil {
		return nil, err
	}
	s.cat = cat
	if s.trusted, err = parsePrefixes(s.cfg.Server.TrustedProxies); err != nil {
		return nil, err
	}
	s.behindProxy = s.cfg.Server.BehindProxy
	for _, g := range s.cfg.Roles.AdminGroups {
		v, err := sid.Parse(g)
		if err != nil {
			return nil, err
		}
		s.adminSIDs = append(s.adminSIDs, v)
	}
	if s.tmpl, err = s.loadTemplates(); err != nil {
		return nil, err
	}
	s.sess = newSessions(s.cfg.IdleTimeout(), s.cfg.AbsoluteTimeout(), now)
	s.sessionName, s.preName, s.sessionSite = sessionCookie, preCookie, http.SameSiteLaxMode
	s.rt = &atomic.Pointer[runtimeSettings]{}
	s.ipLimit = ratelimit.NewBucket(s.cfg.RateLimit.PerIPPerMinute, time.Minute)
	s.tokenLimit = ratelimit.NewBucket(s.cfg.RateLimit.TokenPerIPPerMinute, time.Minute)
	s.accountFails = ratelimit.NewFailures(s.cfg.RateLimit.AccountFailures, time.Duration(s.cfg.RateLimit.AccountWindowMinutes)*time.Minute)
	s.endSessions = newEndSessionTickets(now)
	s.logouts = newLogoutChains(now)
	s.allSessions = []*sessions{s.sess}
	switch s.cfg.AdminMode() {
	case config.AdminShared:
		s.surface = surfacePublic | surfaceAdmin
	case config.AdminDisabled:
		s.surface = surfacePublic
	case config.AdminSeparate:
		s.surface = surfacePublic
		if s.admin, err = s.adminServer(); err != nil {
			return nil, err
		}
		s.allSessions = append(s.allSessions, s.admin.sess)
		s.admin.allSessions = s.allSessions
	}
	s.ApplySettings(settings.Defaults(s.cfg))
	if s.oidc != nil {
		s.oidc.EndSessionURL = s.endSessionURL
	}
	s.mux = http.NewServeMux()
	s.routes()
	return s, nil
}

// adminServer builds the admin listener's handler: the same server with
// its own routes, session table, cookie names and proxy settings.
func (s *Server) adminServer() (*Server, error) {
	a := *s
	a.surface = surfaceAdmin
	a.admin = nil
	a.sess = newSessions(s.cfg.IdleTimeout(), s.cfg.AbsoluteTimeout(), s.now)
	// The admin listener never receives cross-site redirects from relying
	// parties, so its session cookie can be Strict.
	a.sessionName, a.preName, a.sessionSite = adminSessionCookie, adminPreCookie, http.SameSiteStrictMode
	a.behindProxy = s.cfg.Server.AdminBehindProxy
	var err error
	if a.trusted, err = parsePrefixes(s.cfg.Server.AdminTrustedProxies); err != nil {
		return nil, err
	}
	a.host = s.cfg.AdminHost()
	a.mux = http.NewServeMux()
	a.routes()
	return &a, nil
}

func parsePrefixes(list []string) ([]netip.Prefix, error) {
	var out []netip.Prefix
	for _, p := range list {
		pr, err := netip.ParsePrefix(p)
		if err != nil {
			return nil, err
		}
		out = append(out, pr)
	}
	return out, nil
}

// ServeHTTP implements http.Handler.
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if s.host != "" && config.CanonicalHost(r.Host) != s.host {
		// Only the configured admin host name (server.admin_url): no DNS
		// rebinding, and the session cookie stays on one origin.
		http.Error(w, "misdirected request", http.StatusMisdirectedRequest)
		return
	}
	s.mux.ServeHTTP(w, r)
}

// AdminHandler returns the admin listener's handler when the admin pages
// have a listener of their own (server.admin_listen), else nil.
func (s *Server) AdminHandler() http.Handler {
	if s.admin == nil {
		return nil
	}
	return s.admin
}

// Sweep drops expired sessions and tickets (called periodically).
func (s *Server) Sweep() {
	for _, t := range s.allSessions {
		t.sweep()
	}
	s.endSessions.sweep()
	s.logouts.sweep()
}

// SetLimiterClock replaces the limiters' clock (tests).
func (s *Server) SetLimiterClock(now func() time.Time) {
	ratelimit.SetClock(now, s.ipLimit, s.accountFails)
	ratelimit.SetClock(now, s.tokenLimit, nil)
}

// audit appends an event; failures are logged, never shown.
func (s *Server) audit(ctx context.Context, rc *reqCtx, action, target, detail, result string) {
	e := store.AuditEvent{Action: action, Target: target, Detail: detail, Result: result}
	if rc != nil {
		e.IP, e.UserAgent = rc.ip, rc.r.UserAgent()
		if rc.sess != nil {
			rc.sess.mu.Lock()
			e.ActorSID, e.ActorName = rc.sess.userSID, rc.sess.sam
			rc.sess.mu.Unlock()
		}
		if e.ActorName == "" {
			e.ActorName = rc.actorHint
		}
	}
	if _, err := s.store.AppendAudit(ctx, e); err != nil {
		s.log.Error("audit append failed", "action", action, "err", err)
	}
}

// AuditProvider adapts the provider's audit hook to the audit log.
func AuditProvider(st *store.Store, log *slog.Logger) oidcp.AuditFunc {
	return func(ctx context.Context, action, subject, clientID, detail, result string) {
		e := store.AuditEvent{Action: action, ActorName: subject, Target: clientID, Detail: detail, Result: result}
		if r, ok := ctx.Value(requestKey{}).(*http.Request); ok {
			e.UserAgent = r.UserAgent()
			if ip, ok := ctx.Value(ipKey{}).(string); ok {
				e.IP = ip
			}
		}
		if _, err := st.AppendAudit(ctx, e); err != nil {
			log.Error("audit append failed", "action", action, "err", err)
		}
	}
}

type requestKey struct{}
type ipKey struct{}

func contextWith(ctx context.Context, r *http.Request, ip string) context.Context {
	return context.WithValue(context.WithValue(ctx, requestKey{}, r), ipKey{}, ip)
}

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
	// rt holds the settings edited from conductor's panel.
	rt atomic.Pointer[runtimeSettings]
	// logouts are the single logout chains in progress.
	logouts *logoutChains
}

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
	for _, p := range s.cfg.Server.TrustedProxies {
		pr, err := netip.ParsePrefix(p)
		if err != nil {
			return nil, err
		}
		s.trusted = append(s.trusted, pr)
	}
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
	s.ipLimit = ratelimit.NewBucket(s.cfg.RateLimit.PerIPPerMinute, time.Minute)
	s.tokenLimit = ratelimit.NewBucket(s.cfg.RateLimit.TokenPerIPPerMinute, time.Minute)
	s.accountFails = ratelimit.NewFailures(s.cfg.RateLimit.AccountFailures, time.Duration(s.cfg.RateLimit.AccountWindowMinutes)*time.Minute)
	s.endSessions = newEndSessionTickets(now)
	s.logouts = newLogoutChains(now)
	s.ApplySettings(settings.Defaults(s.cfg))
	if s.oidc != nil {
		s.oidc.EndSessionURL = s.endSessionURL
	}
	s.mux = http.NewServeMux()
	s.routes()
	return s, nil
}

// ServeHTTP implements http.Handler.
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) { s.mux.ServeHTTP(w, r) }

// Sweep drops expired sessions and tickets (called periodically).
func (s *Server) Sweep() {
	s.sess.sweep()
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

package web

import (
	"context"
	"net/http"
	"sync"
	"time"

	"github.com/crewjam/saml"

	"github.com/openbasalt/samba-conductor-idp/internal/samlidp"
	"github.com/openbasalt/samba-conductor-idp/internal/store"
)

// SAML single logout through the browser (see samlidp/slo.go for the
// message rules). The SSO session ends first; then every other service
// provider the session signed in to that has a single logout URL gets a
// LogoutRequest, one after the other; finally the initiator gets its
// LogoutResponse (or, for a logout started at the IdP or by an OIDC
// client, the browser goes to its destination). The chain lives in memory,
// bound to the browser that started it, for at most logoutTTL.

// logoutTTL bounds a logout chain and a pending confirmation.
const logoutTTL = 10 * time.Minute

type logoutChain struct {
	browser string
	pending []samlidp.Participant
	// initiator is the SP that asked (empty: the IdP or an OIDC client).
	initiator, initiatorReq, initiatorRelay string
	// final is where the browser goes when the IdP started the logout.
	final   string
	partial bool
	current string // entity ID of the SP whose answer is awaited
	created time.Time
}

type pendingSLO struct {
	browser string
	msg     *samlidp.LogoutMessage
	created time.Time
}

// logoutChains keeps chains by the ID of the request awaiting an answer,
// and unverified LogoutRequests awaiting the user's confirmation.
type logoutChains struct {
	mu      sync.Mutex
	byReq   map[string]*logoutChain
	confirm map[string]*pendingSLO
	now     func() time.Time
}

func newLogoutChains(now func() time.Time) *logoutChains {
	return &logoutChains{byReq: map[string]*logoutChain{}, confirm: map[string]*pendingSLO{}, now: now}
}

func (l *logoutChains) put(reqID string, c *logoutChain) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if len(l.byReq) < 10_000 {
		l.byReq[reqID] = c
	}
}

// take returns and forgets the chain waiting for reqID's answer, only
// for the browser that started it (another browser cannot consume it).
func (l *logoutChains) take(reqID, browser string) *logoutChain {
	l.mu.Lock()
	defer l.mu.Unlock()
	c := l.byReq[reqID]
	if c == nil || !tokensEqual(browser, c.browser) {
		return nil
	}
	delete(l.byReq, reqID)
	if l.now().Sub(c.created) > logoutTTL {
		return nil
	}
	return c
}

func (l *logoutChains) hold(p *pendingSLO) string {
	tok := newToken()
	l.mu.Lock()
	defer l.mu.Unlock()
	if len(l.confirm) < 10_000 {
		l.confirm[tok] = p
	}
	return tok
}

func (l *logoutChains) release(tok string) *pendingSLO {
	l.mu.Lock()
	defer l.mu.Unlock()
	p := l.confirm[tok]
	delete(l.confirm, tok)
	if p == nil || l.now().Sub(p.created) > logoutTTL {
		return nil
	}
	return p
}

func (l *logoutChains) sweep() {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.now()
	for k, c := range l.byReq {
		if now.Sub(c.created) > logoutTTL {
			delete(l.byReq, k)
		}
	}
	for k, p := range l.confirm {
		if now.Sub(p.created) > logoutTTL {
			delete(l.confirm, k)
		}
	}
}

// remember records a service provider this session signed in to (the last
// assertion per SP wins).
func (sess *Session) remember(p samlidp.Participant) {
	sess.mu.Lock()
	defer sess.mu.Unlock()
	for n, old := range sess.participants {
		if old.EntityID == p.EntityID {
			sess.participants[n] = p
			return
		}
	}
	if len(sess.participants) < 100 {
		sess.participants = append(sess.participants, p)
	}
}

// handleSAMLSLO receives LogoutRequests and LogoutResponses.
func (s *Server) handleSAMLSLO(rc *reqCtx) {
	ctx := rc.ctx()
	if !s.ipLimit.Allow("saml:" + rc.ip) {
		rc.errorPage(http.StatusTooManyRequests, "signin.err.rate_ip")
		return
	}
	m, err := s.saml.ParseLogout(ctx, rc.r)
	if err != nil {
		s.log.Info("SAML logout message refused", "err", err)
		s.audit(ctx, rc, "saml.slo", "", truncate(err.Error(), 300), store.ResultDenied)
		rc.errorPage(http.StatusBadRequest, "err.saml_request")
		return
	}
	if m.Response {
		c := s.logouts.take(m.InResponseTo, rc.existingBrowserHash())
		if c == nil || c.current != m.Issuer {
			rc.redirect("/logged-out")
			return
		}
		if m.Status != saml.StatusSuccess {
			c.partial = true
		}
		s.continueLogout(rc, c)
		return
	}
	if !m.Verified {
		// Unsigned (or HTTP-POST, whose XML signature the IdP does not
		// verify): ask the user, as for an OIDC logout without a hint.
		tok := s.logouts.hold(&pendingSLO{browser: rc.browserHash(), msg: m, created: s.now()})
		rc.ensurePreCookie()
		app := m.Issuer
		if sp, err := s.store.GetSP(ctx, m.Issuer); err == nil {
			app = sp.Name
		}
		rc.render(http.StatusOK, "slo_confirm", map[string]any{"T": tok, "App": app})
		return
	}
	s.beginSPLogout(rc, m)
}

// handleSAMLSLOConfirm is the user's answer to an unverified LogoutRequest.
func (s *Server) handleSAMLSLOConfirm(rc *reqCtx) {
	p := s.logouts.release(rc.form("t"))
	if p == nil || !tokensEqual(rc.existingBrowserHash(), p.browser) {
		rc.redirect("/logged-out")
		return
	}
	if rc.form("decision") != "signout" {
		rc.redirect("/")
		return
	}
	s.beginSPLogout(rc, p.msg)
}

// beginSPLogout ends the session for a service provider's LogoutRequest
// and starts the chain to the other participants.
func (s *Server) beginSPLogout(rc *reqCtx, m *samlidp.LogoutMessage) {
	ctx := rc.ctx()
	c := &logoutChain{browser: rc.browserHash(), initiator: m.Issuer, initiatorReq: m.ID, initiatorRelay: m.RelayState, created: s.now()}
	if rc.sess != nil {
		rc.sess.mu.Lock()
		parts := append([]samlidp.Participant(nil), rc.sess.participants...)
		rc.sess.mu.Unlock()
		match := false
		for _, p := range parts {
			if p.EntityID == m.Issuer && p.NameID == m.NameID && (m.SessionIndex == "" || m.SessionIndex == p.SessionIndex) {
				match = true
			}
		}
		if match {
			for _, p := range parts {
				if p.EntityID != m.Issuer {
					c.pending = append(c.pending, p)
				}
			}
			s.endBrowserSession(rc, "saml single logout requested by "+m.Issuer)
		} else {
			// The request names another session (already ended here, or
			// another user's): nothing to end in this browser.
			s.audit(ctx, rc, "saml.slo", m.Issuer, "request does not match this browser's session", store.ResultOK)
		}
	}
	s.continueLogout(rc, c)
}

// signOut ends the browser session and, when SAML service providers took
// part in it, logs them out before going to target.
func (s *Server) signOut(rc *reqCtx, detail, target string) {
	var parts []samlidp.Participant
	if rc.sess != nil {
		rc.sess.mu.Lock()
		parts = append(parts, rc.sess.participants...)
		rc.sess.mu.Unlock()
	}
	s.endBrowserSession(rc, detail)
	if len(parts) == 0 || s.saml == nil {
		s.leaveTo(rc, target)
		return
	}
	s.continueLogout(rc, &logoutChain{browser: rc.browserHash(), pending: parts, final: target, created: s.now()})
}

// continueLogout sends the next LogoutRequest, or ends the chain.
func (s *Server) continueLogout(rc *reqCtx, c *logoutChain) {
	ctx, cancel := context.WithTimeout(rc.ctx(), requestTimeout)
	defer cancel()
	for len(c.pending) > 0 {
		p := c.pending[0]
		c.pending = c.pending[1:]
		sp, err := s.store.GetSP(ctx, p.EntityID)
		if err != nil || !sp.Enabled || sp.SLOURL == "" {
			// An SP without single logout keeps its own session: the
			// logout is partial (a disabled or removed SP does not count).
			if err == nil && sp.Enabled {
				c.partial = true
			}
			continue
		}
		out, err := s.saml.LogoutRequestTo(ctx, sp, p, "")
		if err != nil {
			s.log.Error("SAML logout request failed", "sp", sp.EntityID, "err", err)
			c.partial = true
			continue
		}
		c.current = sp.EntityID
		s.logouts.put(out.ID, c)
		s.audit(ctx, rc, "saml.slo", sp.EntityID, "logout request sent", store.ResultPending)
		s.deliverLogout(rc, sp.Name, out)
		return
	}
	if c.initiator == "" {
		s.leaveTo(rc, c.final)
		return
	}
	sp, err := s.store.GetSP(ctx, c.initiator)
	if err != nil || !sp.Enabled || sp.SLOURL == "" {
		rc.redirect("/logged-out")
		return
	}
	status := saml.StatusSuccess
	if c.partial {
		status = saml.StatusPartialLogout
	}
	out, err := s.saml.LogoutResponseTo(ctx, sp, c.initiatorReq, status, c.initiatorRelay)
	if err != nil {
		s.log.Error("SAML logout response failed", "sp", sp.EntityID, "err", err)
		rc.redirect("/logged-out")
		return
	}
	s.audit(ctx, rc, "saml.slo", sp.EntityID, "logout response sent: "+status, store.ResultOK)
	s.deliverLogout(rc, sp.Name, out)
}

func (s *Server) deliverLogout(rc *reqCtx, app string, out *samlidp.Outgoing) {
	if out.RedirectURL != "" {
		http.Redirect(rc.w, rc.r, out.RedirectURL, http.StatusSeeOther)
		return
	}
	rc.formTargets = append(rc.formTargets, out.Form.URL)
	rc.render(http.StatusOK, "slo_post", map[string]any{"App": app, "Form": out.Form})
}

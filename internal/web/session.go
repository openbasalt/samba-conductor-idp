package web

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"github.com/openbasalt/samba-conductor-idp/internal/samlidp"
	"net/http"
	"sync"
	"time"
)

// Cookie names. The __Host- prefix makes the browser refuse them unless
// Secure, Path=/ and without Domain: no subdomain can plant or read them.
const (
	// sessionCookie is the single sign-on session. SameSite=Lax (not
	// Strict): relying parties send the browser here through cross-site
	// redirects, and a Strict cookie would not come with them, so every
	// sign-in would ask for the password again. State-changing requests
	// are still protected by CSRF tokens and Origin checks.
	sessionCookie = "__Host-idp-session"
	// preCookie carries the CSRF token of the sign-in form (double submit).
	preCookie = "__Host-idp-pre"
	// adminSessionCookie and adminPreCookie replace them on a separate
	// admin listener (server.admin_listen): browsers do not isolate
	// cookies by port, so distinct names (and a separate session table)
	// keep a session of one listener from being presented to the other.
	adminSessionCookie = "__Host-idp-admin-session"
	adminPreCookie     = "__Host-idp-admin-pre"
	// browserCookie identifies the browser an authorization request or a
	// SAML request was continued in; codes are only released to it.
	browserCookie = "__Host-idp-browser"
)

// stage is where a session is in the sign-in flow.
type stage int

const (
	// stageMustChange: the password was right but must be changed.
	stageMustChange stage = iota + 1
	// stageMFA: password verified, second factor pending.
	stageMFA
	// stageEnroll: password verified, 2FA enrollment required first.
	stageEnroll
	// stageFull: signed in.
	stageFull
)

func (s stage) String() string {
	switch s {
	case stageMustChange:
		return "must-change"
	case stageMFA:
		return "mfa"
	case stageEnroll:
		return "enroll"
	case stageFull:
		return "full"
	}
	return "unknown"
}

// Session is one browser's sign-in. Nothing secret about the user is
// kept: the password is forgotten after verification.
type Session struct {
	mu sync.Mutex

	hash      string // SHA-256 of the cookie value (the map key)
	stage     stage
	sam       string // lower-cased sAMAccountName
	guid      string // objectGUID (OIDC subject)
	userSID   string
	name      string
	csrf      string
	created   time.Time
	lastSeen  time.Time
	expires   time.Time // absolute
	authTime  time.Time // when the password was verified
	ip        string
	userAgent string

	mfaVerified bool
	admin       bool
	adminAt     time.Time

	// enrollment in progress (sealed secret), the admin link it uses and
	// recovery codes to show once
	enrollSealed  []byte
	enrollLink    string
	recoveryCodes []string
	mfaFailures   int
	flashes       []flash
	// keyCeremony is the pending security key assertion (conductor's
	// ceremony ID, single use).
	keyCeremony string
	// participants are the SAML service providers this session signed in
	// to (single logout).
	participants []samlidp.Participant
}

type flash struct {
	Kind string // "ok", "error", "info"
	Msg  string // already translated
}

func (s *Session) addFlash(kind, msg string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.flashes = append(s.flashes, flash{Kind: kind, Msg: msg})
}

func (s *Session) takeFlashes() []flash {
	s.mu.Lock()
	defer s.mu.Unlock()
	f := s.flashes
	s.flashes = nil
	return f
}

func (s *Session) snapshotStage() stage {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.stage
}

// amr is the authentication methods reference of this sign-in (RFC 8176).
func (s *Session) amr() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.mfaVerified {
		return []string{"pwd", "otp", "mfa"}
	}
	return []string{"pwd"}
}

// sessions is the in-memory session table: a restart signs everyone out
// of the idp (relying parties keep their own sessions and tokens).
type sessions struct {
	mu       sync.Mutex
	m        map[string]*Session
	idle     time.Duration
	absolute time.Duration
	now      func() time.Time
}

// maxSessions bounds memory; beyond it the oldest sessions are dropped.
const maxSessions = 50_000

func newSessions(idle, absolute time.Duration, now func() time.Time) *sessions {
	return &sessions{m: map[string]*Session{}, idle: idle, absolute: absolute, now: now}
}

// setTimeouts changes the lifetimes. A shorter absolute lifetime also
// shortens running sessions (never lengthens them).
func (t *sessions) setTimeouts(idle, absolute time.Duration) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.idle, t.absolute = idle, absolute
	for _, s := range t.m {
		s.mu.Lock()
		if limit := s.created.Add(absolute); limit.Before(s.expires) {
			s.expires = limit
		}
		s.mu.Unlock()
	}
}

func newToken() string {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		panic("web: crypto/rand failed: " + err.Error())
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

func tokenHash(tok string) string {
	h := sha256.Sum256([]byte("idp-session\x00" + tok))
	return hex.EncodeToString(h[:])
}

func tokensEqual(a, b string) bool {
	return a != "" && len(a) == len(b) && subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}

// create stores a new session and returns its cookie value.
func (t *sessions) create(s *Session) string {
	tok := newToken()
	now := t.now()
	s.hash = tokenHash(tok)
	s.csrf = newToken()
	t.mu.Lock()
	defer t.mu.Unlock()
	s.created, s.lastSeen, s.expires = now, now, now.Add(t.absolute)
	if len(t.m) >= maxSessions {
		t.evictLocked(now)
	}
	t.m[s.hash] = s
	return tok
}

// get returns a live session for a cookie value and refreshes its idle
// timer.
func (t *sessions) get(tok string) *Session {
	if tok == "" || len(tok) > 64 {
		return nil
	}
	h := tokenHash(tok)
	now := t.now()
	t.mu.Lock()
	s, ok := t.m[h]
	idle := t.idle
	t.mu.Unlock()
	if !ok {
		return nil
	}
	// Lock order is table then session: never hold the session's lock
	// while taking the table's.
	s.mu.Lock()
	dead := now.After(s.expires) || now.Sub(s.lastSeen) > idle
	if !dead {
		s.lastSeen = now
	}
	s.mu.Unlock()
	if dead {
		t.mu.Lock()
		delete(t.m, h)
		t.mu.Unlock()
		return nil
	}
	return s
}

// rotate gives a session a new cookie value and CSRF token (after a
// privilege change: second factor verified) and moves it to a stage.
func (t *sessions) rotate(s *Session, next stage) string {
	tok := newToken()
	t.mu.Lock()
	delete(t.m, s.hash)
	s.mu.Lock()
	s.hash = tokenHash(tok)
	s.csrf = newToken()
	s.stage = next
	s.mu.Unlock()
	t.m[s.hash] = s
	t.mu.Unlock()
	return tok
}

func (t *sessions) destroy(s *Session) {
	if s == nil {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	s.mu.Lock()
	delete(t.m, s.hash)
	s.mu.Unlock()
}

// destroyUser ends every session of a user (sign out everywhere).
func (t *sessions) destroyUser(guid string) int {
	t.mu.Lock()
	defer t.mu.Unlock()
	n := 0
	for h, s := range t.m {
		s.mu.Lock()
		match := s.guid == guid
		s.mu.Unlock()
		if match {
			delete(t.m, h)
			n++
		}
	}
	return n
}

func (t *sessions) sweep() {
	now := t.now()
	t.mu.Lock()
	defer t.mu.Unlock()
	for h, s := range t.m {
		s.mu.Lock()
		dead := now.After(s.expires) || now.Sub(s.lastSeen) > t.idle
		s.mu.Unlock()
		if dead {
			delete(t.m, h)
		}
	}
}

func (t *sessions) evictLocked(now time.Time) {
	var oldestKey string
	var oldest time.Time
	for h, s := range t.m {
		if now.After(s.expires) || now.Sub(s.lastSeen) > t.idle {
			delete(t.m, h)
			continue
		}
		if oldestKey == "" || s.lastSeen.Before(oldest) {
			oldestKey, oldest = h, s.lastSeen
		}
	}
	if len(t.m) >= maxSessions && oldestKey != "" {
		delete(t.m, oldestKey)
	}
}

// setCookie writes a __Host- cookie. maxAge 0 = browser session cookie.
func setCookie(w http.ResponseWriter, name, value string, maxAge int, sameSite http.SameSite) {
	http.SetCookie(w, &http.Cookie{Name: name, Value: value, Path: "/", MaxAge: maxAge, Secure: true, HttpOnly: true, SameSite: sameSite})
}

// setSessionCookie writes this listener's session cookie.
func (s *Server) setSessionCookie(w http.ResponseWriter, tok string) {
	setCookie(w, s.sessionName, tok, 0, s.sessionSite)
}

// clearSessionCookie removes this listener's session cookie.
func (s *Server) clearSessionCookie(w http.ResponseWriter) { clearCookie(w, s.sessionName) }

func clearCookie(w http.ResponseWriter, name string) {
	http.SetCookie(w, &http.Cookie{Name: name, Value: "", Path: "/", MaxAge: -1, Secure: true, HttpOnly: true, SameSite: http.SameSiteLaxMode})
}

// endSessionTickets are one-time references from the end_session endpoint
// to the page that ends the browser session and redirects.
type endSessionTickets struct {
	mu  sync.Mutex
	m   map[string]endSessionTicket
	now func() time.Time
}

type endSessionTicket struct {
	subject string
	client  string
	target  string
	hinted  bool
	expires time.Time
}

func newEndSessionTickets(now func() time.Time) *endSessionTickets {
	return &endSessionTickets{m: map[string]endSessionTicket{}, now: now}
}

func (e *endSessionTickets) put(t endSessionTicket) string {
	tok := newToken()
	t.expires = e.now().Add(10 * time.Minute)
	e.mu.Lock()
	defer e.mu.Unlock()
	if len(e.m) >= 10_000 {
		clear(e.m)
	}
	e.m[tok] = t
	return tok
}

func (e *endSessionTickets) take(tok string) (endSessionTicket, bool) {
	e.mu.Lock()
	defer e.mu.Unlock()
	t, ok := e.m[tok]
	delete(e.m, tok)
	if !ok || e.now().After(t.expires) {
		return endSessionTicket{}, false
	}
	return t, true
}

func (e *endSessionTickets) peek(tok string) (endSessionTicket, bool) {
	e.mu.Lock()
	defer e.mu.Unlock()
	t, ok := e.m[tok]
	if !ok || e.now().After(t.expires) {
		return endSessionTicket{}, false
	}
	return t, true
}

func (e *endSessionTickets) sweep() {
	now := e.now()
	e.mu.Lock()
	defer e.mu.Unlock()
	for k, t := range e.m {
		if now.After(t.expires) {
			delete(e.m, k)
		}
	}
}

package web

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net/http"
	"net/url"
	"regexp"
	"strings"

	"github.com/samba-conductor/ad"
	"github.com/samba-conductor/ad/sid"
	"github.com/samba-conductor/conductor-idp/internal/config"
	"github.com/samba-conductor/conductor-idp/internal/directory"
	"github.com/samba-conductor/conductor-idp/internal/mfa"
	"github.com/samba-conductor/conductor-idp/internal/store"
	"github.com/samba-conductor/conductor-idp/internal/totp"
	"rsc.io/qr"
)

// loginMessages are the only notes /login?m= may show.
var loginMessages = map[string]string{
	"signed_out":       "signin.msg.signed_out",
	"password_changed": "signin.msg.password_changed",
	"mfa_required":     "signin.msg.mfa_required",
	"expired":          "signin.msg.expired",
}

// cont is where a sign-in continues once complete: an OIDC authorization
// request ("o.<id>"), a SAML request ("s.<id>") or nothing.
type cont struct {
	kind byte // 'o', 's' or 0
	id   string
}

var contRE = regexp.MustCompile(`^[os]\.[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)

func parseCont(v string) cont {
	if !contRE.MatchString(v) {
		return cont{}
	}
	return cont{kind: v[0], id: v[2:]}
}

func (c cont) String() string {
	if c.kind == 0 {
		return ""
	}
	return string(c.kind) + "." + c.id
}

// with appends the continuation to a path.
func (c cont) with(path string) string {
	if c.kind == 0 {
		return path
	}
	sep := "?"
	if strings.Contains(path, "?") {
		sep = "&"
	}
	return path + sep + "c=" + url.QueryEscape(c.String())
}

func (rc *reqCtx) cont() cont {
	if v := rc.r.URL.Query().Get("c"); v != "" {
		return parseCont(v)
	}
	if rc.r.Method == http.MethodPost {
		return parseCont(rc.r.PostFormValue("c"))
	}
	return cont{}
}

func (rc *reqCtx) form(name string) string { return strings.TrimSpace(rc.r.PostFormValue(name)) }

// rawForm returns a form value untrimmed (passwords).
func (rc *reqCtx) rawForm(name string) string { return rc.r.PostFormValue(name) }

func (rc *reqCtx) flashOK(key string, args ...any) {
	if rc.sess != nil {
		rc.sess.addFlash("ok", rc.T(key, args...))
	}
}

// ensurePreCookie sets the pre-session CSRF cookie of the sign-in form.
func (rc *reqCtx) ensurePreCookie() string {
	if c, err := rc.r.Cookie(preCookie); err == nil && len(c.Value) >= 32 && len(c.Value) <= 64 {
		return c.Value
	}
	tok := newToken()
	setCookie(rc.w, preCookie, tok, 3600, http.SameSiteStrictMode)
	rc.r.AddCookie(&http.Cookie{Name: preCookie, Value: tok})
	return tok
}

// browserHash identifies this browser for request binding, setting the
// cookie on first use.
func (rc *reqCtx) browserHash() string {
	v := ""
	if c, err := rc.r.Cookie(browserCookie); err == nil && len(c.Value) >= 32 && len(c.Value) <= 64 {
		v = c.Value
	} else {
		v = newToken()
		setCookie(rc.w, browserCookie, v, 30*24*3600, http.SameSiteLaxMode)
		rc.r.AddCookie(&http.Cookie{Name: browserCookie, Value: v})
	}
	h := sha256.Sum256([]byte("idp-browser\x00" + v))
	return hex.EncodeToString(h[:])
}

// existingBrowserHash returns the hash of the browser cookie, or "" when
// the browser has none (never set it here: a request without it is not
// the browser that started the flow).
func (rc *reqCtx) existingBrowserHash() string {
	c, err := rc.r.Cookie(browserCookie)
	if err != nil || len(c.Value) < 32 || len(c.Value) > 64 {
		return ""
	}
	h := sha256.Sum256([]byte("idp-browser\x00" + c.Value))
	return hex.EncodeToString(h[:])
}

func cleanLinkToken(t string) string {
	if len(t) < 32 || len(t) > 64 || strings.ContainsFunc(t, func(r rune) bool {
		return (r < 'a' || r > 'z') && (r < 'A' || r > 'Z') && (r < '0' || r > '9') && r != '-' && r != '_'
	}) {
		return ""
	}
	return t
}

// LinkHash is the stored form of an enrollment link token.
func LinkHash(tok string) string {
	h := sha256.Sum256([]byte("idp-enroll\x00" + tok))
	return hex.EncodeToString(h[:])
}

// userIsAdmin reports whether group SIDs include an administrator group.
func (s *Server) userIsAdmin(ctx context.Context, groups []sid.SID, active bool) (bool, error) {
	if !active {
		return false, nil
	}
	admins := s.adminSIDs
	if len(admins) == 0 {
		da, err := s.dir.DomainAdminsSID(ctx)
		if err != nil {
			return false, err
		}
		admins = []sid.SID{da}
	}
	for _, a := range admins {
		if sid.Contains(groups, a) {
			return true, nil
		}
	}
	return false, nil
}

// ---- sign-in page ----

func (s *Server) handleLoginPage(rc *reqCtx) {
	q := rc.r.URL.Query()
	c := rc.cont()
	if ar := q.Get("ar"); ar != "" {
		c = parseCont("o." + ar)
		if c.kind == 0 {
			rc.errorPage(http.StatusBadRequest, "err.flow")
			return
		}
	}
	if c.kind == 'o' {
		if s.startOIDC(rc, c) {
			return
		}
	} else if c.kind == 's' {
		if s.startSAML(rc, c) {
			return
		}
	} else if rc.sess != nil {
		switch rc.sess.snapshotStage() {
		case stageFull:
			rc.redirect("/")
			return
		case stageMFA:
			rc.redirect("/login/2fa")
			return
		case stageEnroll:
			rc.redirect("/login/enroll")
			return
		case stageMustChange:
			rc.redirect("/login/password")
			return
		}
	}
	s.showLogin(rc, c, "", http.StatusOK)
}

// showLogin renders the sign-in form.
func (s *Server) showLogin(rc *reqCtx, c cont, username string, status int) {
	rc.ensurePreCookie()
	d := map[string]any{"C": c.String(), "Username": username, "Enroll": cleanLinkToken(rc.r.URL.Query().Get("enroll"))}
	if k, ok := loginMessages[rc.r.URL.Query().Get("m")]; ok {
		d["Notice"] = rc.T(k)
	}
	s.flowInfo(rc, c, d)
	rc.render(status, "login", d)
}

func (s *Server) loginError(rc *reqCtx, c cont, status int, key, username, enroll string) {
	rc.ensurePreCookie()
	d := map[string]any{"C": c.String(), "Error": rc.T(key), "Username": username, "Enroll": enroll}
	s.flowInfo(rc, c, d)
	rc.render(status, "login", d)
}

// flowInfo names the application being signed in to and allows the
// page's forms to continue to it.
func (s *Server) flowInfo(rc *reqCtx, c cont, d map[string]any) {
	ctx := rc.ctx()
	switch c.kind {
	case 'o':
		ar, err := s.store.GetAuthRequest(ctx, c.id)
		if err != nil {
			return
		}
		if cl, err := s.store.GetClient(ctx, ar.ClientID); err == nil {
			d["App"] = cl.Name
		}
		rc.formTargets = append(rc.formTargets, ar.RedirectURI)
	case 's':
		p, err := s.store.GetSAMLPending(ctx, c.id)
		if err != nil {
			return
		}
		if sp, err := s.store.GetSP(ctx, p.EntityID); err == nil {
			d["App"] = sp.Name
			rc.formTargets = append(rc.formTargets, sp.ACSURLs...)
		}
	}
}

func clipName(s string) string {
	if len(s) > 64 {
		s = s[:64]
	}
	return strings.Map(func(r rune) rune {
		if r < 0x20 {
			return -1
		}
		return r
	}, s)
}

func (s *Server) handleLogin(rc *reqCtx) {
	ctx, cancel := context.WithTimeout(rc.ctx(), requestTimeout)
	defer cancel()
	c := rc.cont()
	typed := rc.form("username")
	password := rc.rawForm("password")
	enroll := cleanLinkToken(rc.form("enroll"))
	rc.actorHint = clipName(typed)
	if !s.ipLimit.Allow("login:" + rc.ip) {
		s.audit(ctx, rc, "signin.rate_limited", rc.ip, "per-address limit", store.ResultDenied)
		s.loginError(rc, c, http.StatusTooManyRequests, "signin.err.rate_ip", typed, enroll)
		return
	}
	sam, ok := directory.NormalizeUsername(typed, s.dir.Realm())
	if !ok || password == "" {
		s.loginError(rc, c, http.StatusUnauthorized, "signin.err.invalid", typed, enroll)
		return
	}
	rc.actorHint = sam
	if s.accountFails.Blocked(sam) {
		s.audit(ctx, rc, "signin.rate_limited", sam, "per-account limit", store.ResultDenied)
		s.loginError(rc, c, http.StatusTooManyRequests, "signin.err.rate_account", typed, enroll)
		return
	}
	if err := s.dir.Authenticate(ctx, sam, password); err != nil {
		s.loginFailed(rc, ctx, c, sam, typed, enroll, err)
		return
	}
	u, err := s.dir.UserBySAM(ctx, sam)
	if err != nil {
		s.log.Error("user lookup after sign-in failed", "user", sam, "err", err)
		s.audit(ctx, rc, "signin.failure", sam, "directory lookup failed", store.ResultFailed)
		s.loginError(rc, c, http.StatusBadGateway, "err.directory", typed, enroll)
		return
	}
	s.accountFails.Reset(sam)
	admin, err := s.userIsAdmin(ctx, u.GroupSIDs, u.Active())
	if err != nil {
		s.log.Error("admin check failed", "err", err)
		s.loginError(rc, c, http.StatusBadGateway, "err.directory", typed, enroll)
		return
	}
	enrolled, err := s.mfa.Enrolled(ctx, u)
	if err != nil {
		// Fail closed: never skip a second factor because its store is down.
		s.log.Error("reading 2FA state", "backend", s.mfa.Name(), "err", err)
		s.audit(ctx, rc, "signin.failure", sam, "2FA backend unavailable", store.ResultFailed)
		s.loginError(rc, c, http.StatusServiceUnavailable, "err.mfa_unavailable", typed, enroll)
		return
	}
	// A new sign-in replaces whatever session this browser had.
	if rc.sess != nil {
		s.sess.destroy(rc.sess)
	}
	sess := &Session{sam: strings.ToLower(u.SAM), guid: u.GUID, userSID: u.SID.String(), name: u.Name(), ip: rc.ip,
		userAgent: rc.r.UserAgent(), authTime: s.now().UTC(), admin: admin, adminAt: s.now()}
	need := admin || s.cfg.MFA.Policy == config.MFARequired || s.flowRequiresMFA(ctx, c)
	switch {
	case enrolled && (need || s.cfg.MFA.Policy != config.MFAOff):
		sess.stage = stageMFA
	case need && s.local == nil:
		s.audit(ctx, rc, "signin.failure", sam, "2FA required but not enrolled (enroll in conductor)", store.ResultDenied)
		s.loginError(rc, c, http.StatusForbidden, "signin.err.enroll_in_conductor", typed, enroll)
		return
	case need:
		if admin && s.cfg.AdminEnrollmentLinkRequired() {
			valid := false
			if enroll != "" {
				valid, _ = s.store.ValidEnrollLink(ctx, LinkHash(enroll), sess.sam)
			}
			if !valid {
				s.audit(ctx, rc, "signin.failure", sam, "administrator without 2FA and without a valid enrollment link", store.ResultDenied)
				s.loginError(rc, c, http.StatusForbidden, "signin.err.admin_link", typed, "")
				return
			}
			sess.enrollLink = LinkHash(enroll)
		}
		sess.stage = stageEnroll
	default:
		sess.stage = stageFull
	}
	tok := s.sess.create(sess)
	setCookie(rc.w, sessionCookie, tok, 0, http.SameSiteLaxMode)
	clearCookie(rc.w, preCookie)
	rc.sess = sess
	s.audit(ctx, rc, "signin.password", sam, "next="+sess.stage.String()+" admin="+boolStr(admin)+" flow="+c.String(), store.ResultOK)
	switch sess.stage {
	case stageMFA:
		rc.redirect(c.with("/login/2fa"))
	case stageEnroll:
		rc.redirect(c.with("/login/enroll"))
	default:
		s.finish(rc, c)
	}
}

func boolStr(b bool) string {
	if b {
		return "yes"
	}
	return "no"
}

// flowRequiresMFA reports whether the application being signed in to
// demands a second factor.
func (s *Server) flowRequiresMFA(ctx context.Context, c cont) bool {
	switch c.kind {
	case 'o':
		if ar, err := s.store.GetAuthRequest(ctx, c.id); err == nil {
			if cl, err := s.store.GetClient(ctx, ar.ClientID); err == nil {
				return cl.RequireMFA
			}
		}
	case 's':
		if p, err := s.store.GetSAMLPending(ctx, c.id); err == nil {
			if sp, err := s.store.GetSP(ctx, p.EntityID); err == nil {
				return sp.RequireMFA
			}
		}
	}
	return false
}

// loginFailed maps a refused sign-in to a clear message. Only expired /
// must-change passwords (proven right by AD) lead to the change page.
func (s *Server) loginFailed(rc *reqCtx, ctx context.Context, c cont, sam, typed, enroll string, err error) {
	var ae *ad.AuthError
	if !errors.As(err, &ae) {
		s.log.Error("sign-in: directory unavailable", "user", sam, "err", err)
		s.audit(ctx, rc, "signin.failure", sam, "directory unavailable", store.ResultFailed)
		s.loginError(rc, c, http.StatusBadGateway, "err.directory", typed, enroll)
		return
	}
	detail := "reason=" + ae.Reason.String() + " code=" + ae.Code
	if ae.PasswordVerified() {
		if rc.sess != nil {
			s.sess.destroy(rc.sess)
		}
		sess := &Session{sam: sam, stage: stageMustChange, ip: rc.ip, userAgent: rc.r.UserAgent()}
		tok := s.sess.create(sess)
		setCookie(rc.w, sessionCookie, tok, 0, http.SameSiteLaxMode)
		clearCookie(rc.w, preCookie)
		rc.sess = sess
		s.audit(ctx, rc, "signin.password_change_required", sam, detail, store.ResultPending)
		rc.redirect(c.with("/login/password"))
		return
	}
	key := "signin.err.invalid"
	switch ae.Reason {
	case ad.ReasonAccountLocked:
		key = "signin.err.locked"
	case ad.ReasonAccountDisabled:
		key = "signin.err.disabled"
	case ad.ReasonAccountExpired:
		key = "signin.err.account_expired"
	case ad.ReasonLogonHours, ad.ReasonWorkstationRestricted, ad.ReasonAccountRestricted:
		key = "signin.err.restricted"
	case ad.ReasonClockSkew:
		key = "signin.err.clock"
	}
	if key == "signin.err.invalid" {
		s.accountFails.Fail(sam)
	}
	s.audit(ctx, rc, "signin.failure", sam, detail, store.ResultDenied)
	s.loginError(rc, c, http.StatusUnauthorized, key, typed, enroll)
}

// ---- password change for expired / must-change accounts ----

func (s *Server) handlePasswordPage(rc *reqCtx) {
	rc.sess.mu.Lock()
	sam := rc.sess.sam
	rc.sess.mu.Unlock()
	rc.render(http.StatusOK, "login_password", map[string]any{"Username": sam, "C": rc.cont().String()})
}

func (s *Server) handlePassword(rc *reqCtx) {
	ctx, cancel := context.WithTimeout(rc.ctx(), requestTimeout)
	defer cancel()
	c := rc.cont()
	rc.sess.mu.Lock()
	sam := rc.sess.sam
	rc.sess.mu.Unlock()
	fail := func(status int, key string) {
		rc.render(status, "login_password", map[string]any{"Username": sam, "C": c.String(), "Error": rc.T(key)})
	}
	if !s.ipLimit.Allow("login:" + rc.ip) {
		fail(http.StatusTooManyRequests, "signin.err.rate_ip")
		return
	}
	if s.accountFails.Blocked(sam) {
		fail(http.StatusTooManyRequests, "signin.err.rate_account")
		return
	}
	oldPw, newPw, confirm := rc.rawForm("current"), rc.rawForm("new"), rc.rawForm("confirm")
	if oldPw == "" || newPw == "" {
		fail(http.StatusBadRequest, "password.err.required")
		return
	}
	if newPw != confirm {
		fail(http.StatusBadRequest, "password.err.mismatch")
		return
	}
	if err := s.dir.ChangeExpiredPassword(ctx, sam, oldPw, newPw); err != nil {
		key, result := passwordChangeError(err)
		if key == "password.err.current" {
			s.accountFails.Fail(sam)
		}
		s.log.Info("expired password change refused", "user", sam, "err", err)
		s.audit(ctx, rc, "password.change_expired", sam, "", result)
		fail(http.StatusBadRequest, key)
		return
	}
	s.accountFails.Reset(sam)
	s.audit(ctx, rc, "password.change_expired", sam, "kpasswd (old password verified)", store.ResultOK)
	s.sess.destroy(rc.sess)
	clearCookie(rc.w, sessionCookie)
	rc.redirect(c.with("/login?m=password_changed"))
}

// passwordChangeError maps a password change error to a message.
func passwordChangeError(err error) (string, string) {
	var ae *ad.AuthError
	switch {
	case errors.As(err, &ae) && ae.Reason == ad.ReasonInvalidCredentials, errors.Is(err, ad.ErrWrongPassword):
		return "password.err.current", store.ResultDenied
	case errors.As(err, &ae):
		return "signin.err.restricted", store.ResultDenied
	case errors.Is(err, ad.ErrPasswordPolicy):
		return "password.err.policy", store.ResultFailed
	case errors.Is(err, ad.ErrAccessDenied):
		return "password.err.policy", store.ResultDenied
	}
	return "err.directory", store.ResultFailed
}

// ---- second factor ----

// maxMFAFailures per session before the session ends.
const maxMFAFailures = 5

func (s *Server) handleMFAPage(rc *reqCtx) {
	rc.render(http.StatusOK, "login_2fa", s.mfaData(rc, ""))
}

func (s *Server) mfaData(rc *reqCtx, errMsg string) map[string]any {
	c := rc.cont()
	d := map[string]any{"C": c.String(), "Error": errMsg, "StepUp": rc.sess.snapshotStage() == stageFull}
	s.flowInfo(rc, c, d)
	return d
}

// sessionUser re-reads the session's user.
func (s *Server) sessionUser(ctx context.Context, sess *Session) (*directory.User, error) {
	sess.mu.Lock()
	guid := sess.guid
	sess.mu.Unlock()
	return s.dir.UserByGUID(ctx, guid)
}

func (s *Server) handleMFA(rc *reqCtx) {
	ctx, cancel := context.WithTimeout(rc.ctx(), requestTimeout)
	defer cancel()
	c := rc.cont()
	sess := rc.sess
	sess.mu.Lock()
	sam := sess.sam
	sess.mu.Unlock()
	rc.actorHint = sam
	if !s.ipLimit.Allow("mfa:" + rc.ip) {
		rc.render(http.StatusTooManyRequests, "login_2fa", s.mfaData(rc, rc.T("signin.err.rate_ip")))
		return
	}
	u, err := s.sessionUser(ctx, sess)
	if err != nil || !u.Active() {
		s.sess.destroy(sess)
		clearCookie(rc.w, sessionCookie)
		rc.redirect(c.with("/login"))
		return
	}
	res, err := s.mfa.Verify(ctx, u, rc.form("code"))
	if err != nil {
		s.log.Error("2FA verification failed", "backend", s.mfa.Name(), "err", err)
		key := "err.mfa_unavailable"
		if !errors.Is(err, mfa.ErrUnavailable) {
			key = "mfa.err.invalid"
		}
		rc.render(http.StatusServiceUnavailable, "login_2fa", s.mfaData(rc, rc.T(key)))
		return
	}
	if !res.OK {
		sess.mu.Lock()
		sess.mfaFailures++
		n := sess.mfaFailures
		sess.mu.Unlock()
		s.audit(ctx, rc, "mfa.failure", sam, "", store.ResultDenied)
		if n >= maxMFAFailures {
			s.sess.destroy(sess)
			clearCookie(rc.w, sessionCookie)
			rc.redirect(c.with("/login"))
			return
		}
		rc.render(http.StatusUnauthorized, "login_2fa", s.mfaData(rc, rc.T("mfa.err.invalid")))
		return
	}
	sess.mu.Lock()
	sess.mfaVerified = true
	sess.mfaFailures = 0
	sess.mu.Unlock()
	tok := s.sess.rotate(sess, stageFull)
	setCookie(rc.w, sessionCookie, tok, 0, http.SameSiteLaxMode)
	detail := "totp"
	if res.Recovery {
		detail = "recovery code"
		rc.flashOK("mfa.recovery_used")
	}
	s.audit(ctx, rc, "mfa.verify", sam, detail+" backend="+s.mfa.Name(), store.ResultOK)
	s.finish(rc, c)
}

// ---- enrollment (local backend) ----

func (s *Server) enrollData(rc *reqCtx, u *directory.User, sec []byte, errMsg string) map[string]any {
	c := rc.cont()
	d := map[string]any{"C": c.String(), "Error": errMsg, "Secret": totp.EncodeSecret(sec), "Account": u.SAM,
		"Issuer": s.cfg.MFA.Issuer, "QR": c.with("/login/enroll/qr.png")}
	s.flowInfo(rc, c, d)
	return d
}

// pendingSecret returns the enrollment secret of the session, creating
// one on first use.
func (s *Server) pendingSecret(sess *Session, u *directory.User) ([]byte, error) {
	sess.mu.Lock()
	sealed := sess.enrollSealed
	sess.mu.Unlock()
	if sealed != nil {
		return s.local.OpenPending(u, sealed)
	}
	sec, err := totp.NewSecret()
	if err != nil {
		return nil, err
	}
	sealed, err = s.local.Seal(u, sec)
	if err != nil {
		return nil, err
	}
	sess.mu.Lock()
	sess.enrollSealed = sealed
	sess.mu.Unlock()
	return sec, nil
}

func (s *Server) enrollAllowed(rc *reqCtx) (*directory.User, bool) {
	if s.local == nil {
		rc.errorPage(http.StatusNotFound, "err.not_found")
		return nil, false
	}
	u, err := s.sessionUser(rc.ctx(), rc.sess)
	if err != nil {
		rc.errorPage(http.StatusBadGateway, "err.directory")
		return nil, false
	}
	if rc.sess.snapshotStage() == stageFull {
		// Voluntary enrollment: only for users without 2FA yet.
		if enrolled, err := s.mfa.Enrolled(rc.ctx(), u); err != nil || enrolled {
			rc.redirect("/")
			return nil, false
		}
	}
	return u, true
}

func (s *Server) handleEnrollPage(rc *reqCtx) {
	u, ok := s.enrollAllowed(rc)
	if !ok {
		return
	}
	sec, err := s.pendingSecret(rc.sess, u)
	if err != nil {
		rc.errorPage(http.StatusInternalServerError, "err.internal")
		return
	}
	defer clear(sec)
	rc.render(http.StatusOK, "enroll", s.enrollData(rc, u, sec, ""))
}

func (s *Server) handleEnrollQR(rc *reqCtx) {
	u, ok := s.enrollAllowed(rc)
	if !ok {
		return
	}
	sec, err := s.pendingSecret(rc.sess, u)
	if err != nil {
		http.Error(rc.w, "internal error", http.StatusInternalServerError)
		return
	}
	defer clear(sec)
	code, err := qr.Encode(totp.URI(s.cfg.MFA.Issuer, u.SAM, sec), qr.M)
	if err != nil {
		http.Error(rc.w, "internal error", http.StatusInternalServerError)
		return
	}
	code.Scale = 6
	rc.w.Header().Set("Content-Type", "image/png")
	_, _ = rc.w.Write(code.PNG())
}

func (s *Server) handleEnroll(rc *reqCtx) {
	ctx, cancel := context.WithTimeout(rc.ctx(), requestTimeout)
	defer cancel()
	u, ok := s.enrollAllowed(rc)
	if !ok {
		return
	}
	c := rc.cont()
	sess := rc.sess
	if !s.ipLimit.Allow("mfa:" + rc.ip) {
		rc.errorPage(http.StatusTooManyRequests, "signin.err.rate_ip")
		return
	}
	sec, err := s.pendingSecret(sess, u)
	if err != nil {
		rc.errorPage(http.StatusInternalServerError, "err.internal")
		return
	}
	defer clear(sec)
	sess.mu.Lock()
	link := sess.enrollLink
	sess.mu.Unlock()
	if link != "" {
		// The administrator's one-time link is consumed with the
		// enrollment (it was checked at sign-in, it must still be valid).
		if ok, err := s.store.UseEnrollLink(ctx, link, u.SAM); err != nil || !ok {
			s.audit(ctx, rc, "mfa.enroll", u.SAM, "enrollment link no longer valid", store.ResultDenied)
			s.sess.destroy(sess)
			clearCookie(rc.w, sessionCookie)
			rc.redirect(c.with("/login"))
			return
		}
	}
	codes, ok, err := s.local.Enroll(ctx, u, sec, rc.form("code"))
	if err != nil {
		rc.errorPage(http.StatusInternalServerError, "err.internal")
		return
	}
	if !ok {
		rc.render(http.StatusBadRequest, "enroll", s.enrollData(rc, u, sec, rc.T("enroll.err.code")))
		return
	}
	sess.mu.Lock()
	sess.enrollSealed = nil
	sess.enrollLink = ""
	sess.mfaVerified = true
	sess.recoveryCodes = codes
	sess.mu.Unlock()
	tok := s.sess.rotate(sess, stageFull)
	setCookie(rc.w, sessionCookie, tok, 0, http.SameSiteLaxMode)
	s.audit(ctx, rc, "mfa.enroll", u.SAM, "totp + recovery codes (local)", store.ResultOK)
	rc.redirect(c.with("/login/recovery-codes"))
}

func (s *Server) handleRecoveryCodes(rc *reqCtx) {
	rc.sess.mu.Lock()
	codes := rc.sess.recoveryCodes
	rc.sess.recoveryCodes = nil
	rc.sess.mu.Unlock()
	if len(codes) == 0 {
		s.finish(rc, rc.cont())
		return
	}
	c := rc.cont()
	d := map[string]any{"Codes": codes, "C": c.String()}
	s.flowInfo(rc, c, d)
	rc.render(http.StatusOK, "recovery_codes", d)
}

func (s *Server) handleContinue(rc *reqCtx) { s.finish(rc, rc.cont()) }

// ---- sign out ----

func (s *Server) handleLogout(rc *reqCtx) {
	if rc.sess != nil {
		s.audit(rc.ctx(), rc, "signout", "", "", store.ResultOK)
		s.sess.destroy(rc.sess)
	}
	clearCookie(rc.w, sessionCookie)
	rc.redirect("/login?m=signed_out")
}

func (s *Server) handleLoggedOut(rc *reqCtx) {
	rc.render(http.StatusOK, "logged_out", nil)
}

// requiresEnrollment reports whether the session's user lacks 2FA but
// the flow needs it (step-up for an application that requires it).
func (s *Server) stepUp(rc *reqCtx, c cont, u *directory.User) {
	enrolled, err := s.mfa.Enrolled(rc.ctx(), u)
	switch {
	case err != nil:
		rc.errorPage(http.StatusServiceUnavailable, "err.mfa_unavailable")
	case enrolled:
		rc.redirect(c.with("/login/2fa"))
	case s.local != nil:
		rc.redirect(c.with("/login/enroll"))
	default:
		rc.errorPage(http.StatusForbidden, "signin.err.enroll_in_conductor")
	}
}

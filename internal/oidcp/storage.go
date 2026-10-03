// Package oidcp is the OpenID Connect provider of conductor-idp: the
// github.com/zitadel/oidc/v3 op package (OpenID certified) running on our
// own SQLite storage, with users and groups read from Samba AD.
//
// Policy enforced on top of the library:
//   - Authorization Code + PKCE (S256) for every client, confidential ones
//     also authenticating with client_secret_basic; no implicit, hybrid,
//     password, client-credentials, device or JWT-bearer grants; responses
//     in the query string only;
//   - authorization codes and refresh tokens stored as SHA-256 hashes; a
//     code works once, and a second use revokes what the first one issued;
//   - refresh tokens rotate on every use; presenting a rotated token
//     revokes its whole chain (and the access tokens it minted); every
//     refresh re-checks the account in AD (enabled, not locked, still in
//     the client's allowed groups);
//   - claims only for scopes the client is registered for, groups by name
//     or SID per client.
package oidcp

import (
	"context"
	"errors"
	"log/slog"
	"slices"
	"strings"
	"time"

	jose "github.com/go-jose/go-jose/v4"
	"github.com/google/uuid"
	"github.com/zitadel/oidc/v3/pkg/oidc"
	"github.com/zitadel/oidc/v3/pkg/op"

	"github.com/samba-conductor/ad/sid"
	"github.com/samba-conductor/conductor-idp/internal/directory"
	"github.com/samba-conductor/conductor-idp/internal/secret"
	"github.com/samba-conductor/conductor-idp/internal/store"
)

// Scopes beyond the standard ones.
const (
	ScopeGroups = "groups"
)

// SupportedScopes is advertised in the discovery document and is what a
// client may be registered for.
var SupportedScopes = []string{oidc.ScopeOpenID, oidc.ScopeProfile, oidc.ScopeEmail, ScopeGroups, oidc.ScopeOfflineAccess}

// Paths of the provider's endpoints (relative to the issuer).
const (
	LoginPath     = "/login"
	CallbackPath  = "/authorize/callback"
	AuthorizePath = "/authorize"
	TokenPath     = "/oauth/token"
	UserinfoPath  = "/userinfo"
	RevokePath    = "/oauth/revoke"
	EndSession    = "/end_session"
	KeysPath      = "/keys"
	Discovery     = "/.well-known/openid-configuration"
	RefreshPrefix = "cidp_rt_"
	authReqTTL    = 15 * time.Minute
	codeTTL       = time.Minute
)

// Lifetimes configure tokens.
type Lifetimes struct {
	IDToken     time.Duration
	AccessToken time.Duration
	Refresh     time.Duration // absolute chain lifetime
	RefreshIdle time.Duration
}

// AuditFunc records a security-relevant event of the provider.
type AuditFunc func(ctx context.Context, action, subject, clientID, detail, result string)

// Storage implements op.Storage.
type Storage struct {
	Store     *store.Store
	Keys      *KeyManager
	Dir       directory.Backend
	Lifetimes Lifetimes
	Logger    *slog.Logger
	Audit     AuditFunc
	Now       func() time.Time
	// EndSessionURL turns a validated post-logout target into the URL that
	// ends the browser session first (set by the web server).
	EndSessionURL func(ctx context.Context, subject, clientID, target string, hinted bool) string
}

var _ op.Storage = (*Storage)(nil)

func (s *Storage) now() time.Time {
	if s.Now != nil {
		return s.Now().UTC()
	}
	return time.Now().UTC()
}

func (s *Storage) log() *slog.Logger {
	if s.Logger != nil {
		return s.Logger
	}
	return slog.Default()
}

func (s *Storage) audit(ctx context.Context, action, subject, clientID, detail, result string) {
	if s.Audit != nil {
		s.Audit(ctx, action, subject, clientID, detail, result)
	}
}

// ---- adapters ----

type authRequest struct{ r *store.AuthRequest }

func (a *authRequest) GetID() string         { return a.r.ID }
func (a *authRequest) GetACR() string        { return "" }
func (a *authRequest) GetAMR() []string      { return a.r.AMR }
func (a *authRequest) GetAudience() []string { return []string{a.r.ClientID} }
func (a *authRequest) GetAuthTime() time.Time {
	return a.r.AuthTime
}
func (a *authRequest) GetClientID() string { return a.r.ClientID }
func (a *authRequest) GetCodeChallenge() *oidc.CodeChallenge {
	if a.r.CodeChallenge == "" {
		return nil
	}
	return &oidc.CodeChallenge{Challenge: a.r.CodeChallenge, Method: oidc.CodeChallengeMethod(a.r.CodeChallengeMethod)}
}
func (a *authRequest) GetNonce() string                   { return a.r.Nonce }
func (a *authRequest) GetRedirectURI() string             { return a.r.RedirectURI }
func (a *authRequest) GetResponseType() oidc.ResponseType { return oidc.ResponseType(a.r.ResponseType) }
func (a *authRequest) GetResponseMode() oidc.ResponseMode { return oidc.ResponseMode(a.r.ResponseMode) }
func (a *authRequest) GetScopes() []string                { return a.r.Scopes }
func (a *authRequest) GetState() string                   { return a.r.State }
func (a *authRequest) GetSubject() string                 { return a.r.Subject }
func (a *authRequest) Done() bool                         { return a.r.Subject != "" }

// tokenSource is implemented by both request kinds that mint tokens.
type tokenSource interface {
	clientIDForTokens() string
	amrForTokens() ([]string, time.Time)
	chainForTokens() string
}

func (a *authRequest) clientIDForTokens() string           { return a.r.ClientID }
func (a *authRequest) amrForTokens() ([]string, time.Time) { return a.r.AMR, a.r.AuthTime }

// chainForTokens: tokens minted from a code belong to the request's chain,
// so a reused code revokes them all.
func (a *authRequest) chainForTokens() string { return a.r.ID }

type refreshRequest struct{ t *store.RefreshToken }

func (r *refreshRequest) GetAMR() []string                    { return r.t.AMR }
func (r *refreshRequest) GetAudience() []string               { return r.t.Audience }
func (r *refreshRequest) GetAuthTime() time.Time              { return r.t.AuthTime }
func (r *refreshRequest) GetClientID() string                 { return r.t.ClientID }
func (r *refreshRequest) GetScopes() []string                 { return r.t.Scopes }
func (r *refreshRequest) GetSubject() string                  { return r.t.Subject }
func (r *refreshRequest) SetCurrentScopes(scopes []string)    { r.t.Scopes = scopes }
func (r *refreshRequest) clientIDForTokens() string           { return r.t.ClientID }
func (r *refreshRequest) amrForTokens() ([]string, time.Time) { return r.t.AMR, r.t.AuthTime }
func (r *refreshRequest) chainForTokens() string              { return r.t.ChainID }

// client adapts store.Client to op.Client.
type client struct {
	c       *store.Client
	idToken time.Duration
}

func (c *client) GetID() string                    { return c.c.ID }
func (c *client) RedirectURIs() []string           { return c.c.RedirectURIs }
func (c *client) PostLogoutRedirectURIs() []string { return c.c.PostLogoutURIs }

// ApplicationType: public clients are native apps (loopback redirects on
// any port, RFC 8252 §7.3); every other redirect URI matches exactly.
func (c *client) ApplicationType() op.ApplicationType {
	if c.c.Public() {
		return op.ApplicationTypeNative
	}
	return op.ApplicationTypeWeb
}
func (c *client) AuthMethod() oidc.AuthMethod {
	if c.c.Public() {
		return oidc.AuthMethodNone
	}
	return oidc.AuthMethodBasic
}
func (c *client) ResponseTypes() []oidc.ResponseType {
	return []oidc.ResponseType{oidc.ResponseTypeCode}
}
func (c *client) GrantTypes() []oidc.GrantType {
	return []oidc.GrantType{oidc.GrantTypeCode, oidc.GrantTypeRefreshToken}
}
func (c *client) LoginURL(id string) string           { return LoginPath + "?ar=" + id }
func (c *client) AccessTokenType() op.AccessTokenType { return op.AccessTokenTypeBearer }
func (c *client) IDTokenLifetime() time.Duration      { return c.idToken }
func (c *client) DevMode() bool                       { return false }
func (c *client) RestrictAdditionalIdTokenScopes() func([]string) []string {
	return func(s []string) []string { return s }
}
func (c *client) RestrictAdditionalAccessTokenScopes() func([]string) []string {
	return func(s []string) []string { return s }
}

// IsScopeAllowed admits the custom scopes the client is registered for.
func (c *client) IsScopeAllowed(scope string) bool { return slices.Contains(c.c.Scopes, scope) }

// IDTokenUserinfoClaimsAssertion puts the granted claims in the ID token,
// so an RP needs no userinfo call right after sign-in.
func (c *client) IDTokenUserinfoClaimsAssertion() bool { return true }
func (c *client) ClockSkew() time.Duration             { return 0 }

// ---- auth requests and codes ----

// CreateAuthRequest stores a validated authorization request. PKCE with
// S256 is mandatory for every client; scopes the client is not registered
// for are dropped; only the query response mode is served.
func (s *Storage) CreateAuthRequest(ctx context.Context, req *oidc.AuthRequest, _ string) (op.AuthRequest, error) {
	if req.CodeChallenge == "" || req.CodeChallengeMethod != oidc.CodeChallengeMethodS256 {
		return nil, oidc.ErrInvalidRequest().WithDescription("PKCE with code_challenge_method=S256 is required")
	}
	if req.ResponseType != oidc.ResponseTypeCode {
		return nil, oidc.ErrInvalidRequest().WithDescription("only response_type=code is supported")
	}
	if req.ResponseMode != "" && req.ResponseMode != oidc.ResponseModeQuery {
		return nil, oidc.ErrInvalidRequest().WithDescription("only response_mode=query is supported")
	}
	c, err := s.Store.GetClient(ctx, req.ClientID)
	if err != nil || !c.Enabled {
		return nil, oidc.ErrInvalidClient().WithDescription("unknown client")
	}
	scopes := slices.DeleteFunc(slices.Clone(req.Scopes), func(sc string) bool {
		return sc != oidc.ScopeOpenID && !slices.Contains(c.Scopes, sc)
	})
	if !slices.Contains(scopes, oidc.ScopeOpenID) {
		return nil, oidc.ErrInvalidScope().WithDescription("the openid scope is required")
	}
	now := s.now()
	r := &store.AuthRequest{
		ID: uuid.NewString(), ClientID: req.ClientID, RedirectURI: req.RedirectURI, State: req.State, Nonce: req.Nonce,
		Scopes: scopes, ResponseType: string(req.ResponseType), ResponseMode: string(req.ResponseMode),
		CodeChallenge: req.CodeChallenge, CodeChallengeMethod: string(req.CodeChallengeMethod),
		Prompt: req.Prompt, LoginHint: req.LoginHint, CreatedAt: now, ExpiresAt: now.Add(authReqTTL),
	}
	for _, t := range req.UILocales {
		r.UILocales += t.String() + " "
	}
	r.UILocales = strings.TrimSpace(r.UILocales)
	if req.MaxAge != nil {
		v := int64(*req.MaxAge)
		r.MaxAge = &v
	}
	if err := s.Store.CreateAuthRequest(ctx, r); err != nil {
		return nil, err
	}
	return &authRequest{r}, nil
}

func (s *Storage) getAuthRequest(ctx context.Context, id string) (*authRequest, error) {
	r, err := s.Store.GetAuthRequest(ctx, id)
	if err != nil {
		return nil, oidc.ErrInvalidRequest().WithDescription("authorization request not found or expired")
	}
	if !s.now().Before(r.ExpiresAt) {
		return nil, oidc.ErrInvalidRequest().WithDescription("authorization request not found or expired")
	}
	return &authRequest{r}, nil
}

// AuthRequestByID implements op.Storage.
func (s *Storage) AuthRequestByID(ctx context.Context, id string) (op.AuthRequest, error) {
	return s.getAuthRequest(ctx, id)
}

// GetAuthRequest returns the stored request (web flow).
func (s *Storage) GetAuthRequest(ctx context.Context, id string) (*store.AuthRequest, error) {
	a, err := s.getAuthRequest(ctx, id)
	if err != nil {
		return nil, err
	}
	return a.r, nil
}

// AuthRequestByCode implements op.Storage: a code is consumed on first
// use; a second use revokes every token issued from it.
func (s *Storage) AuthRequestByCode(ctx context.Context, code string) (op.AuthRequest, error) {
	reqID, err := s.Store.ConsumeAuthCode(ctx, secret.Hash(code))
	if errors.Is(err, store.ErrCodeReused) {
		s.log().Warn("authorization code reused; revoking the tokens it issued", "request", reqID)
		_ = s.Store.RevokeChain(ctx, reqID)
		s.audit(ctx, "oidc.code_reuse", "", "", "request "+reqID, "denied")
		return nil, oidc.ErrInvalidGrant().WithDescription("code invalid or expired")
	}
	if err != nil {
		return nil, oidc.ErrInvalidGrant().WithDescription("code invalid or expired")
	}
	r, err := s.getAuthRequest(ctx, reqID)
	if err != nil || !r.Done() {
		return nil, oidc.ErrInvalidGrant().WithDescription("code invalid or expired")
	}
	return r, nil
}

// SaveAuthCode implements op.Storage.
func (s *Storage) SaveAuthCode(ctx context.Context, id, code string) error {
	return s.Store.SaveAuthCode(ctx, secret.Hash(code), id, s.now().Add(codeTTL))
}

// DeleteAuthRequest implements op.Storage (called once a code is redeemed).
func (s *Storage) DeleteAuthRequest(ctx context.Context, id string) error {
	return s.Store.DeleteAuthRequest(ctx, id)
}

// ErrConsentRequired is the OIDC consent_required error (prompt=none
// when the user has not consented yet); the library has no constructor.
func ErrConsentRequired() *oidc.Error {
	return &oidc.Error{ErrorType: "consent_required", Description: "the user has not consented to this application"}
}

// ---- access policy ----

// Allowed reports whether a user may use a client: an active account, and
// a member of one of the client's allowed groups (by SID) unless the
// client admits every user.
func Allowed(c *store.Client, u *directory.User) bool {
	if !u.Active() {
		return false
	}
	return c.AllowAllUsers || u.InAnyGroup(c.AllowedGroups)
}

// checkUser re-reads the user in AD and applies the client's policy.
func (s *Storage) checkUser(ctx context.Context, subject, clientID string) (*directory.User, *store.Client, error) {
	c, err := s.Store.GetClient(ctx, clientID)
	if err != nil || !c.Enabled {
		return nil, nil, oidc.ErrInvalidClient().WithDescription("unknown client")
	}
	u, err := s.Dir.UserByGUID(ctx, subject)
	if errors.Is(err, directory.ErrNotFound) {
		return nil, nil, oidc.ErrInvalidGrant().WithDescription("the account no longer exists")
	}
	if err != nil {
		s.log().Error("directory lookup failed", "err", err)
		return nil, nil, oidc.ErrServerError().WithDescription("directory unavailable")
	}
	if !Allowed(c, u) {
		return nil, nil, oidc.ErrInvalidGrant().WithDescription("the account may not use this client")
	}
	return u, c, nil
}

// ---- tokens ----

func (s *Storage) newAccessToken(ctx context.Context, clientID, chainID string, req op.TokenRequest) (*store.AccessToken, error) {
	now := s.now()
	t := &store.AccessToken{
		ID: uuid.NewString(), ChainID: chainID, ClientID: clientID, Subject: req.GetSubject(), Scopes: req.GetScopes(),
		Audience: req.GetAudience(), CreatedAt: now, ExpiresAt: now.Add(s.Lifetimes.AccessToken),
	}
	return t, s.Store.CreateAccessToken(ctx, t)
}

// CreateAccessToken implements op.Storage (code exchange without
// offline_access).
func (s *Storage) CreateAccessToken(ctx context.Context, req op.TokenRequest) (string, time.Time, error) {
	src, ok := req.(tokenSource)
	if !ok {
		return "", time.Time{}, oidc.ErrUnsupportedGrantType()
	}
	if _, _, err := s.checkUser(ctx, req.GetSubject(), src.clientIDForTokens()); err != nil {
		return "", time.Time{}, err
	}
	t, err := s.newAccessToken(ctx, src.clientIDForTokens(), src.chainForTokens(), req)
	if err != nil {
		return "", time.Time{}, err
	}
	s.audit(ctx, "oidc.token", req.GetSubject(), t.ClientID, "access token", "ok")
	return t.ID, t.ExpiresAt, nil
}

// CreateAccessAndRefreshTokens implements op.Storage: a new chain on code
// exchange, a rotation on refresh.
func (s *Storage) CreateAccessAndRefreshTokens(ctx context.Context, req op.TokenRequest, current string) (string, string, time.Time, error) {
	src, ok := req.(tokenSource)
	if !ok {
		return "", "", time.Time{}, oidc.ErrUnsupportedGrantType()
	}
	clientID := src.clientIDForTokens()
	if _, _, err := s.checkUser(ctx, req.GetSubject(), clientID); err != nil {
		if current != "" {
			// The account lost access: end the chain.
			if old, gerr := s.Store.GetRefreshTokenByHash(ctx, secret.Hash(current)); gerr == nil {
				_ = s.Store.RevokeChain(ctx, old.ChainID)
			}
			s.audit(ctx, "oidc.refresh", req.GetSubject(), clientID, "account no longer allowed; chain revoked", "denied")
		}
		return "", "", time.Time{}, err
	}
	now := s.now()
	chainID := src.chainForTokens()
	chainExpires := now.Add(s.Lifetimes.Refresh)
	action := "oidc.token"
	if current != "" {
		old, err := s.Store.GetRefreshTokenByHash(ctx, secret.Hash(current))
		if err != nil {
			return "", "", time.Time{}, oidc.ErrInvalidGrant()
		}
		rotated, err := s.Store.RotateRefreshToken(ctx, old.ID)
		if err != nil {
			return "", "", time.Time{}, err
		}
		if !rotated {
			// Lost a race with another use of the same token: reuse.
			s.reuseDetected(ctx, old)
			return "", "", time.Time{}, oidc.ErrInvalidGrant().WithDescription("refresh token reuse detected")
		}
		chainID, chainExpires = old.ChainID, old.ChainExpiresAt
		action = "oidc.refresh"
	}
	amr, authTime := src.amrForTokens()
	value := secret.Token(RefreshPrefix)
	idle := now.Add(s.Lifetimes.RefreshIdle)
	if idle.After(chainExpires) {
		idle = chainExpires
	}
	rt := &store.RefreshToken{
		ID: uuid.NewString(), ChainID: chainID, TokenHash: secret.Hash(value), ClientID: clientID,
		Subject: req.GetSubject(), Scopes: req.GetScopes(), Audience: req.GetAudience(), AMR: amr, AuthTime: authTime,
		CreatedAt: now, ExpiresAt: idle, ChainExpiresAt: chainExpires,
	}
	if err := s.Store.CreateRefreshToken(ctx, rt); err != nil {
		return "", "", time.Time{}, err
	}
	at, err := s.newAccessToken(ctx, clientID, chainID, req)
	if err != nil {
		return "", "", time.Time{}, err
	}
	s.audit(ctx, action, req.GetSubject(), clientID, "access + refresh token", "ok")
	return at.ID, value, at.ExpiresAt, nil
}

func (s *Storage) reuseDetected(ctx context.Context, t *store.RefreshToken) {
	s.log().Warn("refresh token reuse detected; revoking the chain", "client", t.ClientID, "subject", t.Subject)
	if err := s.Store.RevokeChain(ctx, t.ChainID); err != nil {
		s.log().Error("revoking refresh chain", "err", err)
	}
	s.audit(ctx, "oidc.refresh_reuse", t.Subject, t.ClientID, "chain revoked", "denied")
}

// TokenRequestByRefreshToken implements op.Storage.
func (s *Storage) TokenRequestByRefreshToken(ctx context.Context, token string) (op.RefreshTokenRequest, error) {
	t, err := s.Store.GetRefreshTokenByHash(ctx, secret.Hash(token))
	if err != nil {
		return nil, oidc.ErrInvalidGrant().WithDescription("invalid refresh token")
	}
	if !t.RotatedAt.IsZero() {
		s.reuseDetected(ctx, t)
		return nil, oidc.ErrInvalidGrant().WithDescription("refresh token reuse detected")
	}
	if !t.RevokedAt.IsZero() || !s.now().Before(t.ExpiresAt) || !s.now().Before(t.ChainExpiresAt) {
		return nil, oidc.ErrInvalidGrant().WithDescription("invalid refresh token")
	}
	return &refreshRequest{t}, nil
}

// TerminateSession implements op.Storage: RP-initiated logout revokes that
// client's tokens for the user.
func (s *Storage) TerminateSession(ctx context.Context, userID, clientID string) error {
	if userID == "" {
		return nil
	}
	_, err := s.Store.RevokeSubjectTokens(ctx, userID, clientID)
	return err
}

// TerminateSessionFromRequest handles RP-initiated logout. With a valid
// id_token_hint the client's tokens are revoked and the browser session
// ends; without one the user is asked to confirm.
func (s *Storage) TerminateSessionFromRequest(ctx context.Context, req *op.EndSessionRequest) (string, error) {
	hinted := req.IDTokenHintClaims != nil && req.UserID != ""
	if hinted {
		if err := s.TerminateSession(ctx, req.UserID, req.ClientID); err != nil {
			return "", err
		}
		s.audit(ctx, "oidc.end_session", req.UserID, req.ClientID, "rp-initiated logout", "ok")
	}
	if s.EndSessionURL == nil {
		return req.RedirectURI, nil
	}
	return s.EndSessionURL(ctx, req.UserID, req.ClientID, req.RedirectURI, hinted), nil
}

// refreshRefPrefix marks the reference GetRefreshTokenInfo hands back to
// RevokeToken.
const refreshRefPrefix = "rt:"

// GetRefreshTokenInfo implements op.Storage.
func (s *Storage) GetRefreshTokenInfo(ctx context.Context, _ string, token string) (string, string, error) {
	h := secret.Hash(token)
	t, err := s.Store.GetRefreshTokenByHash(ctx, h)
	if err != nil {
		return "", "", op.ErrInvalidRefreshToken
	}
	return t.Subject, refreshRefPrefix + h, nil
}

// RevokeToken implements op.Storage (RFC 7009). Revoking a refresh token
// revokes its chain; unknown tokens are not an error; a client may only
// revoke its own tokens.
func (s *Storage) RevokeToken(ctx context.Context, tokenOrID, userID, clientID string) *oidc.Error {
	revokeRefresh := func(hash string) *oidc.Error {
		rt, err := s.Store.GetRefreshTokenByHash(ctx, hash)
		if err != nil {
			return nil
		}
		if rt.ClientID != clientID {
			return oidc.ErrInvalidClient().WithDescription("token was not issued to this client")
		}
		_ = s.Store.RevokeChain(ctx, rt.ChainID)
		s.audit(ctx, "oidc.revoke", rt.Subject, clientID, "refresh token chain", "ok")
		return nil
	}
	if h, ok := strings.CutPrefix(tokenOrID, refreshRefPrefix); ok {
		return revokeRefresh(h)
	}
	if userID != "" {
		at, err := s.Store.GetAccessToken(ctx, tokenOrID)
		if err != nil {
			return nil
		}
		if at.ClientID != clientID {
			return oidc.ErrInvalidClient().WithDescription("token was not issued to this client")
		}
		_ = s.Store.RevokeAccessToken(ctx, at.ID)
		s.audit(ctx, "oidc.revoke", at.Subject, clientID, "access token", "ok")
		return nil
	}
	return revokeRefresh(secret.Hash(tokenOrID))
}

// SigningKey implements op.Storage.
func (s *Storage) SigningKey(ctx context.Context) (op.SigningKey, error) {
	return s.Keys.SigningKey(ctx)
}

// SignatureAlgorithms implements op.Storage.
func (s *Storage) SignatureAlgorithms(context.Context) ([]jose.SignatureAlgorithm, error) {
	return []jose.SignatureAlgorithm{keyAlg}, nil
}

// KeySet implements op.Storage.
func (s *Storage) KeySet(ctx context.Context) ([]op.Key, error) { return s.Keys.KeySet(ctx) }

// ---- clients ----

// GetClientByClientID implements op.Storage.
func (s *Storage) GetClientByClientID(ctx context.Context, clientID string) (op.Client, error) {
	c, err := s.Store.GetClient(ctx, clientID)
	if err != nil || !c.Enabled {
		return nil, oidc.ErrInvalidClient().WithDescription("unknown client")
	}
	return &client{c: c, idToken: s.Lifetimes.IDToken}, nil
}

// AuthorizeClientIDSecret implements op.Storage.
func (s *Storage) AuthorizeClientIDSecret(ctx context.Context, clientID, clientSecret string) error {
	c, err := s.Store.GetClient(ctx, clientID)
	if err != nil || !c.Enabled || c.Public() || c.SecretHash == "" || clientSecret == "" ||
		!secret.Equal(secret.Hash(clientSecret), c.SecretHash) {
		s.audit(ctx, "oidc.client_auth", "", clientID, "invalid client credentials", "denied")
		return oidc.ErrInvalidClient()
	}
	return nil
}

// ---- claims ----

// SetUserinfoFromScopes is deprecated upstream; SetUserinfoFromRequest
// does the work.
func (s *Storage) SetUserinfoFromScopes(context.Context, *oidc.UserInfo, string, string, []string) error {
	return nil
}

// SetUserinfoFromRequest fills the ID token claims.
func (s *Storage) SetUserinfoFromRequest(ctx context.Context, info *oidc.UserInfo, req op.IDTokenRequest, scopes []string) error {
	return s.setUserinfo(ctx, info, req.GetSubject(), req.GetClientID(), scopes)
}

// SetUserinfoFromToken fills the userinfo endpoint answer.
func (s *Storage) SetUserinfoFromToken(ctx context.Context, info *oidc.UserInfo, tokenID, _, _ string) error {
	t, err := s.Store.GetAccessToken(ctx, tokenID)
	if err != nil || !t.RevokedAt.IsZero() || !s.now().Before(t.ExpiresAt) {
		return errors.New("token is invalid or expired")
	}
	return s.setUserinfo(ctx, info, t.Subject, t.ClientID, t.Scopes)
}

// SetIntrospectionFromToken implements op.Storage. The introspection
// endpoint is not served; this only answers the library's interface.
func (s *Storage) SetIntrospectionFromToken(context.Context, *oidc.IntrospectionResponse, string, string, string) error {
	return errors.New("introspection is not supported")
}

// GetPrivateClaimsFromScopes implements op.Storage (JWT access tokens only,
// which are not issued).
func (s *Storage) GetPrivateClaimsFromScopes(context.Context, string, string, []string) (map[string]any, error) {
	return nil, nil
}

// GetKeyByIDAndClientID implements op.Storage; the JWT profile grant is off.
func (s *Storage) GetKeyByIDAndClientID(context.Context, string, string) (*jose.JSONWebKey, error) {
	return nil, errors.New("jwt profile grant is not supported")
}

// ValidateJWTProfileScopes implements op.Storage; the JWT profile grant is off.
func (s *Storage) ValidateJWTProfileScopes(context.Context, string, []string) ([]string, error) {
	return nil, errors.New("jwt profile grant is not supported")
}

// Health implements op.Storage.
func (s *Storage) Health(ctx context.Context) error { return s.Store.Ping(ctx) }

func (s *Storage) setUserinfo(ctx context.Context, info *oidc.UserInfo, subject, clientID string, scopes []string) error {
	u, c, err := s.checkUser(ctx, subject, clientID)
	if err != nil {
		return err
	}
	claims, err := Claims(ctx, s.Dir, c, u, scopes)
	if err != nil {
		return err
	}
	info.Subject = u.GUID
	if v, ok := claims["preferred_username"].(string); ok {
		info.PreferredUsername = v
		info.Name, _ = claims["name"].(string)
		info.GivenName, _ = claims["given_name"].(string)
		info.FamilyName, _ = claims["family_name"].(string)
	}
	if v, ok := claims["email"].(string); ok {
		info.Email = v
		info.EmailVerified = oidc.Bool(true)
	}
	if v, ok := claims["groups"]; ok {
		info.AppendClaims("groups", v)
	}
	return nil
}

// Claims computes the claims a client gets for a user and scopes: only
// what the client is registered for and the user granted.
func Claims(ctx context.Context, dir directory.Backend, c *store.Client, u *directory.User, scopes []string) (map[string]any, error) {
	out := map[string]any{"sub": u.GUID}
	for _, sc := range scopes {
		if sc != oidc.ScopeOpenID && !slices.Contains(c.Scopes, sc) {
			continue
		}
		switch sc {
		case oidc.ScopeProfile:
			out["preferred_username"] = u.SAM
			out["name"] = u.Name()
			if u.GivenName != "" {
				out["given_name"] = u.GivenName
			}
			if u.Surname != "" {
				out["family_name"] = u.Surname
			}
		case oidc.ScopeEmail:
			// AD's mail attribute is managed by administrators (users
			// cannot write it on themselves), so it is presented as
			// verified. Accounts without mail get no email claim.
			if u.Mail != "" {
				out["email"] = u.Mail
			}
		case ScopeGroups:
			groups, err := GroupsClaim(ctx, dir, c.GroupsClaim, c.GroupsFilter, u)
			if err != nil {
				return nil, err
			}
			if groups != nil {
				out["groups"] = groups
			}
		}
	}
	return out, nil
}

// GroupsClaim renders a user's groups as names or SIDs, optionally limited
// to a filter of SIDs. It returns nil when the style is "none".
func GroupsClaim(ctx context.Context, dir directory.Backend, style string, filter []string, u *directory.User) ([]string, error) {
	if style != store.GroupsNames && style != store.GroupsSIDs {
		return nil, nil
	}
	var sids []sid.SID
	for _, g := range u.GroupSIDs {
		if len(filter) > 0 && !slices.Contains(filter, g.String()) {
			continue
		}
		sids = append(sids, g)
	}
	out := []string{}
	if style == store.GroupsSIDs {
		for _, g := range sids {
			out = append(out, g.String())
		}
		slices.Sort(out)
		return out, nil
	}
	names, err := dir.GroupNames(ctx, sids)
	if err != nil {
		return nil, err
	}
	for _, g := range sids {
		if n := names[g.String()]; n != "" {
			out = append(out, n)
		}
	}
	slices.Sort(out)
	return out, nil
}

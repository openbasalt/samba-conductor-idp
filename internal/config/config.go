// Package config loads and validates /etc/conductor-idp/idp.toml.
//
// Unknown keys are an error (a typo must not silently fall back to a
// default), and every value that weakens security has to be spelled out.
package config

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/BurntSushi/toml"
	"github.com/samba-conductor/ad/sid"
)

// DefaultPath is where conductor-idp looks for its configuration.
const DefaultPath = "/etc/conductor-idp/idp.toml"

// MFA policies for users who are not administrators.
const (
	MFAOff      = "off"
	MFAOptional = "optional"
	MFARequired = "required"
)

// MFA backends.
const (
	// MFABackendLocal keeps TOTP secrets and recovery codes in the idp's
	// own database (sealed with the master key).
	MFABackendLocal = "local"
	// MFABackendConductor verifies codes against conductor's 2FA store
	// through conductor's local Unix-socket API (docs/decisions.md D4).
	MFABackendConductor = "conductor"
)

// Config is the whole file.
type Config struct {
	Server         Server         `toml:"server"`
	Domain         Domain         `toml:"domain"`
	ServiceAccount ServiceAccount `toml:"service_account"`
	Roles          Roles          `toml:"roles"`
	MFA            MFA            `toml:"mfa"`
	Keys           Keys           `toml:"keys"`
	Tokens         Tokens         `toml:"tokens"`
	Session        Session        `toml:"session"`
	RateLimit      RateLimit      `toml:"ratelimit"`
	State          State          `toml:"state"`
	UI             UI             `toml:"ui"`
	SAML           SAML           `toml:"saml"`
}

// Server is the HTTP listener and the public identity of the provider.
type Server struct {
	// Issuer is the public base URL ("https://idp.example.com"), used as
	// the OIDC issuer and as the base of every SAML URL. https only.
	Issuer string `toml:"issuer"`
	// Listen address, e.g. ":9443" or "127.0.0.1:9080" (behind a proxy).
	Listen string `toml:"listen"`
	// TLSCert and TLSKey enable the built-in TLS listener.
	TLSCert string `toml:"tls_cert"`
	TLSKey  string `toml:"tls_key"`
	// BehindProxy serves plain HTTP for a TLS-terminating reverse proxy on
	// the same host; only allowed on a loopback address.
	BehindProxy bool `toml:"behind_proxy"`
	// TrustedProxies whose X-Forwarded-For is believed (CIDRs).
	TrustedProxies []string `toml:"trusted_proxies"`
}

// Domain is how the AD domain is reached.
type Domain struct {
	Realm string `toml:"realm"`
	// CAFile pins the CA that signs the DCs' LDAPS certificates.
	CAFile string `toml:"ca_file"`
	// DCs replaces DNS SRV discovery when set.
	DCs []string `toml:"dcs"`
	// Preferred DCs are tried first.
	Preferred []string `toml:"preferred"`
	// DNSServers used for SRV discovery instead of the system resolver.
	DNSServers []string `toml:"dns_servers"`
	// SimpleBindFallback verifies passwords with an LDAP simple bind over
	// TLS when no KDC answers. Off by default.
	SimpleBindFallback bool `toml:"simple_bind_fallback"`
}

// ServiceAccount is the read-only AD account the idp uses for lookups that
// happen without the user (claims, refresh, userinfo).
type ServiceAccount struct {
	// Username is the sAMAccountName, e.g. "svc-conductor-idp".
	Username string `toml:"username"`
	// PasswordFile holds the password. Empty:
	// $CREDENTIALS_DIRECTORY/ad-password (systemd LoadCredential).
	PasswordFile string `toml:"password_file"`
}

// Roles map AD groups (by SID) to idp roles.
type Roles struct {
	// AdminGroups may use the idp's admin pages. Empty means the domain's
	// Domain Admins (RID 512).
	AdminGroups []string `toml:"admin_groups"`
	// CacheSeconds bounds how long a role check is reused (at most 60).
	CacheSeconds int `toml:"cache_seconds"`
}

// MFA is the second-factor policy.
type MFA struct {
	// Policy for users who are not administrators: off, optional,
	// required. Administrators always need 2FA.
	Policy string `toml:"policy"`
	// Backend is "local" or "conductor".
	Backend string `toml:"backend"`
	// ConductorSocket is conductor's 2FA verification socket (backend
	// "conductor").
	ConductorSocket string `toml:"conductor_socket"`
	// AdminEnrollmentRequiresLink: an administrator without 2FA may enroll
	// only through a one-time link (`conductor-idp enroll-link`), so a
	// stolen administrator password is not enough (default true).
	AdminEnrollmentRequiresLink *bool `toml:"admin_enrollment_requires_link"`
	// Issuer shown in authenticator apps.
	Issuer string `toml:"issuer"`
}

// Keys configures the master key and signing-key rotation.
type Keys struct {
	// MasterKeyFile holds the 32-byte key that seals signing keys and TOTP
	// secrets. Empty: $CREDENTIALS_DIRECTORY/master-key.
	MasterKeyFile string `toml:"master_key_file"`
	// RotateDays: a new OIDC signing key after this many days.
	RotateDays int `toml:"rotate_days"`
	// OverlapHours: a replaced key stays published this long.
	OverlapHours int `toml:"overlap_hours"`
}

// Tokens are lifetimes.
type Tokens struct {
	IDTokenMinutes     int `toml:"id_token_minutes"`
	AccessTokenMinutes int `toml:"access_token_minutes"`
	// RefreshTokenHours is the absolute lifetime of a refresh chain.
	RefreshTokenHours int `toml:"refresh_token_hours"`
	// RefreshIdleHours: a refresh token unused this long expires.
	RefreshIdleHours int `toml:"refresh_idle_hours"`
}

// Session is the idp's browser session (single sign-on).
type Session struct {
	IdleMinutes   int `toml:"idle_minutes"`
	AbsoluteHours int `toml:"absolute_hours"`
}

// RateLimit bounds sign-in, 2FA and token endpoints.
type RateLimit struct {
	PerIPPerMinute       int `toml:"per_ip_per_minute"`
	AccountFailures      int `toml:"account_failures"`
	AccountWindowMinutes int `toml:"account_window_minutes"`
	// TokenPerIPPerMinute bounds the token, revocation and userinfo
	// endpoints per client address.
	TokenPerIPPerMinute int `toml:"token_per_ip_per_minute"`
}

// State is where the database lives.
type State struct {
	Database string `toml:"database"`
}

// UI preferences.
type UI struct {
	DefaultLanguage string `toml:"default_language"`
	// ProductName is shown in the page header.
	ProductName string `toml:"product_name"`
}

// SAML enables the SAML 2.0 identity provider.
type SAML struct {
	Enabled bool `toml:"enabled"`
	// AssertionMinutes is how long an assertion is valid.
	AssertionMinutes int `toml:"assertion_minutes"`
}

// Load reads and validates a file.
func Load(path string) (*Config, error) {
	c := Default()
	md, err := toml.DecodeFile(path, c)
	if err != nil {
		return nil, fmt.Errorf("config: %w", err)
	}
	if und := md.Undecoded(); len(und) > 0 {
		keys := make([]string, len(und))
		for i, k := range und {
			keys[i] = k.String()
		}
		return nil, fmt.Errorf("config: unknown keys: %s", strings.Join(keys, ", "))
	}
	if err := c.Validate(); err != nil {
		return nil, err
	}
	return c, nil
}

// Default returns the defaults every file starts from.
func Default() *Config {
	return &Config{
		Server:    Server{Listen: ":9443"},
		Roles:     Roles{CacheSeconds: 60},
		MFA:       MFA{Policy: MFAOptional, Backend: MFABackendLocal, Issuer: "Samba Conductor IdP"},
		Keys:      Keys{RotateDays: 90, OverlapHours: 48},
		Tokens:    Tokens{IDTokenMinutes: 5, AccessTokenMinutes: 10, RefreshTokenHours: 24 * 30, RefreshIdleHours: 24 * 7},
		Session:   Session{IdleMinutes: 60, AbsoluteHours: 8},
		RateLimit: RateLimit{PerIPPerMinute: 30, AccountFailures: 5, AccountWindowMinutes: 15, TokenPerIPPerMinute: 120},
		State:     State{Database: "/var/lib/conductor-idp/idp.db"},
		UI:        UI{DefaultLanguage: "en", ProductName: "Samba Conductor"},
		SAML:      SAML{AssertionMinutes: 5},
	}
}

// Validate checks the values and the security rules.
func (c *Config) Validate() error {
	var errs []error
	bad := func(format string, a ...any) { errs = append(errs, fmt.Errorf("config: "+format, a...)) }

	if u, err := url.Parse(c.Server.Issuer); err != nil || u.Scheme != "https" || u.Host == "" ||
		(u.Path != "" && u.Path != "/") || u.RawQuery != "" || u.Fragment != "" || u.User != nil {
		bad("server.issuer must be https://host[:port] without a path (got %q)", c.Server.Issuer)
	}
	host, _, err := net.SplitHostPort(c.Server.Listen)
	if err != nil {
		bad("server.listen %q: %v", c.Server.Listen, err)
	}
	tlsOn := c.Server.TLSCert != "" || c.Server.TLSKey != ""
	switch {
	case tlsOn && (c.Server.TLSCert == "" || c.Server.TLSKey == ""):
		bad("server.tls_cert and server.tls_key go together")
	case tlsOn && c.Server.BehindProxy:
		bad("server.behind_proxy and built-in TLS are exclusive")
	case !tlsOn && !c.Server.BehindProxy:
		bad("TLS is required: set server.tls_cert/tls_key, or server.behind_proxy with a loopback listen address")
	case !tlsOn && !isLoopback(host):
		bad("server.behind_proxy requires a loopback listen address (got %q)", c.Server.Listen)
	}
	for _, p := range c.Server.TrustedProxies {
		if _, err := netip.ParsePrefix(p); err != nil {
			bad("server.trusted_proxies %q: %v", p, err)
		}
	}
	if len(c.Server.TrustedProxies) > 0 && !c.Server.BehindProxy {
		bad("server.trusted_proxies only makes sense with server.behind_proxy")
	}

	if c.Domain.Realm == "" || strings.ContainsAny(c.Domain.Realm, " /\\") {
		bad("domain.realm is required")
	}
	if c.Domain.CAFile == "" || !filepath.IsAbs(c.Domain.CAFile) {
		bad("domain.ca_file must be an absolute path (the pinned domain CA)")
	}
	for _, s := range c.Domain.DNSServers {
		if _, err := netip.ParseAddr(s); err != nil {
			bad("domain.dns_servers %q is not an IP address", s)
		}
	}
	if c.ServiceAccount.Username == "" || strings.ContainsAny(c.ServiceAccount.Username, "\\@/ ") {
		bad("service_account.username must be a plain sAMAccountName")
	}
	if c.ServiceAccount.PasswordFile != "" && !filepath.IsAbs(c.ServiceAccount.PasswordFile) {
		bad("service_account.password_file must be absolute")
	}
	for _, s := range c.Roles.AdminGroups {
		if _, err := sid.Parse(s); err != nil {
			bad("roles.admin_groups: %q is not a SID", s)
		}
	}
	if c.Roles.CacheSeconds < 0 || c.Roles.CacheSeconds > 60 {
		bad("roles.cache_seconds must be 0-60")
	}
	if !slices.Contains([]string{MFAOff, MFAOptional, MFARequired}, c.MFA.Policy) {
		bad("mfa.policy must be off, optional or required")
	}
	switch c.MFA.Backend {
	case MFABackendLocal:
	case MFABackendConductor:
		if !filepath.IsAbs(c.MFA.ConductorSocket) {
			bad("mfa.conductor_socket must be an absolute path with backend \"conductor\"")
		}
	default:
		bad("mfa.backend must be local or conductor")
	}
	if c.MFA.Issuer == "" || len(c.MFA.Issuer) > 64 || strings.ContainsAny(c.MFA.Issuer, ":") {
		bad("mfa.issuer must be 1-64 characters without ':'")
	}
	if c.Keys.MasterKeyFile != "" && !filepath.IsAbs(c.Keys.MasterKeyFile) {
		bad("keys.master_key_file must be absolute")
	}
	if c.Keys.RotateDays < 1 || c.Keys.RotateDays > 730 {
		bad("keys.rotate_days must be 1-730")
	}
	if c.Keys.OverlapHours < 1 || c.Keys.OverlapHours > 24*30 {
		bad("keys.overlap_hours must be 1-720")
	}
	t := c.Tokens
	if t.IDTokenMinutes < 1 || t.IDTokenMinutes > 60 || t.AccessTokenMinutes < 1 || t.AccessTokenMinutes > 60 {
		bad("tokens: id and access tokens live 1-60 minutes")
	}
	if t.RefreshTokenHours < 1 || t.RefreshTokenHours > 24*90 || t.RefreshIdleHours < 1 || t.RefreshIdleHours > t.RefreshTokenHours {
		bad("tokens: refresh_token_hours 1-2160 and refresh_idle_hours 1-refresh_token_hours")
	}
	if c.Session.IdleMinutes < 1 || c.Session.IdleMinutes > 24*60 {
		bad("session.idle_minutes must be 1-1440")
	}
	if c.Session.AbsoluteHours < 1 || c.Session.AbsoluteHours > 24 {
		bad("session.absolute_hours must be 1-24")
	}
	r := c.RateLimit
	if r.PerIPPerMinute < 1 || r.AccountFailures < 1 || r.AccountWindowMinutes < 1 || r.TokenPerIPPerMinute < 1 {
		bad("ratelimit values must be positive")
	}
	if !filepath.IsAbs(c.State.Database) {
		bad("state.database must be absolute")
	}
	if c.UI.DefaultLanguage != "en" && c.UI.DefaultLanguage != "pt-BR" {
		bad("ui.default_language must be en or pt-BR")
	}
	if c.UI.ProductName == "" || len(c.UI.ProductName) > 64 {
		bad("ui.product_name must be 1-64 characters")
	}
	if c.SAML.AssertionMinutes < 1 || c.SAML.AssertionMinutes > 30 {
		bad("saml.assertion_minutes must be 1-30")
	}
	return errors.Join(errs...)
}

func isLoopback(host string) bool {
	if host == "localhost" {
		return true
	}
	a, err := netip.ParseAddr(host)
	return err == nil && a.IsLoopback()
}

// Issuer returns the issuer without a trailing slash.
func (c *Config) Issuer() string { return strings.TrimRight(c.Server.Issuer, "/") }

// IssuerHost returns the host[:port] of the issuer (the expected Host and
// Origin of browser requests).
func (c *Config) IssuerHost() string {
	u, err := url.Parse(c.Issuer())
	if err != nil {
		return ""
	}
	return u.Host
}

// TLS reports whether the built-in TLS listener is used.
func (c *Config) TLS() bool { return c.Server.TLSCert != "" }

// IdleTimeout of browser sessions.
func (c *Config) IdleTimeout() time.Duration {
	return time.Duration(c.Session.IdleMinutes) * time.Minute
}

// AbsoluteTimeout of browser sessions.
func (c *Config) AbsoluteTimeout() time.Duration {
	return time.Duration(c.Session.AbsoluteHours) * time.Hour
}

// RoleCacheTTL is how long a role check is reused.
func (c *Config) RoleCacheTTL() time.Duration {
	return time.Duration(c.Roles.CacheSeconds) * time.Second
}

// AdminEnrollmentLinkRequired reports whether admins enroll only by link.
func (c *Config) AdminEnrollmentLinkRequired() bool {
	return c.MFA.AdminEnrollmentRequiresLink == nil || *c.MFA.AdminEnrollmentRequiresLink
}

// credential resolves a file setting or its systemd credential default.
func credential(explicit, name string) (string, error) {
	if explicit != "" {
		return explicit, nil
	}
	dir := os.Getenv("CREDENTIALS_DIRECTORY")
	if dir == "" {
		return "", fmt.Errorf("config: no file configured for %s and no systemd credentials directory (LoadCredential=%s:...)", name, name)
	}
	return filepath.Join(dir, name), nil
}

// MasterKeyPath resolves the master key file.
func (c *Config) MasterKeyPath() (string, error) {
	return credential(c.Keys.MasterKeyFile, "master-key")
}

// ServicePasswordPath resolves the service account's password file.
func (c *Config) ServicePasswordPath() (string, error) {
	return credential(c.ServiceAccount.PasswordFile, "ad-password")
}

// Lifetimes as durations.
func (c *Config) IDTokenTTL() time.Duration {
	return time.Duration(c.Tokens.IDTokenMinutes) * time.Minute
}

// AccessTokenTTL is the access token lifetime.
func (c *Config) AccessTokenTTL() time.Duration {
	return time.Duration(c.Tokens.AccessTokenMinutes) * time.Minute
}

// RefreshTTL is the absolute lifetime of a refresh chain.
func (c *Config) RefreshTTL() time.Duration {
	return time.Duration(c.Tokens.RefreshTokenHours) * time.Hour
}

// RefreshIdleTTL is how long an unused refresh token stays valid.
func (c *Config) RefreshIdleTTL() time.Duration {
	return time.Duration(c.Tokens.RefreshIdleHours) * time.Hour
}

// KeyRotateAfter is the signing-key rotation period.
func (c *Config) KeyRotateAfter() time.Duration {
	return time.Duration(c.Keys.RotateDays) * 24 * time.Hour
}

// KeyOverlap is how long a replaced key stays published.
func (c *Config) KeyOverlap() time.Duration { return time.Duration(c.Keys.OverlapHours) * time.Hour }

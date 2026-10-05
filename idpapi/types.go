package idpapi

import (
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"
)

// Vocabulary shared with conductor's forms. conductor-idp's registry
// enforces the same values (a test keeps them in sync).
var (
	// ClientKinds of OIDC clients.
	ClientKinds = []string{"confidential", "public"}
	// GroupsClaims are the renderings of the groups claim.
	GroupsClaims = []string{"none", "names", "sids"}
	// Scopes a client may be given (openid is always included).
	Scopes = []string{"openid", "profile", "email", "groups", "offline_access"}
	// NameIDFormats a SAML registration may use.
	NameIDFormats = []string{
		"urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress",
		"urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified",
		"urn:oasis:names:tc:SAML:2.0:nameid-format:persistent",
	}
	// NameIDSources are the single-valued sources that identify a user.
	NameIDSources = []string{"email", "upn", "username", "guid"}
	// Sources of SAML attribute values.
	Sources = []string{"email", "upn", "username", "name", "given_name", "surname", "groups", "group_sids", "guid"}
	// SLOBindings a service provider's single logout endpoint may use.
	SLOBindings = []string{"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect", "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"}
	// MFAPolicies for users who are not administrators.
	MFAPolicies = []string{"off", "optional", "required"}
)

// Bounds of free-text fields.
const (
	maxName  = 100
	maxURI   = 2048
	maxList  = 50
	maxText  = 2000
	maxGroup = 200
)

func checkList(name string, v []string, max, each int) error {
	if len(v) > max {
		return fmt.Errorf("%s: at most %d entries", name, max)
	}
	for _, s := range v {
		if len(s) > each || strings.ContainsAny(s, "\x00\r\n") {
			return fmt.Errorf("%s: an entry is too long or has control characters", name)
		}
	}
	return nil
}

func checkText(name, v string, max int) error {
	if len(v) > max || strings.ContainsRune(v, 0) {
		return fmt.Errorf("%s: at most %d bytes", name, max)
	}
	return nil
}

// ---- status ----

// Status describes the provider.
type Status struct {
	Version         string `json:"version"`
	Protocol        int    `json:"protocol"`
	Issuer          string `json:"issuer"`
	DiscoveryURL    string `json:"discovery_url"`
	SAMLEnabled     bool   `json:"saml_enabled"`
	SAMLMetadataURL string `json:"saml_metadata_url,omitempty"`
	SAMLSSOURL      string `json:"saml_sso_url,omitempty"`
	SAMLSLOURL      string `json:"saml_slo_url,omitempty"`
	MFABackend      string `json:"mfa_backend"`
	Clients         int    `json:"clients"`
	SPs             int    `json:"sps"`
	// DirectoryOK is false when the service account cannot read AD.
	DirectoryOK bool `json:"directory_ok"`
}

// ---- OIDC clients ----

// ClientInput is what an administrator provides for an OIDC client.
type ClientInput struct {
	Name           string   `json:"name"`
	Kind           string   `json:"kind"` // confidential or public (fixed after creation)
	RedirectURIs   []string `json:"redirect_uris"`
	PostLogoutURIs []string `json:"post_logout_uris"`
	Scopes         []string `json:"scopes"`
	// Groups are the allowed AD groups by SID (names are resolved too).
	Groups        []string `json:"groups"`
	AllowAllUsers bool     `json:"allow_all_users"`
	FirstParty    bool     `json:"first_party"`
	GroupsClaim   string   `json:"groups_claim"`
	GroupsFilter  []string `json:"groups_filter"`
	RequireMFA    bool     `json:"require_mfa"`
}

// Validate bounds the input (the full rules are the server's).
func (c ClientInput) Validate() error {
	return errors.Join(checkText("name", c.Name, maxName), checkText("kind", c.Kind, 20),
		checkList("redirect_uris", c.RedirectURIs, maxList, maxURI), checkList("post_logout_uris", c.PostLogoutURIs, maxList, maxURI),
		checkList("scopes", c.Scopes, 10, 32), checkList("groups", c.Groups, maxList, maxGroup),
		checkText("groups_claim", c.GroupsClaim, 10), checkList("groups_filter", c.GroupsFilter, maxList, maxGroup))
}

// Client is a registered OIDC client (never its secret).
type Client struct {
	ID string `json:"id"`
	ClientInput
	Enabled         bool      `json:"enabled"`
	HasSecret       bool      `json:"has_secret"`
	CreatedAt       time.Time `json:"created_at"`
	UpdatedAt       time.Time `json:"updated_at"`
	SecretRotatedAt time.Time `json:"secret_rotated_at"`
}

// ClientRef names a client.
type ClientRef struct {
	ID string `json:"id"`
}

// Validate implements Params.
func (c ClientRef) Validate() error {
	if c.ID == "" || len(c.ID) > 64 || strings.ContainsAny(c.ID, " /\x00") {
		return errors.New("id: a client_id is required")
	}
	return nil
}

// ClientCreateParams registers a client.
type ClientCreateParams struct {
	Input ClientInput `json:"input"`
}

// Validate implements Params.
func (p ClientCreateParams) Validate() error { return p.Input.Validate() }

// ClientUpdateParams replaces a client's settings (not its kind or secret).
type ClientUpdateParams struct {
	ID    string      `json:"id"`
	Input ClientInput `json:"input"`
}

// Validate implements Params.
func (p ClientUpdateParams) Validate() error {
	return errors.Join(ClientRef{p.ID}.Validate(), p.Input.Validate())
}

// ClientEnableParams enables or disables a client.
type ClientEnableParams struct {
	ID      string `json:"id"`
	Enabled bool   `json:"enabled"`
}

// Validate implements Params.
func (p ClientEnableParams) Validate() error { return ClientRef{p.ID}.Validate() }

// ClientSecret is the result of client.create and client.rotate: the
// secret is shown once (empty for public clients).
type ClientSecret struct {
	Client Client `json:"client"`
	Secret string `json:"secret,omitempty"`
}

// ClientPreviewParams shows what a user would get from a client: either a
// registered one (ID) or a draft (Input).
type ClientPreviewParams struct {
	ID       string       `json:"id,omitempty"`
	Input    *ClientInput `json:"input,omitempty"`
	Username string       `json:"username"`
}

// Validate implements Params.
func (p ClientPreviewParams) Validate() error {
	if (p.ID == "") == (p.Input == nil) {
		return errors.New("give either id or input")
	}
	if p.Input != nil {
		if err := p.Input.Validate(); err != nil {
			return err
		}
	}
	return checkUsername(p.Username)
}

func checkUsername(u string) error {
	if u == "" || len(u) > 256 || strings.ContainsAny(u, "\x00\r\n") {
		return errors.New("username: required")
	}
	return nil
}

// Value is a named list of values (a claim or an attribute).
type Value struct {
	Name   string   `json:"name"`
	Values []string `json:"values"`
}

// Preview is what a real user would receive.
type Preview struct {
	// User is the account the preview was built for.
	User    string `json:"user"`
	Allowed bool   `json:"allowed"`
	// Reason explains a refusal (not a member of an allowed group,
	// disabled, locked, no value for the NameID).
	Reason string `json:"reason,omitempty"`
	// NameID and its format (SAML only).
	NameIDFormat string `json:"nameid_format,omitempty"`
	NameID       string `json:"nameid,omitempty"`
	// Values are the ID token / userinfo claims (OIDC) or the attributes
	// (SAML).
	Values []Value `json:"values"`
}

// ---- SAML service providers ----

// Attribute maps an AD-derived value to a SAML attribute name.
type Attribute struct {
	Name   string `json:"name"`
	Source string `json:"source"`
}

// SPInput is what an administrator provides for a service provider.
type SPInput struct {
	EntityID         string      `json:"entity_id"`
	Name             string      `json:"name"`
	ACSURLs          []string    `json:"acs_urls"`
	NameIDFormat     string      `json:"nameid_format"`
	NameIDSource     string      `json:"nameid_source"`
	Attributes       []Attribute `json:"attributes"`
	Groups           []string    `json:"groups"`
	AllowAllUsers    bool        `json:"allow_all_users"`
	EncryptAssertion bool        `json:"encrypt_assertion"`
	// EncryptionCert is the SP's DER certificate (from its metadata).
	EncryptionCert []byte `json:"encryption_cert,omitempty"`
	IdPInitiated   bool   `json:"idp_initiated"`
	DefaultRelay   string `json:"default_relay"`
	RequireMFA     bool   `json:"require_mfa"`
	// SLOURL and SLOBinding are the SP's single logout endpoint (empty:
	// the SP takes no part in single logout).
	SLOURL     string `json:"slo_url"`
	SLOBinding string `json:"slo_binding"`
	// SigningCert is the SP's DER signing certificate: a LogoutRequest
	// signed with it (HTTP-Redirect binding) ends the session without a
	// confirmation page.
	SigningCert []byte `json:"signing_cert,omitempty"`
}

// Validate bounds the input.
func (s SPInput) Validate() error {
	var errs []error
	errs = append(errs, checkText("entity_id", s.EntityID, 1024), checkText("name", s.Name, maxName),
		checkList("acs_urls", s.ACSURLs, maxList, maxURI), checkText("nameid_format", s.NameIDFormat, 200),
		checkText("nameid_source", s.NameIDSource, 32), checkList("groups", s.Groups, maxList, maxGroup),
		checkText("default_relay", s.DefaultRelay, 512), checkText("slo_url", s.SLOURL, maxURI),
		checkText("slo_binding", s.SLOBinding, 200))
	if len(s.Attributes) > maxList {
		errs = append(errs, errors.New("attributes: at most 50"))
	}
	for _, a := range s.Attributes {
		errs = append(errs, checkText("attribute name", a.Name, 256), checkText("attribute source", a.Source, 32))
	}
	if len(s.EncryptionCert) > 16<<10 || len(s.SigningCert) > 16<<10 {
		errs = append(errs, errors.New("certificates: at most 16 KiB"))
	}
	return errors.Join(errs...)
}

// Cert describes a certificate (never a private key).
type Cert struct {
	Subject  string    `json:"subject"`
	NotAfter time.Time `json:"not_after"`
	SHA256   string    `json:"sha256"`
}

// SP is a registered service provider.
type SP struct {
	SPInput
	Enabled        bool      `json:"enabled"`
	CreatedAt      time.Time `json:"created_at"`
	UpdatedAt      time.Time `json:"updated_at"`
	EncryptionInfo *Cert     `json:"encryption_info,omitempty"`
	SigningInfo    *Cert     `json:"signing_info,omitempty"`
}

// SPRef names a service provider.
type SPRef struct {
	EntityID string `json:"entity_id"`
}

// Validate implements Params.
func (r SPRef) Validate() error {
	if r.EntityID == "" || len(r.EntityID) > 1024 {
		return errors.New("entity_id: required")
	}
	return nil
}

// SPMetadataParams imports an SP's metadata, given as a document or as an
// https URL conductor-idp fetches once (1 MiB at most, no redirects to
// another scheme). Nothing is saved: the result prefills a form.
type SPMetadataParams struct {
	XML string `json:"xml,omitempty"`
	URL string `json:"url,omitempty"`
}

// Validate implements Params.
func (p SPMetadataParams) Validate() error {
	if (p.XML == "") == (p.URL == "") {
		return errors.New("give either xml or url")
	}
	if len(p.XML) > 1<<20 {
		return errors.New("xml: at most 1 MiB")
	}
	if p.URL != "" && (!strings.HasPrefix(p.URL, "https://") || len(p.URL) > maxURI) {
		return errors.New("url: an https URL is required")
	}
	return nil
}

// SPDraft is a parsed metadata document.
type SPDraft struct {
	Input    SPInput  `json:"input"`
	Warnings []string `json:"warnings,omitempty"`
}

// SPCreateParams registers a service provider.
type SPCreateParams struct {
	Input SPInput `json:"input"`
}

// Validate implements Params.
func (p SPCreateParams) Validate() error { return p.Input.Validate() }

// SPUpdateParams replaces a registration (the entity ID cannot change).
// Certificates left empty in Input keep the registered ones, unless the
// matching Clear flag is set.
type SPUpdateParams struct {
	EntityID            string  `json:"entity_id"`
	Input               SPInput `json:"input"`
	ClearEncryptionCert bool    `json:"clear_encryption_cert,omitempty"`
	ClearSigningCert    bool    `json:"clear_signing_cert,omitempty"`
}

// Validate implements Params.
func (p SPUpdateParams) Validate() error {
	return errors.Join(SPRef{p.EntityID}.Validate(), p.Input.Validate())
}

// SPEnableParams enables or disables a service provider.
type SPEnableParams struct {
	EntityID string `json:"entity_id"`
	Enabled  bool   `json:"enabled"`
}

// Validate implements Params.
func (p SPEnableParams) Validate() error { return SPRef{p.EntityID}.Validate() }

// SPPreviewParams shows the NameID and attributes a user would get from a
// registered SP (EntityID) or a draft (Input).
type SPPreviewParams struct {
	EntityID string   `json:"entity_id,omitempty"`
	Input    *SPInput `json:"input,omitempty"`
	Username string   `json:"username"`
}

// Validate implements Params.
func (p SPPreviewParams) Validate() error {
	if (p.EntityID == "") == (p.Input == nil) {
		return errors.New("give either entity_id or input")
	}
	if p.Input != nil {
		if err := p.Input.Validate(); err != nil {
			return err
		}
	}
	return checkUsername(p.Username)
}

// ---- keys ----

// Key purposes.
const (
	KeyOIDC = "oidc"
	KeySAML = "saml"
)

// Key is a published signing key (public facts only).
type Key struct {
	ID        string    `json:"id"`
	Purpose   string    `json:"purpose"`
	Alg       string    `json:"alg"`
	CreatedAt time.Time `json:"created_at"`
	// RetireAt is when the key leaves the JWKS or the metadata (zero: not
	// scheduled).
	RetireAt time.Time `json:"retire_at"`
	// Signing is the key that signs now; the others are published only
	// (overlap of a rotation).
	Signing bool  `json:"signing"`
	Cert    *Cert `json:"cert,omitempty"`
}

// Keys is the state of both key sets.
type Keys struct {
	OIDC         []Key `json:"oidc"`
	SAML         []Key `json:"saml"`
	SAMLEnabled  bool  `json:"saml_enabled"`
	RotateDays   int   `json:"rotate_days"`
	OverlapHours int   `json:"overlap_hours"`
	// NextOIDCRotation is when the scheduled rotation will happen.
	NextOIDCRotation time.Time `json:"next_oidc_rotation"`
	// SAMLSwitchAt is when a staged SAML rotation makes the new key sign
	// (zero when none is staged).
	SAMLSwitchAt time.Time `json:"saml_switch_at"`
}

// KeysRotateParams rotates one key set. Immediate applies to SAML only:
// the new key signs at once (emergency) instead of after the overlap.
type KeysRotateParams struct {
	Purpose   string `json:"purpose"`
	Immediate bool   `json:"immediate"`
}

// Validate implements Params.
func (p KeysRotateParams) Validate() error {
	if p.Purpose != KeyOIDC && p.Purpose != KeySAML {
		return errors.New("purpose: oidc or saml")
	}
	if p.Immediate && p.Purpose != KeySAML {
		return errors.New("immediate: SAML only")
	}
	return nil
}

// KeyRotated names the new key.
type KeyRotated struct {
	ID string `json:"id"`
}

// KeysCertParams asks for a SAML signing certificate (empty ID: the one
// that signs now).
type KeysCertParams struct {
	ID string `json:"id,omitempty"`
}

// Validate implements Params.
func (p KeysCertParams) Validate() error {
	if len(p.ID) > 64 {
		return errors.New("id: too long")
	}
	return nil
}

// CertPEM is a SAML signing certificate to give to service providers.
type CertPEM struct {
	ID   string `json:"id"`
	PEM  string `json:"pem"`
	Cert Cert   `json:"cert"`
}

// ---- settings ----

// Settings are what administrators edit from the panel; they override the
// configuration file's values.
type Settings struct {
	SessionIdleMinutes   int `json:"session_idle_minutes"`
	SessionAbsoluteHours int `json:"session_absolute_hours"`
	// MFAPolicy for users who are not administrators (local 2FA backend
	// only; with the conductor backend, conductor's policy applies).
	MFAPolicy string `json:"mfa_policy"`
	// ConsentText is an extra note on the consent screen, per language
	// ("en", "pt-BR"); empty: none.
	ConsentText map[string]string `json:"consent_text"`
}

// Languages of the consent text.
var Languages = []string{"en", "pt-BR"}

// Validate checks the ranges.
func (s Settings) Validate() error {
	var errs []error
	if s.SessionIdleMinutes < 1 || s.SessionIdleMinutes > 24*60 {
		errs = append(errs, errors.New("session_idle_minutes: 1-1440"))
	}
	if s.SessionAbsoluteHours < 1 || s.SessionAbsoluteHours > 24 {
		errs = append(errs, errors.New("session_absolute_hours: 1-24"))
	}
	if !slices.Contains(MFAPolicies, s.MFAPolicy) {
		errs = append(errs, errors.New("mfa_policy: off, optional or required"))
	}
	for lang, t := range s.ConsentText {
		if !slices.Contains(Languages, lang) {
			errs = append(errs, fmt.Errorf("consent_text: unknown language %q", lang))
		}
		errs = append(errs, checkText("consent_text", t, maxText))
	}
	return errors.Join(errs...)
}

// SettingsView is the current settings with their origin.
type SettingsView struct {
	// Version increases with every saved change (0: never edited, the
	// file's values apply).
	Version  int64    `json:"version"`
	Settings Settings `json:"settings"`
	// Defaults are the configuration file's values.
	Defaults   Settings `json:"defaults"`
	MFABackend string   `json:"mfa_backend"`
	// MFAPolicyShared: the second-factor policy is conductor's (backend
	// "conductor"), MFAPolicy is not used.
	MFAPolicyShared bool      `json:"mfa_policy_shared"`
	UpdatedAt       time.Time `json:"updated_at"`
	UpdatedBy       string    `json:"updated_by"`
}

// SettingsUpdateParams saves new settings. BaseVersion must be the version
// the editor started from (optimistic concurrency).
type SettingsUpdateParams struct {
	BaseVersion int64    `json:"base_version"`
	Settings    Settings `json:"settings"`
}

// Validate implements Params.
func (p SettingsUpdateParams) Validate() error {
	if p.BaseVersion < 0 {
		return errors.New("base_version: not negative")
	}
	return p.Settings.Validate()
}

// ---- activity and audit ----

// ActivityParams selects a period of days ending now.
type ActivityParams struct {
	Days int `json:"days"`
}

// Validate implements Params.
func (p ActivityParams) Validate() error {
	if p.Days < 1 || p.Days > 90 {
		return errors.New("days: 1-90")
	}
	return nil
}

// AppActivity counts sign-ins to one application.
type AppActivity struct {
	Kind    string `json:"kind"` // oidc or saml
	ID      string `json:"id"`   // client_id or entity ID
	Name    string `json:"name"`
	SignIns int    `json:"sign_ins"`
	Denied  int    `json:"denied"`
	Users   int    `json:"users"`
}

// Activity summarizes the audit log over a period.
type Activity struct {
	Since time.Time     `json:"since"`
	Until time.Time     `json:"until"`
	Apps  []AppActivity `json:"apps"`
	// SignIns are successful password sign-ins; Failures refused ones
	// (wrong password, disabled...); Lockouts the refusals because the
	// account is locked in AD; RateLimited the refusals by the idp's own
	// limits; MFAFailures wrong second factors.
	SignIns     int `json:"sign_ins"`
	Failures    int `json:"failures"`
	Lockouts    int `json:"lockouts"`
	RateLimited int `json:"rate_limited"`
	MFAFailures int `json:"mfa_failures"`
	// Recent are the latest refusals (newest first, at most 20).
	Recent []AuditEvent `json:"recent"`
}

// AuditEvent is one row of conductor-idp's audit log.
type AuditEvent struct {
	ID     int64     `json:"id"`
	Time   time.Time `json:"ts"`
	Actor  string    `json:"actor"`
	Action string    `json:"action"`
	Target string    `json:"target"`
	Detail string    `json:"detail"`
	Result string    `json:"result"`
	IP     string    `json:"ip"`
}

// AuditListParams filters the log (empty fields match everything).
type AuditListParams struct {
	Actor  string `json:"actor,omitempty"`
	Action string `json:"action,omitempty"`
	Target string `json:"target,omitempty"`
	Result string `json:"result,omitempty"`
	Offset int    `json:"offset"`
	Limit  int    `json:"limit"`
}

// Validate implements Params.
func (p AuditListParams) Validate() error {
	if p.Offset < 0 || p.Limit < 1 || p.Limit > 500 {
		return errors.New("offset >= 0, limit 1-500")
	}
	return errors.Join(checkText("actor", p.Actor, 256), checkText("action", p.Action, 64),
		checkText("target", p.Target, 512), checkText("result", p.Result, 16))
}

// AuditPage is a window of the log, newest first.
type AuditPage struct {
	Events []AuditEvent `json:"events"`
	More   bool         `json:"more"`
}

// AuditVerify is the result of a chain check.
type AuditVerify struct {
	Rows     int    `json:"rows"`
	LastHash string `json:"last_hash"`
	BrokenAt int64  `json:"broken_at"`
	Reason   string `json:"reason,omitempty"`
}

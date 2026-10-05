package idpapi

import (
	"errors"
	"fmt"
	"net/url"
	"regexp"
	"strings"
)

// Preset is a guided starting point for a common application: it turns a
// few answers (a host name, a domain) into a client or a service provider
// registration that the administrator then reviews like any other. A
// preset never bypasses the form: groups, consent and 2FA are still chosen
// by the administrator.
type Preset struct {
	ID string `json:"id"`
	// Name is the product name (not translated).
	Name string `json:"name"`
	// Kind is "oidc" or "saml".
	Kind string `json:"kind"`
	// Params are the questions, in order.
	Params []PresetParam `json:"params"`
}

// PresetParam is one question of a preset. Its label is translated by the
// client from "sso.preset.param.<Key>".
type PresetParam struct {
	Key      string `json:"key"`
	Example  string `json:"example"`
	Required bool   `json:"required"`
}

// Preset kinds.
const (
	KindOIDC = "oidc"
	KindSAML = "saml"
)

// Presets are the guided applications, in display order.
var Presets = []Preset{
	{ID: "google-workspace", Name: "Google Workspace", Kind: KindSAML, Params: []PresetParam{
		{Key: "domain", Example: "example.com", Required: true},
		{Key: "entity_id", Example: "https://accounts.google.com/samlrp/03abc123"},
		{Key: "acs_url", Example: "https://accounts.google.com/samlrp/acs?rpid=03abc123"},
	}},
	{ID: "grafana", Name: "Grafana", Kind: KindOIDC, Params: []PresetParam{
		{Key: "base_url", Example: "https://grafana.example.com", Required: true},
	}},
	{ID: "nextcloud", Name: "Nextcloud", Kind: KindOIDC, Params: []PresetParam{
		{Key: "base_url", Example: "https://cloud.example.com", Required: true},
	}},
	{ID: "gitlab", Name: "GitLab", Kind: KindOIDC, Params: []PresetParam{
		{Key: "base_url", Example: "https://gitlab.example.com", Required: true},
	}},
	{ID: "generic-oidc", Name: "OpenID Connect", Kind: KindOIDC, Params: []PresetParam{
		{Key: "redirect_uri", Example: "https://app.example.com/oauth2/callback", Required: true},
	}},
	{ID: "generic-saml", Name: "SAML 2.0", Kind: KindSAML},
}

// PresetByID returns a preset.
func PresetByID(id string) (Preset, bool) {
	for _, p := range Presets {
		if p.ID == id {
			return p, true
		}
	}
	return Preset{}, false
}

var domainRE = regexp.MustCompile(`^([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$`)

// baseURL validates an https base URL (a path is kept, a trailing slash
// removed).
func baseURL(v string) (string, error) {
	u, err := url.Parse(strings.TrimSpace(v))
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return "", errors.New("an https URL without query is required")
	}
	return strings.TrimRight(u.String(), "/"), nil
}

func (p Preset) values(in map[string]string) (map[string]string, error) {
	out := map[string]string{}
	var errs []error
	for _, q := range p.Params {
		v := strings.TrimSpace(in[q.Key])
		if v == "" && q.Required {
			errs = append(errs, fmt.Errorf("%s: required", q.Key))
		}
		if len(v) > maxURI {
			errs = append(errs, fmt.Errorf("%s: too long", q.Key))
		}
		out[q.Key] = v
	}
	return out, errors.Join(errs...)
}

// Client builds the client registration of an OIDC preset. Groups are left
// empty: the administrator picks them.
func (p Preset) Client(in map[string]string) (ClientInput, error) {
	if p.Kind != KindOIDC {
		return ClientInput{}, errors.New("not an OIDC preset")
	}
	v, err := p.values(in)
	if err != nil {
		return ClientInput{}, err
	}
	c := ClientInput{Kind: "confidential", Scopes: []string{"openid", "profile", "email"}, GroupsClaim: "none"}
	base := ""
	if v["base_url"] != "" {
		if base, err = baseURL(v["base_url"]); err != nil {
			return ClientInput{}, fmt.Errorf("base_url: %w", err)
		}
	}
	switch p.ID {
	case "grafana":
		// Grafana generic OAuth: groups as names for role mapping
		// (role_attribute_path), PKCE on (use_pkce = true).
		c.Name = "Grafana"
		c.RedirectURIs = []string{base + "/login/generic_oauth"}
		c.PostLogoutURIs = []string{base + "/login"}
		c.Scopes = append(c.Scopes, "groups")
		c.GroupsClaim = "names"
		c.FirstParty = true
	case "nextcloud":
		// Nextcloud "OpenID Connect user backend" (user_oidc) app.
		c.Name = "Nextcloud"
		c.RedirectURIs = []string{base + "/apps/user_oidc/code"}
		c.Scopes = append(c.Scopes, "groups")
		c.GroupsClaim = "names"
		c.FirstParty = true
	case "gitlab":
		// GitLab omniauth openid_connect provider (pkce: true).
		c.Name = "GitLab"
		c.RedirectURIs = []string{base + "/users/auth/openid_connect/callback"}
		c.FirstParty = true
	case "generic-oidc":
		c.Name = "OpenID Connect application"
		c.RedirectURIs = []string{v["redirect_uri"]}
	default:
		return ClientInput{}, errors.New("unknown preset")
	}
	return c, nil
}

// SP builds the service provider registration of a SAML preset.
func (p Preset) SP(in map[string]string) (SPInput, error) {
	if p.Kind != KindSAML {
		return SPInput{}, errors.New("not a SAML preset")
	}
	v, err := p.values(in)
	if err != nil {
		return SPInput{}, err
	}
	switch p.ID {
	case "google-workspace":
		// Google's SSO profile for a third-party IdP: e-mail NameID, no
		// attributes, no single logout (Google signs users out with a
		// redirect to the "sign-out page URL" instead). Legacy profiles use
		// google.com/a/<domain> and the /a/<domain>/acs endpoint; the
		// profiles created in the Admin console today show their own
		// entity ID and ACS URL ("samlrp"), which take precedence.
		d := strings.ToLower(strings.TrimSpace(v["domain"]))
		if !domainRE.MatchString(d) {
			return SPInput{}, errors.New("domain: a DNS domain name is required")
		}
		sp := SPInput{Name: "Google Workspace (" + d + ")", EntityID: "google.com/a/" + d,
			ACSURLs:      []string{"https://www.google.com/a/" + d + "/acs"},
			NameIDFormat: NameIDFormats[0], NameIDSource: "email", Attributes: []Attribute{}}
		if e := v["entity_id"]; e != "" {
			sp.EntityID = e
		}
		if a := v["acs_url"]; a != "" {
			if !strings.HasPrefix(a, "https://") {
				return SPInput{}, errors.New("acs_url: an https URL is required")
			}
			sp.ACSURLs = []string{a}
		}
		return sp, nil
	case "generic-saml":
		return SPInput{Name: "SAML application", NameIDFormat: NameIDFormats[0], NameIDSource: "email", Attributes: []Attribute{}}, nil
	}
	return SPInput{}, errors.New("unknown preset")
}

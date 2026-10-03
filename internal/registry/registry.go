// Package registry validates and builds client and service-provider
// registrations. The CLI and the admin pages share it, so both enforce the
// same rules.
package registry

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"slices"
	"strings"

	"github.com/zitadel/oidc/v3/pkg/oidc"

	"github.com/samba-conductor/ad/sid"
	"github.com/samba-conductor/conductor-idp/internal/directory"
	"github.com/samba-conductor/conductor-idp/internal/oidcp"
	"github.com/samba-conductor/conductor-idp/internal/samlidp"
	"github.com/samba-conductor/conductor-idp/internal/secret"
	"github.com/samba-conductor/conductor-idp/internal/store"
)

// SecretPrefix marks client secrets.
const SecretPrefix = "cidp_cs_"

// ClientInput is what an administrator provides.
type ClientInput struct {
	Name           string
	Kind           string // confidential or public
	RedirectURIs   []string
	PostLogoutURIs []string
	Scopes         []string
	// Groups are SIDs or group names (resolved to SIDs).
	Groups        []string
	AllowAllUsers bool
	FirstParty    bool
	GroupsClaim   string
	GroupsFilter  []string // SIDs or names
	RequireMFA    bool
}

// ValidRedirect checks a redirect or post-logout URI: absolute, no
// fragment, https or a loopback http URI (local tools), or a private-use
// scheme for public (native) clients.
func ValidRedirect(raw string, public bool) error {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme == "" {
		return fmt.Errorf("%q is not an absolute URI", raw)
	}
	if u.Fragment != "" || strings.Contains(raw, "#") {
		return fmt.Errorf("%q must not contain a fragment", raw)
	}
	if u.User != nil {
		return fmt.Errorf("%q must not contain credentials", raw)
	}
	switch u.Scheme {
	case "https":
		if u.Host == "" {
			return fmt.Errorf("%q has no host", raw)
		}
		return nil
	case "http":
		h := u.Hostname()
		if h == "localhost" || h == "127.0.0.1" || h == "::1" {
			return nil
		}
		return fmt.Errorf("%q: plain http is only allowed for loopback hosts", raw)
	default:
		// Private-use URI schemes (RFC 8252 §7.1) need a dot (reverse
		// domain name) and are for native apps only.
		if public && strings.Contains(u.Scheme, ".") {
			return nil
		}
		return fmt.Errorf("%q: scheme %q is not allowed", raw, u.Scheme)
	}
}

// ResolveGroups turns SIDs or group names into SID strings.
func ResolveGroups(ctx context.Context, dir directory.Backend, in []string) ([]string, error) {
	var out []string
	for _, g := range in {
		g = strings.TrimSpace(g)
		if g == "" {
			continue
		}
		if s, err := sid.Parse(g); err == nil {
			out = append(out, s.String())
			continue
		}
		if dir == nil {
			return nil, fmt.Errorf("group %q is not a SID (no directory to resolve names)", g)
		}
		s, err := dir.GroupByName(ctx, g)
		if errors.Is(err, directory.ErrGroupNotFound) {
			return nil, fmt.Errorf("group %q not found", g)
		}
		if err != nil {
			return nil, err
		}
		out = append(out, s.String())
	}
	slices.Sort(out)
	return slices.Compact(out), nil
}

// BuildClient validates input into a client (without ID and secret).
func BuildClient(ctx context.Context, dir directory.Backend, in ClientInput) (*store.Client, error) {
	var errs []error
	bad := func(format string, a ...any) { errs = append(errs, fmt.Errorf(format, a...)) }
	name := strings.TrimSpace(in.Name)
	if name == "" || len(name) > 100 {
		bad("name must be 1-100 characters")
	}
	if in.Kind != store.ClientConfidential && in.Kind != store.ClientPublic {
		bad("kind must be confidential or public")
	}
	public := in.Kind == store.ClientPublic
	if len(in.RedirectURIs) == 0 {
		bad("at least one redirect URI is required")
	}
	for _, u := range in.RedirectURIs {
		if err := ValidRedirect(u, public); err != nil {
			errs = append(errs, err)
		}
	}
	for _, u := range in.PostLogoutURIs {
		if err := ValidRedirect(u, public); err != nil {
			errs = append(errs, err)
		}
	}
	scopes := []string{oidc.ScopeOpenID}
	for _, sc := range in.Scopes {
		if !slices.Contains(oidcp.SupportedScopes, sc) {
			bad("unsupported scope %q", sc)
			continue
		}
		if !slices.Contains(scopes, sc) {
			scopes = append(scopes, sc)
		}
	}
	claim := in.GroupsClaim
	if claim == "" {
		claim = store.GroupsNone
	}
	if !slices.Contains([]string{store.GroupsNone, store.GroupsNames, store.GroupsSIDs}, claim) {
		bad("groups claim must be none, names or sids")
	}
	if claim != store.GroupsNone && !slices.Contains(scopes, oidcp.ScopeGroups) {
		scopes = append(scopes, oidcp.ScopeGroups)
	}
	if claim == store.GroupsNone {
		scopes = slices.DeleteFunc(scopes, func(s string) bool { return s == oidcp.ScopeGroups })
	}
	groups, err := ResolveGroups(ctx, dir, in.Groups)
	if err != nil {
		errs = append(errs, err)
	}
	if len(groups) == 0 && !in.AllowAllUsers {
		bad("give at least one allowed group, or allow all users explicitly")
	}
	filter, err := ResolveGroups(ctx, dir, in.GroupsFilter)
	if err != nil {
		errs = append(errs, err)
	}
	if err := errors.Join(errs...); err != nil {
		return nil, err
	}
	return &store.Client{
		Name: name, Kind: in.Kind, RedirectURIs: dedupe(in.RedirectURIs), PostLogoutURIs: dedupe(in.PostLogoutURIs),
		Scopes: scopes, AllowedGroups: groups, AllowAllUsers: in.AllowAllUsers, FirstParty: in.FirstParty,
		GroupsClaim: claim, GroupsFilter: filter, RequireMFA: in.RequireMFA, Enabled: true,
	}, nil
}

func dedupe(in []string) []string {
	var out []string
	for _, v := range in {
		v = strings.TrimSpace(v)
		if v != "" && !slices.Contains(out, v) {
			out = append(out, v)
		}
	}
	return out
}

// NewClientID returns a client_id.
func NewClientID() string { return secret.Token("cidp_")[:30] }

// NewSecret returns a client secret and its stored hash.
func NewSecret() (string, string) {
	v := secret.Token(SecretPrefix)
	return v, secret.Hash(v)
}

// CreateClient validates, stores and returns a client with its secret
// (empty for public clients), shown once.
func CreateClient(ctx context.Context, st *store.Store, dir directory.Backend, in ClientInput) (*store.Client, string, error) {
	c, err := BuildClient(ctx, dir, in)
	if err != nil {
		return nil, "", err
	}
	c.ID = NewClientID()
	var plain string
	if !c.Public() {
		plain, c.SecretHash = NewSecret()
	}
	if err := st.CreateClient(ctx, c); err != nil {
		return nil, "", err
	}
	return c, plain, nil
}

// UpdateClient applies new settings to an existing client; consents are
// forgotten when the scopes grow (users are asked again).
func UpdateClient(ctx context.Context, st *store.Store, dir directory.Backend, id string, in ClientInput) (*store.Client, error) {
	old, err := st.GetClient(ctx, id)
	if err != nil {
		return nil, err
	}
	in.Kind = old.Kind
	c, err := BuildClient(ctx, dir, in)
	if err != nil {
		return nil, err
	}
	c.ID, c.Enabled = old.ID, old.Enabled
	if err := st.UpdateClient(ctx, c); err != nil {
		return nil, err
	}
	for _, sc := range c.Scopes {
		if !slices.Contains(old.Scopes, sc) {
			if err := st.DeleteConsents(ctx, id); err != nil {
				return nil, err
			}
			break
		}
	}
	return c, nil
}

// RotateSecret gives a confidential client a new secret (shown once) and
// revokes nothing: the old secret stops working at once.
func RotateSecret(ctx context.Context, st *store.Store, id string) (string, error) {
	c, err := st.GetClient(ctx, id)
	if err != nil {
		return "", err
	}
	if c.Public() {
		return "", errors.New("public clients have no secret")
	}
	plain, hash := NewSecret()
	return plain, st.SetClientSecret(ctx, id, hash)
}

// SPInput is what an administrator provides for a SAML service provider.
type SPInput struct {
	EntityID         string
	Name             string
	ACSURLs          []string
	NameIDFormat     string
	NameIDSource     string
	Attributes       []store.SAMLAttribute
	Groups           []string // SIDs or names
	AllowAllUsers    bool
	EncryptAssertion bool
	EncryptionCert   []byte
	IdPInitiated     bool
	DefaultRelay     string
	RequireMFA       bool
}

// BuildSP validates input into a registration.
func BuildSP(ctx context.Context, dir directory.Backend, in SPInput) (*store.SAMLSP, error) {
	var errs []error
	bad := func(format string, a ...any) { errs = append(errs, fmt.Errorf(format, a...)) }
	if in.EntityID == "" || len(in.EntityID) > 1024 || strings.ContainsAny(in.EntityID, " \t\n") {
		bad("entity ID is required (no spaces)")
	}
	name := strings.TrimSpace(in.Name)
	if name == "" || len(name) > 100 {
		bad("name must be 1-100 characters")
	}
	acs := dedupe(in.ACSURLs)
	if len(acs) == 0 {
		bad("at least one ACS URL is required")
	}
	for _, a := range acs {
		if !samlidp.ValidACS(a) {
			bad("ACS URL %q must be https (or http on a loopback host)", a)
		}
	}
	if !slices.Contains(samlidp.NameIDFormats, in.NameIDFormat) {
		bad("unsupported NameID format %q", in.NameIDFormat)
	}
	if !slices.Contains(samlidp.NameIDSources, in.NameIDSource) {
		bad("NameID source must be one of %s", strings.Join(samlidp.NameIDSources, ", "))
	}
	for _, a := range in.Attributes {
		if a.Name == "" || len(a.Name) > 256 || !slices.Contains(samlidp.Sources, a.Source) {
			bad("attribute %q: source must be one of %s", a.Name, strings.Join(samlidp.Sources, ", "))
		}
	}
	if in.EncryptAssertion && len(in.EncryptionCert) == 0 {
		bad("encryption needs the SP's certificate (import its metadata)")
	}
	if len(in.DefaultRelay) > 512 {
		bad("default RelayState is too long")
	}
	groups, err := ResolveGroups(ctx, dir, in.Groups)
	if err != nil {
		errs = append(errs, err)
	}
	if len(groups) == 0 && !in.AllowAllUsers {
		bad("give at least one allowed group, or allow all users explicitly")
	}
	if err := errors.Join(errs...); err != nil {
		return nil, err
	}
	return &store.SAMLSP{EntityID: in.EntityID, Name: name, ACSURLs: acs, NameIDFormat: in.NameIDFormat,
		NameIDSource: in.NameIDSource, Attributes: in.Attributes, AllowedGroups: groups, AllowAllUsers: in.AllowAllUsers,
		EncryptAssertion: in.EncryptAssertion, EncryptionCert: in.EncryptionCert, IdPInitiated: in.IdPInitiated,
		DefaultRelay: in.DefaultRelay, RequireMFA: in.RequireMFA, Enabled: true}, nil
}

// ParseAttributes reads "Name=source" pairs (one per element).
func ParseAttributes(lines []string) ([]store.SAMLAttribute, error) {
	var out []store.SAMLAttribute
	for _, l := range lines {
		l = strings.TrimSpace(l)
		if l == "" {
			continue
		}
		name, source, ok := strings.Cut(l, "=")
		if !ok {
			return nil, fmt.Errorf("attribute %q must be Name=source", l)
		}
		out = append(out, store.SAMLAttribute{Name: strings.TrimSpace(name), Source: strings.TrimSpace(source)})
	}
	return out, nil
}

// FormatAttributes renders attributes as "Name=source" lines.
func FormatAttributes(a []store.SAMLAttribute) []string {
	out := make([]string, len(a))
	for i, v := range a {
		out[i] = v.Name + "=" + v.Source
	}
	return out
}

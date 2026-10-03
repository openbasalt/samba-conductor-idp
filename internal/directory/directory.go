// Package directory adapts the ad library to conductor-idp.
//
// Passwords are verified with the user's own credentials (Kerberos AS
// exchange first, LDAP simple bind over TLS only when configured and no KDC
// answers) and forgotten right away: the idp keeps no user credential.
// Everything that happens without the user (claims, refresh, userinfo,
// role checks) reads AD with a read-only service account.
//
// Helpers that the ad library does not offer yet (lookup by objectGUID,
// SID-to-name resolution in batches, a renewing service-account session)
// live here; they are listed in docs/decisions.md for upstreaming.
package directory

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"sync"
	"time"

	ad "github.com/openbasalt/samba-conductor-ad"
	"github.com/openbasalt/samba-conductor-ad/escape"
	"github.com/openbasalt/samba-conductor-ad/sid"
)

// User is what the idp knows about an account, read from AD.
type User struct {
	// GUID is the objectGUID in its canonical string form: the stable
	// subject identifier (it survives renames and moves).
	GUID        string
	SID         sid.SID
	DN          string
	SAM         string
	UPN         string
	Mail        string
	DisplayName string
	GivenName   string
	Surname     string
	Enabled     bool
	Locked      bool
	Expired     bool // accountExpires in the past
	// GroupSIDs are every group the user belongs to, transitively,
	// including the primary group.
	GroupSIDs []sid.SID
}

// Active reports whether the account may sign in.
func (u *User) Active() bool { return u.Enabled && !u.Locked && !u.Expired }

// Name returns the display name, or the account name.
func (u *User) Name() string {
	if u.DisplayName != "" {
		return u.DisplayName
	}
	return u.SAM
}

// InAnyGroup reports whether the user is a member of one of the SIDs.
func (u *User) InAnyGroup(sids []string) bool {
	for _, s := range sids {
		want, err := sid.Parse(s)
		if err != nil {
			continue
		}
		if sid.Contains(u.GroupSIDs, want) {
			return true
		}
	}
	return false
}

// Backend is the directory as the rest of the idp sees it (a fake in
// tests).
type Backend interface {
	Realm() string
	// Authenticate verifies a password. Refusals are *ad.AuthError; any
	// other error means the directory could not decide.
	Authenticate(ctx context.Context, sam, password string) error
	// ChangeExpiredPassword changes a password with the old one (kpasswd),
	// for accounts that must change or whose password expired.
	ChangeExpiredPassword(ctx context.Context, sam, oldPassword, newPassword string) error
	UserBySAM(ctx context.Context, sam string) (*User, error)
	UserByGUID(ctx context.Context, guid string) (*User, error)
	// GroupNames maps SIDs (string form) to group sAMAccountNames.
	GroupNames(ctx context.Context, sids []sid.SID) (map[string]string, error)
	// DomainAdminsSID is the SID of the domain's Domain Admins group.
	DomainAdminsSID(ctx context.Context) (sid.SID, error)
	// GroupByName resolves a group's sAMAccountName to its SID.
	GroupByName(ctx context.Context, name string) (sid.SID, error)
}

// ErrNotFound is returned for an unknown user.
var ErrNotFound = errors.New("directory: user not found")

// Options configure a Directory.
type Options struct {
	Config ad.Config
	// SimpleBindFallback verifies passwords with an LDAP simple bind when
	// no KDC answers.
	SimpleBindFallback bool
	ServiceUser        string
	ServicePassword    string
	// CacheTTL bounds how long a user lookup is reused (default 30 s).
	CacheTTL time.Duration
}

// Directory is the real Backend.
type Directory struct {
	cfg      ad.Config
	fallback bool
	svcUser  string
	svcPass  string
	cacheTTL time.Duration

	mu      sync.Mutex
	svc     *ad.Session
	users   map[string]cachedUser // by GUID and "sam:"+sam
	names   map[string]cachedName
	daSID   sid.SID
	daUntil time.Time
	now     func() time.Time
}

type cachedUser struct {
	u     *User
	until time.Time
}

type cachedName struct {
	name  string
	until time.Time
}

// maxCache bounds the caches; when full they are cleared.
const maxCache = 10_000

// New builds a Directory.
func New(o Options) (*Directory, error) {
	if o.ServiceUser == "" || o.ServicePassword == "" {
		return nil, errors.New("directory: service account username and password are required")
	}
	ttl := o.CacheTTL
	if ttl <= 0 {
		ttl = 30 * time.Second
	}
	return &Directory{cfg: o.Config, fallback: o.SimpleBindFallback, svcUser: o.ServiceUser, svcPass: o.ServicePassword,
		cacheTTL: ttl, users: map[string]cachedUser{}, names: map[string]cachedName{}, now: time.Now}, nil
}

// ADConfig builds the ad.Config from the configured values.
func ADConfig(realm, caFile string, dcs, preferred, dnsServers []string) (ad.Config, error) {
	pemData, err := os.ReadFile(caFile)
	if err != nil {
		return ad.Config{}, fmt.Errorf("directory: reading the domain CA: %w", err)
	}
	pool, err := ad.CertPoolFromPEM(pemData)
	if err != nil {
		return ad.Config{}, err
	}
	cfg := ad.Config{Realm: strings.ToUpper(realm), DCs: dcs, Preferred: preferred, RootCAs: pool}
	if len(dnsServers) > 0 {
		cfg.Resolver = ad.NewDNSResolver(dnsServers...)
	}
	return cfg, nil
}

// Realm returns the Kerberos realm.
func (d *Directory) Realm() string { return d.cfg.Realm }

// Authenticate verifies a user's password and forgets it.
func (d *Directory) Authenticate(ctx context.Context, sam, password string) error {
	s, err := ad.SignIn(ctx, d.cfg, sam, password)
	if err == nil {
		s.Close()
		return nil
	}
	var ae *ad.AuthError
	if errors.As(err, &ae) || !d.fallback {
		return err
	}
	// No KDC answered: the explicit simple-bind fallback decides.
	conn, berr := ad.Connect(ctx, d.cfg, ad.SimpleAuth(sam, password))
	if berr != nil {
		return berr
	}
	_ = conn.Close()
	return nil
}

// ChangeExpiredPassword changes a password through kpasswd.
func (d *Directory) ChangeExpiredPassword(ctx context.Context, sam, oldPassword, newPassword string) error {
	if err := ad.ChangePasswordKerberos(ctx, d.cfg, sam, oldPassword, newPassword); err != nil {
		return err
	}
	d.forget("sam:" + strings.ToLower(sam))
	return nil
}

// serviceAuth returns an authenticator for the service account, renewing
// its Kerberos ticket before it expires.
func (d *Directory) serviceAuth(ctx context.Context) (ad.Authenticator, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.svc != nil && d.svc.Expires().After(d.now().Add(5*time.Minute)) {
		return ad.KerberosAuth(d.svc), nil
	}
	if d.svc != nil {
		d.svc.Close()
		d.svc = nil
	}
	s, err := ad.SignIn(ctx, d.cfg, d.svcUser, d.svcPass)
	if err == nil {
		d.svc = s
		return ad.KerberosAuth(s), nil
	}
	var ae *ad.AuthError
	if errors.As(err, &ae) {
		return nil, fmt.Errorf("directory: the service account was refused (%s): %w", ae.Reason, err)
	}
	if d.fallback {
		return ad.SimpleAuth(d.svcUser, d.svcPass), nil
	}
	return nil, err
}

// connect opens an LDAPS connection as the service account.
func (d *Directory) connect(ctx context.Context) (*ad.Conn, error) {
	auth, err := d.serviceAuth(ctx)
	if err != nil {
		return nil, err
	}
	return ad.Connect(ctx, d.cfg, auth)
}

// Close forgets the service ticket.
func (d *Directory) Close() {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.svc != nil {
		d.svc.Close()
		d.svc = nil
	}
}

// Check verifies that the service account can bind and read (startup).
func (d *Directory) Check(ctx context.Context) error {
	conn, err := d.connect(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = conn.Close() }()
	_, err = conn.DomainSID(ctx)
	return err
}

func (d *Directory) cached(key string) *User {
	d.mu.Lock()
	defer d.mu.Unlock()
	c, ok := d.users[key]
	if !ok || d.now().After(c.until) {
		return nil
	}
	return c.u
}

func (d *Directory) remember(u *User) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if len(d.users) >= maxCache {
		clear(d.users)
	}
	until := d.now().Add(d.cacheTTL)
	d.users[u.GUID] = cachedUser{u: u, until: until}
	d.users["sam:"+strings.ToLower(u.SAM)] = cachedUser{u: u, until: until}
}

func (d *Directory) forget(key string) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if c, ok := d.users[key]; ok {
		delete(d.users, c.u.GUID)
		delete(d.users, "sam:"+strings.ToLower(c.u.SAM))
	}
}

// UserBySAM reads a user by sAMAccountName.
func (d *Directory) UserBySAM(ctx context.Context, sam string) (*User, error) {
	key := "sam:" + strings.ToLower(sam)
	if u := d.cached(key); u != nil {
		return u, nil
	}
	return d.lookup(ctx, escape.Eq("sAMAccountName", sam))
}

// UserByGUID reads a user by objectGUID (the subject).
func (d *Directory) UserByGUID(ctx context.Context, guid string) (*User, error) {
	g, err := sid.ParseGUID(guid)
	if err != nil {
		return nil, ErrNotFound
	}
	if u := d.cached(g.String()); u != nil {
		return u, nil
	}
	return d.lookup(ctx, escape.EqBytes("objectGUID", g.Bytes()))
}

func (d *Directory) lookup(ctx context.Context, f escape.Filter) (*User, error) {
	conn, err := d.connect(ctx)
	if err != nil {
		return nil, err
	}
	defer func() { _ = conn.Close() }()
	var found *ad.User
	for u, err := range conn.Users(ctx, "", f) {
		if err != nil {
			return nil, err
		}
		found = &u
		break
	}
	if found == nil {
		return nil, ErrNotFound
	}
	groups, err := groupSIDs(ctx, conn, found)
	if err != nil {
		return nil, err
	}
	u := &User{
		GUID: found.GUID.String(), SID: found.SID, DN: found.DN, SAM: found.SAMAccountName, UPN: found.UserPrincipalName,
		Mail: found.Mail, DisplayName: found.DisplayName, GivenName: found.GivenName, Surname: found.Surname,
		Enabled: found.Enabled(), Locked: found.Locked(), Expired: found.AccountExpired(d.now()), GroupSIDs: groups,
	}
	d.remember(u)
	return u, nil
}

// groupSIDs returns every group SID of a user: tokenGroups computed by the
// DC, or (when the service account may not read tokenGroups) an in-chain
// membership search plus the primary group.
func groupSIDs(ctx context.Context, conn *ad.Conn, u *ad.User) ([]sid.SID, error) {
	sids, err := conn.TokenGroups(ctx, u.DN)
	if err == nil && len(sids) > 0 {
		return sids, nil
	}
	var out []sid.SID
	for e, serr := range conn.Search(ctx, ad.SearchRequest{
		Filter:     escape.And(escape.Eq("objectClass", "group"), escape.InChain("member", u.DN)),
		Attributes: []string{"objectSid"},
	}) {
		if serr != nil {
			return nil, serr
		}
		if s, perr := sid.FromBytes(e.GetRawAttributeValue("objectSid")); perr == nil {
			out = append(out, s)
		}
	}
	if dom, ok := u.SID.Domain(); ok && u.PrimaryGroupID != 0 {
		if pg, werr := dom.WithRID(u.PrimaryGroupID); werr == nil && !sid.Contains(out, pg) {
			out = append(out, pg)
		}
	}
	return out, nil
}

// nameBatch is how many SIDs go into one OR filter.
const nameBatch = 50

// GroupNames resolves group SIDs to sAMAccountNames (cached 5 minutes).
// SIDs that are not groups of this domain (well-known SIDs) are left out.
func (d *Directory) GroupNames(ctx context.Context, sids []sid.SID) (map[string]string, error) {
	out := map[string]string{}
	var missing []sid.SID
	now := d.now()
	d.mu.Lock()
	for _, s := range sids {
		if c, ok := d.names[s.String()]; ok && now.Before(c.until) {
			if c.name != "" {
				out[s.String()] = c.name
			}
			continue
		}
		missing = append(missing, s)
	}
	d.mu.Unlock()
	if len(missing) == 0 {
		return out, nil
	}
	conn, err := d.connect(ctx)
	if err != nil {
		return nil, err
	}
	defer func() { _ = conn.Close() }()
	resolved := map[string]string{}
	for i := 0; i < len(missing); i += nameBatch {
		chunk := missing[i:min(i+nameBatch, len(missing))]
		parts := make([]escape.Filter, len(chunk))
		for j, s := range chunk {
			parts[j] = escape.EqBytes("objectSid", s.Bytes())
		}
		for e, serr := range conn.Search(ctx, ad.SearchRequest{
			Filter:     escape.And(escape.Eq("objectClass", "group"), escape.Or(parts...)),
			Attributes: []string{"objectSid", "sAMAccountName"},
		}) {
			if serr != nil {
				return nil, serr
			}
			if s, perr := sid.FromBytes(e.GetRawAttributeValue("objectSid")); perr == nil {
				resolved[s.String()] = e.GetAttributeValue("sAMAccountName")
			}
		}
	}
	d.mu.Lock()
	if len(d.names) >= maxCache {
		clear(d.names)
	}
	until := now.Add(5 * time.Minute)
	for _, s := range missing {
		name := resolved[s.String()]
		d.names[s.String()] = cachedName{name: name, until: until}
		if name != "" {
			out[s.String()] = name
		}
	}
	d.mu.Unlock()
	return out, nil
}

// DomainAdminsSID returns the SID of Domain Admins (RID 512), cached.
func (d *Directory) DomainAdminsSID(ctx context.Context) (sid.SID, error) {
	d.mu.Lock()
	if !d.daSID.IsZero() && d.now().Before(d.daUntil) {
		s := d.daSID
		d.mu.Unlock()
		return s, nil
	}
	d.mu.Unlock()
	conn, err := d.connect(ctx)
	if err != nil {
		return sid.SID{}, err
	}
	defer func() { _ = conn.Close() }()
	s, err := conn.WellKnownGroupSID(ctx, sid.RIDDomainAdmins)
	if err != nil {
		return sid.SID{}, err
	}
	d.mu.Lock()
	d.daSID, d.daUntil = s, d.now().Add(time.Hour)
	d.mu.Unlock()
	return s, nil
}

// GroupByName resolves a group's sAMAccountName to its SID.
func (d *Directory) GroupByName(ctx context.Context, name string) (sid.SID, error) {
	conn, err := d.connect(ctx)
	if err != nil {
		return sid.SID{}, err
	}
	defer func() { _ = conn.Close() }()
	g, err := conn.FindGroup(ctx, name)
	if errors.Is(err, ad.ErrNotFound) {
		return sid.SID{}, ErrGroupNotFound
	}
	if err != nil {
		return sid.SID{}, err
	}
	return g.SID, nil
}

// ErrGroupNotFound is returned for an unknown group name.
var ErrGroupNotFound = errors.New("directory: group not found")

// NormalizeUsername turns "DOMAIN\\user", "user@realm" or "user" into the
// sAMAccountName part, lower-cased. ok is false for input that cannot be
// an account name (or names another realm).
func NormalizeUsername(input, realm string) (string, bool) {
	u := strings.TrimSpace(input)
	if _, after, ok := strings.Cut(u, "\\"); ok {
		u = after
	}
	if before, after, ok := strings.Cut(u, "@"); ok {
		if !strings.EqualFold(after, realm) {
			return "", false
		}
		u = before
	}
	if u == "" || len(u) > 64 || strings.ContainsAny(u, "\"/\\[]:;|=,+*?<>@") || strings.ContainsFunc(u, func(r rune) bool { return r < 0x20 }) {
		return "", false
	}
	return strings.ToLower(u), true
}

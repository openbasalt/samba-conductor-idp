package main

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/user"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/openbasalt/samba-conductor-idp/internal/directory"
	"github.com/openbasalt/samba-conductor-idp/internal/mfa"
	"github.com/openbasalt/samba-conductor-idp/internal/registry"
	"github.com/openbasalt/samba-conductor-idp/internal/samlidp"
	"github.com/openbasalt/samba-conductor-idp/internal/secret"
	"github.com/openbasalt/samba-conductor-idp/internal/store"
	"github.com/openbasalt/samba-conductor-idp/internal/web"
)

// multi is a repeatable string flag (also accepts comma-separated values).
type multi []string

func (m *multi) String() string { return strings.Join(*m, ",") }
func (m *multi) Set(v string) error {
	for _, p := range strings.Split(v, ",") {
		if p = strings.TrimSpace(p); p != "" {
			*m = append(*m, p)
		}
	}
	return nil
}

// actor names the operator of CLI changes in the audit log.
func actor() string {
	if u, err := user.Current(); err == nil {
		return "cli:" + u.Username
	}
	return "cli"
}

func (e *env) audit(ctx context.Context, action, target, detail string) {
	if _, err := e.store.AppendAudit(ctx, store.AuditEvent{ActorName: actor(), Action: action, Target: target, Detail: detail,
		Result: store.ResultOK}); err != nil {
		fmt.Fprintln(os.Stderr, "warning: audit append failed:", err)
	}
}

// optionalDirectory returns the directory when the service account's
// password is reachable (needed to resolve group names), else nil.
func (e *env) optionalDirectory() directory.Backend {
	d, err := e.directory()
	if err != nil {
		return nil
	}
	return d
}

func parse(fs *flag.FlagSet, args []string) error {
	if err := fs.Parse(args); err != nil {
		return usageError(err.Error())
	}
	return nil
}

// ---- client ----

type clientFlags struct {
	name, kind, groupsClaim                       string
	redirects, postLogout, scopes, groups, filter multi
	allowAll, firstParty, requireMFA              bool
}

func (f *clientFlags) register(fs *flag.FlagSet, withKind bool) {
	fs.StringVar(&f.name, "name", "", "display name")
	if withKind {
		fs.StringVar(&f.kind, "kind", "confidential", "confidential or public")
	}
	fs.Var(&f.redirects, "redirect-uri", "redirect URI (repeatable, exact match)")
	fs.Var(&f.postLogout, "post-logout-uri", "post-logout redirect URI (repeatable)")
	fs.Var(&f.scopes, "scope", "scope beyond openid: profile, email, groups, offline_access (repeatable)")
	fs.Var(&f.groups, "group", "allowed AD group, SID or name (repeatable)")
	fs.BoolVar(&f.allowAll, "allow-all-users", false, "allow every domain user (instead of groups)")
	fs.BoolVar(&f.firstParty, "first-party", false, "skip the consent screen")
	fs.StringVar(&f.groupsClaim, "groups-claim", "none", "groups claim: none, names or sids")
	fs.Var(&f.filter, "groups-filter", "only these groups in the claim, SID or name (repeatable)")
	fs.BoolVar(&f.requireMFA, "require-mfa", false, "require two-factor authentication")
}

func (f *clientFlags) input() registry.ClientInput {
	return registry.ClientInput{Name: f.name, Kind: f.kind, RedirectURIs: f.redirects, PostLogoutURIs: f.postLogout,
		Scopes: f.scopes, Groups: f.groups, AllowAllUsers: f.allowAll, FirstParty: f.firstParty, GroupsClaim: f.groupsClaim,
		GroupsFilter: f.filter, RequireMFA: f.requireMFA}
}

func cmdClient(ctx context.Context, cfgPath string, args []string) error {
	if len(args) == 0 {
		return usageError("client add|list|show|update|rotate|enable|disable|remove")
	}
	e, err := openEnv(ctx, cfgPath)
	if err != nil {
		return err
	}
	defer e.close()
	sub, args := args[0], args[1:]
	switch sub {
	case "add":
		fs := flag.NewFlagSet("client add", flag.ContinueOnError)
		var f clientFlags
		f.register(fs, true)
		if err := parse(fs, args); err != nil {
			return err
		}
		c, plain, err := registry.CreateClient(ctx, e.store, e.optionalDirectory(), f.input())
		if err != nil {
			return err
		}
		e.audit(ctx, "admin.client_create", c.ID, "name="+c.Name+" kind="+c.Kind+" redirects="+strings.Join(c.RedirectURIs, " "))
		fmt.Printf("client_id:     %s\n", c.ID)
		if plain != "" {
			fmt.Printf("client_secret: %s\n", plain)
			fmt.Fprintln(os.Stderr, "Store the secret now: it is kept hashed and cannot be shown again.")
		}
		return nil
	case "list":
		cs, err := e.store.ListClients(ctx)
		if err != nil {
			return err
		}
		tw := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
		fmt.Fprintln(tw, "CLIENT_ID\tNAME\tKIND\tENABLED\tREDIRECT_URIS")
		for _, c := range cs {
			fmt.Fprintf(tw, "%s\t%s\t%s\t%t\t%s\n", c.ID, c.Name, c.Kind, c.Enabled, strings.Join(c.RedirectURIs, " "))
		}
		return tw.Flush()
	case "show":
		if len(args) != 1 {
			return usageError("client show CLIENT_ID")
		}
		c, err := e.store.GetClient(ctx, args[0])
		if err != nil {
			return err
		}
		c.SecretHash = ""
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(c)
	case "update":
		if len(args) < 1 {
			return usageError("client update CLIENT_ID [flags] (every setting is replaced)")
		}
		id := args[0]
		old, err := e.store.GetClient(ctx, id)
		if err != nil {
			return err
		}
		fs := flag.NewFlagSet("client update", flag.ContinueOnError)
		var f clientFlags
		f.register(fs, false)
		if err := parse(fs, args[1:]); err != nil {
			return err
		}
		if f.name == "" {
			f.name = old.Name
		}
		c, err := registry.UpdateClient(ctx, e.store, e.optionalDirectory(), id, f.input())
		if err != nil {
			return err
		}
		e.audit(ctx, "admin.client_update", c.ID, "redirects="+strings.Join(c.RedirectURIs, " ")+" groups="+strings.Join(c.AllowedGroups, ","))
		fmt.Println("updated", c.ID)
		return nil
	case "rotate":
		if len(args) != 1 {
			return usageError("client rotate CLIENT_ID")
		}
		plain, err := registry.RotateSecret(ctx, e.store, args[0])
		if err != nil {
			return err
		}
		e.audit(ctx, "admin.client_rotate_secret", args[0], "")
		fmt.Printf("client_secret: %s\n", plain)
		return nil
	case "enable", "disable":
		if len(args) != 1 {
			return usageError("client " + sub + " CLIENT_ID")
		}
		c, err := e.store.GetClient(ctx, args[0])
		if err != nil {
			return err
		}
		c.Enabled = sub == "enable"
		if err := e.store.UpdateClient(ctx, c); err != nil {
			return err
		}
		e.audit(ctx, "admin.client_toggle", c.ID, sub+"d")
		fmt.Println(sub+"d", c.ID)
		return nil
	case "remove":
		if len(args) != 1 {
			return usageError("client remove CLIENT_ID")
		}
		if err := e.store.DeleteClient(ctx, args[0]); err != nil {
			return err
		}
		e.audit(ctx, "admin.client_delete", args[0], "")
		fmt.Println("removed", args[0])
		return nil
	}
	return usageError("unknown client command " + sub)
}

// ---- saml ----

type spFlags struct {
	metadata, entityID, name, nameIDFormat, nameIDSource, relay, encCert string
	acs, attrs, groups                                                   multi
	allowAll, encrypt, idpInit, requireMFA                               bool
}

func (f *spFlags) register(fs *flag.FlagSet) {
	fs.StringVar(&f.metadata, "metadata", "", "SP metadata XML file, - for standard input (fills entity ID, ACS URLs, encryption certificate)")
	fs.StringVar(&f.entityID, "entity-id", "", "SP entity ID (without -metadata)")
	fs.StringVar(&f.name, "name", "", "display name")
	fs.Var(&f.acs, "acs", "ACS URL, HTTP-POST binding (repeatable)")
	fs.StringVar(&f.nameIDFormat, "nameid-format", samlidp.NameIDEmail, "NameID format URI")
	fs.StringVar(&f.nameIDSource, "nameid-source", samlidp.SourceEmail, "NameID value: email, upn, username, guid")
	fs.Var(&f.attrs, "attr", "attribute Name=source (repeatable); sources: "+strings.Join(samlidp.Sources, ", "))
	fs.Var(&f.groups, "group", "allowed AD group, SID or name (repeatable)")
	fs.BoolVar(&f.allowAll, "allow-all-users", false, "allow every domain user")
	fs.BoolVar(&f.encrypt, "encrypt", false, "encrypt assertions (needs the SP certificate)")
	fs.StringVar(&f.encCert, "encryption-cert", "", "SP encryption certificate (PEM file), when not in the metadata")
	fs.BoolVar(&f.idpInit, "idp-initiated", false, "allow IdP-initiated sign-in")
	fs.StringVar(&f.relay, "default-relay-state", "", "RelayState for IdP-initiated sign-in")
	fs.BoolVar(&f.requireMFA, "require-mfa", false, "require two-factor authentication")
}

func (f *spFlags) input(existing *store.SAMLSP) (registry.SPInput, error) {
	in := registry.SPInput{EntityID: f.entityID, Name: f.name, ACSURLs: f.acs, NameIDFormat: f.nameIDFormat,
		NameIDSource: f.nameIDSource, Groups: f.groups, AllowAllUsers: f.allowAll, EncryptAssertion: f.encrypt,
		IdPInitiated: f.idpInit, DefaultRelay: f.relay, RequireMFA: f.requireMFA}
	if existing != nil {
		in.EntityID = existing.EntityID
		in.EncryptionCert = existing.EncryptionCert
	}
	if f.metadata != "" {
		b, err := readFileOrStdin(f.metadata)
		if err != nil {
			return in, err
		}
		draft, err := samlidp.ParseSPMetadata(b)
		if err != nil {
			return in, err
		}
		if existing != nil && draft.EntityID != existing.EntityID {
			return in, errors.New("the metadata is for another entity ID")
		}
		in.EntityID = draft.EntityID
		if len(in.ACSURLs) == 0 {
			in.ACSURLs = draft.ACSURLs
		}
		in.EncryptionCert = draft.EncryptionCert
	}
	if f.encCert != "" {
		der, err := readCertDER(f.encCert)
		if err != nil {
			return in, err
		}
		in.EncryptionCert = der
	}
	attrs, err := registry.ParseAttributes(f.attrs)
	if err != nil {
		return in, err
	}
	in.Attributes = attrs
	return in, nil
}

func cmdSAML(ctx context.Context, cfgPath string, args []string) error {
	if len(args) == 0 {
		return usageError("saml add|list|show|update|enable|disable|remove")
	}
	e, err := openEnv(ctx, cfgPath)
	if err != nil {
		return err
	}
	defer e.close()
	sub, args := args[0], args[1:]
	switch sub {
	case "add":
		fs := flag.NewFlagSet("saml add", flag.ContinueOnError)
		var f spFlags
		f.register(fs)
		if err := parse(fs, args); err != nil {
			return err
		}
		in, err := f.input(nil)
		if err != nil {
			return err
		}
		sp, err := registry.BuildSP(ctx, e.optionalDirectory(), in)
		if err != nil {
			return err
		}
		if err := e.store.CreateSP(ctx, sp); err != nil {
			return err
		}
		e.audit(ctx, "admin.sp_create", sp.EntityID, "name="+sp.Name+" acs="+strings.Join(sp.ACSURLs, " "))
		fmt.Println("registered", sp.EntityID)
		fmt.Println("IdP metadata:", e.cfg.Issuer()+samlidp.MetadataPath)
		return nil
	case "list":
		sps, err := e.store.ListSPs(ctx)
		if err != nil {
			return err
		}
		tw := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
		fmt.Fprintln(tw, "ENTITY_ID\tNAME\tENABLED\tNAMEID")
		for _, sp := range sps {
			fmt.Fprintf(tw, "%s\t%s\t%t\t%s\n", sp.EntityID, sp.Name, sp.Enabled, sp.NameIDSource)
		}
		return tw.Flush()
	case "show":
		if len(args) != 1 {
			return usageError("saml show ENTITY_ID")
		}
		sp, err := e.store.GetSP(ctx, args[0])
		if err != nil {
			return err
		}
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(sp)
	case "update":
		if len(args) < 1 {
			return usageError("saml update ENTITY_ID [flags] (every setting is replaced)")
		}
		old, err := e.store.GetSP(ctx, args[0])
		if err != nil {
			return err
		}
		fs := flag.NewFlagSet("saml update", flag.ContinueOnError)
		var f spFlags
		f.register(fs)
		if err := parse(fs, args[1:]); err != nil {
			return err
		}
		if f.name == "" {
			f.name = old.Name
		}
		if len(f.acs) == 0 && f.metadata == "" {
			f.acs = old.ACSURLs
		}
		in, err := f.input(old)
		if err != nil {
			return err
		}
		sp, err := registry.BuildSP(ctx, e.optionalDirectory(), in)
		if err != nil {
			return err
		}
		sp.Enabled = old.Enabled
		if err := e.store.UpdateSP(ctx, sp); err != nil {
			return err
		}
		e.audit(ctx, "admin.sp_update", sp.EntityID, "acs="+strings.Join(sp.ACSURLs, " "))
		fmt.Println("updated", sp.EntityID)
		return nil
	case "enable", "disable":
		if len(args) != 1 {
			return usageError("saml " + sub + " ENTITY_ID")
		}
		sp, err := e.store.GetSP(ctx, args[0])
		if err != nil {
			return err
		}
		sp.Enabled = sub == "enable"
		if err := e.store.UpdateSP(ctx, sp); err != nil {
			return err
		}
		e.audit(ctx, "admin.sp_toggle", sp.EntityID, sub+"d")
		fmt.Println(sub+"d", sp.EntityID)
		return nil
	case "remove":
		if len(args) != 1 {
			return usageError("saml remove ENTITY_ID")
		}
		if err := e.store.DeleteSP(ctx, args[0]); err != nil {
			return err
		}
		e.audit(ctx, "admin.sp_delete", args[0], "")
		fmt.Println("removed", args[0])
		return nil
	}
	return usageError("unknown saml command " + sub)
}

// ---- keys ----

func cmdKeys(ctx context.Context, cfgPath string, args []string) error {
	if len(args) == 0 {
		return usageError("keys list | keys rotate oidc | keys rotate saml [-immediate]")
	}
	e, err := openEnv(ctx, cfgPath)
	if err != nil {
		return err
	}
	defer e.close()
	switch args[0] {
	case "list":
		tw := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
		fmt.Fprintln(tw, "PURPOSE\tKEY_ID\tCREATED\tRETIRES")
		for _, p := range []string{store.KeyOIDC, store.KeySAML} {
			keys, err := e.store.ListSigningKeys(ctx, p, time.Now())
			if err != nil {
				return err
			}
			for _, k := range keys {
				retire := "-"
				if !k.RetireAt.IsZero() {
					retire = k.RetireAt.Format(time.RFC3339)
				}
				fmt.Fprintf(tw, "%s\t%s\t%s\t%s\n", p, k.ID, k.CreatedAt.Format(time.RFC3339), retire)
			}
		}
		return tw.Flush()
	case "rotate":
		if len(args) < 2 {
			return usageError("keys rotate oidc|saml [-immediate]")
		}
		fs := flag.NewFlagSet("keys rotate", flag.ContinueOnError)
		immediate := fs.Bool("immediate", false, "SAML: switch at once instead of after the overlap")
		if err := parse(fs, args[2:]); err != nil {
			return err
		}
		p, err := e.providers()
		if err != nil {
			return err
		}
		var id string
		switch args[1] {
		case store.KeyOIDC:
			id, err = p.oidc.Rotate(ctx)
		case store.KeySAML:
			id, err = p.saml.Rotate(ctx, *immediate)
		default:
			return usageError("keys rotate oidc|saml")
		}
		if err != nil {
			return err
		}
		e.audit(ctx, "admin.key_rotate", args[1], "new key "+id)
		fmt.Println("new", args[1], "key", id, "(running servers pick it up within a minute)")
		return nil
	}
	return usageError("unknown keys command " + args[0])
}

// ---- enroll-link, mfa ----

func cmdEnrollLink(ctx context.Context, cfgPath string, args []string) error {
	fs := flag.NewFlagSet("enroll-link", flag.ContinueOnError)
	username := fs.String("user", "", "the administrator's sAMAccountName")
	if err := parse(fs, args); err != nil {
		return err
	}
	if *username == "" {
		return usageError("enroll-link -user NAME")
	}
	e, err := openEnv(ctx, cfgPath)
	if err != nil {
		return err
	}
	defer e.close()
	sam := strings.ToLower(*username)
	tok := secret.Token("")
	if err := e.store.CreateEnrollLink(ctx, web.LinkHash(tok), sam, actor(), web.EnrollLinkTTL); err != nil {
		return err
	}
	e.audit(ctx, "admin.enroll_link", sam, "valid 24 h")
	fmt.Println(e.cfg.EnrollURL() + "/login?enroll=" + tok)
	return nil
}

func cmdMFA(ctx context.Context, cfgPath string, args []string) error {
	if len(args) == 0 || args[0] != "reset" {
		return usageError("mfa reset -user NAME")
	}
	fs := flag.NewFlagSet("mfa reset", flag.ContinueOnError)
	username := fs.String("user", "", "sAMAccountName")
	if err := parse(fs, args[1:]); err != nil {
		return err
	}
	e, err := openEnv(ctx, cfgPath)
	if err != nil {
		return err
	}
	defer e.close()
	dir, err := e.directory()
	if err != nil {
		return fmt.Errorf("the directory is needed to find the user: %w", err)
	}
	defer dir.Close()
	u, err := dir.UserBySAM(ctx, *username)
	if err != nil {
		return err
	}
	removed, err := (&mfa.Local{Store: e.store}).Reset(ctx, u.GUID)
	if err != nil {
		return err
	}
	e.audit(ctx, "admin.mfa_reset", u.SAM, fmt.Sprintf("removed=%t (sessions end at the server's next role check)", removed))
	fmt.Printf("2FA of %s removed: %t\n", u.SAM, removed)
	return nil
}

// ---- audit ----

func cmdAudit(ctx context.Context, cfgPath string, args []string) error {
	if len(args) == 0 {
		return usageError("audit verify | audit export")
	}
	e, err := openEnv(ctx, cfgPath)
	if err != nil {
		return err
	}
	defer e.close()
	switch args[0] {
	case "verify":
		res, err := e.store.VerifyAudit(ctx)
		if err != nil {
			return err
		}
		if res.BrokenAt != 0 {
			return fmt.Errorf("audit chain broken at row %d: %s", res.BrokenAt, res.Reason)
		}
		fmt.Printf("audit chain intact: %d rows, last hash %s\n", res.Rows, res.LastHash)
		return nil
	case "export":
		fs := flag.NewFlagSet("audit export", flag.ContinueOnError)
		action := fs.String("action", "", "action prefix")
		since := fs.String("since", "", "RFC 3339 time")
		if err := parse(fs, args[1:]); err != nil {
			return err
		}
		f := store.AuditFilter{Action: *action}
		if *since != "" {
			t, err := time.Parse(time.RFC3339, *since)
			if err != nil {
				return usageError("-since must be RFC 3339")
			}
			f.Since = t
		}
		_, err := e.store.ExportAudit(ctx, f, os.Stdout)
		return err
	}
	return usageError("unknown audit command " + args[0])
}

// ---- gen-key ----

func cmdGenKey(args []string) error {
	if len(args) != 1 {
		return usageError("gen-key FILE")
	}
	k, err := secret.GenerateKeyHex()
	if err != nil {
		return err
	}
	f, err := os.OpenFile(args[0], os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	if _, err := f.WriteString(k + "\n"); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	fmt.Println("wrote", args[0])
	return nil
}

// readCertDER reads a PEM (or DER) certificate file.
func readCertDER(path string) ([]byte, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	if blk, _ := pem.Decode(b); blk != nil {
		b = blk.Bytes
	}
	if _, err := x509.ParseCertificate(b); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return b, nil
}

// readFileOrStdin reads a file, or standard input for "-" (bounded).
func readFileOrStdin(path string) ([]byte, error) {
	if path != "-" {
		return os.ReadFile(path)
	}
	return io.ReadAll(io.LimitReader(os.Stdin, 1<<20))
}

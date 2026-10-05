// Package api is conductor-idp's local management API: what conductor's
// "Single sign-on" section uses (protocol in the public idpapi package).
//
// Security:
//   - a Unix socket only (no network listener), handed over by systemd
//     socket activation (conductor-idp-api.socket, 0660, group conductor)
//     or created with api.socket_group;
//   - every connection's peer is checked with SO_PEERCRED: only the
//     configured UIDs (default: the conductor user) are served;
//   - requests are typed and allowlisted, decoded strictly, size-bounded;
//   - every mutation is written to the hash-chained audit log with the AD
//     user conductor acted for (actor "conductor:<user>@<address>");
//   - a confidential client's secret is generated here and returned once
//     (client.create, client.rotate), stored hashed, never logged or
//     audited; signing keys never leave the process (certificates do).
//
// conductor checks the administrator role and asks for a fresh second
// factor before it sends a mutation; this server trusts that decision
// because only conductor's UID can connect.
package api

import (
	"bufio"
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"slices"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/openbasalt/samba-conductor-idp/idpapi"
	"github.com/openbasalt/samba-conductor-idp/internal/config"
	"github.com/openbasalt/samba-conductor-idp/internal/directory"
	"github.com/openbasalt/samba-conductor-idp/internal/oidcp"
	"github.com/openbasalt/samba-conductor-idp/internal/registry"
	"github.com/openbasalt/samba-conductor-idp/internal/samlidp"
	"github.com/openbasalt/samba-conductor-idp/internal/settings"
	"github.com/openbasalt/samba-conductor-idp/internal/sockutil"
	"github.com/openbasalt/samba-conductor-idp/internal/store"
)

// KeyRotator rotates signing keys.
type KeyRotator interface {
	RotateOIDC(ctx context.Context) (string, error)
	RotateSAML(ctx context.Context, immediate bool) (string, error)
}

// Options build a Server.
type Options struct {
	Config *config.Config
	Store  *store.Store
	Dir    directory.Backend
	// SAML is nil when SAML is off.
	SAML     *samlidp.IdP
	SAMLKeys *samlidp.KeyManager
	Keys     KeyRotator
	// Apply makes saved settings effective in the web server.
	Apply   func(idpapi.Settings)
	Logger  *slog.Logger
	Version string
	// AllowedUIDs may connect (from api.allowed_users / allowed_uids).
	AllowedUIDs []int
	// HTTP fetches SP metadata by URL (nil: a default client).
	HTTP *http.Client
}

// Server is a running management API.
type Server struct {
	o       Options
	log     *slog.Logger
	allowed map[int]bool
	ln      *net.UnixListener
	sem     chan struct{}
	wg      sync.WaitGroup
	// peerCred is replaced in tests.
	peerCred func(*net.UnixConn) (int, error)
	now      func() time.Time
}

// New builds a server (not listening yet).
func New(o Options) (*Server, error) {
	if o.Logger == nil {
		o.Logger = slog.Default()
	}
	if o.HTTP == nil {
		o.HTTP = metadataClient()
	}
	s := &Server{o: o, log: o.Logger, allowed: map[int]bool{}, sem: make(chan struct{}, 8), peerCred: sockutil.PeerUID, now: time.Now}
	for _, u := range o.AllowedUIDs {
		s.allowed[u] = true
	}
	if len(s.allowed) == 0 {
		return nil, errors.New("api: no peer is allowed (api.allowed_users / api.allowed_uids)")
	}
	return s, nil
}

// Listen opens the socket (systemd socket activation first).
func (s *Server) Listen() error {
	ln, activated, err := sockutil.Listen(s.o.Config.API.Socket, s.o.Config.API.SocketGroup)
	if err != nil {
		return err
	}
	s.ln = ln
	s.log.Info("management API listening", "socket", s.o.Config.API.Socket, "socket_activation", activated)
	return nil
}

// Serve accepts connections until ctx ends.
func (s *Server) Serve(ctx context.Context) error {
	if s.ln == nil {
		return errors.New("api: not listening")
	}
	go func() {
		<-ctx.Done()
		_ = s.ln.Close()
	}()
	for {
		c, err := s.ln.AcceptUnix()
		if err != nil {
			if ctx.Err() != nil {
				break
			}
			s.log.Warn("accept failed", "err", err)
			time.Sleep(100 * time.Millisecond)
			continue
		}
		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			s.serveConn(ctx, c)
		}()
	}
	s.wg.Wait()
	return nil
}

func (s *Server) serveConn(ctx context.Context, c *net.UnixConn) {
	defer func() { _ = c.Close() }()
	uid, err := s.peerCred(c)
	if err != nil || !s.allowed[uid] {
		s.log.Warn("management API connection refused: peer not allowed", "uid", uid, "err", err)
		return
	}
	select {
	case s.sem <- struct{}{}:
		defer func() { <-s.sem }()
	case <-ctx.Done():
		return
	}
	_ = c.SetReadDeadline(time.Now().Add(30 * time.Second))
	var req idpapi.Request
	if err := idpapi.ReadMessage(bufio.NewReaderSize(c, 64<<10), &req); err != nil {
		_ = idpapi.WriteMessage(c, idpapi.ErrorResponse("", &idpapi.Error{Code: idpapi.CodeBadRequest, Message: "unreadable request"}))
		return
	}
	_ = c.SetWriteDeadline(time.Now().Add(90 * time.Second))
	rctx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()
	if err := idpapi.WriteMessage(c, s.Handle(rctx, req)); err != nil {
		s.log.Warn("writing the response failed", "op", req.Op, "err", err)
	}
}

// Handle answers one request (also the entry point of tests).
func (s *Server) Handle(ctx context.Context, req idpapi.Request) idpapi.Response {
	params, err := req.Decode()
	if err != nil {
		var e *idpapi.Error
		if !errors.As(err, &e) {
			e = &idpapi.Error{Code: idpapi.CodeBadRequest, Message: err.Error()}
		}
		return idpapi.ErrorResponse(req.ID, e)
	}
	result, target, detail, err := s.dispatch(ctx, req.Op, params)
	if req.Op.Mutating() || req.Op == idpapi.OpSPMetadata {
		res := store.ResultOK
		if err != nil {
			res = store.ResultFailed
			detail = strings.TrimSpace(detail + " error: " + err.Error())
		}
		s.audit(ctx, req, "api."+string(req.Op), target, detail, res)
	}
	if err != nil {
		return idpapi.ErrorResponse(req.ID, toAPIError(err))
	}
	resp, err := idpapi.OKResponse(req.ID, result)
	if err != nil {
		return idpapi.ErrorResponse(req.ID, &idpapi.Error{Code: idpapi.CodeFailed, Message: err.Error()})
	}
	return resp
}

func (s *Server) audit(ctx context.Context, req idpapi.Request, action, target, detail, result string) {
	e := store.AuditEvent{ActorSID: req.Actor.SID, ActorName: req.Actor.String(), Action: action, Target: target,
		Detail: detail, Result: result, IP: req.Actor.IP, UserAgent: "conductor"}
	if _, err := s.o.Store.AppendAudit(ctx, e); err != nil {
		s.log.Error("audit append failed", "action", action, "err", err)
	}
}

// invalidError carries validation messages.
type invalidError struct{ err error }

func (e invalidError) Error() string { return e.err.Error() }

func invalid(err error) error {
	if err == nil {
		return nil
	}
	return invalidError{err}
}

func toAPIError(err error) *idpapi.Error {
	var e *idpapi.Error
	if errors.As(err, &e) {
		return e
	}
	var inv invalidError
	switch {
	case errors.As(err, &inv):
		var details []string
		for _, l := range strings.Split(inv.err.Error(), "\n") {
			if l = strings.TrimSpace(l); l != "" {
				details = append(details, l)
			}
		}
		return &idpapi.Error{Code: idpapi.CodeInvalid, Message: "the registration is not valid", Details: details}
	case errors.Is(err, store.ErrNotFound), errors.Is(err, directory.ErrNotFound):
		return &idpapi.Error{Code: idpapi.CodeNotFound, Message: "not found"}
	case errors.Is(err, store.ErrConflict):
		return &idpapi.Error{Code: idpapi.CodeConflict, Message: "already registered"}
	case errors.Is(err, store.ErrStale):
		return &idpapi.Error{Code: idpapi.CodeConflict, Message: "changed since it was read"}
	case errors.Is(err, errSAMLOff):
		return &idpapi.Error{Code: idpapi.CodeForbidden, Message: err.Error()}
	}
	return &idpapi.Error{Code: idpapi.CodeFailed, Message: err.Error()}
}

var errSAMLOff = errors.New("SAML is not enabled ([saml] enabled in idp.toml)")

// dispatch runs an operation and returns its result, plus the audit
// target and detail of mutations.
func (s *Server) dispatch(ctx context.Context, op idpapi.Op, p idpapi.Params) (any, string, string, error) {
	st := s.o.Store
	switch op {
	case idpapi.OpStatus:
		return s.status(ctx), "", "", nil

	case idpapi.OpClientList:
		cs, err := st.ListClients(ctx)
		if err != nil {
			return nil, "", "", err
		}
		out := make([]idpapi.Client, 0, len(cs))
		for _, c := range cs {
			out = append(out, clientView(c))
		}
		return out, "", "", nil
	case idpapi.OpClientGet:
		c, err := st.GetClient(ctx, p.(*idpapi.ClientRef).ID)
		if err != nil {
			return nil, "", "", err
		}
		return clientView(c), "", "", nil
	case idpapi.OpClientCreate:
		in := p.(*idpapi.ClientCreateParams).Input
		c, plain, err := registry.CreateClient(ctx, st, s.o.Dir, clientInput(in))
		if err != nil {
			return nil, "", "name=" + in.Name, invalidOr(err)
		}
		return idpapi.ClientSecret{Client: clientView(c), Secret: plain}, c.ID, clientDetail(c), nil
	case idpapi.OpClientUpdate:
		q := p.(*idpapi.ClientUpdateParams)
		c, err := registry.UpdateClient(ctx, st, s.o.Dir, q.ID, clientInput(q.Input))
		if err != nil {
			return nil, q.ID, "", invalidOr(err)
		}
		return clientView(c), c.ID, clientDetail(c), nil
	case idpapi.OpClientRotate:
		id := p.(*idpapi.ClientRef).ID
		plain, err := registry.RotateSecret(ctx, st, id)
		if err != nil {
			if !errors.Is(err, store.ErrNotFound) {
				err = invalid(err)
			}
			return nil, id, "", err
		}
		c, err := st.GetClient(ctx, id)
		if err != nil {
			return nil, id, "", err
		}
		return idpapi.ClientSecret{Client: clientView(c), Secret: plain}, id, "secret rotated", nil
	case idpapi.OpClientEnable:
		q := p.(*idpapi.ClientEnableParams)
		c, err := st.GetClient(ctx, q.ID)
		if err != nil {
			return nil, q.ID, "", err
		}
		c.Enabled = q.Enabled
		if err := st.UpdateClient(ctx, c); err != nil {
			return nil, q.ID, "", err
		}
		return clientView(c), q.ID, fmt.Sprintf("enabled=%v", q.Enabled), nil
	case idpapi.OpClientDelete:
		id := p.(*idpapi.ClientRef).ID
		c, err := st.GetClient(ctx, id)
		if err != nil {
			return nil, id, "", err
		}
		return struct{}{}, id, "name=" + c.Name, st.DeleteClient(ctx, id)
	case idpapi.OpClientPreview:
		return s.clientPreview(ctx, p.(*idpapi.ClientPreviewParams))

	case idpapi.OpSPList:
		sps, err := st.ListSPs(ctx)
		if err != nil {
			return nil, "", "", err
		}
		out := make([]idpapi.SP, 0, len(sps))
		for _, sp := range sps {
			out = append(out, spView(sp))
		}
		return out, "", "", nil
	case idpapi.OpSPGet:
		sp, err := st.GetSP(ctx, p.(*idpapi.SPRef).EntityID)
		if err != nil {
			return nil, "", "", err
		}
		return spView(sp), "", "", nil
	case idpapi.OpSPMetadata:
		return s.spMetadata(ctx, p.(*idpapi.SPMetadataParams))
	case idpapi.OpSPCreate:
		if s.o.SAML == nil {
			return nil, "", "", errSAMLOff
		}
		in := p.(*idpapi.SPCreateParams).Input
		sp, err := registry.BuildSP(ctx, s.o.Dir, spInput(in))
		if err != nil {
			return nil, in.EntityID, "", invalid(err)
		}
		if err := st.CreateSP(ctx, sp); err != nil {
			return nil, in.EntityID, "", err
		}
		return spView(sp), sp.EntityID, spDetail(sp), nil
	case idpapi.OpSPUpdate:
		q := p.(*idpapi.SPUpdateParams)
		old, err := st.GetSP(ctx, q.EntityID)
		if err != nil {
			return nil, q.EntityID, "", err
		}
		in := q.Input
		in.EntityID = old.EntityID
		if len(in.EncryptionCert) == 0 && !q.ClearEncryptionCert {
			in.EncryptionCert = old.EncryptionCert
		}
		if len(in.SigningCert) == 0 && !q.ClearSigningCert {
			in.SigningCert = old.SigningCert
		}
		sp, err := registry.BuildSP(ctx, s.o.Dir, spInput(in))
		if err != nil {
			return nil, q.EntityID, "", invalid(err)
		}
		sp.Enabled = old.Enabled
		if err := st.UpdateSP(ctx, sp); err != nil {
			return nil, q.EntityID, "", err
		}
		return spView(sp), sp.EntityID, spDetail(sp), nil
	case idpapi.OpSPEnable:
		q := p.(*idpapi.SPEnableParams)
		sp, err := st.GetSP(ctx, q.EntityID)
		if err != nil {
			return nil, q.EntityID, "", err
		}
		sp.Enabled = q.Enabled
		if err := st.UpdateSP(ctx, sp); err != nil {
			return nil, q.EntityID, "", err
		}
		return spView(sp), sp.EntityID, fmt.Sprintf("enabled=%v", q.Enabled), nil
	case idpapi.OpSPDelete:
		id := p.(*idpapi.SPRef).EntityID
		sp, err := st.GetSP(ctx, id)
		if err != nil {
			return nil, id, "", err
		}
		return struct{}{}, id, "name=" + sp.Name, st.DeleteSP(ctx, id)
	case idpapi.OpSPPreview:
		return s.spPreview(ctx, p.(*idpapi.SPPreviewParams))

	case idpapi.OpKeysList:
		k, err := s.keys(ctx)
		return k, "", "", err
	case idpapi.OpKeysRotate:
		q := p.(*idpapi.KeysRotateParams)
		var id string
		var err error
		switch {
		case q.Purpose == idpapi.KeyOIDC:
			id, err = s.o.Keys.RotateOIDC(ctx)
		case s.o.SAML == nil:
			err = errSAMLOff
		default:
			id, err = s.o.Keys.RotateSAML(ctx, q.Immediate)
		}
		detail := "new key " + id
		if q.Immediate {
			detail += " (immediate)"
		}
		return idpapi.KeyRotated{ID: id}, q.Purpose, detail, err
	case idpapi.OpKeysCert:
		c, err := s.samlCert(ctx, p.(*idpapi.KeysCertParams).ID)
		return c, "", "", err

	case idpapi.OpSettingsGet:
		v, err := settings.Load(ctx, st, s.o.Config)
		return v, "", "", err
	case idpapi.OpSettingsUpdate:
		q := p.(*idpapi.SettingsUpdateParams)
		in := q.Settings
		if in.ConsentText == nil {
			in.ConsentText = map[string]string{}
		}
		for k, v := range in.ConsentText {
			if strings.TrimSpace(v) == "" {
				delete(in.ConsentText, k)
			}
		}
		if _, err := settings.Save(ctx, st, q.BaseVersion, in, "conductor"); err != nil {
			return nil, "settings", "", err
		}
		v, err := settings.Load(ctx, st, s.o.Config)
		if err != nil {
			return nil, "settings", "", err
		}
		if s.o.Apply != nil {
			s.o.Apply(v.Settings)
		}
		detail := fmt.Sprintf("version=%d session_idle_minutes=%d session_absolute_hours=%d mfa_policy=%s consent_text_languages=%d",
			v.Version, in.SessionIdleMinutes, in.SessionAbsoluteHours, in.MFAPolicy, len(in.ConsentText))
		return v, "settings", detail, nil

	case idpapi.OpActivity:
		a, err := s.activity(ctx, p.(*idpapi.ActivityParams).Days)
		return a, "", "", err
	case idpapi.OpAuditList:
		q := p.(*idpapi.AuditListParams)
		evs, more, err := st.ListAudit(ctx, store.AuditFilter{Actor: q.Actor, Action: q.Action, Target: q.Target, Result: q.Result}, q.Offset, q.Limit)
		if err != nil {
			return nil, "", "", err
		}
		return idpapi.AuditPage{Events: auditViews(evs), More: more}, "", "", nil
	case idpapi.OpAuditVerify:
		v, err := st.VerifyAudit(ctx)
		return idpapi.AuditVerify{Rows: v.Rows, LastHash: v.LastHash, BrokenAt: v.BrokenAt, Reason: v.Reason}, "", "", err
	}
	return nil, "", "", &idpapi.Error{Code: idpapi.CodeBadRequest, Message: "unknown operation"}
}

// invalidOr marks registry validation errors (anything but store errors).
func invalidOr(err error) error {
	if errors.Is(err, store.ErrNotFound) || errors.Is(err, store.ErrConflict) {
		return err
	}
	return invalid(err)
}

func (s *Server) status(ctx context.Context) idpapi.Status {
	c := s.o.Config
	st := idpapi.Status{Version: s.o.Version, Protocol: idpapi.ProtocolVersion, Issuer: c.Issuer(),
		DiscoveryURL: c.Issuer() + oidcp.Discovery, SAMLEnabled: s.o.SAML != nil, MFABackend: c.MFA.Backend}
	if s.o.SAML != nil {
		st.SAMLMetadataURL, st.SAMLSSOURL, st.SAMLSLOURL = s.o.SAML.EntityID(), s.o.SAML.SSOURL(), s.o.SAML.SLOURL()
	}
	if cs, err := s.o.Store.ListClients(ctx); err == nil {
		st.Clients = len(cs)
	}
	if sps, err := s.o.Store.ListSPs(ctx); err == nil {
		st.SPs = len(sps)
	}
	if ch, ok := s.o.Dir.(interface{ Check(context.Context) error }); ok {
		cctx, cancel := context.WithTimeout(ctx, 10*time.Second)
		st.DirectoryOK = ch.Check(cctx) == nil
		cancel()
	} else {
		st.DirectoryOK = true
	}
	return st
}

// ---- conversions ----

func clientInput(in idpapi.ClientInput) registry.ClientInput {
	return registry.ClientInput{Name: in.Name, Kind: in.Kind, RedirectURIs: in.RedirectURIs, PostLogoutURIs: in.PostLogoutURIs,
		Scopes: in.Scopes, Groups: in.Groups, AllowAllUsers: in.AllowAllUsers, FirstParty: in.FirstParty,
		GroupsClaim: in.GroupsClaim, GroupsFilter: in.GroupsFilter, RequireMFA: in.RequireMFA}
}

func clientView(c *store.Client) idpapi.Client {
	return idpapi.Client{ID: c.ID, ClientInput: idpapi.ClientInput{Name: c.Name, Kind: c.Kind, RedirectURIs: nz(c.RedirectURIs),
		PostLogoutURIs: nz(c.PostLogoutURIs), Scopes: nz(c.Scopes), Groups: nz(c.AllowedGroups), AllowAllUsers: c.AllowAllUsers,
		FirstParty: c.FirstParty, GroupsClaim: c.GroupsClaim, GroupsFilter: nz(c.GroupsFilter), RequireMFA: c.RequireMFA},
		Enabled: c.Enabled, HasSecret: c.SecretHash != "", CreatedAt: c.CreatedAt, UpdatedAt: c.UpdatedAt, SecretRotatedAt: c.SecretRotatedAt}
}

func clientDetail(c *store.Client) string {
	return fmt.Sprintf("name=%s kind=%s redirects=%s scopes=%s groups=%s all_users=%v first_party=%v require_mfa=%v groups_claim=%s",
		c.Name, c.Kind, strings.Join(c.RedirectURIs, " "), strings.Join(c.Scopes, ","), strings.Join(c.AllowedGroups, ","),
		c.AllowAllUsers, c.FirstParty, c.RequireMFA, c.GroupsClaim)
}

func nz(v []string) []string {
	if v == nil {
		return []string{}
	}
	return v
}

func spInput(in idpapi.SPInput) registry.SPInput {
	attrs := make([]store.SAMLAttribute, 0, len(in.Attributes))
	for _, a := range in.Attributes {
		attrs = append(attrs, store.SAMLAttribute{Name: strings.TrimSpace(a.Name), Source: a.Source})
	}
	return registry.SPInput{EntityID: strings.TrimSpace(in.EntityID), Name: in.Name, ACSURLs: in.ACSURLs, NameIDFormat: in.NameIDFormat,
		NameIDSource: in.NameIDSource, Attributes: attrs, Groups: in.Groups, AllowAllUsers: in.AllowAllUsers,
		EncryptAssertion: in.EncryptAssertion, EncryptionCert: in.EncryptionCert, IdPInitiated: in.IdPInitiated,
		DefaultRelay: in.DefaultRelay, RequireMFA: in.RequireMFA, SLOURL: strings.TrimSpace(in.SLOURL), SLOBinding: in.SLOBinding,
		SigningCert: in.SigningCert}
}

func spView(sp *store.SAMLSP) idpapi.SP {
	attrs := make([]idpapi.Attribute, 0, len(sp.Attributes))
	for _, a := range sp.Attributes {
		attrs = append(attrs, idpapi.Attribute{Name: a.Name, Source: a.Source})
	}
	return idpapi.SP{SPInput: idpapi.SPInput{EntityID: sp.EntityID, Name: sp.Name, ACSURLs: nz(sp.ACSURLs), NameIDFormat: sp.NameIDFormat,
		NameIDSource: sp.NameIDSource, Attributes: attrs, Groups: nz(sp.AllowedGroups), AllowAllUsers: sp.AllowAllUsers,
		EncryptAssertion: sp.EncryptAssertion, EncryptionCert: sp.EncryptionCert, IdPInitiated: sp.IdPInitiated,
		DefaultRelay: sp.DefaultRelay, RequireMFA: sp.RequireMFA, SLOURL: sp.SLOURL, SLOBinding: sp.SLOBinding, SigningCert: sp.SigningCert},
		Enabled: sp.Enabled, CreatedAt: sp.CreatedAt, UpdatedAt: sp.UpdatedAt,
		EncryptionInfo: certInfo(sp.EncryptionCert), SigningInfo: certInfo(sp.SigningCert)}
}

func spDetail(sp *store.SAMLSP) string {
	return fmt.Sprintf("name=%s acs=%s nameid=%s/%s groups=%s all_users=%v encrypt=%v idp_initiated=%v require_mfa=%v slo=%s",
		sp.Name, strings.Join(sp.ACSURLs, " "), sp.NameIDFormat, sp.NameIDSource, strings.Join(sp.AllowedGroups, ","),
		sp.AllowAllUsers, sp.EncryptAssertion, sp.IdPInitiated, sp.RequireMFA, sp.SLOURL)
}

func certInfo(der []byte) *idpapi.Cert {
	if len(der) == 0 {
		return nil
	}
	c, err := x509.ParseCertificate(der)
	if err != nil {
		return nil
	}
	sum := sha256.Sum256(der)
	return &idpapi.Cert{Subject: c.Subject.String(), NotAfter: c.NotAfter, SHA256: fingerprint(sum[:])}
}

func fingerprint(b []byte) string {
	h := strings.ToUpper(hex.EncodeToString(b))
	var parts []string
	for i := 0; i < len(h); i += 2 {
		parts = append(parts, h[i:i+2])
	}
	return strings.Join(parts, ":")
}

func auditViews(evs []store.AuditEvent) []idpapi.AuditEvent {
	out := make([]idpapi.AuditEvent, 0, len(evs))
	for _, e := range evs {
		out = append(out, idpapi.AuditEvent{ID: e.ID, Time: e.Time, Actor: e.ActorName, Action: e.Action, Target: e.Target,
			Detail: e.Detail, Result: e.Result, IP: e.IP})
	}
	return out
}

// ---- previews ----

func (s *Server) user(ctx context.Context, typed string) (*directory.User, error) {
	sam, ok := directory.NormalizeUsername(typed, s.o.Dir.Realm())
	if !ok {
		return nil, invalid(errors.New("not a valid account name"))
	}
	u, err := s.o.Dir.UserBySAM(ctx, sam)
	if err != nil {
		if errors.Is(err, directory.ErrNotFound) {
			return nil, &idpapi.Error{Code: idpapi.CodeNotFound, Message: "no such user"}
		}
		return nil, err
	}
	return u, nil
}

func refusal(u *directory.User) string {
	switch {
	case !u.Enabled:
		return "account disabled"
	case u.Locked:
		return "account locked"
	case u.Expired:
		return "account expired"
	}
	return "not a member of an allowed group"
}

func (s *Server) clientPreview(ctx context.Context, q *idpapi.ClientPreviewParams) (any, string, string, error) {
	var c *store.Client
	var err error
	if q.ID != "" {
		c, err = s.o.Store.GetClient(ctx, q.ID)
	} else {
		in := *q.Input
		if in.Kind == "" {
			in.Kind = store.ClientConfidential
		}
		c, err = registry.BuildClient(ctx, s.o.Dir, clientInput(in))
		err = invalidOr(err)
	}
	if err != nil {
		return nil, "", "", err
	}
	u, err := s.user(ctx, q.Username)
	if err != nil {
		return nil, "", "", err
	}
	pv := idpapi.Preview{User: u.SAM, Allowed: oidcp.Allowed(c, u), Values: []idpapi.Value{}}
	if !pv.Allowed {
		pv.Reason = refusal(u)
	}
	claims, err := oidcp.Claims(ctx, s.o.Dir, c, u, c.Scopes)
	if err != nil {
		return nil, "", "", err
	}
	for name, v := range claims {
		pv.Values = append(pv.Values, idpapi.Value{Name: name, Values: claimValues(v)})
	}
	sort.Slice(pv.Values, func(i, j int) bool { return pv.Values[i].Name < pv.Values[j].Name })
	return pv, "", "", nil
}

func claimValues(v any) []string {
	switch t := v.(type) {
	case string:
		return []string{t}
	case []string:
		return t
	}
	return []string{fmt.Sprint(v)}
}

func (s *Server) spPreview(ctx context.Context, q *idpapi.SPPreviewParams) (any, string, string, error) {
	if s.o.SAML == nil {
		return nil, "", "", errSAMLOff
	}
	var sp *store.SAMLSP
	var err error
	if q.EntityID != "" {
		sp, err = s.o.Store.GetSP(ctx, q.EntityID)
	} else {
		in := *q.Input
		if in.EntityID == "" {
			in.EntityID = "urn:preview"
		}
		if len(in.ACSURLs) == 0 {
			in.ACSURLs = []string{"https://preview.invalid/acs"}
		}
		sp, err = registry.BuildSP(ctx, s.o.Dir, spInput(in))
		err = invalidOr(err)
	}
	if err != nil {
		return nil, "", "", err
	}
	u, err := s.user(ctx, q.Username)
	if err != nil {
		return nil, "", "", err
	}
	pv := idpapi.Preview{User: u.SAM, Allowed: samlidp.Allowed(sp, u), NameIDFormat: sp.NameIDFormat, Values: []idpapi.Value{}}
	if !pv.Allowed {
		pv.Reason = refusal(u)
	}
	ids, err := s.o.SAML.Values(ctx, sp.NameIDSource, u)
	if err != nil {
		return nil, "", "", err
	}
	if len(ids) == 1 {
		pv.NameID = ids[0]
	} else if pv.Allowed {
		pv.Allowed, pv.Reason = false, "the user has no value for the NameID source "+sp.NameIDSource
	}
	for _, a := range sp.Attributes {
		vals, err := s.o.SAML.Values(ctx, a.Source, u)
		if err != nil {
			return nil, "", "", err
		}
		if vals == nil {
			vals = []string{}
		}
		pv.Values = append(pv.Values, idpapi.Value{Name: a.Name, Values: vals})
	}
	return pv, "", "", nil
}

// ---- SP metadata ----

// metadataClient fetches SP metadata: https only (also after redirects),
// a short timeout, the system's CA pool.
func metadataClient() *http.Client {
	return &http.Client{Timeout: 15 * time.Second, CheckRedirect: func(r *http.Request, via []*http.Request) error {
		if len(via) >= 3 || r.URL.Scheme != "https" {
			return errors.New("metadata: too many redirects or not https")
		}
		return nil
	}}
}

func (s *Server) spMetadata(ctx context.Context, q *idpapi.SPMetadataParams) (any, string, string, error) {
	raw := []byte(q.XML)
	target, detail := "", "document"
	if q.URL != "" {
		target, detail = q.URL, "fetched by URL"
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, q.URL, nil)
		if err != nil {
			return nil, target, detail, invalid(err)
		}
		req.Header.Set("Accept", "application/samlmetadata+xml, application/xml, text/xml")
		resp, err := s.o.HTTP.Do(req)
		if err != nil {
			return nil, target, detail, invalid(fmt.Errorf("fetching the metadata: %w", err))
		}
		defer func() { _ = resp.Body.Close() }()
		if resp.StatusCode != http.StatusOK {
			return nil, target, detail, invalid(fmt.Errorf("fetching the metadata: HTTP %d", resp.StatusCode))
		}
		raw, err = io.ReadAll(io.LimitReader(resp.Body, 1<<20+1))
		if err != nil {
			return nil, target, detail, invalid(err)
		}
	}
	sp, err := samlidp.ParseSPMetadata(raw)
	if err != nil {
		return nil, target, detail, invalid(err)
	}
	if target == "" {
		target = sp.EntityID
	}
	d := idpapi.SPDraft{Input: spView(sp).SPInput}
	d.Input.Attributes = []idpapi.Attribute{}
	d.Input.Groups = []string{}
	if len(sp.EncryptionCert) == 0 {
		d.Warnings = append(d.Warnings, "no_encryption_cert")
	}
	if sp.SLOURL == "" {
		d.Warnings = append(d.Warnings, "no_slo")
	} else if len(sp.SigningCert) == 0 {
		d.Warnings = append(d.Warnings, "no_signing_cert")
	}
	return d, target, detail + " entity_id=" + sp.EntityID, nil
}

// ---- keys ----

func (s *Server) keys(ctx context.Context) (idpapi.Keys, error) {
	c := s.o.Config
	now := s.now()
	out := idpapi.Keys{SAMLEnabled: s.o.SAML != nil, RotateDays: c.Keys.RotateDays, OverlapHours: c.Keys.OverlapHours,
		OIDC: []idpapi.Key{}, SAML: []idpapi.Key{}}
	oidcKeys, err := s.o.Store.ListSigningKeys(ctx, store.KeyOIDC, now)
	if err != nil {
		return out, err
	}
	for n, k := range oidcKeys {
		out.OIDC = append(out.OIDC, idpapi.Key{ID: k.ID, Purpose: idpapi.KeyOIDC, Alg: k.Alg, CreatedAt: k.CreatedAt, RetireAt: k.RetireAt, Signing: n == 0})
	}
	if len(oidcKeys) > 0 {
		out.NextOIDCRotation = oidcKeys[0].CreatedAt.Add(c.KeyRotateAfter())
	}
	if s.o.SAML == nil {
		return out, nil
	}
	samlKeys, err := s.o.Store.ListSigningKeys(ctx, store.KeySAML, now)
	if err != nil {
		return out, err
	}
	for n, k := range samlKeys {
		out.SAML = append(out.SAML, idpapi.Key{ID: k.ID, Purpose: idpapi.KeySAML, Alg: k.Alg, CreatedAt: k.CreatedAt, RetireAt: k.RetireAt,
			Signing: n == len(samlKeys)-1, Cert: certInfo(k.Cert)})
	}
	if len(samlKeys) > 1 {
		out.SAMLSwitchAt = samlKeys[len(samlKeys)-1].RetireAt
	}
	return out, nil
}

func (s *Server) samlCert(ctx context.Context, id string) (idpapi.CertPEM, error) {
	if s.o.SAML == nil {
		return idpapi.CertPEM{}, errSAMLOff
	}
	keys, err := s.o.Store.ListSigningKeys(ctx, store.KeySAML, s.now())
	if err != nil {
		return idpapi.CertPEM{}, err
	}
	if len(keys) == 0 {
		return idpapi.CertPEM{}, store.ErrNotFound
	}
	k := keys[len(keys)-1] // the signing one
	if id != "" {
		i := slices.IndexFunc(keys, func(k *store.SigningKey) bool { return k.ID == id })
		if i < 0 {
			return idpapi.CertPEM{}, store.ErrNotFound
		}
		k = keys[i]
	}
	info := certInfo(k.Cert)
	if info == nil {
		return idpapi.CertPEM{}, errors.New("the key has no certificate")
	}
	return idpapi.CertPEM{ID: k.ID, PEM: string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: k.Cert})), Cert: *info}, nil
}

// ---- activity ----

func (s *Server) activity(ctx context.Context, days int) (idpapi.Activity, error) {
	until := s.now().UTC()
	since := until.Add(-time.Duration(days) * 24 * time.Hour)
	a := idpapi.Activity{Since: since, Until: until, Apps: []idpapi.AppActivity{}, Recent: []idpapi.AuditEvent{}}
	rows, locked, err := s.o.Store.Activity(ctx, since)
	if err != nil {
		return a, err
	}
	a.Lockouts = locked
	names := map[string]string{}
	if cs, err := s.o.Store.ListClients(ctx); err == nil {
		for _, c := range cs {
			names["oidc\x00"+c.ID] = c.Name
		}
	}
	if sps, err := s.o.Store.ListSPs(ctx); err == nil {
		for _, sp := range sps {
			names["saml\x00"+sp.EntityID] = sp.Name
		}
	}
	apps := map[string]*idpapi.AppActivity{}
	app := func(kind, id string) *idpapi.AppActivity {
		k := kind + "\x00" + id
		if apps[k] == nil {
			apps[k] = &idpapi.AppActivity{Kind: kind, ID: id, Name: names[k]}
		}
		return apps[k]
	}
	for _, r := range rows {
		switch r.Action {
		case "oidc.authorize", "saml.sso":
			if r.Target == "" {
				continue
			}
			kind := "oidc"
			if r.Action == "saml.sso" {
				kind = "saml"
			}
			x := app(kind, r.Target)
			switch r.Result {
			case store.ResultOK:
				x.SignIns += r.Rows
				x.Users += r.Actors
			case store.ResultDenied:
				x.Denied += r.Rows
			}
		case "signin.password":
			if r.Result == store.ResultOK {
				a.SignIns += r.Rows
			}
		case "signin.failure":
			a.Failures += r.Rows
		case "signin.rate_limited":
			a.RateLimited += r.Rows
		case "mfa.failure":
			a.MFAFailures += r.Rows
		}
	}
	for _, x := range apps {
		a.Apps = append(a.Apps, *x)
	}
	sort.Slice(a.Apps, func(i, j int) bool {
		if a.Apps[i].SignIns != a.Apps[j].SignIns {
			return a.Apps[i].SignIns > a.Apps[j].SignIns
		}
		return a.Apps[i].ID < a.Apps[j].ID
	})
	recent, _, err := s.o.Store.ListAudit(ctx, store.AuditFilter{Result: store.ResultDenied, Since: since}, 0, 20)
	if err != nil {
		return a, err
	}
	a.Recent = auditViews(recent)
	return a, nil
}

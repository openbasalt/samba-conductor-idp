package mfa

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"time"

	"github.com/openbasalt/samba-conductor-idp/idpapi"
	"github.com/openbasalt/samba-conductor-idp/internal/directory"
)

// Conductor verifies second factors against conductor's 2FA store through
// conductor's local socket (protocol: idpapi, MFAProtocolVersion). Users
// are identified by SID because conductor keys its 2FA store by SID; the
// user's group SIDs travel along so conductor applies its own role-based
// policy.
type Conductor struct {
	Socket  string
	Timeout time.Duration
}

// Name implements Backend.
func (c *Conductor) Name() string { return "conductor" }

// CanEnroll implements Backend: enrollment happens in conductor.
func (c *Conductor) CanEnroll() bool { return false }

func request(op string, u *directory.User) idpapi.MFARequest {
	groups := make([]string, 0, len(u.GroupSIDs))
	for _, g := range u.GroupSIDs {
		groups = append(groups, g.String())
	}
	return idpapi.MFARequest{V: idpapi.MFAProtocolVersion, Op: op, UserSID: u.SID.String(), User: u.SAM, Groups: groups}
}

func (c *Conductor) call(ctx context.Context, req idpapi.MFARequest) (idpapi.MFAAnswer, error) {
	timeout := c.Timeout
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	var d net.Dialer
	conn, err := d.DialContext(ctx, "unix", c.Socket)
	if err != nil {
		return idpapi.MFAAnswer{}, fmt.Errorf("%w: %v", ErrUnavailable, err)
	}
	defer func() { _ = conn.Close() }()
	if dl, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(dl)
	}
	if err := json.NewEncoder(conn).Encode(req); err != nil {
		return idpapi.MFAAnswer{}, fmt.Errorf("%w: %v", ErrUnavailable, err)
	}
	line, err := bufio.NewReader(io.LimitReader(conn, idpapi.MFAMaxMessage)).ReadBytes('\n')
	if err != nil {
		return idpapi.MFAAnswer{}, fmt.Errorf("%w: %v", ErrUnavailable, err)
	}
	var a idpapi.MFAAnswer
	if err := json.Unmarshal(line, &a); err != nil || a.V != idpapi.MFAProtocolVersion {
		return idpapi.MFAAnswer{}, fmt.Errorf("%w: malformed answer (protocol version %d expected)", ErrUnavailable, idpapi.MFAProtocolVersion)
	}
	switch a.Error {
	case "":
		return a, nil
	case idpapi.MFAErrKeyRequired:
		return a, ErrKeyRequired
	case idpapi.MFAErrInternal, idpapi.MFAErrVersion:
		return a, fmt.Errorf("%w: conductor: %s", ErrUnavailable, a.Error)
	}
	return a, fmt.Errorf("mfa: conductor refused: %s", a.Error)
}

// State implements Backend.
func (c *Conductor) State(ctx context.Context, u *directory.User) (State, error) {
	a, err := c.call(ctx, request(idpapi.MFAOpStatus, u))
	if err != nil {
		return State{}, err
	}
	return State{Enrolled: a.Enrolled, TOTP: a.TOTP, Keys: a.Keys, Shared: true, Required: a.Required, Policy: a.Policy, KeyRequired: a.KeyRequired}, nil
}

// Verify implements Backend.
func (c *Conductor) Verify(ctx context.Context, u *directory.User, code string) (Result, error) {
	req := request(idpapi.MFAOpVerify, u)
	req.Code = code
	a, err := c.call(ctx, req)
	if err != nil {
		return Result{}, err
	}
	return Result{OK: a.OK, Recovery: a.OK && a.Recovery}, nil
}

// BeginKey implements KeyBackend.
func (c *Conductor) BeginKey(ctx context.Context, u *directory.User) (Ceremony, error) {
	a, err := c.call(ctx, request(idpapi.MFAOpKeyBegin, u))
	if err != nil {
		return Ceremony{}, err
	}
	if a.Ceremony == "" || len(a.Options) == 0 {
		return Ceremony{}, fmt.Errorf("%w: no ceremony", ErrUnavailable)
	}
	return Ceremony{ID: a.Ceremony, Options: a.Options}, nil
}

// FinishKey implements KeyBackend.
func (c *Conductor) FinishKey(ctx context.Context, u *directory.User, ceremony, response string) (bool, error) {
	req := request(idpapi.MFAOpKeyFinish, u)
	req.Ceremony, req.Response = ceremony, response
	a, err := c.call(ctx, req)
	if err != nil {
		return false, err
	}
	return a.OK, nil
}

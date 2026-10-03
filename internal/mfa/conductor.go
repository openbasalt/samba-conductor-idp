package mfa

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"time"

	"github.com/openbasalt/samba-conductor-idp/internal/directory"
)

// Conductor verifies second factors against conductor's 2FA store through
// conductor's local verification socket.
//
// Protocol (version 1; the server side is to be added to conductor, see
// docs/decisions.md D4): one JSON request per connection, one JSON answer
// line. The server authorizes the peer by SO_PEERCRED (only the
// conductor-idp system user), rate limits per user, and audits every call.
//
//	→ {"v":1,"op":"status","user_sid":"S-1-5-21-…"}
//	← {"v":1,"enrolled":true}
//	→ {"v":1,"op":"verify","user_sid":"S-1-5-21-…","code":"123456"}
//	← {"v":1,"ok":true,"recovery":false}
//	← {"v":1,"error":"rate_limited"}
//
// Users are identified by SID because conductor keys its 2FA store by SID.
type Conductor struct {
	Socket  string
	Timeout time.Duration
}

// Name implements Backend.
func (c *Conductor) Name() string { return "conductor" }

// CanEnroll implements Backend: enrollment happens in conductor.
func (c *Conductor) CanEnroll() bool { return false }

type socketRequest struct {
	V       int    `json:"v"`
	Op      string `json:"op"`
	UserSID string `json:"user_sid"`
	Code    string `json:"code,omitempty"`
}

type socketAnswer struct {
	V        int    `json:"v"`
	Enrolled bool   `json:"enrolled"`
	OK       bool   `json:"ok"`
	Recovery bool   `json:"recovery"`
	Error    string `json:"error"`
}

// maxAnswer bounds the answer line.
const maxAnswer = 4096

func (c *Conductor) call(ctx context.Context, req socketRequest) (socketAnswer, error) {
	timeout := c.Timeout
	if timeout <= 0 {
		timeout = 5 * time.Second
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	var d net.Dialer
	conn, err := d.DialContext(ctx, "unix", c.Socket)
	if err != nil {
		return socketAnswer{}, fmt.Errorf("%w: %v", ErrUnavailable, err)
	}
	defer func() { _ = conn.Close() }()
	if dl, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(dl)
	}
	req.V = 1
	if err := json.NewEncoder(conn).Encode(req); err != nil {
		return socketAnswer{}, fmt.Errorf("%w: %v", ErrUnavailable, err)
	}
	line, err := bufio.NewReader(io.LimitReader(conn, maxAnswer)).ReadBytes('\n')
	if err != nil {
		return socketAnswer{}, fmt.Errorf("%w: %v", ErrUnavailable, err)
	}
	var a socketAnswer
	if err := json.Unmarshal(line, &a); err != nil || a.V != 1 {
		return socketAnswer{}, fmt.Errorf("%w: malformed answer", ErrUnavailable)
	}
	if a.Error != "" {
		return a, fmt.Errorf("mfa: conductor refused: %s", a.Error)
	}
	return a, nil
}

// Enrolled implements Backend.
func (c *Conductor) Enrolled(ctx context.Context, u *directory.User) (bool, error) {
	a, err := c.call(ctx, socketRequest{Op: "status", UserSID: u.SID.String()})
	return a.Enrolled, err
}

// Verify implements Backend.
func (c *Conductor) Verify(ctx context.Context, u *directory.User, code string) (Result, error) {
	a, err := c.call(ctx, socketRequest{Op: "verify", UserSID: u.SID.String(), Code: code})
	if err != nil {
		return Result{}, err
	}
	return Result{OK: a.OK, Recovery: a.OK && a.Recovery}, nil
}

package mfa

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"net"
	"path/filepath"
	"testing"

	"github.com/openbasalt/samba-conductor-ad/sid"
	"github.com/openbasalt/samba-conductor-idp/idpapi"
	"github.com/openbasalt/samba-conductor-idp/internal/directory"
)

// fakeConductor answers the socket protocol the way conductor does.
func fakeConductor(t *testing.T, answer func(req idpapi.MFARequest) idpapi.MFAAnswer) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "mfa.sock")
	l, err := net.Listen("unix", p)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = l.Close() })
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			var req idpapi.MFARequest
			line, _ := bufio.NewReader(c).ReadBytes('\n')
			_ = json.Unmarshal(line, &req)
			a := answer(req)
			if err := req.Validate(); err != nil {
				a = idpapi.MFAAnswer{V: idpapi.MFAProtocolVersion, Error: idpapi.MFAErrBadRequest}
			}
			_ = json.NewEncoder(c).Encode(a)
			_ = c.Close()
		}
	}()
	return p
}

func TestConductorBackend(t *testing.T) {
	u := &directory.User{GUID: "g", SAM: "alice", SID: sid.MustParse("S-1-5-21-1-2-3-1105"),
		GroupSIDs: []sid.SID{sid.MustParse("S-1-5-21-1-2-3-512")}}
	v := idpapi.MFAProtocolVersion
	sock := fakeConductor(t, func(req idpapi.MFARequest) idpapi.MFAAnswer {
		if req.UserSID != "S-1-5-21-1-2-3-1105" || len(req.Groups) != 1 {
			return idpapi.MFAAnswer{V: v, Error: idpapi.MFAErrBadRequest}
		}
		switch req.Op {
		case idpapi.MFAOpStatus:
			return idpapi.MFAAnswer{V: v, Enrolled: true, TOTP: true, Keys: 1, Required: true, Policy: "optional"}
		case idpapi.MFAOpVerify:
			if req.Code == "999999" {
				return idpapi.MFAAnswer{V: v, Error: idpapi.MFAErrKeyRequired}
			}
			return idpapi.MFAAnswer{V: v, OK: req.Code == "123456"}
		case idpapi.MFAOpKeyBegin:
			return idpapi.MFAAnswer{V: v, Ceremony: "cer-0123456789abcdef", Options: json.RawMessage(`{"publicKey":{}}`)}
		case idpapi.MFAOpKeyFinish:
			return idpapi.MFAAnswer{V: v, OK: req.Ceremony == "cer-0123456789abcdef" && req.Response == "{}"}
		}
		return idpapi.MFAAnswer{V: v, Error: "unknown_op"}
	})
	c := &Conductor{Socket: sock}
	ctx := context.Background()
	st, err := c.State(ctx, u)
	if err != nil || !st.Enrolled || !st.Shared || !st.Required || st.Keys != 1 || st.Policy != "optional" {
		t.Fatalf("state %+v %v", st, err)
	}
	if r, err := c.Verify(ctx, u, "123456"); err != nil || !r.OK {
		t.Fatalf("verify %+v %v", r, err)
	}
	if r, _ := c.Verify(ctx, u, "000000"); r.OK {
		t.Fatal("wrong code accepted")
	}
	if _, err := c.Verify(ctx, u, "999999"); !errors.Is(err, ErrKeyRequired) {
		t.Fatalf("key required: %v", err)
	}
	cer, err := c.BeginKey(ctx, u)
	if err != nil || cer.ID == "" {
		t.Fatalf("begin %+v %v", cer, err)
	}
	if ok, err := c.FinishKey(ctx, u, cer.ID, "{}"); err != nil || !ok {
		t.Fatalf("finish %v %v", ok, err)
	}
	// A dead socket is "unavailable", never "no 2FA".
	dead := &Conductor{Socket: filepath.Join(t.TempDir(), "none.sock")}
	if _, err := dead.State(ctx, u); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("dead socket: %v", err)
	}
}

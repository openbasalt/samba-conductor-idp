package mfa

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"net"
	"path/filepath"
	"testing"

	"github.com/samba-conductor/ad/sid"
	"github.com/samba-conductor/conductor-idp/internal/directory"
)

// fakeConductor answers the socket protocol the way conductor will.
func fakeConductor(t *testing.T, answer func(req socketRequest) socketAnswer) string {
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
			var req socketRequest
			line, _ := bufio.NewReader(c).ReadBytes('\n')
			_ = json.Unmarshal(line, &req)
			_ = json.NewEncoder(c).Encode(answer(req))
			_ = c.Close()
		}
	}()
	return p
}

func TestConductorBackend(t *testing.T) {
	u := &directory.User{GUID: "g", SID: sid.MustParse("S-1-5-21-1-2-3-1105")}
	sock := fakeConductor(t, func(req socketRequest) socketAnswer {
		if req.UserSID != "S-1-5-21-1-2-3-1105" || req.V != 1 {
			return socketAnswer{V: 1, Error: "bad_request"}
		}
		switch req.Op {
		case "status":
			return socketAnswer{V: 1, Enrolled: true}
		case "verify":
			return socketAnswer{V: 1, OK: req.Code == "123456"}
		}
		return socketAnswer{V: 1, Error: "unknown_op"}
	})
	c := &Conductor{Socket: sock}
	ctx := context.Background()
	if ok, err := c.Enrolled(ctx, u); err != nil || !ok {
		t.Fatalf("enrolled %v %v", ok, err)
	}
	if r, err := c.Verify(ctx, u, "123456"); err != nil || !r.OK {
		t.Fatalf("verify %+v %v", r, err)
	}
	if r, _ := c.Verify(ctx, u, "000000"); r.OK {
		t.Fatal("wrong code accepted")
	}
	// A dead socket is "unavailable", never "no 2FA".
	dead := &Conductor{Socket: filepath.Join(t.TempDir(), "none.sock")}
	if _, err := dead.Enrolled(ctx, u); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("dead socket: %v", err)
	}
}

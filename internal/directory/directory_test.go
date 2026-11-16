package directory

import (
	"context"
	"errors"
	"testing"
	"time"

	ad "github.com/openbasalt/samba-conductor-ad"
	"github.com/openbasalt/samba-conductor-ad/sid"
)

// An empty password is refused before any KDC or DC is contacted, also
// with the simple-bind fallback enabled (an empty simple bind would be an
// unauthenticated bind that "succeeds").
func TestAuthenticateEmptyPassword(t *testing.T) {
	d, err := New(Options{
		// 192.0.2.1 (TEST-NET-1) is never reachable: a network attempt
		// would show up as a timeout instead of an immediate refusal.
		Config:             ad.Config{Realm: "LAB.TEST", DCs: []string{"192.0.2.1"}, InsecureSkipTLSVerifyForTestsOnly: true, DialTimeout: 5 * time.Second},
		SimpleBindFallback: true,
		ServiceUser:        "svc",
		ServicePassword:    "x",
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	err = d.Authenticate(ctx, "alice", "")
	var ae *ad.AuthError
	if !errors.As(err, &ae) || ae.Reason != ad.ReasonInvalidCredentials {
		t.Fatalf("empty password: %v", err)
	}
}

func TestPasswordChangedSince(t *testing.T) {
	signIn := time.Date(2026, 3, 1, 12, 0, 0, 0, time.UTC)
	before := int64(ad.FileTimeFrom(signIn.Add(-time.Hour)))
	after := int64(ad.FileTimeFrom(signIn.Add(time.Hour)))
	for _, c := range []struct {
		name    string
		current int64
		pwdSet  int64
		want    bool
	}{
		{"unchanged", before, before, false},
		{"changed", after, before, true},
		{"set to an older value", before - 1, before, true},
		{"must change now", 0, before, true},
		{"legacy record, set before the sign-in", before, 0, false},
		{"legacy record, set after the sign-in", after, 0, true},
		{"legacy record, must change now", 0, 0, true},
	} {
		u := &User{PwdLastSet: c.current}
		if got := u.PasswordChangedSince(c.pwdSet, signIn); got != c.want {
			t.Errorf("%s: %v", c.name, got)
		}
	}
	if !(&User{PwdLastSet: before}).PasswordChangedSince(0, time.Time{}) {
		t.Error("legacy record without a sign-in time is not trusted")
	}
}

type holders map[string][]string

func (h holders) Realm() string                                                       { return "LAB.TEST" }
func (h holders) Authenticate(context.Context, string, string) error                  { return nil }
func (h holders) ChangeExpiredPassword(context.Context, string, string, string) error { return nil }
func (h holders) UserBySAM(context.Context, string) (*User, error)                    { return nil, ErrNotFound }
func (h holders) UserByGUID(context.Context, string) (*User, error)                   { return nil, ErrNotFound }
func (h holders) GroupNames(context.Context, []sid.SID) (map[string]string, error) {
	return nil, nil
}
func (h holders) DomainAdminsSID(context.Context) (sid.SID, error)     { return sid.SID{}, nil }
func (h holders) GroupByName(context.Context, string) (sid.SID, error) { return sid.SID{}, nil }
func (h holders) AddressHolders(_ context.Context, a string) ([]string, error) {
	if v, ok := h[a]; ok {
		return v, nil
	}
	return nil, errors.New("directory down")
}

func TestMailUnique(t *testing.T) {
	ctx := context.Background()
	me := "11111111-1111-4111-8111-111111111111"
	dir := holders{"a@x.test": {me}, "b@x.test": {me, "22222222-2222-4222-8222-222222222222"}, "c@x.test": {}}
	for addr, want := range map[string]bool{"a@x.test": true, "b@x.test": false, "c@x.test": true, "": false} {
		got, err := MailUnique(ctx, dir, &User{GUID: me, Mail: addr})
		if err != nil || got != want {
			t.Errorf("%q: %v %v", addr, got, err)
		}
	}
	if _, err := MailUnique(ctx, dir, &User{GUID: me, Mail: "down@x.test"}); err == nil {
		t.Error("a directory error was taken as unique")
	}
}

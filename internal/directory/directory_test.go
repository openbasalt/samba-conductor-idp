package directory

import (
	"context"
	"errors"
	"testing"
	"time"

	ad "github.com/openbasalt/samba-conductor-ad"
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

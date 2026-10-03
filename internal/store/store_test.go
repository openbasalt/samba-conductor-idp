package store

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"
)

func open(t *testing.T) *Store {
	t.Helper()
	s, err := Open(context.Background(), filepath.Join(t.TempDir(), "idp.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s
}

func TestAuditChain(t *testing.T) {
	s := open(t)
	ctx := context.Background()
	for i := 0; i < 5; i++ {
		if _, err := s.AppendAudit(ctx, AuditEvent{ActorName: "alice", Action: "signin.password", Target: "x", Result: ResultOK}); err != nil {
			t.Fatal(err)
		}
	}
	v, err := s.VerifyAudit(ctx)
	if err != nil || v.BrokenAt != 0 || v.Rows != 5 {
		t.Fatalf("%+v %v", v, err)
	}
	if _, err := s.db.ExecContext(ctx, `UPDATE audit SET detail = 'tampered' WHERE id = 3`); err != nil {
		t.Fatal(err)
	}
	if v, _ := s.VerifyAudit(ctx); v.BrokenAt != 3 {
		t.Fatalf("tampering not detected: %+v", v)
	}
}

func TestCodeConsumedOnce(t *testing.T) {
	s := open(t)
	ctx := context.Background()
	if err := s.SaveAuthCode(ctx, "h1", "req-1", time.Now().Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	if id, err := s.ConsumeAuthCode(ctx, "h1"); err != nil || id != "req-1" {
		t.Fatalf("%q %v", id, err)
	}
	if id, err := s.ConsumeAuthCode(ctx, "h1"); !errors.Is(err, ErrCodeReused) || id != "req-1" {
		t.Fatalf("reuse: %q %v", id, err)
	}
	if _, err := s.ConsumeAuthCode(ctx, "nope"); !errors.Is(err, ErrNotFound) {
		t.Fatal(err)
	}
	_ = s.SaveAuthCode(ctx, "h2", "req-2", time.Now().Add(-time.Second))
	if _, err := s.ConsumeAuthCode(ctx, "h2"); !errors.Is(err, ErrNotFound) {
		t.Fatal("expired code accepted")
	}
}

func TestRefreshRotateOnce(t *testing.T) {
	s := open(t)
	ctx := context.Background()
	c := &Client{ID: "c1", Name: "c", Kind: ClientPublic, RedirectURIs: []string{"https://x/cb"}, Scopes: []string{"openid"},
		AllowAllUsers: true, GroupsClaim: GroupsNone, Enabled: true}
	if err := s.CreateClient(ctx, c); err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	rt := &RefreshToken{ID: "r1", ChainID: "ch", TokenHash: "th", ClientID: "c1", Subject: "u", AuthTime: now, CreatedAt: now,
		ExpiresAt: now.Add(time.Hour), ChainExpiresAt: now.Add(time.Hour)}
	if err := s.CreateRefreshToken(ctx, rt); err != nil {
		t.Fatal(err)
	}
	if ok, _ := s.RotateRefreshToken(ctx, "r1"); !ok {
		t.Fatal("first rotation refused")
	}
	if ok, _ := s.RotateRefreshToken(ctx, "r1"); ok {
		t.Fatal("second rotation accepted")
	}
	_ = s.CreateAccessToken(ctx, &AccessToken{ID: "a1", ChainID: "ch", ClientID: "c1", Subject: "u", CreatedAt: now, ExpiresAt: now.Add(time.Hour)})
	if err := s.RevokeChain(ctx, "ch"); err != nil {
		t.Fatal(err)
	}
	if at, _ := s.GetAccessToken(ctx, "a1"); at.RevokedAt.IsZero() {
		t.Fatal("access token of the chain not revoked")
	}
	// Deleting the client removes its tokens.
	if err := s.DeleteClient(ctx, "c1"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.GetRefreshTokenByHash(ctx, "th"); !errors.Is(err, ErrNotFound) {
		t.Fatal("tokens of a deleted client kept")
	}
}

func TestTOTPStepMonotonic(t *testing.T) {
	s := open(t)
	ctx := context.Background()
	if err := s.SaveTOTP(ctx, "g", []byte("sealed"), 100, []string{"h1", "h2"}); err != nil {
		t.Fatal(err)
	}
	if ok, _ := s.AdvanceTOTPStep(ctx, "g", 100); ok {
		t.Fatal("same step accepted")
	}
	if ok, _ := s.AdvanceTOTPStep(ctx, "g", 101); !ok {
		t.Fatal("next step refused")
	}
	if ok, _ := s.UseRecoveryCode(ctx, "g", "h1"); !ok {
		t.Fatal("recovery code refused")
	}
	if ok, _ := s.UseRecoveryCode(ctx, "g", "h1"); ok {
		t.Fatal("recovery code reused")
	}
	if n, _ := s.RecoveryCodesLeft(ctx, "g"); n != 1 {
		t.Fatalf("%d left", n)
	}
}

func TestSAMLPendingReplay(t *testing.T) {
	s := open(t)
	ctx := context.Background()
	p := &SAMLPending{ID: "p1", EntityID: "sp", RequestID: "id-1", Payload: []byte("<x/>"), BrowserHash: "b", ReceivedAt: time.Now(), ExpiresAt: time.Now().Add(time.Minute)}
	if err := s.CreateSAMLPending(ctx, p); err != nil {
		t.Fatal(err)
	}
	p.ID = "p2"
	if err := s.CreateSAMLPending(ctx, p); !errors.Is(err, ErrConflict) {
		t.Fatalf("replay: %v", err)
	}
	if ok, _ := s.FinishSAMLPending(ctx, "p1"); !ok {
		t.Fatal("finish")
	}
	if ok, _ := s.FinishSAMLPending(ctx, "p1"); ok {
		t.Fatal("finished twice")
	}
}

package registry

import (
	"context"
	"strings"
	"testing"

	"github.com/openbasalt/samba-conductor-idp/internal/store"
)

func TestValidRedirect(t *testing.T) {
	for raw, ok := range map[string]bool{
		"https://app.example.com/cb":   true,
		"http://localhost:8080/cb":     true,
		"http://127.0.0.1/cb":          true,
		"http://app.example.com/cb":    false,
		"https://app.example.com/cb#x": false,
		"https://u:p@app.example.com/": false,
		"javascript:alert(1)":          false,
		"com.example.app:/cb":          false, // only for public clients
		"relative/cb":                  false,
	} {
		if err := ValidRedirect(raw, false); (err == nil) != ok {
			t.Errorf("%s: %v", raw, err)
		}
	}
	if err := ValidRedirect("com.example.app:/cb", true); err != nil {
		t.Errorf("private-use scheme for a public client: %v", err)
	}
}

func TestBuildClientRules(t *testing.T) {
	ctx := context.Background()
	base := ClientInput{Name: "App", Kind: store.ClientConfidential, RedirectURIs: []string{"https://a.example/cb"},
		Groups: []string{"S-1-5-21-1-2-3-1101"}}
	c, err := BuildClient(ctx, nil, base)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(c.Scopes, ",") != "openid" {
		t.Fatalf("scopes %v", c.Scopes)
	}
	in := base
	in.Groups = nil
	if _, err := BuildClient(ctx, nil, in); err == nil {
		t.Fatal("client without groups and without allow-all accepted")
	}
	in = base
	in.GroupsClaim = store.GroupsNames
	c, _ = BuildClient(ctx, nil, in)
	if !strings.Contains(strings.Join(c.Scopes, ","), "groups") {
		t.Fatal("groups claim without the groups scope")
	}
	in = base
	in.Scopes = []string{"admin"}
	if _, err := BuildClient(ctx, nil, in); err == nil {
		t.Fatal("unknown scope accepted")
	}
	in = base
	in.Groups = []string{"Engineering"}
	if _, err := BuildClient(ctx, nil, in); err == nil {
		t.Fatal("group name accepted without a directory")
	}
}

// email_verified: off unless asked; an update without the field (the
// management API) keeps the stored value.
func TestClientEmailVerified(t *testing.T) {
	ctx := context.Background()
	st, err := store.Open(ctx, ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = st.Close() }()
	in := ClientInput{Name: "RP", Kind: store.ClientConfidential, RedirectURIs: []string{"https://rp.test/cb"}, AllowAllUsers: true}
	c, _, err := CreateClient(ctx, st, nil, in)
	if err != nil || c.EmailVerified {
		t.Fatalf("default: %+v %v", c, err)
	}
	yes := true
	in.EmailVerified = &yes
	if c, err = UpdateClient(ctx, st, nil, c.ID, in); err != nil || !c.EmailVerified {
		t.Fatalf("set: %+v %v", c, err)
	}
	in.EmailVerified = nil
	if c, err = UpdateClient(ctx, st, nil, c.ID, in); err != nil || !c.EmailVerified {
		t.Fatalf("kept: %+v %v", c, err)
	}
	if got, _ := st.GetClient(ctx, c.ID); !got.EmailVerified {
		t.Fatal("not stored")
	}
}

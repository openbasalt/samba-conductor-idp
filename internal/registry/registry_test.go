package registry

import (
	"context"
	"strings"
	"testing"

	"github.com/samba-conductor/conductor-idp/internal/store"
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

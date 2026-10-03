package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const valid = `
[server]
issuer = "https://idp.example.com"
listen = ":9443"
tls_cert = "/etc/conductor-idp/tls/cert.pem"
tls_key = "/etc/conductor-idp/tls/key.pem"
[domain]
realm = "EXAMPLE.COM"
ca_file = "/etc/conductor-idp/domain-ca.pem"
[service_account]
username = "svc-conductor-idp"
`

func write(t *testing.T, body string) string {
	p := filepath.Join(t.TempDir(), "idp.toml")
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestLoadValid(t *testing.T) {
	c, err := Load(write(t, valid))
	if err != nil {
		t.Fatal(err)
	}
	if c.Issuer() != "https://idp.example.com" || c.MFA.Backend != MFABackendLocal || c.Tokens.IDTokenMinutes != 5 {
		t.Fatalf("%+v", c)
	}
}

func TestRejects(t *testing.T) {
	for name, edit := range map[string][2]string{
		"unknown key":    {"[service_account]", "[service_account]\ntypo = 1"},
		"http issuer":    {`"https://idp.example.com"`, `"http://idp.example.com"`},
		"issuer path":    {`"https://idp.example.com"`, `"https://idp.example.com/idp"`},
		"no tls public":  {`tls_cert = "/etc/conductor-idp/tls/cert.pem"`, `behind_proxy = true`},
		"bad backend":    {"[service_account]", "[mfa]\nbackend = \"x\"\n[service_account]"},
		"conductor sock": {"[service_account]", "[mfa]\nbackend = \"conductor\"\n[service_account]"},
		"bad admin sid":  {"[service_account]", "[roles]\nadmin_groups = [\"Domain Admins\"]\n[service_account]"},
	} {
		body := strings.Replace(valid, edit[0], edit[1], 1)
		if name == "no tls public" {
			body = strings.Replace(body, `tls_key = "/etc/conductor-idp/tls/key.pem"`, "", 1)
		}
		if _, err := Load(write(t, body)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

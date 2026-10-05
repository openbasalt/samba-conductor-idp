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

func TestExampleLoads(t *testing.T) {
	if _, err := Load("../../idp.toml.example"); err != nil {
		t.Fatal(err)
	}
}

func TestAdminListener(t *testing.T) {
	behindProxy := strings.Replace(strings.Replace(valid, `tls_cert = "/etc/conductor-idp/tls/cert.pem"`, "behind_proxy = true", 1),
		`tls_key = "/etc/conductor-idp/tls/key.pem"`, "", 1)
	behindProxy = strings.Replace(behindProxy, `listen = ":9443"`, `listen = "127.0.0.1:9080"`, 1)
	server := func(base, extra string) string { return strings.Replace(base, "[domain]", extra+"\n[domain]", 1) }

	for name, tc := range map[string]struct {
		body string
		mode AdminMode
		url  string
		tls  bool
	}{
		"unset":                   {valid, AdminShared, "https://idp.example.com", false},
		"off":                     {server(valid, `admin_listen = "off"`), AdminDisabled, "", false},
		"separate, main cert":     {server(valid, `admin_listen = "10.0.0.5:9444"`), AdminSeparate, "https://idp.example.com:9444", true},
		"separate, own url":       {server(valid, "admin_listen = \"10.0.0.5:9444\"\nadmin_url = \"https://idp-admin.example.com:9444\""), AdminSeparate, "https://idp-admin.example.com:9444", true},
		"separate, same port ip":  {server(strings.Replace(valid, `":9443"`, `"203.0.113.10:9443"`, 1), `admin_listen = "10.0.0.5:9443"`+"\nadmin_url = \"https://idp-admin.example.com\""), AdminSeparate, "https://idp-admin.example.com", true},
		"main behind proxy, cert": {server(behindProxy, "admin_listen = \"10.0.0.5:9444\"\nadmin_tls_cert = \"/c\"\nadmin_tls_key = \"/k\""), AdminSeparate, "https://idp.example.com:9444", true},
		"both behind proxy":       {server(behindProxy, "admin_listen = \"127.0.0.1:9081\"\nadmin_behind_proxy = true\nadmin_trusted_proxies = [\"127.0.0.1/32\"]\nadmin_url = \"https://idp-admin.example.com\""), AdminSeparate, "https://idp-admin.example.com", false},
	} {
		c, err := Load(write(t, tc.body))
		if err != nil {
			t.Errorf("%s: %v", name, err)
			continue
		}
		_, _, tlsOn := c.AdminTLS()
		if c.AdminMode() != tc.mode || c.AdminBaseURL() != tc.url || tlsOn != tc.tls {
			t.Errorf("%s: mode %v url %q tls %v", name, c.AdminMode(), c.AdminBaseURL(), tlsOn)
		}
	}

	for name, tc := range map[string]struct{ body, want string }{
		"keys without listen":       {server(valid, `admin_url = "https://a.example.com"`), "need server.admin_listen"},
		"keys with off":             {server(valid, "admin_listen = \"off\"\nadmin_behind_proxy = true"), "need server.admin_listen"},
		"bad address":               {server(valid, `admin_listen = "nope"`), `must be "off" or an address`},
		"same as listen":            {server(valid, `admin_listen = ":9443"`), "overlaps server.listen"},
		"wildcard overlap":          {server(valid, `admin_listen = "10.0.0.5:9443"`), "overlaps server.listen"},
		"half own tls":              {server(valid, "admin_listen = \"10.0.0.5:9444\"\nadmin_tls_cert = \"/c\""), "go together"},
		"tls and proxy":             {server(valid, "admin_listen = \"127.0.0.1:9444\"\nadmin_tls_cert = \"/c\"\nadmin_tls_key = \"/k\"\nadmin_behind_proxy = true\nadmin_url = \"https://a.example.com\""), "exclusive"},
		"proxy not loopback":        {server(valid, "admin_listen = \"10.0.0.5:9444\"\nadmin_behind_proxy = true\nadmin_url = \"https://a.example.com\""), "requires a loopback"},
		"proxy without url":         {server(valid, "admin_listen = \"127.0.0.1:9444\"\nadmin_behind_proxy = true"), "admin_url is required"},
		"no tls at all":             {server(behindProxy, `admin_listen = "10.0.0.5:9444"`), "admin listener needs TLS"},
		"trusted without proxy":     {server(valid, "admin_listen = \"10.0.0.5:9444\"\nadmin_trusted_proxies = [\"127.0.0.1/32\"]"), "only makes sense"},
		"bad trusted":               {server(valid, "admin_listen = \"127.0.0.1:9444\"\nadmin_behind_proxy = true\nadmin_url = \"https://a.example.com\"\nadmin_trusted_proxies = [\"x\"]"), "admin_trusted_proxies \"x\""},
		"http admin url":            {server(valid, "admin_listen = \"10.0.0.5:9444\"\nadmin_url = \"http://a.example.com\""), "admin_url must be https"},
		"admin url with path":       {server(valid, "admin_listen = \"10.0.0.5:9444\"\nadmin_url = \"https://a.example.com/admin\""), "admin_url must be https"},
		"admin url = issuer origin": {server(valid, "admin_listen = \"10.0.0.5:9444\"\nadmin_url = \"https://idp.example.com:443\""), "another origin"},
	} {
		_, err := Load(write(t, tc.body))
		if err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: got %v, want an error with %q", name, err, tc.want)
		}
	}
}

func TestAdminHostCanonical(t *testing.T) {
	c, err := Load(write(t, strings.Replace(valid, "[domain]", "admin_listen = \"10.0.0.5:9444\"\nadmin_url = \"https://IdP-Admin.example.com\"\n[domain]", 1)))
	if err != nil {
		t.Fatal(err)
	}
	for _, h := range []string{"idp-admin.example.com", "idp-admin.example.com:443", "IDP-ADMIN.example.com"} {
		if CanonicalHost(h) != c.AdminHost() {
			t.Errorf("%s: %s != %s", h, CanonicalHost(h), c.AdminHost())
		}
	}
	if CanonicalHost("idp-admin.example.com:9444") == c.AdminHost() || CanonicalHost("evil.example.com") == c.AdminHost() {
		t.Error("foreign host accepted")
	}
}

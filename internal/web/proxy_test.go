package web

import (
	"net/http/httptest"
	"testing"
)

func TestClientIPBehindProxy(t *testing.T) {
	trusted, err := parsePrefixes([]string{"127.0.0.1/32", "::1/128"})
	if err != nil {
		t.Fatal(err)
	}
	s := &Server{behindProxy: true, trusted: trusted}
	for name, tc := range map[string]struct {
		peer, xff, want string
	}{
		// A client that reaches the listener directly cannot choose its
		// address through X-Forwarded-For.
		"untrusted peer, spoofed loopback": {"192.0.2.10:40000", "127.0.0.1", "192.0.2.10"},
		"untrusted peer, spoofed client":   {"192.0.2.10:40000", "203.0.113.5", "192.0.2.10"},
		"trusted proxy":                    {"127.0.0.1:50000", "203.0.113.5", "203.0.113.5"},
		"trusted proxy over IPv6":          {"[::1]:50000", "203.0.113.5", "203.0.113.5"},
		"client-supplied entry is ignored": {"127.0.0.1:50000", "198.51.100.7, 203.0.113.5", "203.0.113.5"},
		"chain of trusted proxies":         {"127.0.0.1:50000", "203.0.113.5, 127.0.0.1", "203.0.113.5"},
		"trusted proxy, no header":         {"127.0.0.1:50000", "", "127.0.0.1"},
		"trusted proxy, malformed entry":   {"127.0.0.1:50000", "not-an-ip", "127.0.0.1"},
	} {
		r := httptest.NewRequest("GET", "https://idp.example.com/login", nil)
		r.RemoteAddr = tc.peer
		if tc.xff != "" {
			r.Header.Set("X-Forwarded-For", tc.xff)
		}
		if got := s.clientIP(r); got != tc.want {
			t.Errorf("%s: clientIP = %q, want %q", name, got, tc.want)
		}
	}
	// Without trusted proxies the header is never believed (config.Validate
	// refuses that combination; this keeps the code safe on its own).
	s = &Server{behindProxy: true}
	r := httptest.NewRequest("GET", "https://idp.example.com/login", nil)
	r.RemoteAddr = "127.0.0.1:50000"
	r.Header.Set("X-Forwarded-For", "203.0.113.5")
	if got := s.clientIP(r); got != "127.0.0.1" {
		t.Fatalf("no trusted proxies: clientIP = %q", got)
	}
}

// A proxy that adds its own X-Forwarded-For line (instead of extending the
// client's) must not let the client's line decide the address.
func TestClientIPMultipleForwardedLines(t *testing.T) {
	trusted, err := parsePrefixes([]string{"127.0.0.1/32"})
	if err != nil {
		t.Fatal(err)
	}
	s := &Server{behindProxy: true, trusted: trusted}
	r := httptest.NewRequest("GET", "https://idp.example.com/login", nil)
	r.RemoteAddr = "127.0.0.1:50000"
	r.Header.Add("X-Forwarded-For", "198.51.100.7")
	r.Header.Add("X-Forwarded-For", "203.0.113.5")
	if got := s.clientIP(r); got != "203.0.113.5" {
		t.Fatalf("clientIP = %q, want the proxy's entry", got)
	}
	r.Header.Del("X-Forwarded-For")
	r.Header.Add("X-Forwarded-For", "198.51.100.7, 192.0.2.1")
	r.Header.Add("X-Forwarded-For", "203.0.113.5, 127.0.0.1")
	if got := s.clientIP(r); got != "203.0.113.5" {
		t.Fatalf("clientIP over a proxy chain = %q", got)
	}
}

// Address rate limits group an IPv6 client by its /64; the audit address
// stays complete.
func TestLimitIPGroupsIPv6(t *testing.T) {
	for ip, want := range map[string]string{
		"2001:db8:1:2::10":          "2001:db8:1:2::/64",
		"2001:db8:1:2:aaaa:bbbb::1": "2001:db8:1:2::/64",
		"203.0.113.5":               "203.0.113.5",
	} {
		rc := &reqCtx{ip: ip}
		if got := rc.limitIP(); got != want {
			t.Errorf("limitIP(%q) = %q, want %q", ip, got, want)
		}
		if rc.ip != ip {
			t.Errorf("rc.ip changed to %q", rc.ip)
		}
	}
}

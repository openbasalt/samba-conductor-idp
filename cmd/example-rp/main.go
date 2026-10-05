// Command example-rp is a minimal OpenID Connect relying party for testing
// conductor-idp: Authorization Code + PKCE with the zitadel/oidc client,
// then it shows the verified ID token claims and the userinfo answer, and
// refreshes once (to exercise rotation). Not for production use.
//
//	EXAMPLE_RP_SECRET=... example-rp -issuer https://idp.example.com \
//	    -client-id cidp_... -ca /path/ca.pem -listen 127.0.0.1:5556
//
// -credentials FILE reads client_id= and client_secret= lines instead;
// -tls-cert and -tls-key serve https (a non-loopback redirect URI must be
// https).
package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"flag"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/zitadel/oidc/v3/pkg/client/rp"
	httphelper "github.com/zitadel/oidc/v3/pkg/http"
	"github.com/zitadel/oidc/v3/pkg/oidc"
)

var page = template.Must(template.New("p").Parse(`<!doctype html><html><head><meta charset="utf-8"><title>example-rp</title></head>
<body><h1 data-e2e="rp-text-title">example-rp: signed in</h1>
<h2>ID token claims</h2><pre data-e2e="rp-text-claims">{{.Claims}}</pre>
<h2>Userinfo</h2><pre data-e2e="rp-text-userinfo">{{.Userinfo}}</pre>
<h2>Refresh</h2><p data-e2e="rp-text-refresh">{{.Refresh}}</p>
<p><a href="{{.Logout}}" data-e2e="rp-link-logout">Sign out (RP-initiated logout)</a></p></body></html>`))

func main() {
	issuer := flag.String("issuer", "", "issuer URL")
	clientID := flag.String("client-id", "", "client_id")
	listen := flag.String("listen", "127.0.0.1:5556", "listen address")
	redirect := flag.String("redirect", "http://localhost:5556/callback", "redirect URI (registered)")
	caFile := flag.String("ca", "", "CA file that signs the idp's certificate")
	scopes := flag.String("scopes", "openid profile email groups offline_access", "scopes")
	credFile := flag.String("credentials", "", "file with client_id= and client_secret= lines")
	tlsCert := flag.String("tls-cert", "", "TLS certificate (serve https)")
	tlsKey := flag.String("tls-key", "", "TLS key")
	flag.Parse()
	secret := os.Getenv("EXAMPLE_RP_SECRET")
	if *credFile != "" {
		raw, err := os.ReadFile(*credFile)
		if err != nil {
			log.Fatal(err)
		}
		for _, l := range strings.Split(string(raw), "\n") {
			k, v, _ := strings.Cut(strings.TrimSpace(l), "=")
			switch k {
			case "client_id":
				*clientID = v
			case "client_secret":
				secret = v
			}
		}
	}
	if *issuer == "" || *clientID == "" {
		log.Fatal("-issuer and -client-id are required")
	}
	httpClient := &http.Client{Timeout: 15 * time.Second}
	if *caFile != "" {
		pem, err := os.ReadFile(*caFile)
		if err != nil {
			log.Fatal(err)
		}
		pool := x509.NewCertPool()
		pool.AppendCertsFromPEM(pem)
		httpClient.Transport = &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}}
	}
	key := []byte(uuid.NewString()[:32])
	cookies := httphelper.NewCookieHandler(key, key, httphelper.WithUnsecure())
	ctx := context.Background()
	provider, err := rp.NewRelyingPartyOIDC(ctx, *issuer, *clientID, secret, *redirect, strings.Fields(*scopes),
		rp.WithPKCE(cookies), rp.WithHTTPClient(httpClient), rp.WithVerifierOpts(rp.WithIssuedAtOffset(5*time.Second)))
	if err != nil {
		log.Fatal(err)
	}
	http.Handle("/login", rp.AuthURLHandler(func() string { return uuid.NewString() }, provider))
	http.Handle("/callback", rp.CodeExchangeHandler(func(w http.ResponseWriter, r *http.Request,
		tokens *oidc.Tokens[*oidc.IDTokenClaims], state string, relying rp.RelyingParty) {
		claims, _ := json.MarshalIndent(tokens.IDTokenClaims, "", "  ")
		info, err := rp.Userinfo[*oidc.UserInfo](r.Context(), tokens.AccessToken, tokens.TokenType, tokens.IDTokenClaims.GetSubject(), relying)
		userinfo := ""
		if err != nil {
			userinfo = "error: " + err.Error()
		} else {
			b, _ := json.MarshalIndent(info, "", "  ")
			userinfo = string(b)
		}
		refresh := "no refresh token"
		if tokens.RefreshToken != "" {
			nt, err := rp.RefreshTokens[*oidc.IDTokenClaims](r.Context(), relying, tokens.RefreshToken, "", "")
			switch {
			case err != nil:
				refresh = "refresh failed: " + err.Error()
			case nt.RefreshToken != "" && nt.RefreshToken != tokens.RefreshToken:
				refresh = "refresh ok, token rotated"
				// The old token is now a reuse: the provider must refuse it.
				if _, err := rp.RefreshTokens[*oidc.IDTokenClaims](r.Context(), relying, tokens.RefreshToken, "", ""); err != nil {
					refresh += "; reuse refused"
				} else {
					refresh += "; REUSE ACCEPTED (bug)"
				}
			default:
				refresh = "refresh ok, token NOT rotated (bug)"
			}
		}
		logout := fmt.Sprintf("%s/end_session?id_token_hint=%s&post_logout_redirect_uri=%s", *issuer, tokens.IDToken,
			strings.TrimSuffix(*redirect, "/callback")+"/bye")
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_ = page.Execute(w, map[string]any{"Claims": string(claims), "Userinfo": userinfo, "Refresh": refresh, "Logout": logout})
	}, provider))
	http.HandleFunc("/bye", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write([]byte(`<!doctype html><p data-e2e="rp-text-bye">example-rp: signed out</p><a href="/login">sign in</a>`))
	})
	http.HandleFunc("/", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write([]byte(`<!doctype html><a href="/login" data-e2e="rp-link-login">Sign in with Samba Conductor</a>`))
	})
	srv := &http.Server{Addr: *listen, ReadHeaderTimeout: 10 * time.Second}
	if *tlsCert != "" {
		log.Printf("example-rp on https://%s", *listen)
		log.Fatal(srv.ListenAndServeTLS(*tlsCert, *tlsKey))
	}
	log.Printf("example-rp on http://%s", *listen)
	log.Fatal(srv.ListenAndServe())
}

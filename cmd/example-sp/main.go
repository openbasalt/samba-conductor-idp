// Command example-sp is a minimal SAML 2.0 service provider for testing
// conductor-idp (crewjam/saml samlsp): it publishes its metadata at
// /saml/metadata (import it in the idp), signs in through the idp and
// shows the NameID and attributes it received. /logout starts a SAML
// single logout (HTTP-Redirect, query-signed with the SP's key) and
// /saml/slo answers the idp's logout messages. Not for production use.
//
//	example-sp -idp-metadata https://idp.example.com/saml/metadata -ca ca.pem \
//	    -url http://localhost:8000 -listen 127.0.0.1:8000
package main

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"flag"
	"fmt"
	"html/template"
	"log"
	"math/big"
	"net/http"
	"net/url"
	"os"
	"sort"
	"time"

	"github.com/crewjam/saml/samlsp"
)

var page = template.Must(template.New("p").Parse(`<!doctype html><html><head><meta charset="utf-8"><title>example-sp</title></head>
<body><h1 data-e2e="sp-text-title">example-sp: signed in</h1>
<p>NameID: <b data-e2e="sp-text-nameid">{{.NameID}}</b></p>
<table border="1" data-e2e="sp-table-attributes">{{range .Attrs}}<tr><td>{{.K}}</td><td data-e2e="sp-attr-{{.K}}">{{.V}}</td></tr>{{end}}</table>
<p><a href="/logout" data-e2e="sp-link-logout">Sign out (single logout)</a></p>
</body></html>`))

var signedOut = []byte(`<!doctype html><html><head><meta charset="utf-8"><title>example-sp</title></head>
<body><h1 data-e2e="sp-text-signed-out">example-sp: signed out</h1></body></html>`)

func main() {
	idpMD := flag.String("idp-metadata", "", "idp metadata URL")
	caFile := flag.String("ca", "", "CA file that signs the idp's certificate")
	root := flag.String("url", "http://localhost:8000", "this SP's base URL")
	listen := flag.String("listen", "127.0.0.1:8000", "listen address")
	flag.Parse()
	client := &http.Client{Timeout: 15 * time.Second}
	if *caFile != "" {
		pem, err := os.ReadFile(*caFile)
		if err != nil {
			log.Fatal(err)
		}
		pool := x509.NewCertPool()
		pool.AppendCertsFromPEM(pem)
		client.Transport = &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}}
	}
	mdURL, err := url.Parse(*idpMD)
	if err != nil {
		log.Fatal(err)
	}
	md, err := samlsp.FetchMetadata(context.Background(), client, *mdURL)
	if err != nil {
		log.Fatal(err)
	}
	key, cert := selfSigned()
	rootURL, _ := url.Parse(*root)
	sp, err := samlsp.New(samlsp.Options{URL: *rootURL, Key: key, Certificate: cert, IDPMetadata: md, AllowIDPInitiated: true})
	if err != nil {
		log.Fatal(err)
	}
	http.Handle("/saml/", sp)
	slo := &sloHandler{sp: sp, idpCert: idpSigningCert(md)}
	http.HandleFunc("/saml/slo", slo.serveSLO)
	http.HandleFunc("/logout", slo.logout)
	http.Handle("/", sp.RequireAccount(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s := samlsp.SessionFromContext(r.Context())
		type kv struct{ K, V string }
		var rows []kv
		if sa, ok := s.(samlsp.SessionWithAttributes); ok {
			for k, v := range sa.GetAttributes() {
				rows = append(rows, kv{k, fmt.Sprint(v)})
			}
		}
		sort.Slice(rows, func(i, j int) bool { return rows[i].K < rows[j].K })
		nameID := ""
		if c, ok := s.(samlsp.JWTSessionClaims); ok {
			nameID = c.Subject
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_ = page.Execute(w, map[string]any{"NameID": nameID, "Attrs": rows})
	})))
	log.Printf("example-sp on %s (metadata %s/saml/metadata)", *root, *root)
	srv := &http.Server{Addr: *listen, ReadHeaderTimeout: 10 * time.Second}
	log.Fatal(srv.ListenAndServe())
}

// selfSigned returns a throwaway SP key and certificate.
func selfSigned() (*rsa.PrivateKey, *x509.Certificate) {
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		log.Fatal(err)
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(time.Now().UnixNano()), Subject: pkix.Name{CommonName: "example-sp"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(365 * 24 * time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &k.PublicKey, k)
	if err != nil {
		log.Fatal(err)
	}
	c, _ := x509.ParseCertificate(der)
	return k, c
}

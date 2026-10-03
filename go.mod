module github.com/samba-conductor/conductor-idp

go 1.27.0

// The ad library is local only until the family's GitHub home is decided;
// the family go.work resolves it too.
replace github.com/samba-conductor/ad => ../ad

require (
	github.com/BurntSushi/toml v1.6.0
	github.com/beevik/etree v1.8.1
	github.com/crewjam/saml v0.5.1
	github.com/go-jose/go-jose/v4 v4.1.5
	github.com/go-ldap/ldap/v3 v3.4.14
	github.com/google/uuid v1.6.0
	github.com/russellhaering/goxmldsig v1.6.1
	github.com/samba-conductor/ad v0.0.0
	github.com/zitadel/oidc/v3 v3.51.11
	modernc.org/sqlite v1.60.1
	rsc.io/qr v0.2.0
)

require (
	github.com/Azure/go-ntlmssp v0.1.1 // indirect
	github.com/bmatcuk/doublestar/v4 v4.10.2 // indirect
	github.com/cespare/xxhash/v2 v2.3.0 // indirect
	github.com/dustin/go-humanize v1.0.1 // indirect
	github.com/go-asn1-ber/asn1-ber v1.5.8 // indirect
	github.com/go-chi/chi/v5 v5.3.2 // indirect
	github.com/go-crypt/x v0.4.12 // indirect
	github.com/go-krb5/krb5 v0.1.0 // indirect
	github.com/go-krb5/x v0.3.2 // indirect
	github.com/go-logr/logr v1.4.4 // indirect
	github.com/go-logr/stdr v1.2.2 // indirect
	github.com/golang-jwt/jwt/v4 v4.5.2 // indirect
	github.com/gorilla/securecookie v1.1.2 // indirect
	github.com/jonboulle/clockwork v0.5.0 // indirect
	github.com/mattermost/xml-roundtrip-validator v0.1.0 // indirect
	github.com/mattn/go-isatty v0.0.24 // indirect
	github.com/muhlemmer/gu v0.3.1 // indirect
	github.com/muhlemmer/httpforwarded v0.1.0 // indirect
	github.com/ncruces/go-strftime v1.0.0 // indirect
	github.com/remyoudompheng/bigfft v0.0.0-20230129092748-24d4a6f8daec // indirect
	github.com/rs/cors v1.11.1 // indirect
	github.com/zitadel/schema v1.3.2 // indirect
	go.opentelemetry.io/auto/sdk v1.2.1 // indirect
	go.opentelemetry.io/otel v1.46.0 // indirect
	go.opentelemetry.io/otel/metric v1.46.0 // indirect
	go.opentelemetry.io/otel/trace v1.46.0 // indirect
	golang.org/x/crypto v0.57.0 // indirect
	golang.org/x/net v0.58.0 // indirect
	golang.org/x/oauth2 v0.37.0 // indirect
	golang.org/x/sys v0.48.0 // indirect
	golang.org/x/text v0.42.0 // indirect
	modernc.org/libc v1.77.1 // indirect
	modernc.org/mathutil v1.7.1 // indirect
	modernc.org/memory v1.12.1 // indirect
)

// example-sp is a lab-only SAML service provider (crewjam samlsp) that
// drives conductor-idp in the e2e suite. It is a module of its own so the
// service-provider side of crewjam/saml, which conductor-idp never runs
// (it is an identity provider), stays out of the idp module's build and
// vulnerability gate: see docs/decisions.md D16. It is never packaged.
module github.com/openbasalt/samba-conductor-idp/cmd/example-sp

go 1.27.4

require (
	github.com/beevik/etree v1.8.1
	github.com/crewjam/saml v0.5.1
)

require (
	github.com/golang-jwt/jwt/v4 v4.5.2 // indirect
	github.com/jonboulle/clockwork v0.5.0 // indirect
	github.com/mattermost/xml-roundtrip-validator v0.1.0 // indirect
	github.com/russellhaering/goxmldsig v1.6.1 // indirect
	golang.org/x/crypto v0.57.0 // indirect
)

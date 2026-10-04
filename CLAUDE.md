# conductor-idp: guidelines

OpenID Connect provider and SAML 2.0 IdP backed by Samba AD (Authorization Code + PKCE, groups claim by SID/name, consent, rotating refresh tokens). Decisions: docs/decisions.md; lab: docs/usage-p4.md (own lab, never the shared conductor-lab VMs).

- Read `../CLAUDE.md` (family rules) and [architecture.md](https://github.com/openbasalt/samba-conductor-docs/blob/main/architecture.md).
- Go: `go test ./...`, `go vet ./...`, gofmt, govulncheck. Code comments and docs in English.
- Commit with explicit paths (never `git add -A`).

# conductor-idp — Guidelines

OAuth2 / OpenID Connect provider backed by Samba AD (Authorization Code + PKCE, groups claim by SID/name, consent, rotating refresh tokens); SAML 2.0 later.

- Read `../CLAUDE.md` (family rules) and `../planning/docs/architecture.md`.
- Go: `go test ./...`, `go vet ./...`, gofmt, govulncheck. Code comments and docs in English.
- Commit with explicit paths (never `git add -A`).

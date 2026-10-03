# conductor-idp

OpenID Connect provider and SAML 2.0 identity provider backed by Samba AD.
Part of Samba Conductor v2; design in `../planning/docs/architecture.md`,
spec in `../planning/docs/p4-spec.md`.

Status: **P4 complete** (2026-10-03): OIDC and SAML validated end to end in
an isolated two-DC lab with an independent OIDC client, Grafana and a
crewjam SAML SP, desktop and mobile ([`docs/usage-p4.md`](docs/usage-p4.md)).

| | |
|---|---|
| ![Sign-in](docs/screenshots/desktop/01-login.png) | ![Consent on a phone](docs/screenshots/mobile/03-consent.png) |
| ![Admin: client](docs/screenshots/desktop/10-admin-client.png) | ![SAML SP](docs/screenshots/desktop/17-saml-sp.png) |

## What it does

- **OIDC** (zitadel/oidc v3, OpenID certified, on our own SQLite storage):
  Authorization Code + PKCE S256 only (also for confidential clients),
  discovery narrowed to what is served, JWKS with ES256 keys sealed at rest
  and rotated with an overlap, token, userinfo, revocation, end_session.
  Codes single use (reuse revokes what they issued); opaque access tokens;
  refresh tokens hashed, rotated, reuse revokes the chain; every refresh
  re-checks the account and its groups in AD.
- **SAML 2.0** (crewjam/saml): SP- and IdP-initiated SSO, signed response
  and assertion, optional encryption, metadata, per-SP NameID, attribute
  mapping and allowed groups; SP data only from the admin registry,
  request IDs answered once, staged signing-key rotation.
- **AD**: passwords verified with Kerberos (simple bind fallback when
  configured) and never kept; bind sub-codes handled (expired and
  must-change go to a change page that needs the old password; locked,
  disabled, expired get a clear message); claims and policy read with a
  read-only service account; `sub` = objectGUID; `groups` by name or SID,
  nested.
- **Clients and SPs** registered by administrators: CLI
  (`conductor-idp client|saml …`) and admin pages; exact redirect URIs,
  allowed AD groups by SID, scopes, consent (first-party skip), optional
  mandatory 2FA per client.
- **2FA**: TOTP + recovery codes, mandatory for administrators (enrolled
  through a one-time link), `off/optional/required` for others. Local
  backend now; a client for conductor's verification socket is ready for
  a single 2FA store (docs/decisions.md D4).
- **Security**: no JavaScript at all (CSP `script-src 'none'`, form-action
  limited to the flow's own targets), CSRF tokens + Fetch metadata,
  `__Host-` cookies, rate limits per address and per account, hash-chained
  audit log, systemd sandbox, i18n en + pt-BR, `data-e2e` everywhere.

## Documentation

- [Install and operate](docs/install.md) (config reference: [`idp.toml.example`](idp.toml.example))
- [Decisions](docs/decisions.md)
- [P4 lab run](docs/usage-p4.md) and [screenshots](docs/screenshots/)

## Development

```sh
make check                      # gofmt, vet, staticcheck, govulncheck, go test -race
make build                      # bin/conductor-idp (CGO off, static)
make package                    # dist/: .deb for amd64 and arm64, SBOMs
make lintian                    # Debian 13's lintian on dist/*.deb
scripts/lab-deploy.sh [--snapshot]   # build on server-home, install on the idp lab's dc1
e2e/run-lab.sh [desktop|mobile]      # Playwright suite on server-home
```

| Path | What |
|---|---|
| `cmd/conductor-idp` | `serve`, `client`, `saml`, `keys`, `enroll-link`, `mfa reset`, `audit`, `gen-key`, `check` |
| `cmd/example-rp`, `cmd/example-sp` | test relying parties (OIDC, SAML) for the lab |
| `internal/oidcp` | op storage, keys, provider, claims |
| `internal/samlidp` | SAML IdP on crewjam, SAML keys |
| `internal/web` | pages, flows, admin, middleware, sessions |
| `internal/directory` | AD access through `ad` (user sign-in, service account) |
| `internal/mfa` | local TOTP backend, conductor socket client |
| `internal/store` | SQLite state, migrations, audit chain |
| `internal/registry` | validation of client and SP registrations |
| `deploy/systemd` | unit |
| `e2e`, `scripts/lab` | Playwright suite, lab install |

The module uses `replace github.com/samba-conductor/ad => ../ad` until the
family has a public home.

License: see LICENSE.

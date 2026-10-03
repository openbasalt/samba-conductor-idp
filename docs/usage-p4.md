# P4 lab run (2026-10-02/03)

What was run to validate conductor-idp end to end. No secrets here: they
live only on the lab host in 0600 files under `~/conductor-idplab/state`.

## Lab

A private copy of `planning/lab` (the shared `conductor-lab-*` VMs were not
touched), re-parameterized:

| Item | Value |
|---|---|
| Prefix / network | `conductor-idplab`, libvirt NAT network `conductor-idplab`, bridge `cndidp0`, `10.96.0.0/24` |
| DCs | `conductor-idplab-dc1` 10.96.0.10, `conductor-idplab-dc2` 10.96.0.11 (domain `lab.conductor.test`, same seed as the shared lab) |
| Scripts | `~/conductor-idplab/lab` (copy, `common.sh` patched), `scripts/lab/idp-lab.sh` |
| State | `~/conductor-idplab/state` (SSH key, lab CA, secrets, client secrets) |
| Snapshots | `seeded`, `idp-p4` (seeded + conductor-idp on dc1 + test clients) |
| idp | `https://dc1.lab.conductor.test:9443`, unit `conductor-idp` on dc1 |

```sh
# on the lab host, once: copy planning/lab to ~/conductor-idplab/lab and patch common.sh
# (PREFIX=conductor-idplab, BRIDGE=cndidp0, SUBNET=10.96.0, MACs 52:54:00:96:00:1x,
#  LAB_HOME=~/conductor-idplab/state), then:
~/conductor-idplab/lab/up.sh                      # 2 DCs, seed, snapshot "seeded" (~7 min)
# from the laptop:
scripts/lab-deploy.sh --snapshot                  # build on the lab host, install on dc1, snapshot idp-p4
e2e/run-lab.sh                                    # Playwright desktop + mobile
```

`lab-deploy.sh` output (abridged):

```
created svc-conductor-idp
wrote /etc/conductor-idp/credentials/master-key
active
configuration: ok
master key: ok
service account bind and read: ok
[lab] registering the lab's test clients
[lab] taking snapshot 'idp-p4' of both DCs
[lab] conductor-idp on dc1: https://dc1.lab.conductor.test:9443/
```

## Relying parties in the e2e run

| RP | How | What it proves |
|---|---|---|
| example RP (`cmd/example-rp`) | zitadel `rp` client, PKCE, confidential, third-party | consent, ID token verified by an independent OIDC client, userinfo, refresh rotation, reuse refused, RP-initiated logout |
| Grafana 12.1.1 | unmodified generic OAuth, `use_pkce=true`, client CA = lab CA | a common third-party app signs users in with name/email from the idp |
| example SP (`cmd/example-sp`) | crewjam `samlsp`, metadata imported with `saml add -metadata -`, encryption on | SP-initiated and IdP-initiated SAML, signed + encrypted assertion accepted by an independent SP, attributes |

## Playwright results

```
=== project desktop
  ✓  1 sign-in page in English and Portuguese, no scripts
  ✓  2 example RP: consent, claims with nested groups, refresh rotation, logout
  ✓  3 single sign-on: a second sign-in needs no password, consent is remembered
  ✓  4 a user outside the allowed groups is refused
  ✓  5 refusals: wrong password, locked, disabled, expired account
  ✓  6 expired and must-change passwords go to a change page that needs the old password
  ✓  7 an administrator without 2FA needs the one-time link
  ✓  8 the administrator enrolls TOTP with the link and reaches the admin pages
  ✓  9 a second sign-in asks for the code; an admin page creates a client
  ✓ 10 SP-initiated SAML with an encrypted, signed assertion
  ✓ 11 IdP-initiated SAML from the start page
  ✓ 12 SAML refuses a user outside the allowed groups
  ✓ 13 Grafana signs in through conductor-idp
  13 passed (28.9s)
=== audit chain on dc1 after the desktop run
audit chain intact: 51 rows

=== project mobile (Pixel 7)
  13 passed (45.1s)
=== audit chain on dc1 after the mobile run
audit chain intact: 51 rows
```

Every page is checked for CSP violations (none). The groups claim of
`user0001` contains `Engineering`, `Platform-Team`, `Engineering-Leads`,
`All-Staff` and `Domain Users`: nested membership resolved by the DC and
named with the read-only service account.

## Go tests and gates

`make check` (gofmt, vet, staticcheck, govulncheck, `go test -race`): green.
govulncheck reports no reachable vulnerability (one in
`golang.org/x/crypto/openpgp`, which is not imported).

The `internal/web` suite drives the real HTTP server (httptest TLS, fake
directory) through: discovery narrowing; code flow with consent; ID token
signature against the JWKS; claims; code reuse revoking issued tokens;
refresh rotation and reuse revoking the chain; PKCE missing / plain /
wrong verifier; exact redirect URI; implicit refused; group policy;
prompt none / login / max_age / consent; callback bound to the browser;
revocation (and a foreign client cannot revoke); refresh re-checks the
account; public client; wrong client secret; RP-initiated logout; account
rate limit; CSRF (missing token, cross-site); security headers and
cookies; every page route guarded (anonymous and non-admin); expired
password change; admin enrollment link, TOTP replay refused, recovery code
single use; admin creates/rotates/deletes a client; policy `required`
enrollment; client-required step-up; 2FA backend down fails closed;
language and theme. SAML: SP-initiated (Redirect and POST bindings)
verified by crewjam's own ServiceProvider, request replay refused,
tampered response rejected by the SP, encrypted assertion, unknown SP,
foreign ACS URL, wrong Destination, IdP-initiated, missing NameID value,
staged key rotation.

## OpenID Foundation conformance suite

Not run in P4 (documented gap). The suite is a Java/Maven build plus
MongoDB and needs a browser-automation script for our sign-in form; it is
the next step for P6 (packaging), when a stable public test host exists.
Its "basic" profile checks overlap the Go suite above (PKCE, code reuse,
nonce, prompt/max_age, refresh, discovery); expected gaps: we refuse
requests without PKCE (the basic profile has tests without it, which will
fail by design), `response_mode=form_post` and request objects.

## Screenshots

`docs/screenshots/{desktop,mobile}`: sign-in (en, pt-BR dark), consent, the
example RP's claims, denied, password change, 2FA, admin clients/client/
SAML/keys/audit, SAML continue, the example SP, Grafana. Pages showing a
TOTP secret, recovery codes or a client secret are not committed.

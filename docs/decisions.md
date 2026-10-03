# conductor-idp decisions (P4)

Decisions taken while building P4 (spec: `../planning/docs/p4-spec.md`).
They live here, not in `planning/docs/decisions.md`, while P3 edits that
file; the orchestrator may merge them later.

## D1. Libraries

- OIDC: `github.com/zitadel/oidc/v3` `op` (OpenID certified), v3.51.11, on
  our own storage, the same pattern as `rc-account` (no code shared).
- SAML: `github.com/crewjam/saml` v0.5.1 with `goxmldsig` raised to v1.6.1
  and `etree` to v1.8.1 (newest releases at the time).
- SQLite through `modernc.org/sqlite` (CGO off), like conductor.

## D2. OIDC policy on top of the library

- Authorization Code + PKCE S256 only, for every client (confidential ones
  also authenticate with `client_secret_basic`). `plain`, implicit,
  hybrid, password, client credentials, device, JWT bearer and token
  exchange are not served; `response_mode` is `query` only (the library's
  `form_post` page needs an inline script). Discovery is rewritten to say
  exactly that, and introspection is neither mounted nor advertised.
- ID tokens ES256, 5 minutes; access tokens opaque (the library's
  encrypted `id:subject`, key derived by HKDF from the master key), 10
  minutes; refresh tokens `cidp_rt_…`, SHA-256 stored, 30-day chain, 7-day
  idle, rotated on every use. A rotated token presented again revokes its
  whole chain and the access tokens it minted.
- A code works once. Codes are consumed atomically; a second use returns
  `invalid_grant` and revokes everything the first use issued (tokens from
  a code share the authorization request's chain ID).
- Every token issuance, refresh and userinfo call re-reads the user in AD
  (cache ≤ 30 s) and re-applies the client's policy (enabled, not locked,
  not expired, member of an allowed group by SID). A refresh refused for
  that reason ends the chain.
- Redirect URIs match exactly. Confidential clients: https, or http on a
  loopback host. Public clients are "native": loopback redirects on any
  port (RFC 8252 §7.3) and private-use schemes with a dot are allowed. The
  only exception to exact matching is that loopback-port rule.
- `sub` is the objectGUID (canonical string): stable across renames and
  moves, not the SID (which changes on domain migration). Pairwise
  subjects are not offered yet.
- `email_verified` is true when `mail` is set: AD's `mail` is managed by
  administrators (users cannot write it on themselves, see the `ad` lab
  test of self-writable attributes).
- The `groups` claim comes from tokenGroups (nested, primary group
  included), rendered as sAMAccountNames or SIDs per client, optionally
  limited to a filter of SIDs. Names come from one batched SID lookup.
- Consent: first-party clients skip it; others store the granted scopes
  per user and client; new scopes on a client forget its consents.
- `prompt=none|login|consent|select_account` and `max_age` are honoured;
  `prompt=none` answers `login_required`, `consent_required`,
  `interaction_required` or `access_denied` instead of showing a page.

## D3. Browser binding of authorization and SAML requests

The library's callback (`/authorize/callback?id=…`) releases a code for any
completed request ID. conductor-idp binds each request to the browser that
first continued it (`__Host-idp-browser`, a random cookie, hashed in the
row) and serves the callback only to that browser, so a leaked request ID
is worthless. SAML pending requests are bound the same way.

## D4. Second factor: local backend now, conductor as the source of truth

The spec prefers one source of truth for 2FA. Decision:

- `mfa.backend = "conductor"` is the target when the idp runs on the same
  host as conductor: the idp asks conductor's 2FA store through a local
  Unix socket (`internal/mfa/conductor.go` documents protocol v1:
  `status` and `verify` by user SID, one JSON request per connection, peer
  checked with SO_PEERCRED by conductor, per-user rate limits and audit
  on conductor's side). Enrollment then happens only in conductor.
- `mfa.backend = "local"` (default) keeps TOTP secrets in the idp's
  database, sealed with AES-256-GCM under the master key and bound to the
  user's objectGUID, with hashed single-use recovery codes. It is needed
  when the idp runs elsewhere (it only needs LDAPS/Kerberos), and today,
  because conductor does not serve the socket yet.
- The server side of the socket is **not implemented** (P4 may not change
  conductor); the client and a fake server test exist. Upstream item for
  conductor.
- Policy is conductor's: administrators always (one-time enrollment link
  for an administrator without 2FA, `enroll-link` CLI or admin page);
  others `off`/`optional`/`required`; a client or SAML app can require it
  (step-up for an already signed-in user). Failure of the 2FA backend
  fails closed.
- WebAuthn is not offered: credentials are bound to the RP ID (conductor's
  host name), so they cannot be reused by an idp on another name, and the
  spec keeps pages script-free except for WebAuthn. Deferred.

## D5. Sessions and cookies

- The SSO session is server-side in memory (a restart signs users out of
  the idp, not out of relying parties), idle 60 min, absolute 8 h, new ID
  after the second factor. The idp keeps no user credential: the password
  is verified with a Kerberos AS exchange (or simple bind fallback) and
  forgotten.
- `__Host-idp-session` is SameSite=**Lax**, not Strict: relying parties
  send the browser here through cross-site redirects, and a Strict cookie
  would not come along (every sign-in would ask for the password again).
  Every POST still needs a CSRF token plus same-origin Fetch metadata /
  Origin. The pre-session CSRF cookie is Strict.

## D6. CSP and forms that continue cross-origin

No script on any page (`script-src 'none'`). CSP `form-action` is applied
by browsers to the redirects that follow a form submission, so a sign-in
form that ends in a redirect to the RP would be blocked by `form-action
'self'`. Pages of a flow therefore allow exactly `'self'` plus the origin
of the request's (already validated) redirect URI or the SP's registered
ACS URLs. Because there is no script, the SAML response page needs one
click on "Continue" (no auto-submit). A nonce'd auto-submit script could
be added later if the owner prefers one click less.

## D7. SAML hardening

- SP "metadata" given to crewjam is built from the admin registry only
  (ACS URLs with HTTP-POST binding; encryption certificate only when
  encryption is enabled for that SP). SP metadata is never fetched, and an
  imported metadata document is parsed once into the registration.
- AuthnRequests are accepted unsigned and never signature-checked
  (`WantAuthnRequestsSigned=false`): the idp verifies no XML signature at
  all, so XML signature wrapping has nothing to wrap on our side. What the
  request may influence is limited to choosing among registered ACS URLs
  (crewjam `getACSEndpoint` matches registered endpoints only), and its
  `Destination`, when present, must be our SSO URL. Requests are size
  bounded, round-trip validated (`xml-roundtrip-validator`), DTD-free
  (`encoding/xml`), and a request ID is answered once per SP.
- Responses and assertions are always signed (RSA-SHA256, exclusive C14N,
  RSA 3072 key). Encryption (crewjam: RSA-OAEP + AES-128-CBC) only when
  enabled per SP; the SP-side CBC padding-oracle risk is the SP's to
  avoid, so encryption stays opt-in.
- Assertions: audience = SP entity ID, recipient = ACS, `InResponseTo`,
  validity 5 min with 30 s skew, AuthnInstant = password time. Attributes
  are only the per-SP mapping. The library's `DefaultAssertionMaker` is
  not used (it adds attributes by default).
- An AuthnRequest is validated when it arrives (its age) and again when
  the response is built, as of its arrival time.
- SAML key rotation is staged: a rotation publishes the new certificate
  next to the current one; the current key keeps signing until the
  overlap ends (SPs pin certificates; Google Workspace takes one at a
  time). `-immediate` exists for emergencies.
- Single logout (SLO) is not implemented (deferred).

## D8. Keys and secrets

- Master key: 32 bytes from systemd `LoadCredential=master-key`; seals the
  signing keys (AAD = key ID) and TOTP secrets (AAD = objectGUID), and
  derives the access-token key.
- Service account password: `LoadCredential=ad-password`. The account is a
  plain user (Domain Users only). In the lab it resolves nested group
  membership of other users without extra rights (e2e checks it).
- OIDC keys rotate every 90 days (a check every 10 minutes), the old key
  stays in the JWKS 48 h. Retired keys are deleted.
- The CLI needs these credentials only for `keys rotate`, `check` and
  group-name resolution; it is run through `systemd-run` with the same
  `LoadCredential` lines (docs/install.md).

## D9. Lab

Own lab, as the spec requires: a copy of `planning/lab` on server-home with
prefix `conductor-idplab`, bridge `cndidp0`, subnet **10.96.0.0/24** (the
spec suggested 10.94, but P3's drill network already used 10.94 and P5's
lab 10.95), state in `~/conductor-idplab/state`, two DCs (same domain
name, isolated network). conductor-idp runs on dc1; the test relying
parties (example RP, example SP, Grafana) run in containers on the host.

## Helpers implemented here for upstreaming to `ad`

- Lookup of a user by objectGUID (`directory.UserByGUID`, an
  `EqBytes("objectGUID", …)` search).
- Batched SID → group sAMAccountName resolution (`GroupNames`, OR filter in
  chunks of 50).
- A renewing service-account Kerberos session (re-SignIn 5 min before the
  TGT ends) for long-running services.
- Group membership fallback when tokenGroups is unreadable (in-chain search
  + primary group): the same logic as `conductor/internal/directory`.
- `NormalizeUsername` (also duplicated in conductor).

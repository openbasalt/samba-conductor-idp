# conductor-idp decisions

Design decisions of conductor-idp, with their reasons. The design overview
is [design.md](design.md).

## D1. Libraries

- OIDC: `github.com/zitadel/oidc/v3` `op` (OpenID certified), v3.51.11, on
  our own storage.
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

## D4. Second factor: conductor as the source of truth

- `mfa.backend = "conductor"`: when the idp runs on conductor's host, it
  asks conductor's 2FA store through conductor's local Unix socket
  (protocol version 2 in `idpapi/mfa.go`: `status`, `verify`, `key.begin`,
  `key.finish`, by user SID, one JSON request per connection). conductor
  serves it (conductor-mfa.socket, `[idp] mfa_socket`), checks the peer
  with SO_PEERCRED (only the conductor-idp user), rate limits per user with
  the same limiter as its own sign-in, and audits every verification. Users
  enroll in conductor only.
- The policy is conductor's too: the request carries the user's group SIDs
  (read by the idp's service account) and conductor maps them to its own
  roles, exactly as at its sign-in, to answer whether a second factor is
  required and whether a security key is mandatory
  (`webauthn.admin_required`; TOTP codes are then refused at the source,
  recovery codes stay the emergency path). The idp still requires a second
  factor for its own administrators and for clients and SPs marked
  "require MFA".
- `mfa.backend = "local"` (default) keeps TOTP secrets in the idp's
  database, sealed with AES-256-GCM under the master key and bound to the
  user's objectGUID, with hashed single-use recovery codes. It is needed
  when the idp runs elsewhere (it only needs LDAPS/Kerberos).
- Security keys and passkeys (conductor backend): the IdP's second-factor
  page starts an assertion through conductor (`key.begin` returns the
  options; the ceremony stays in conductor, single use, five minutes,
  bound to the user), runs the WebAuthn script under a per-response CSP
  nonce with Subresource Integrity (the only script of the IdP), and sends
  the result back (`key.finish`; conductor validates it, including the
  origin and the signature counter). Credentials are bound to conductor's
  RP ID, so the IdP's origin must be one of conductor's WebAuthn origins:
  a shared parent domain as RP ID (`conductor.example.com` and
  `idp.example.com` under `example.com`), or WebAuthn related origins,
  which conductor publishes at `/.well-known/webauthn`.
- A failure of the 2FA backend fails closed.

## D5. Sessions and cookies

- The SSO session is server-side in memory (a restart signs users out of
  the idp, not out of relying parties), idle 60 min, absolute 8 h, new ID
  after the second factor. The idp keeps no user credential: the password
  is verified with a Kerberos AS exchange (or simple bind fallback) and
  forgotten.
- `__Host-idp-session` is SameSite=Lax, not Strict: relying parties
  send the browser here through cross-site redirects, and a Strict cookie
  would not come along (every sign-in would ask for the password again).
  Every POST still needs a CSRF token plus same-origin Fetch metadata /
  Origin. The pre-session CSRF cookie is Strict.

## D6. CSP and forms that continue cross-origin

No script on any page (`script-src 'none'`), except the WebAuthn script
on the second-factor page when the user has a security key (conductor
backend, D4): one self-hosted file under a per-response nonce and
Subresource Integrity, with `connect-src 'none'`. CSP `form-action` is applied
by browsers to the redirects that follow a form submission, so a sign-in
form that ends in a redirect to the RP would be blocked by `form-action
'self'`. Pages of a flow therefore allow exactly `'self'` plus the origin
of the request's (already validated) redirect URI or the SP's registered
ACS URLs. Because there is no script, the SAML response page needs one
click on "Continue" (no auto-submit). A nonce'd auto-submit script could
be added later if one click less is preferred.

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
- Single logout: see D11.
- SP metadata imported by URL from conductor's panel is fetched once by
  the idp (https only, also after redirects, at most 1 MiB, 15 s) and only
  prefills the form the administrator reviews; it is never fetched again
  and never trusted at runtime.

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

Own lab, as the spec requires: a copy of the lab tooling on the lab host with
prefix `conductor-idplab`, bridge `cndidp0`, subnet 10.96.0.0/24 (the
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

## D10. Management API for conductor

- conductor's "Single sign-on" section is a client of a local management
  API (`idpapi`, the same design as conductor-sync's `syncapi`): a Unix
  socket handed over by systemd (conductor-idp-api.socket, owned by
  conductor-idp and the conductor group, 0660) or created by the service,
  SO_PEERCRED admitting only the conductor user (the unit runs with
  `PrivateUsers=no` so the peer's UID is visible), one typed, allowlisted,
  strictly decoded request per connection.
- conductor decides who may do what (administrators only, re-checked
  against AD) and requires the password and a fresh second factor before
  any mutation; the idp trusts that decision because only conductor's UID
  can connect, and records every mutation in its own audit chain with the
  acting AD user (`conductor:<user>@<address>`).
- Validation stays in one place: the API uses the same registry as the
  CLI and the idp's own admin pages. conductor previews a draft (claims or
  assertion for a real user) before proposing it, which also validates it.
- Secrets: a confidential client's secret is generated by the idp and
  returned once (create, rotate); conductor shows it once and keeps it
  nowhere. Signing keys never leave the idp; only certificates and key IDs
  do.
- Certificates of an SP left empty in an update keep the registered ones;
  clearing them is explicit.

## D11. SAML single logout

- Endpoint `<issuer>/saml/slo`, HTTP-Redirect and HTTP-POST, advertised in
  the metadata. An SP takes part when its registration has a single logout
  URL and binding (from its metadata, HTTP-Redirect preferred).
- An incoming LogoutRequest is parsed with the same bounds as an
  AuthnRequest (size, round-trip validation, no DTD, age within five
  minutes, `Destination` = the SLO URL). The idp verifies no XML signature
  (D7). A request signed with the HTTP-Redirect query signature (RSA with
  SHA-256 or SHA-512) by the SP's registered signing certificate ends the
  session at once; anything else (unsigned, HTTP-POST) shows a
  confirmation page, as for an OpenID Connect logout without an ID token
  hint, so a forged request cannot sign a user out behind their back.
- The request must name the browser session's own participant (NameID and,
  when given, SessionIndex); otherwise nothing is ended in that browser.
- The session ends first; then every other SP of the session with a single
  logout URL receives a LogoutRequest in turn (query-signed for
  HTTP-Redirect, XML-signed for HTTP-POST, which needs one click without
  script), and finally the initiator gets a LogoutResponse (`Success`, or
  `PartialLogout` when a participant could not be logged out). A logout
  started at the IdP or by an OpenID Connect client (end_session) runs the
  same chain before going to its destination.
- The chain is in memory, bound to the browser that started it (a
  response from another browser neither continues nor consumes it), and
  expires after ten minutes. Participants are recorded per browser
  session at each assertion (entity ID, NameID, SessionIndex).

## D12. Settings edited from conductor

- Session lifetimes (idle, absolute), the local second-factor policy and a
  consent screen note per language are stored in the database (one
  versioned row, optimistic concurrency) and override `idp.toml`, whose
  values stay the defaults. They apply at once, also to running sessions
  (a shorter absolute lifetime ends them sooner, never later).
- With the conductor 2FA backend the local policy is not used; conductor
  shows its own policy instead.

## D13. OpenID Foundation conformance suite

Run locally against a test deployment (the suite's own containers, a local
build of its current sources): plans `oidcc-basic-certification-test-plan`
(discovery, static clients, `client_secret_basic`) and
`oidcc-config-certification-test-plan`. Because conductor-idp requires
PKCE S256 for every client (D2), the suite was patched locally to send a
`code_challenge` in every authorization request and the `code_verifier` at
the token endpoint (two lines in `AbstractOIDCCServerTest`); without that
patch every test except `oidcc-ensure-request-with-valid-pkce-succeeds`
stops at the authorization endpoint, which is the intended behaviour.

Results of the basic plan (35 modules): 20 passed; 7 passed with warnings;
4 need a reviewer's screenshot by design (the error page for an
unregistered redirect URI and for a request object whose redirect URI
differs, and the login page shown again for `prompt=login` and
`max_age=1`: all showed the expected page); 4 skipped (the `address` and
`phone` scopes and request objects are not supported); 1 failed:
`oidcc-server-client-secret-post`, since confidential clients authenticate
with `client_secret_basic` only. The warnings: the ID token carries a
`client_id` claim (added by the library), `acr` is not returned when
`acr_values` is requested, the `claims` request parameter is not supported
(`claims_parameter_supported` is false), and the test user had no value for
some standard claims of the `profile` scope. The config plan fails one
check: OpenID Connect Core makes RS256 mandatory to implement for ID token
signatures, and conductor-idp signs with ES256 only.

Found and fixed by the run: token endpoint answers to a refresh grant had
no `Cache-Control: no-store` (RFC 6749 5.1); every token and userinfo
answer now has it.

Deliberate deviations, kept: PKCE for every client, `client_secret_basic`
only, ES256 only, no request objects, no `claims` parameter. Each of them
narrows what clients can do rather than weakening a check; RS256 (for
clients that cannot verify ES256) and `client_secret_post` are the ones a
certification would need.

## D14. Admin pages on a separate listener (2026-10-05)

The sign-in pages and the OpenID Connect and SAML endpoints have to be
reachable by every user, often from the internet; the admin pages
(`/admin`) only by administrators. `server.admin_listen` separates them.

- Unset: the admin pages stay on the main listener, as before; the service
  logs a line recommending `admin_listen` for a deployment exposed to the
  internet. Existing files keep working unchanged.
- An address: the admin pages move to a second listener of their own,
  meant for an internal network or a VPN. The main listener does not
  register any admin route, so `/admin` and everything below it answer
  exactly like an unknown path (a plain 404, no redirect and nothing that
  names the admin listener), and the public home page no longer links to
  them. The admin listener serves the admin pages and only what an
  administrator needs to reach them: the sign-in, password change,
  second-factor and enrollment pages, sign-out, static files and
  `/healthz`. It serves no OpenID Connect or SAML endpoint, no consent page
  and continues no flow; a user who is not an administrator is refused at
  sign-in there, and the second factor is always required.
- `"off"`: no admin pages anywhere. Clients and SAML service providers are
  then managed with the CLI and through the management API (conductor's
  "Single sign-on" section, D10).
- TLS and proxies follow the main listener's rules: built-in TLS
  (`admin_tls_cert` and `admin_tls_key`, defaulting to the main
  certificate) or `admin_behind_proxy` on a loopback address with its own
  `admin_trusted_proxies`. Address overlaps with `listen` are refused.
- `admin_url` is the admin origin as browsers see it; it is used for
  enrollment links and, when set, the admin listener answers only for its
  host name (421 otherwise), which closes DNS rebinding and keeps the
  admin cookies on one origin. Without it the default is the issuer's host
  name with the admin port; behind a proxy it is required.
- Sessions are separate per listener: each has its own in-memory session
  table and its own cookie names (`__Host-idp-admin-session` and
  `__Host-idp-admin-pre` on the admin listener). Browsers do not isolate
  cookies by port, so the names differ even when both listeners share a
  host name, and a session of one listener presented to the other under
  any name is unknown there. The admin session cookie is SameSite=Strict
  (no relying party ever redirects to the admin listener); the public one
  stays Lax (D5). CSRF tokens, Fetch metadata and `Origin` checks apply on
  both. A second-factor reset from the admin pages ends the user's
  sessions on both listeners.
- Administrator enrollment links: with a separate admin listener, only
  that listener accepts them (the public sign-in form drops the token and
  an administrator without a second factor is refused there), and
  `enroll-link` and the admin pages print links on the admin origin. An
  administrator's second factor is therefore set up only from the internal
  network, and a leaked link plus a phished password is useless from the
  internet. Enrolled administrators still sign in to applications on the
  public listener with their second factor. With the admin pages off, the
  public listener keeps accepting enrollment links, because it is the only
  place where an administrator can enroll with the local second-factor
  backend; with the conductor backend administrators enroll in conductor.
- WebAuthn (conductor backend): security keys are bound to conductor's RP
  ID and conductor checks the origin of every assertion, so the admin
  origin must be one of conductor's WebAuthn origins (under the shared RP
  ID, or in its related origins), as the public origin already is (D4).
  Otherwise security keys fail on the admin listener and administrators
  are left with their authenticator app, or only their recovery codes when
  conductor requires a security key for them.

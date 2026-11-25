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
  not expired, member of an allowed group by SID, password not changed
  since the sign-in, D19). A refresh refused for that reason ends the
  chain.
- Redirect URIs match exactly. Confidential clients: https, or http on a
  loopback host. Public clients are "native": loopback redirects on any
  port (RFC 8252 §7.3) and private-use schemes with a dot are allowed. The
  only exception to exact matching is that loopback-port rule.
- `sub` is the objectGUID (canonical string): stable across renames and
  moves, not the SID (which changes on domain migration). Pairwise
  subjects are not offered yet.
- `email` and `email_verified`: see D18 (the address must be unique in
  the directory; `email_verified` is a per-client opt-in).
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
  is verified with Kerberos (or simple bind fallback, see D17) and
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

## D15. Branding of the user-facing pages (2026-10-05)

The sign-in, second-factor, enrollment, consent, logout and error pages
carry the organization's look; the admin pages and the protocol endpoints
never do.

- Level 1 (organization name, logos for the light and dark themes,
  favicon, sign-in background image, primary and accent colors, texts per
  language, support contact, links) is edited in conductor (Settings >
  Branding) and arrives through the management API: `branding.get` and
  `branding.update`. The update is self-contained: it carries the document
  and every image it references, conductor-idp checks them again (the
  document's rules, each image by content against its description) and
  replaces what it had in one transaction. It keeps the branding in its
  own database, so the pages keep their look when conductor is down or
  restarted, and records conductor's version number. Every update is in
  the audit chain with the acting administrator.
- Protocol versioning: a new operation is additive and keeps protocol
  version 1 (an older conductor-idp answers "not allowlisted", which
  conductor reports as "too old for branding"); changing an existing
  operation's parameters or result bumps it, since both sides decode
  strictly. Existing results were not changed. Version 2 (D23) is the first bump.
- Shared code: the document, its limits and checks, the contrast rules,
  the image checks, the stylesheet generator and the override engine are
  the public `branding` package of this module, used by both programs.
- CSP unchanged. Colors are CSS custom properties in a generated
  same-origin stylesheet (`/branding/theme.css`, versioned by its hash),
  never inline styles; images are served from `/branding/assets/<sha256>`
  with their checked type, `nosniff`, a `default-src 'none'` policy and a
  long cache (the URL is the digest). Only `branding.allowed_origins` can
  widen the policy, and only `img-src` and `font-src` of branded pages.
- Contrast: the primary color colors links and buttons, so it must reach
  4.5:1 on the light background and surface (WCAG AA) or it is refused;
  the dark theme uses a lighter mix that reaches 4.5:1 there; text on
  brand colors is white or black, whichever contrasts more (one of them
  always reaches 4.58:1). An accent color below 3:1 against the header is
  a warning.
- Images: PNG, JPEG and WebP (ICO and PNG for the favicon), identified by
  their magic bytes, dimensions read from the header only, size limits per
  slot (logos 256 KiB, favicon 64 KiB, background 1 MiB). SVG is refused:
  it is a document that can carry scripts and links, and no sanitizer is
  shipped; a raster image covers the need.
- Level 2 (`branding.templates_dir`): files that replace the header, the
  footer and the sign-in box, html/template with auto-escaping. Read at
  startup only. A lint refuses scripts, other documents, `<link>`,
  `<meta>`, `<style>`, inline styles, event handlers, script and data URLs,
  the script nonce, nested definitions and forms that post elsewhere; a
  sample rendering must keep the contract (required fields, actions and
  data-e2e hooks, `alt` on images, images from this origin or an
  allowlisted one). A refused file keeps the built-in partial with a
  warning in the log; an override that fails at runtime on a page's data
  is replaced by the built-in partial for that response. Each override
  records the hash of the built-in body it was written against, and
  `conductor-idp templates check` (and the startup log) reports overrides
  whose built-in partial changed after an upgrade.
- Never on the admin side: the admin listener registers no branding route
  and renders the built-in partials; on a shared listener the admin pages
  do the same. A stored branding that no longer validates is ignored with
  an error in the log (product look): a bad branding must never stop users
  from signing in.
- The consent note stays a setting (D12), edited with the other single
  sign-on settings; conductor's Branding page shows it and links there.

## D16. GO-2026-6909 (crewjam/saml assertion parsing) and the example SP module (2026-11-13)

GO-2026-6909 affects every crewjam/saml release (no fixed version) in the
service-provider side of the library: `ServiceProvider.ParseResponse`,
`ParseXMLResponse`, `ParseXMLArtifactResponse` and `validateAssertion`
panic on a signed assertion without `<saml:Issuer>`, and `Subject.NameID`
is matched in any XML namespace, so a signed assertion can carry a spoofed
NameID.

- conductor-idp is the identity provider. It builds and signs assertions
  and never parses or validates one it receives: no code outside tests
  calls those functions, and the `Subject.NameID` it reads back
  (`samlidp.finish`, for the single logout participant) is the one it has
  just built itself. The messages it does parse from service providers are
  AuthnRequests (D7) and logout messages (D11), which the advisory does
  not cover.
- govulncheck reported the advisory for the idp only because
  `cmd/example-sp`, the lab's test SP built on crewjam `samlsp`, was in the
  same module: its `samlsp.Middleware` is an `http.Handler`, so the call
  graph of the whole module let `http.ServeMux.ServeHTTP` in the idp's
  server reach `ServiceProvider.ParseResponse`. Scanning the idp's own
  packages without the example SP finds no reachable vulnerable symbol.
- `cmd/example-sp` is now a Go module of its own
  (`github.com/openbasalt/samba-conductor-idp/cmd/example-sp`). It is a
  lab tool, never packaged, and talks only to the lab idp. The idp
  module's govulncheck gate stays unchanged and strict (any finding
  fails); `make check` vets, staticchecks and builds the example module
  but does not run govulncheck on it, since it is an SP and does call the
  affected functions. Tests in `internal/web` use `ServiceProvider` as an
  independent SP to check the idp's responses; they parse only responses
  the idp under test produced.
- Revisit when crewjam/saml publishes a fixed release (raise it in both
  modules), or before the idp ever consumes assertions from another
  identity provider (federation or SAML-to-OIDC bridging): that code must
  not use the affected functions while the advisory is open.

## D17. Password verification proves the KDC (2026-11-13)

- An AS exchange alone does not prove a password: Kerberos does not
  authenticate the KDC to the client, so whoever answers in its place (on
  the network path to port 88, or through a forged `_kerberos._tcp` SRV
  record when `domain.dcs` is not set) can encrypt the reply with a key
  derived from the password that was typed. `Authenticate` therefore uses
  `ad.SignInVerified`: the ticket obtains a service ticket for `ldap/<dc>`
  and binds the CA-pinned LDAPS connection with SASL GSSAPI. A forged KDC
  does not know the DC's key, so the DC refuses its ticket. One extra TGS
  exchange and one LDAP bind per sign-in.
- The DC's WhoAmI answer must name the normalized `sAMAccountName` the user
  typed, so the account later read with the service account is the one the
  directory authenticated, not only the one typed. The simple bind fallback
  checks WhoAmI the same way.
- A failed verification matches `ad.ErrKDCNotVerified`: it fails closed,
  never falls back to the simple bind, counts no per-account failure, is
  logged as an error and audited as `signin.failure` with detail
  `kdc answer not verified` (or `identity mismatch`), and the user sees the
  generic directory error, except for an identity mismatch: a DC answered
  there, so the user sees a neutral refusal (`signin.err.refused`, HTTP
  403) that neither points at the network nor gives the reason. A wrong
  password stays `signin.err.invalid`.
- Expired and must-change answers come from the KDC and are unauthenticated
  as well. Forging one only reaches the password change page for the typed
  account, which creates no SSO session. The change itself
  (`ad.ChangePasswordKerberos`) is confirmed with a verified sign-in using
  the new password before the idp reports success, resets the per-account
  counter or audits the change; afterwards the user signs in again through
  the verified path.
- Empty passwords are refused before any network exchange.

## D18. E-mail assertions (2026-11-16)

- AD keeps `mail` unique nowhere, and whoever may write `mail` on any
  object (delegated user administrators, HR provisioning, Account
  Operators) could copy another person's address. At a relying party or
  SP that keys accounts on e-mail (the Google Workspace preset uses an
  e-mail NameID) that is an account takeover across a trust boundary.
- Before an address is asserted, one indexed search with the service
  account looks for every object that holds it in `mail`, in
  `proxyAddresses` (`smtp:`) or as `userPrincipalName` (cached like user
  lookups, 30 s). When any object other than the user holds it:
  - OpenID Connect: the `email` claim (and `email_verified`) is left out
    of the ID token and userinfo, logged and audited as
    `oidc.email_withheld`; the sign-in itself goes on.
  - SAML: an e-mail NameID or attribute fails the response (the NameID
    cannot be left out); the user sees that the address is also set on
    another account, and the audit log records the refusal. The
    management API's previews report it as a refusal reason.
  A directory error fails closed (no claim, no assertion).
- `email_verified` is a per-client setting, off by default (CLI
  `-email-verified`, admin pages). conductor-idp cannot prove that the
  account holder controls the mailbox; only a client whose operator
  decided to trust the directory's `mail` should get `true`. The
  management API carries it from protocol version 2 (D23): conductor's
  client form sets it, off by default.

## D19. Revocation when credentials change (2026-11-16)

- Sessions, authorization requests, refresh chains and access tokens
  record the account's `pwdLastSet` at the password verification. AD
  changes it on every password change or reset and writes 0 for "must
  change at next logon". Any difference afterwards ends them: the browser
  session on its next use of the account (sign-in continuation, consent,
  SAML response, home page, admin role re-check), refresh (the chain is
  revoked and audited), userinfo and the token exchange. Rows written
  before the value was kept compare `pwdLastSet` with the authentication
  time (access tokens: their creation time) instead.
- A revocation (`user_revocations`, one row per account) ends everything
  the account holds at once: refresh and access tokens for every client,
  its consents, authorization requests completed and not redeemed yet,
  and the browsers known to it (D20). Every listener checks the stored
  time on each request with a session, so sessions that started before it
  end on their next request, also when the revocation came from another
  process (CLI or management API) or from the other listener.
- What revokes: a password change through the expired-password page; a
  second-factor reset (admin pages, `mfa reset`); a new enrollment (the
  enrolling session stays, every other one ends: they were made without
  the factor); `user revoke` on the CLI, the admin pages' users tab and
  the management API's `user.revoke` (additive, protocol 1). A
  second-factor change made in conductor (conductor backend) is not seen
  by the idp until conductor calls `user.revoke`.
- An account is never revoked for something it did not do: a failed
  sign-in, a refused second factor or a rate limit change nothing here.

## D20. Failure limits that cannot lock the owner out (2026-11-16)

- Second factor: wrong codes, recovery codes and security keys count per
  account (objectGUID), whatever the session or address
  (`ratelimit.mfa_failures`, default 10, within
  `ratelimit.mfa_window_minutes`, default 60, at most 24 h). Past the
  limit the second factor is refused without being checked until the
  oldest failure leaves the window; the lock is logged and audited
  (`mfa.locked`). A correct password never resets the counter. The
  per-session limit (5, then the sign-in starts over) stays. Only someone
  who already has the password reaches this step, and the lock ends by
  itself; the password sign-in is not affected.
- Password: a browser that completed a password sign-in for an account
  is remembered for it (`known_devices`: the hash of the browser cookie,
  30 days, at most 20 per account). It is judged by a counter of its own
  (account and browser) instead of the account-wide one, so wrong
  passwords typed elsewhere (anyone can type a user name) never lock the
  owner out of the browser they use. Any other browser follows the
  account-wide limit as before; failures from a known browser count there
  too. A revocation forgets the account's browsers.
- Locked, disabled, expired and restricted accounts get the
  wrong-password message: the KDC may report those states before the
  password is proven, and naming them told anyone the state of any
  account. The audit log keeps the reason; the clock-skew message stays.

## D21. Second-factor enrollment needs more than a password (2026-11-16)

- `mfa.enrollment = "link"` (default): a user without a second factor
  sets one up only through a one-time link from an administrator
  (`enroll-link`, admin pages; 24 h, single use, bound to the user), as
  administrators already did. Without one, a sign-in that needs a second
  factor is refused with a message to ask for a link, and the home page
  offers no enrollment. A stolen password (or a forged KDC answer) can no
  longer bind the attacker's authenticator and lock the owner out.
- `"self"`: users who are not administrators may enroll without a link
  right after a password verified within the last ten minutes; an older
  session signs in again first. Administrators keep following
  `admin_enrollment_requires_link`.
- The link is consumed with the enrollment, after a valid code (a wrong
  code keeps it); losing a race with another use of the same link undoes
  the enrollment. Administrator links work on the admin listener only
  (D14); other users' links point at the issuer, and the public sign-in
  form carries a link only when it is valid and not an administrator's.
- With the conductor backend, users enroll in conductor and this setting
  does not apply.

## D22. CORS and logout hints (2026-11-16)

- The library's default CORS policy (any origin, with credentials, on
  every endpoint) is replaced: CORS headers only on the token, userinfo,
  revocation and key set endpoints, for any origin but never with
  credentials; the authorization endpoint, its callback and end_session
  are navigations and get none. Discovery keeps
  `Access-Control-Allow-Origin: *` without credentials.
- `end_session` with an ID token hint signs the browser out at once only
  when the hint's subject is the browser session's user. The library also
  accepts expired hints, so anyone's own old ID token used to sign any
  victim out through a link; a hint for another user now gets the
  confirmation page, like a request without a hint.

## D23. Management protocol version 2: email_verified (2026-11-16)

- `client.create`, `client.update`, `client.get`, `client.list`,
  `client.rotate`, `client.set_enabled` and `client.preview` carry
  `email_verified` in the client input (D18), so conductor's client form
  can set it. Adding a field to existing parameters and results is an
  incompatible change for strict decoders, so the management protocol
  moves to version 2 (D15).
- There is no version negotiation: a request of another version is
  answered with the `version` error, and conductor shows it. conductor and
  conductor-idp are upgraded together, as before; a conductor that still
  speaks version 1 sees conductor-idp as incompatible until it is updated
  too. The 2FA socket protocol (`idpapi/mfa.go`, served by conductor) has
  its own version and does not change.
- An update through the API now sets the value it carries (it no longer
  keeps the stored one); the CLI and the admin pages are unchanged.

# conductor-idp: design

`conductor-idp` is an OpenID Connect provider and a SAML 2.0 identity
provider backed by Samba Active Directory. Applications send users to it;
it verifies the AD password with Kerberos (and forgets it), applies the
second-factor policy, checks that the user belongs to an AD group the
application is allowed for (by SID), asks for consent where needed, and
returns tokens or a signed assertion built from AD attributes. It needs
only LDAPS and Kerberos to a DC, so it may run on the DC's host or
elsewhere. The cross-cutting design is in
[architecture.md](https://github.com/openbasalt/samba-conductor-docs/blob/main/architecture.md#integration-components)
and packaging in
[packaging.md](https://github.com/openbasalt/samba-conductor-docs/blob/main/packaging.md).
The detailed choices and their reasons are in
[decisions.md](decisions.md); this document describes the resulting
behavior.

## Building blocks

- OIDC: `github.com/zitadel/oidc/v3` (`op` package, OpenID certified) on
  conductor-idp's own SQLite storage; conductor-idp narrows what the
  library serves (below).
- SAML: `github.com/crewjam/saml`, with the SP side of the library fed
  only from the administrator's registry.
- AD: the
  [ad library](https://github.com/openbasalt/samba-conductor-ad/blob/main/docs/design.md)
  for sign-in (Kerberos, simple bind fallback when configured) and a
  read-only service account (a plain domain user) for claims, group
  membership and policy checks.
- State: SQLite through a pure-Go driver: clients, SAML service
  providers, sealed signing keys, hashed tokens, consents, local
  second-factor data, the audit log. The SSO session is in memory.

## OpenID Connect

Served endpoints: discovery, JWKS, authorize, token, userinfo, revocation
and end_session. Discovery is rewritten to advertise exactly what is
served.

- Authorization Code with PKCE S256 only, for every client; confidential
  clients also authenticate with `client_secret_basic` (the secret is
  stored hashed and shown once). Implicit, hybrid, password, client
  credentials, device, token exchange, JWT bearer and the `plain` PKCE
  method are not served; introspection is not mounted; `response_mode`
  is `query` only.
- Redirect URIs match exactly. Confidential clients use https (or http on
  a loopback host). Public (native) clients may use loopback redirects on
  any port (RFC 8252) and private-use schemes.
- A code works once. A second use returns `invalid_grant` and revokes
  everything the first use issued.
- Each authorization request is bound to the browser that first
  continued it (a random cookie, stored hashed); the library's callback is
  served only to that browser, so a leaked request ID is worthless.
- `prompt=none|login|consent|select_account` and `max_age` are honoured;
  `prompt=none` answers with the standard error instead of a page.

### Tokens

- ID tokens: ES256, 5 minutes. Access tokens: opaque, 10 minutes.
- Refresh tokens: opaque, stored as SHA-256 hashes, rotated on every use,
  30-day chain, 7-day idle limit. A rotated token presented again revokes
  its whole chain and the access tokens it minted.
- Every token issuance, refresh and userinfo call re-reads the user in AD
  (cached at most 30 s) and re-applies the client's policy: account
  enabled, not locked, not expired, member of an allowed group. A refresh
  refused for that reason ends the chain.

### JWKS rotation

- Signing keys are ES256, sealed at rest with AES-256-GCM under a master
  key from systemd `LoadCredential` (additional data: the key ID).
- Keys rotate every 90 days by default (checked every 10 minutes). The
  previous key stays in the JWKS for an overlap (48 h by default) so
  relying parties can validate tokens it signed; retired keys are deleted.
  `conductor-idp keys rotate` rotates on demand.

### Claims

- `sub` is the AD objectGUID: stable across renames and moves, and not
  the SID, which changes on a domain migration.
- `preferred_username`, `name`, `email` and `email_verified` (true when
  AD `mail` is set, since users cannot write `mail` on themselves).
- `groups` from `tokenGroups` (nested, primary group included), rendered
  as names or SIDs per client, optionally limited to a list of SIDs. Only
  what the client's scopes allow is released.

## SAML 2.0 identity provider

- SP-initiated and IdP-initiated SSO (the latter per SP), HTTP-POST
  binding to registered ACS URLs, metadata endpoint.
- Responses and assertions are always signed (RSA-SHA256, exclusive
  C14N, RSA 3072). Assertion encryption is opt-in per SP.
- Assertions: audience is the SP entity ID, recipient the ACS URL,
  `InResponseTo` set, validity 5 minutes with 30 s skew. Attributes are
  exactly the SP's mapping; the library's default assertion maker (which
  adds attributes) is not used. NameID format and source per SP.
- AuthnRequests are accepted unsigned and never signature-checked, so
  there is no XML signature verification on the IdP side to attack with
  signature wrapping. A request can only choose among registered ACS URLs;
  its `Destination`, when present, must be the IdP's SSO URL. Requests are
  size-bounded, round-trip validated, parsed without DTDs, checked for age
  on arrival and again when answered, and each request ID is answered
  once per SP. Pending requests are bound to the browser as in OIDC.
- SP metadata is never fetched. An imported metadata document is parsed
  once into the registration.
- SAML key rotation is staged: the new certificate is published next to
  the current one and the current key keeps signing until the overlap
  ends, because SPs pin certificates. An immediate rotation exists for
  emergencies.
- Single logout (`<issuer>/saml/slo`): a LogoutRequest signed with the
  HTTP-Redirect query signature by the SP's registered signing
  certificate ends the session; any other request asks the user first.
  The other SPs of the session then receive a signed LogoutRequest in
  turn, and the initiator a LogoutResponse. A logout started at the IdP
  or by an OpenID Connect client runs the same chain.

## Client and SP registration

- Administrators register OIDC clients and SAML SPs from conductor's
  "Single sign-on" section (through the local management API, below),
  through the CLI (`conductor-idp client` and `conductor-idp saml`
  commands) or on the admin pages of conductor-idp itself. Administrators
  are members of the configured admin groups, matched by SID and
  re-checked against AD.
- conductor's section adds guided presets (Google Workspace, Grafana,
  Nextcloud, GitLab, generic OpenID Connect and SAML), metadata import by
  URL, file or text, a preview of the claims or of the assertion for a
  real user, signing keys with certificate download, settings and
  activity per application.
- A client has a kind (confidential or public), redirect and post-logout
  URIs, scopes, the groups claim format and filter, first-party flag and
  an optional mandatory second factor. An SP has its entity ID, ACS URLs,
  NameID format and source, attribute mapping, optional encryption
  certificate, IdP-initiated flag and default relay state.
- Group gating: each client or SP lists the AD groups allowed to use it,
  stored as SIDs (names are resolved at registration). A registration with
  no groups is refused unless "all users" is chosen explicitly. Membership
  is evaluated by SID with nested groups, at sign-in and again at every
  token issuance and refresh.

## Consent

- First-party clients skip the consent screen.
- For other clients, the scopes granted are stored per user and client;
  adding scopes to a client forgets its consents, so users are asked
  again.

## Second factor

- The policy: administrators always need a second factor (an
  administrator without one enrolls through a one-time link from
  `conductor-idp enroll-link` or the admin pages); everyone else follows
  `off`, `optional` or `required`; a client or SP can require it, which
  steps up an already signed-in user.
- Backend `local` (default): TOTP secrets in conductor-idp's database,
  sealed with AES-256-GCM under the master key (additional data: the
  objectGUID), and hashed single-use recovery codes.
- Backend `conductor`: conductor's second factor, through conductor's
  local socket (peer checked by conductor): one enrollment for both
  (authenticator app, recovery codes, security keys and passkeys) and
  conductor's role-based policy. Security keys registered in conductor
  work at the IdP when the IdP's origin is one of conductor's WebAuthn
  origins (a shared parent domain as RP ID, or WebAuthn related origins).
- A failing second-factor backend fails closed.

## Management API

- A local Unix socket (systemd socket activation) that only the conductor
  user may use (SO_PEERCRED): typed, allowlisted operations for clients,
  SPs, metadata import, previews, signing keys, settings, activity and the
  audit log. Every mutation is audited with the AD user conductor acted
  for. A client secret is returned once and stored only as a hash.
- Settings edited there (session lifetimes, the local second-factor
  policy, a consent screen note per language) are stored in the database
  and override the configuration file, whose values remain the defaults.

## Sessions and web hardening

- The SSO session is server-side, in memory (a restart signs users out of
  the IdP, not of relying parties): idle 60 minutes, absolute 8 hours, a
  new ID after the second factor. No user credential is kept.
- `__Host-idp-session` is SameSite=Lax because relying parties send the
  browser through cross-site redirects; every POST still needs a CSRF
  token plus same-origin Fetch metadata or `Origin`. The pre-session CSRF
  cookie is Strict.
- No JavaScript on any page (`script-src 'none'`), except the WebAuthn
  script on the second-factor page (nonce and Subresource Integrity). CSP
  `form-action` is `'self'` plus the origin of the request's validated
  redirect URI or the SP's registered ACS URLs, because browsers apply it
  to the redirects after a form. The SAML response page therefore needs one click.
- Rate limits per address and per account (kept below the domain lockout
  threshold) on sign-in, and per address on the token endpoint.
- AD bind sub-codes are handled as in conductor: expired and must-change
  passwords go to a change page that needs the old password.
- A hash-chained audit log (`conductor-idp audit verify`), a sandboxed
  systemd unit, internationalized pages (English and Brazilian
  Portuguese).

## Secrets

- `master-key` (32 bytes) and `ad-password` (the service account) come
  from systemd `LoadCredential`. The master key seals signing keys and
  TOTP secrets and derives the access-token key.
- CLI commands that need these credentials run through `systemd-run` with
  the same `LoadCredential` lines.

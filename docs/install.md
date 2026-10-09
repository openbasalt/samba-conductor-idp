# Installing conductor-idp (Debian 13 / Ubuntu 26.04)

Basalt OS and Fedora (RPM packages, SELinux): `install-fedora.md`.

conductor-idp needs LDAPS (636) and Kerberos (88) to a DC. It can run on a
DC or on any other host. Install it from the Debian package (recommended;
Ubuntu 24.04 is best effort) or from source. The from-source steps are what
`scripts/lab/remote-install-idp.sh` does in the lab; the package steps are
what the package lab (`lab/pkglab/`) runs.

## 0. The package

Install from the OpenBasalt APT repository (Debian 13, Ubuntu 24.04 and
26.04, amd64). Check that the key's fingerprint is
`3601 7348 42BD 4E48 2D19  DE4A E4EE D5EC A395 B302` (OpenBasalt release
key) before installing it; stop if it differs.

```sh
curl -fsSLo /tmp/openbasalt-release-key.asc https://obpkg.org/keys/openbasalt-release-key.asc
gpg --show-keys --with-fingerprint /tmp/openbasalt-release-key.asc
sudo install -d -m 0755 /etc/apt/keyrings
sudo gpg --dearmor -o /etc/apt/keyrings/openbasalt.gpg /tmp/openbasalt-release-key.asc
sudo chmod 0644 /etc/apt/keyrings/openbasalt.gpg
printf 'Types: deb\nURIs: https://obpkg.org/apt\nSuites: stable\nComponents: main\nSigned-By: /etc/apt/keyrings/openbasalt.gpg\n' |
  sudo tee /etc/apt/sources.list.d/openbasalt.sources
sudo apt update
sudo apt install conductor-idp
```

The same repository carries every Samba Conductor package (`conductor`,
`conductor-idp`, `conductor-sync`, `conductor-backup`, `conductor-files`).
A release `.deb` can also be installed directly
(`sudo apt install ./conductor-idp_<version>_amd64.deb`) after checking it against
the release's signed `SHA256SUMS`.

The package installs `/usr/bin/conductor-idp`, its unit
(`/usr/lib/systemd/system/conductor-idp.service`) and man page, and the
conffile `/etc/conductor-idp/idp.toml` (the example values); it creates the
`conductor-idp` user, `/etc/conductor-idp` (root:conductor-idp 0750) with
`tls/` (0750) and `credentials/` (root 0700), and `/var/lib/conductor-idp`.
It does not enable or start anything. Then: step 1, the certificates of
step 2, steps 3 and 4 (edit the installed `idp.toml`), and `systemctl
enable --now conductor-idp` (step 5). In the CLI alias of step 6 the binary
is `/usr/bin/conductor-idp`.

Samba 4.19 (Ubuntu 24.04, best effort): see the `ldap server require
strong auth` note in conductor's install doc (Requirements); the idp's
Kerberos binds need it too.

## 1. A read-only service account

A plain domain user, member of Domain Users only, password never expires:

```sh
samba-tool user add svc-conductor-idp --random-password   # then set a known password:
samba-tool user setpassword svc-conductor-idp              # prompts; keep it for step 3
samba-tool user setexpiry svc-conductor-idp --noexpiry
```

It only reads users and groups (including tokenGroups and nested
membership); it never writes.

## 2. User, files, binary

From source only (the package does this):

```sh
useradd --system --user-group --home-dir /var/lib/conductor-idp --no-create-home --shell /usr/sbin/nologin conductor-idp
install -m 0755 conductor-idp /usr/local/bin/
install -d -m 0750 -o root -g conductor-idp /etc/conductor-idp /etc/conductor-idp/tls
install -d -m 0700 -o root -g root /etc/conductor-idp/credentials
```

Both ways, the certificates:

```sh
install -m 0644 cert.pem /etc/conductor-idp/tls/cert.pem                    # the idp's TLS certificate
install -m 0640 -o root -g conductor-idp key.pem /etc/conductor-idp/tls/key.pem
install -m 0644 domain-ca.pem /etc/conductor-idp/domain-ca.pem              # CA of the DCs' LDAPS certificates
```

## 3. Secrets (systemd credentials, root only)

```sh
conductor-idp gen-key /etc/conductor-idp/credentials/master-key            # 0600, 32 random bytes (hex)
(umask 077; cat > /etc/conductor-idp/credentials/ad-password)              # paste the service account password, Ctrl-D
```

The master key seals the signing keys and the TOTP secrets: back it up
with the database. Losing it means new signing keys (relying parties
re-fetch the JWKS; SAML SPs need the new certificate) and 2FA re-enrollment.

## 4. Configuration

With the package, edit `/etc/conductor-idp/idp.toml` (already 0640,
root:conductor-idp; an upgrade keeps your edits and puts a newer default
next to it as `idp.toml.dpkg-dist`). From source, copy `idp.toml.example`
to `/etc/conductor-idp/idp.toml` (0640, root:conductor-idp). Set at least `server.issuer`, `domain.realm`,
`domain.ca_file`, `service_account.username`. Every key is documented in
the example; unknown keys are rejected.

The issuer is the public `https://host[:port]` without a path. Relying
parties pin it, and the SAML entity ID is `<issuer>/saml/metadata`.

Behind a reverse proxy: `listen = "127.0.0.1:9080"`, `behind_proxy = true`,
`trusted_proxies = ["127.0.0.1/32", "::1/128"]`; the proxy terminates TLS for
the issuer's host name. `trusted_proxies` is required with `behind_proxy`
(and `admin_trusted_proxies` with `admin_behind_proxy`): rate limits and the
audit log use the client address from the `X-Forwarded-For` header the proxy
adds, and only requests from those addresses are believed.

## 5. Service

```sh
install -m 0644 deploy/systemd/conductor-idp.service /etc/systemd/system/   # source install only
systemctl daemon-reload
systemctl enable --now conductor-idp
```

Package upgrades (`apt upgrade`) restart the service when it is running and
keep the configuration, credentials and database. `apt purge conductor-idp`
deletes `/etc/conductor-idp` (with the master key) and
`/var/lib/conductor-idp`.

The unit runs without capabilities and with `ProtectSystem=strict`; state
in `/var/lib/conductor-idp/idp.db`. To listen on 443 directly, add
`AmbientCapabilities=CAP_NET_BIND_SERVICE` and
`CapabilityBoundingSet=CAP_NET_BIND_SERVICE`, or use a proxy.

## 6. The CLI

Commands that only touch the database run as the service user:

```sh
sudo -u conductor-idp conductor-idp client list
```

Commands that need the master key or the directory (`keys rotate`,
`check`, group names in `client add -group Engineering`, `mfa reset`) get
the same credentials as the service through `systemd-run`:

```sh
alias cidp='sudo systemd-run --quiet --wait --pipe --collect --uid=conductor-idp --gid=conductor-idp \
  -p LoadCredential=master-key:/etc/conductor-idp/credentials/master-key \
  -p LoadCredential=ad-password:/etc/conductor-idp/credentials/ad-password \
  -p StateDirectory=conductor-idp /usr/local/bin/conductor-idp -config /etc/conductor-idp/idp.toml'
cidp check
cidp client add -name Grafana -redirect-uri https://grafana.example.com/login/generic_oauth \
  -scope profile -scope email -scope groups -group Engineering -groups-claim names -first-party
cidp enroll-link -user jsilva.admin        # first administrator: one-time 2FA enrollment link
```

`-metadata -` reads SP metadata from standard input (`curl …/metadata | cidp saml add -metadata - …`).

## 7. First administrator

Administrators (Domain Admins, or `roles.admin_groups`) always need 2FA.
Without an enrollment they can enroll only through a one-time link
(`enroll-link`, valid 24 h). After that, the admin pages are at
`<issuer>/admin`, or on the admin listener when `server.admin_listen` is
set (section 10).

## 8. Managing it from conductor (optional)

conductor's "Single sign-on" section manages clients, SAML service
providers, signing keys, settings and activity through conductor-idp's
local management API, when both run on the same host:

```sh
# idp.toml
[api]
enabled = true
```

```sh
sudo systemctl stop conductor-idp                      # a socket unit does not start while its service runs
sudo systemctl enable --now conductor-idp-api.socket   # /run/conductor-idp/api.sock, conductor-idp:conductor 0660
sudo systemctl start conductor-idp
```

The socket admits only the `conductor` user (`SO_PEERCRED`; the unit runs
with `PrivateUsers=no` for that reason). Then set `[idp] enabled = true` in
`conductor.toml` and restart conductor. Changes made there are confirmed
in conductor with the administrator's password and second factor and
audited by both; conductor-idp's audit log names the actor as
`conductor:<user>@<address>`. Session lifetimes, the local second-factor
policy and the consent screen note edited there are stored in the
database and override `idp.toml` (the file's values become the defaults
shown next to them).

## 9. One second factor with conductor (optional)

On conductor's host, conductor-idp can use conductor's second factor
instead of its own: one enrollment for both (authenticator app, recovery
codes and security keys), and conductor's policy (administrators,
delegated roles, `[mfa] policy`, `webauthn.admin_required`).

```sh
# idp.toml
[mfa]
backend = "conductor"
conductor_socket = "/run/conductor/mfa.sock"
```

On the conductor side (conductor's install doc has the details):
`[idp] mfa_socket = true` in `conductor.toml`, `systemctl enable
conductor-mfa.socket` (owned by conductor, group `conductor-idp`, 0660),
and a drop-in with `PrivateUsers=no` for conductor.service. With this
backend users enroll in conductor only; the idp's own enrollment pages and
`enroll-link` are not used.

Security keys and passkeys registered in conductor work at the IdP when
the IdP's origin is one of conductor's WebAuthn origins: give both a
common parent domain as `webauthn.rp_id` (`rp_id = "example.com"`,
`origins = ["https://conductor.example.com:8443",
"https://idp.example.com:9443"]`), or list the IdP's origin in
`webauthn.related_origins` when conductor answers on the RP ID's host
itself. Keys registered before such a change are bound to the old RP ID
and must be registered again.

## 10. Exposing the IdP to the internet

Users and relying parties outside the network need the sign-in pages and
the OpenID Connect and SAML endpoints; nobody outside needs the admin
pages. Serve the admin pages on a listener of their own, on an internal or
VPN address, and expose only the main listener:

```toml
# idp.toml: the main listener behind the reverse proxy that faces the internet
[server]
issuer = "https://idp.example.com"
listen = "127.0.0.1:9080"
behind_proxy = true
trusted_proxies = ["127.0.0.1/32"]
# the admin pages on the VPN address only, with built-in TLS
admin_listen = "10.0.0.5:9444"
admin_tls_cert = "/etc/conductor-idp/tls/admin-cert.pem"
admin_tls_key = "/etc/conductor-idp/tls/admin-key.pem"
admin_url = "https://idp-admin.example.com:9444"
```

With built-in TLS on the main listener instead (`listen = ":9443"` and
`tls_cert`/`tls_key`), bind it to the public address rather than all
addresses when the admin listener uses the same port, and leave out
`admin_tls_cert`/`admin_tls_key` to reuse the main certificate (it must
then also be valid for the host name of `admin_url`). With
`admin_listen = "off"` there are no admin pages at all; clients and SAML
service providers are then managed with the CLI (section 6) or from
conductor (section 8).

What changes:

- The main listener answers 404 for `/admin` and every path below it,
  like any unknown path, and the home page no longer links to the admin
  pages. Put only this listener behind the reverse proxy; never forward
  the admin port.
- The admin listener serves the admin pages and the sign-in pages an
  administrator needs to reach them, nothing else (no OpenID Connect or
  SAML endpoint). Only administrators can sign in there, always with a
  second factor. Its sessions and cookies are its own: signing in on one
  listener does not sign in on the other.
- `server.admin_url` is the address administrators type. When set, the
  admin listener answers only for its host name. Without it the default is
  the issuer's host name with the admin port. Behind a proxy of its own
  (`admin_listen = "127.0.0.1:9081"`, `admin_behind_proxy = true`,
  `admin_trusted_proxies`, which is then required), `admin_url` is required.
- Administrator enrollment links (`cidp enroll-link`, or the admin pages)
  point at `admin_url` and work only there: open them over the VPN. The
  main listener refuses them. With `admin_listen = "off"` they stay on the
  issuer, since there is nowhere else to enroll.
- With the conductor second-factor backend and security keys (section 9),
  add the admin origin to conductor's WebAuthn origins too, or keys will
  not work on the admin listener.
- Allow the admin port only from the VPN or internal network in the host
  firewall. `cidp check` prints where the admin pages are served.

## 11. Branding (optional)

The organization's look (name, logos, colors, texts, support contact,
links) is set in conductor, Settings > Branding, and sent here through the
management API (section 8); nothing to configure on this side. Without
conductor the pages keep the product look.

Template overrides are files on this host:

```sh
install -d -o root -g conductor-idp -m 0750 /etc/conductor-idp/templates
conductor-idp templates list                     # the partials and their contract
conductor-idp templates show signin-box > /etc/conductor-idp/templates/signin-box.html
# edit it, then in idp.toml:  [branding] templates_dir = "/etc/conductor-idp/templates"
conductor-idp templates check                    # also run after every upgrade
systemctl restart conductor-idp
```

The files are read at startup. `templates check` exits with an error when
an override is refused or was written against an older built-in partial.
See [branding.md](branding.md).

## Relying parties

- OIDC discovery: `<issuer>/.well-known/openid-configuration`. Clients must
  use PKCE S256; confidential ones send the secret with HTTP Basic.
- Grafana (`[auth.generic_oauth]`): `use_pkce = true`, `auth_style =
  InHeader`, `scopes = openid profile email groups`,
  `login_attribute_path = preferred_username`, `role_attribute_path =
  contains(groups[*], 'Domain Admins') && 'Admin' || 'Viewer'`, auth/token/
  api URLs `<issuer>/authorize`, `/oauth/token`, `/userinfo`.
- SAML: metadata `<issuer>/saml/metadata`, SSO URL `<issuer>/saml/sso`,
  single logout URL `<issuer>/saml/slo` (HTTP-Redirect and HTTP-POST).
  An SP takes part in single logout when its registration has a single
  logout URL; its LogoutRequests end the session without a confirmation
  only when signed with the HTTP-Redirect query signature by its
  registered signing certificate.
- Google Workspace (or Cloud Identity): register the SP with entity ID
  `google.com/a/<domain>` and ACS `https://www.google.com/a/<domain>/acs`
  for a legacy SSO profile, or the entity ID and ACS URL Google's Admin
  console shows for a SAML SSO profile created there
  (`https://accounts.google.com/samlrp/...`); NameID format emailAddress,
  NameID source `email`. In the Admin console (Security, Authentication,
  SSO with third party IdP): sign-in page URL = the SSO URL, IdP entity ID
  = the metadata URL, sign-out page URL = `<issuer>/logged-out`, and the
  verification certificate from the metadata (conductor's Single sign-on
  section shows these values and downloads the certificate). Google takes
  one certificate at a time: during a staged SAML key rotation, upload the
  new certificate before the switch. Google does not use SAML single
  logout.

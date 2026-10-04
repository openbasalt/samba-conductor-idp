# Installing conductor-idp (Debian 13 / Ubuntu 26.04)

Basalt OS and Fedora (RPM packages, SELinux): `install-fedora.md`.

conductor-idp needs LDAPS (636) and Kerberos (88) to a DC. It can run on a
DC or on any other host. Install it from the Debian package (recommended;
Ubuntu 24.04 is best effort) or from source. The from-source steps are what
`scripts/lab/remote-install-idp.sh` does in the lab; the package steps are
what the package lab (`../planning/lab/pkglab/`) runs.

## 0. The package

The project's APT repository is not published yet; until it is, install the
`.deb` of a release directly (`sudo apt install ./conductor-idp_<version>_amd64.deb`,
after checking it against the release's signed `SHA256SUMS`). Once the
repository is published:

```sh
curl -fsSLo /tmp/samba-conductor.gpg https://apt.openbasalt.org/samba-conductor/samba-conductor-archive-keyring.gpg
gpg --show-keys /tmp/samba-conductor.gpg     # must be 3601734842BD4E482D19DE4AE4EED5ECA395B302 (OpenBasalt release key)
sudo install -m 0644 /tmp/samba-conductor.gpg /usr/share/keyrings/samba-conductor-archive-keyring.gpg
printf 'Types: deb\nURIs: https://apt.openbasalt.org/samba-conductor\nSuites: stable\nComponents: main\nSigned-By: /usr/share/keyrings/samba-conductor-archive-keyring.gpg\n' |
  sudo tee /etc/apt/sources.list.d/samba-conductor.sources
sudo apt update
sudo apt install conductor-idp
```

The package installs `/usr/bin/conductor-idp`, its unit
(`/usr/lib/systemd/system/conductor-idp.service`) and man page, and the
conffile `/etc/conductor-idp/idp.toml` (the example values); it creates the
`conductor-idp` user, `/etc/conductor-idp` (root:conductor-idp 0750) with
`tls/` (0750) and `credentials/` (root 0700), and `/var/lib/conductor-idp`.
**It does not enable or start anything.** Then: step 1, the certificates of
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
`trusted_proxies = ["127.0.0.1/32"]`; the proxy terminates TLS for the
issuer's host name.

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
`<issuer>/admin`.

## Relying parties

- OIDC discovery: `<issuer>/.well-known/openid-configuration`. Clients must
  use PKCE S256; confidential ones send the secret with HTTP Basic.
- Grafana (`[auth.generic_oauth]`): `use_pkce = true`, `auth_style =
  InHeader`, `scopes = openid profile email groups`,
  `login_attribute_path = preferred_username`, `role_attribute_path =
  contains(groups[*], 'Domain Admins') && 'Admin' || 'Viewer'`, auth/token/
  api URLs `<issuer>/authorize`, `/oauth/token`, `/userinfo`.
- SAML: metadata `<issuer>/saml/metadata`, SSO URL `<issuer>/saml/sso`.
  Google Workspace: register the SP with entity ID `google.com` (or
  `google.com/a/<domain>`), ACS `https://www.google.com/a/<domain>/acs`,
  NameID format emailAddress, NameID source `email`; upload the IdP
  certificate from the metadata and set the sign-in URL to the SSO URL.
  Not tested against Google itself in P4.

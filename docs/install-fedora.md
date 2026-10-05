# Installing conductor-idp on Basalt OS / Fedora

conductor-idp on Basalt OS (Fedora 44 based, SELinux enforcing) or
Fedora 44, from the RPM packages, on a domain controller or any host
with LDAPS access to one. The steps are those of `docs/install.md`; this
page lists what differs. The Basalt OS package lab
(see
[testing.md](https://github.com/openbasalt/samba-conductor-docs/blob/main/testing.md)) runs them with
SELinux enforcing, including an OpenID Connect sign-in (authorization code
with PKCE, ID token, userinfo) against Fedora's `samba-dc` (MIT Kerberos).

## 0. The package

```sh
sudo dnf install conductor-idp            # Basalt OS: from basalt-tools
sudo dnf install ./conductor-idp-<version>-1.x86_64.rpm ./conductor-idp-selinux-<version>-1.noarch.rpm
                                          # Fedora, or a release's assets (check SHA256SUMS)
```

`conductor-idp-selinux` comes with it wherever the targeted policy is
installed. The package creates the `conductor-idp` user (sysusers.d) and
owns `/etc/conductor-idp` (root:conductor-idp 0750) with `tls/` (0750) and
`credentials/` (root 0700), `idp.toml` (0640, `%config(noreplace)`) and
`/var/lib/conductor-idp` (0700). Nothing is enabled or started.

## 1. Then

Steps 1 and 3 to 7 of `docs/install.md` are the same (`conductor-idp
gen-key`, the service account password in `credentials/ad-password`, edit
`idp.toml`, `systemctl enable --now conductor-idp`). Open the port:

```sh
sudo firewall-cmd --permanent --add-port=9443/tcp && sudo firewall-cmd --reload
```

With the admin pages on a listener of their own (`server.admin_listen`,
section 10 of `docs/install.md`), open the admin port only to the VPN or
internal network, for example through the `internal` zone:

```sh
sudo firewall-cmd --permanent --zone=internal --add-source=10.0.0.0/24
sudo firewall-cmd --permanent --zone=internal --add-port=9444/tcp && sudo firewall-cmd --reload
```

## SELinux

conductor-idp runs in `conductor_idp_t`: it reads `/etc/conductor-idp`
(`conductor_idp_conf_t`), manages `/var/lib/conductor-idp`
(`conductor_idp_var_lib_t`), listens on its HTTPS port and connects to the
DCs over LDAP/LDAPS and Kerberos. The credentials directory
(`conductor_idp_cred_t`) is readable by systemd only.

The default port 9443 is typed `pki_ca_port_t` by the base policy, as are
9444 to 9447 (the policy lets conductor-idp bind them, and any
`http_port_t` port), so an admin listener on 9444 needs no change. Another
port: `sudo semanage port -a -t http_port_t -p tcp <port>`.

CLI commands that touch the database (`conductor-idp client add`, ...) are
best run as the service runs them, so files keep the service's owner and
label:

```sh
sudo systemd-run --quiet --wait --pipe --collect --uid=conductor-idp --gid=conductor-idp \
  -p LoadCredential=master-key:/etc/conductor-idp/credentials/master-key \
  -p StateDirectory=conductor-idp /usr/bin/conductor-idp -config /etc/conductor-idp/idp.toml client list
```

## Upgrade and removal

`dnf upgrade` restarts the service when it runs and keeps an edited
`idp.toml` (the new default lands as `idp.toml.rpmnew`). `dnf remove`
stops and disables it, removes the packaged files and the policy module and
keeps the master key, the service account's password, the TLS files,
`/var/lib/conductor-idp` and the user (relabeled to the system defaults).

# Runs as root on the lab's dc1 (prefixed with planning/lab/remote/lib.sh by
# vm_root_script, which sets DOMAIN, REALM…). Installs conductor-idp as
# docs/install.md describes. Inputs: /root/idp-install (binary, unit,
# certificates) and /root/idp-secrets.env (the service account password).
src=/root/idp-install

# 1. The read-only service account (a plain user, no extra groups). Created
#    with SamDB on the DC; the password comes from the environment, never
#    from a command line.
set -a
# shellcheck disable=SC1091
. /root/idp-secrets.env
set +a
python3 - <<'PY'
import os
from samba.auth import system_session
from samba.param import LoadParm
from samba.samdb import SamDB
lp = LoadParm()
lp.load_default()
samdb = SamDB(url="/var/lib/samba/private/sam.ldb", session_info=system_session(), lp=lp)
sam = "svc-conductor-idp"
res = samdb.search(base=str(samdb.domain_dn()), expression="(sAMAccountName=%s)" % sam, attrs=["dn"])
pw = os.environ["IDP_SVC_PASSWORD"]
if len(res) == 0:
    samdb.newuser(sam, pw, givenname="Conductor", surname="IdP service")
    print("created %s" % sam)
else:
    samdb.setpassword("(sAMAccountName=%s)" % sam, pw, force_change_at_next_login=False)
    print("reset the password of %s" % sam)
# The password must not expire (DONT_EXPIRE_PASSWORD) and the account is
# only for the service: no interactive use is expected.
dn = samdb.search(base=str(samdb.domain_dn()), expression="(sAMAccountName=%s)" % sam, attrs=["userAccountControl"])[0]
uac = int(dn["userAccountControl"][0]) | 0x10000
samdb.modify_ldif("dn: %s\nchangetype: modify\nreplace: userAccountControl\nuserAccountControl: %d\n" % (dn.dn, uac))
PY

# 2. System user, directories, binary, certificates.
getent passwd conductor-idp >/dev/null ||
  useradd --system --user-group --home-dir /var/lib/conductor-idp --no-create-home --shell /usr/sbin/nologin conductor-idp
install -m 0755 "$src/conductor-idp" /usr/local/bin/
install -d -m 0750 -o root -g conductor-idp /etc/conductor-idp /etc/conductor-idp/tls
install -d -m 0700 -o root -g root /etc/conductor-idp/credentials
install -m 0644 "$src/cert.pem" /etc/conductor-idp/tls/cert.pem
install -m 0640 -o root -g conductor-idp "$src/key.pem" /etc/conductor-idp/tls/key.pem
install -m 0644 "$src/ca.pem" /etc/conductor-idp/domain-ca.pem

# 3. Secrets as systemd credentials (root-only files).
[ -f /etc/conductor-idp/credentials/master-key ] || conductor-idp gen-key /etc/conductor-idp/credentials/master-key
(umask 077; printf '%s\n' "$IDP_SVC_PASSWORD" >/etc/conductor-idp/credentials/ad-password)
unset IDP_SVC_PASSWORD
rm -f /root/idp-secrets.env

# 4. Configuration (only once: an upgrade keeps it).
if [ ! -f /etc/conductor-idp/idp.toml ]; then
  cat >/etc/conductor-idp/idp.toml <<TOML
[server]
issuer = "https://dc1.$DOMAIN:9443"
listen = ":9443"
tls_cert = "/etc/conductor-idp/tls/cert.pem"
tls_key = "/etc/conductor-idp/tls/key.pem"

[domain]
realm = "$REALM"
ca_file = "/etc/conductor-idp/domain-ca.pem"
preferred = ["dc1.$DOMAIN"]

[service_account]
username = "svc-conductor-idp"

[mfa]
policy = "optional"

[saml]
enabled = true
TOML
  chmod 0640 /etc/conductor-idp/idp.toml
  chgrp conductor-idp /etc/conductor-idp/idp.toml
fi

# 5. Unit and start (restart on upgrade).
install -m 0644 "$src/conductor-idp.service" /etc/systemd/system/
systemctl daemon-reload
systemctl enable conductor-idp >/dev/null 2>&1
systemctl restart conductor-idp
for _ in $(seq 30); do ss -ltn | grep -q ":9443 " && break; sleep 1; done
systemctl is-active conductor-idp
rm -rf "$src"

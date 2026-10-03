#!/usr/bin/env bash
# conductor-idp's lab, on the lab host: a copy of planning/lab with its own
# prefix (conductor-idplab), bridge (cndidp0), subnet (10.96.0.0/24) and
# state directory (~/conductor-idplab/state), so the shared conductor-lab
# VMs are never touched. See docs/usage-p4.md.
#
#   idp-lab.sh install BUILD_DIR [--snapshot]   install/upgrade conductor-idp on dc1
#   idp-lab.sh clients                          (re)register the lab's test clients
#   idp-lab.sh cli ARGS...                      run conductor-idp ARGS on dc1 as the service user
#
# Run on the lab host with LAB_DIR pointing at the patched lab copy
# (default ~/conductor-idplab/lab).
set -euo pipefail
LAB_COPY="${IDP_LAB_DIR:-$HOME/conductor-idplab/lab}"
# shellcheck disable=SC1091
source "$LAB_COPY/common.sh"
[ "$PREFIX" = "conductor-idplab" ] || die "refusing to run against lab prefix $PREFIX"
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
IDP_SECRETS="$LAB_HOME/idp-secrets.env"
CLIENTS="$LAB_HOME/idp-clients.env"
IDP_SNAPSHOT="${IDP_SNAPSHOT:-idp-p4}"

# run_cli ARGS...: conductor-idp on dc1 as the service user, with the
# systemd credentials the service itself gets (docs/install.md).
run_cli() {
  local q
  q="$(printf '%q ' "$@")"
  vm_ssh dc1 "sudo systemd-run --quiet --wait --pipe --collect --uid=conductor-idp --gid=conductor-idp \
    -p LoadCredential=master-key:/etc/conductor-idp/credentials/master-key \
    -p LoadCredential=ad-password:/etc/conductor-idp/credentials/ad-password \
    -p StateDirectory=conductor-idp /usr/local/bin/conductor-idp -config /etc/conductor-idp/idp.toml $q"
}

issue_cert() {
  local tls="$LAB_HOME/tls"
  [ -f "$tls/idp-dc1.pem" ] && return
  log "issuing the conductor-idp TLS certificate for dc1"
  (umask 077; openssl genrsa -out "$tls/idp-dc1.key" 3072 2>/dev/null)
  openssl req -new -key "$tls/idp-dc1.key" -subj "/CN=dc1.$DOMAIN" -out "$tls/idp-dc1.csr"
  printf '%s\n' "basicConstraints=CA:FALSE" "keyUsage=critical,digitalSignature,keyEncipherment" \
    "extendedKeyUsage=serverAuth" "subjectAltName=DNS:dc1.$DOMAIN,DNS:idp.$DOMAIN,IP:${DC_IP[dc1]}" >"$tls/idp-dc1.ext"
  openssl x509 -req -in "$tls/idp-dc1.csr" -CA "$tls/ca.pem" -CAkey "$tls/ca.key" -CAcreateserial \
    -days 825 -sha256 -extfile "$tls/idp-dc1.ext" -out "$tls/idp-dc1.pem" 2>/dev/null
  rm -f "$tls/idp-dc1.csr" "$tls/idp-dc1.ext"
}

ensure_secrets() {
  if [ ! -s "$IDP_SECRETS" ]; then
    (umask 077; printf 'IDP_SVC_PASSWORD=Svc-%s-9z\n' "$(openssl rand -base64 32 | tr -dc 'A-Za-z0-9' | head -c 28)" >"$IDP_SECRETS")
  fi
  chmod 0600 "$IDP_SECRETS"
}

install_idp() {
  local build="$1"
  for f in conductor-idp conductor-idp.service; do [ -f "$build/$f" ] || die "$build/$f missing"; done
  issue_cert
  ensure_secrets
  wait_ssh dc1
  wait_samba dc1
  local stage opts
  stage="$(mktemp -d)"
  trap 'rm -rf "$stage"' RETURN
  cp "$build/conductor-idp" "$build/conductor-idp.service" "$stage/"
  cp "$LAB_HOME/tls/idp-dc1.pem" "$stage/cert.pem"
  cp "$LAB_HOME/tls/idp-dc1.key" "$stage/key.pem"
  cp "$LAB_HOME/tls/ca.pem" "$stage/ca.pem"
  mapfile -t opts < <(ssh_opts)
  tar -C "$stage" -czf - . | ssh "${opts[@]}" "debian@${DC_IP[dc1]}" \
    'sudo sh -c "umask 077; rm -rf /root/idp-install; mkdir -p /root/idp-install; tar -C /root/idp-install -xzf -"'
  ssh "${opts[@]}" "debian@${DC_IP[dc1]}" 'sudo sh -c "umask 077; cat > /root/idp-secrets.env"' <"$IDP_SECRETS"
  vm_root_script dc1 "$HERE/remote-install-idp.sh" "$DOMAIN" "$REALM" "$NETBIOS" "${DC_IP[dc1]}" "${DC_IP[dc2]}" "$GATEWAY"
  run_cli check
}

register_clients() {
  log "registering the lab's test clients"
  local out rp graf
  run_cli client list | awk 'NR>1 {print $1}' | while read -r id; do run_cli client remove "$id" >/dev/null; done
  out="$(run_cli client add -name "Example RP" -redirect-uri http://localhost:5556/callback \
    -post-logout-uri http://localhost:5556/bye -scope profile -scope email -scope groups -scope offline_access \
    -group Engineering -groups-claim names)"
  rp="$out"
  out="$(run_cli client add -name "Grafana" -redirect-uri http://localhost:3300/login/generic_oauth \
    -scope profile -scope email -scope groups -group Engineering -group "Domain Admins" -groups-claim names -first-party)"
  graf="$out"
  (
    umask 077
    {
      printf 'RP_CLIENT_ID=%s\n' "$(awk '/^client_id:/ {print $2}' <<<"$rp")"
      printf 'RP_CLIENT_SECRET=%s\n' "$(awk '/^client_secret:/ {print $2}' <<<"$rp")"
      printf 'GRAFANA_CLIENT_ID=%s\n' "$(awk '/^client_id:/ {print $2}' <<<"$graf")"
      printf 'GRAFANA_CLIENT_SECRET=%s\n' "$(awk '/^client_secret:/ {print $2}' <<<"$graf")"
    } >"$CLIENTS"
  )
  log "client ids and secrets in $CLIENTS (0600)"
}

snapshot() {
  log "taking snapshot '$IDP_SNAPSHOT' of both DCs (shut down cleanly first)"
  for dc in "${DCS[@]}"; do virsh -q shutdown "$(vm_name "$dc")" || true; done
  for dc in "${DCS[@]}"; do
    for _ in $(seq 1 90); do
      [ "$(virsh domstate "$(vm_name "$dc")")" = "shut off" ] && break
      sleep 2
    done
  done
  for dc in "${DCS[@]}"; do
    name="$(vm_name "$dc")"
    if virsh snapshot-info "$name" "$IDP_SNAPSHOT" >/dev/null 2>&1; then virsh -q snapshot-delete "$name" "$IDP_SNAPSHOT"; fi
    virsh -q snapshot-create-as "$name" "$IDP_SNAPSHOT" "seeded lab + conductor-idp on dc1, $(date -u +%FT%TZ)"
  done
  for dc in "${DCS[@]}"; do virsh -q start "$(vm_name "$dc")"; done
  for dc in "${DCS[@]}"; do wait_ssh "$dc"; wait_samba "$dc"; done
  vm_ssh dc1 'for i in $(seq 60); do ss -ltn | grep -q ":9443 " && exit 0; sleep 1; done; exit 1' || die "conductor-idp not listening"
}

case "${1:-}" in
  install)
    shift
    build="${1:?BUILD_DIR}"
    snap="${2:-}"
    if [ "$snap" = "--snapshot" ]; then "$LAB_COPY/reset.sh" seeded; fi
    install_idp "$build"
    register_clients
    if [ "$snap" = "--snapshot" ]; then snapshot; fi
    log "conductor-idp on dc1: https://dc1.$DOMAIN:9443/"
    ;;
  clients) register_clients ;;
  cli) shift; run_cli "$@" ;;
  *) echo "usage: idp-lab.sh install BUILD_DIR [--snapshot] | clients | cli ARGS..." >&2; exit 2 ;;
esac

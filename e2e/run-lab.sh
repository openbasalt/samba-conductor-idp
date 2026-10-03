#!/usr/bin/env bash
# Run the Playwright suite on server-home against conductor-idp on the idp
# lab's dc1, once per project (desktop, mobile), each on a freshly reset
# lab (snapshot idp-p4, made by scripts/lab-deploy.sh --snapshot).
#
#   e2e/run-lab.sh                    # both projects
#   e2e/run-lab.sh desktop
#   E2E_GREP='SAML' e2e/run-lab.sh desktop
#
# Relying parties run next to the browser on server-home (host network):
# the example RP (:5556), the example SAML SP (:8000) and Grafana (:3300),
# in containers named conductor-idplab-*, removed afterwards. Secrets stay
# on server-home (0600 env files, deleted after the run). After each run
# the audit chain is verified on dc1. Screenshots and the HTML report are
# copied back to e2e/screenshots and e2e/playwright-report.
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."
LAB_HOST="${LAB_HOST:-server-home}"
projects=()
for a in "$@"; do
  case "$a" in
    desktop|mobile) projects+=("$a") ;;
    *) echo "unknown argument $a" >&2; exit 2 ;;
  esac
done
[ ${#projects[@]} -gt 0 ] || projects=(desktop mobile)

rsync -a --delete --exclude node_modules/ --exclude test-results/ --exclude playwright-report/ --exclude screenshots/ --exclude .auth/ \
  e2e/ "$LAB_HOST:conductor-idplab/src/conductor-idp/e2e/"
rsync -a scripts/ "$LAB_HOST:conductor-idplab/src/conductor-idp/scripts/"

rc=0
for p in "${projects[@]}"; do
  echo "=== project $p"
  ssh -o BatchMode=yes "$LAB_HOST" bash -s -- "$p" "$(printf '%q' "${E2E_GREP:-}")" <<'REMOTE' || rc=$?
set -euo pipefail
project="$1" grep="${2:-}"
BASE="$HOME/conductor-idplab"
LAB_HOME="$BASE/state"
E2E="$BASE/src/conductor-idp/e2e"
BUILD="$BASE/build"
IDPLAB="$BASE/src/conductor-idp/scripts/lab/idp-lab.sh"
DC1=10.96.0.10
HOSTMAP="dc1.lab.conductor.test:$DC1"
IMG=mcr.microsoft.com/playwright:v1.62.1-noble
cleanup() {
  docker rm -f conductor-idplab-rp conductor-idplab-sp conductor-idplab-grafana >/dev/null 2>&1 || true
  rm -f "${envf:-}" "${rpenv:-}" "${grafenv:-}"
}
trap cleanup EXIT
cleanup
"$BASE/lab/reset.sh" idp-p4 </dev/null >/dev/null 2>&1
SSH="ssh -n -i $LAB_HOME/id_ed25519 -o BatchMode=yes -o UserKnownHostsFile=$LAB_HOME/known_hosts -o LogLevel=ERROR debian@$DC1"
$SSH 'for i in $(seq 90); do ss -ltn | grep -q ":9443 " && exit 0; sleep 1; done; exit 1'
# The service account check at boot may have run before Samba was up.
sleep 3
link="$("$IDPLAB" cli enroll-link -user lab.admin </dev/null | tail -n 1)"
spki="$(openssl x509 -in "$LAB_HOME/tls/idp-dc1.pem" -pubkey -noout | openssl pkey -pubin -outform der | openssl dgst -sha256 -binary | base64)"
set -a; . "$LAB_HOME/idp-clients.env"; set +a
rpenv="$(mktemp)"; grafenv="$(mktemp)"; envf="$(mktemp)"
chmod 600 "$rpenv" "$grafenv" "$envf"
printf 'EXAMPLE_RP_SECRET=%s\n' "$RP_CLIENT_SECRET" >"$rpenv"
issuer=https://dc1.lab.conductor.test:9443
{
  printf 'GF_SERVER_HTTP_PORT=3300\nGF_SERVER_ROOT_URL=http://localhost:3300\nGF_AUTH_GENERIC_OAUTH_ENABLED=true\n'
  printf 'GF_AUTH_GENERIC_OAUTH_NAME=Samba Conductor\nGF_AUTH_GENERIC_OAUTH_CLIENT_ID=%s\nGF_AUTH_GENERIC_OAUTH_CLIENT_SECRET=%s\n' "$GRAFANA_CLIENT_ID" "$GRAFANA_CLIENT_SECRET"
  printf 'GF_AUTH_GENERIC_OAUTH_SCOPES=openid profile email groups\nGF_AUTH_GENERIC_OAUTH_AUTH_URL=%s/authorize\n' "$issuer"
  printf 'GF_AUTH_GENERIC_OAUTH_TOKEN_URL=%s/oauth/token\nGF_AUTH_GENERIC_OAUTH_API_URL=%s/userinfo\n' "$issuer" "$issuer"
  printf 'GF_AUTH_GENERIC_OAUTH_USE_PKCE=true\nGF_AUTH_GENERIC_OAUTH_AUTH_STYLE=InHeader\nGF_AUTH_GENERIC_OAUTH_TLS_CLIENT_CA=/etc/lab-ca.pem\n'
  printf 'GF_AUTH_GENERIC_OAUTH_LOGIN_ATTRIBUTE_PATH=preferred_username\nGF_AUTH_GENERIC_OAUTH_EMAIL_ATTRIBUTE_PATH=email\n'
  printf "GF_AUTH_GENERIC_OAUTH_ROLE_ATTRIBUTE_PATH=contains(groups[*], 'Domain Admins') && 'Admin' || 'Viewer'\n"
  printf 'GF_AUTH_GENERIC_OAUTH_ALLOW_SIGN_UP=true\nGF_AUTH_SIGNOUT_REDIRECT_URL=%s/logged-out\nGF_ANALYTICS_REPORTING_ENABLED=false\nGF_ANALYTICS_CHECK_FOR_UPDATES=false\n' "$issuer"
} >"$grafenv"
docker run -d --name conductor-idplab-rp --network host --add-host "$HOSTMAP" --security-opt label=disable --env-file "$rpenv" \
  -v "$BUILD:/b:ro" -v "$LAB_HOME/ca.pem:/ca.pem:ro" -u "$(id -u):$(id -g)" "$IMG" \
  /b/example-rp -issuer "$issuer" -client-id "$RP_CLIENT_ID" -ca /ca.pem >/dev/null
docker run -d --name conductor-idplab-sp --network host --add-host "$HOSTMAP" --security-opt label=disable \
  -v "$BUILD:/b:ro" -v "$LAB_HOME/ca.pem:/ca.pem:ro" -u "$(id -u):$(id -g)" "$IMG" \
  /b/example-sp -idp-metadata "$issuer/saml/metadata" -ca /ca.pem >/dev/null
docker run -d --name conductor-idplab-grafana --network host --add-host "$HOSTMAP" --security-opt label=disable \
  --env-file "$grafenv" -v "$LAB_HOME/ca.pem:/etc/lab-ca.pem:ro" grafana/grafana-oss:12.1.1 >/dev/null
for i in $(seq 60); do curl -fsS -o /dev/null http://localhost:8000/saml/metadata && break; sleep 1; done
curl -fsS http://localhost:8000/saml/metadata | "$IDPLAB" cli saml add -metadata - -name "Example SP" \
  -nameid-format urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress -nameid-source email \
  -attr uid=username -attr memberOf=groups -attr mail=email -group Engineering -encrypt -idp-initiated >/dev/null
for i in $(seq 90); do curl -fsS -o /dev/null http://localhost:3300/api/health && break; sleep 1; done
rm -rf "$E2E/.auth" "$E2E/screenshots/$project" "$E2E/test-results"
install -d -m 0700 "$E2E/.auth"
( set -a; . "$LAB_HOME/secrets.env"; set +a
  printf 'E2E_USER_PASSWORD=%s\nE2E_ADMIN_PASSWORD=%s\nE2E_ADMIN_ENROLL_URL=%s\nE2E_CERT_SPKI=%s\n' \
    "$LAB_USER_PASSWORD" "$LAB_TESTADMIN_PASSWORD" "$link" "$spki" >"$envf" )
docker run --rm --network host --add-host "$HOSTMAP" --security-opt label=disable \
  -u "$(id -u):$(id -g)" -e HOME=/tmp -e CI=1 --env-file "$envf" -e E2E_GREP="$grep" -v "$E2E:/work" -w /work "$IMG" </dev/null \
  sh -c 'npm ci --no-audit --no-fund --loglevel=error >/dev/null && npx playwright test --project='"$project"' ${E2E_GREP:+--grep "$E2E_GREP"}' || test_rc=$?
echo "=== audit chain on dc1 after the $project run"
"$IDPLAB" cli audit verify </dev/null
exit "${test_rc:-0}"
REMOTE
  mkdir -p e2e/screenshots "e2e/playwright-report/$p"
  rsync -a "$LAB_HOST:conductor-idplab/src/conductor-idp/e2e/screenshots/" e2e/screenshots/ || true
  rsync -a --delete "$LAB_HOST:conductor-idplab/src/conductor-idp/e2e/playwright-report/" "e2e/playwright-report/$p/" || true
done
exit "$rc"

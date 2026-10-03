#!/usr/bin/env bash
# Build conductor-idp (and the test tools) on the lab host and install it on
# the idp lab's dc1 (scripts/lab/idp-lab.sh).
#
#   scripts/lab-deploy.sh               # build + install/upgrade on dc1
#   scripts/lab-deploy.sh --snapshot    # … from the seeded snapshot, then snapshot idp-p4
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/../.."   # the family directory
LAB_HOST="${LAB_HOST:-server-home}"
VERSION="$(git -C conductor-idp describe --always --dirty 2>/dev/null || echo dev)"
rsync -a --delete --exclude .git/ --exclude /conductor-idp/bin/ --exclude node_modules/ --exclude /conductor-idp/e2e/test-results/ \
  --exclude /conductor-idp/e2e/playwright-report/ ad conductor-idp "$LAB_HOST:conductor-idplab/src/"
# A Go workspace over the two copies (planning/scripts/family-gowork.sh): the
# lab runs the local ad, not the version go.mod pins, and the lab host needs
# no access to the private repositories.
ssh -o BatchMode=yes "$LAB_HOST" "cd conductor-idplab/src && bash -s -- ad conductor-idp" <planning/scripts/family-gowork.sh
ssh -o BatchMode=yes "$LAB_HOST" bash -s -- "$VERSION" "${1:-}" <<'REMOTE'
set -euo pipefail
version="$1" snap="${2:-}"
export GOWORK="$HOME/conductor-idplab/src/go.work" GOTOOLCHAIN=go1.27.0 CGO_ENABLED=0
cd ~/conductor-idplab/src/conductor-idp
out=~/conductor-idplab/build
mkdir -p "$out"
for cmd in conductor-idp example-rp example-sp; do
  go build -trimpath -ldflags "-s -w -X main.version=$version" -o "$out/$cmd" "./cmd/$cmd"
done
cp deploy/systemd/conductor-idp.service "$out/"
scripts/lab/idp-lab.sh install "$out" $snap
REMOTE

#!/bin/bash
# Verifies that the scratch base stays hidden on a host that bind-mounts
# /var/tmp onto /tmp, a common hardening step. There the scratch base is
# also reachable as /tmp/buildcage-<uid>, under a writable path, so covering
# /var/tmp/buildcage-<uid> alone would leave it readable and, in persistent
# mode, writable from the sandbox.
set -uo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/helpers.sh"

: "${BUILDCAGE_LOCAL_IMAGE_REF:?BUILDCAGE_LOCAL_IMAGE_REF must be set to the locally built proxy image}"

ALIAS="/tmp/buildcage-$(id -u)"
WORKDIR=$(mktemp -d)
cleanup() {
  sudo -n umount /var/tmp 2>/dev/null
  sudo -n rm -rf "$ALIAS"
  rm -rf "$WORKDIR"
}
trap cleanup EXIT

sudo -n mount --bind /tmp /var/tmp || {
  echo "  FAIL  could not bind-mount /tmp onto /var/tmp"
  exit 1
}

# 0700, or ensureOwnScratchBase rejects the base as tampered with.
mkdir -p "$ALIAS/sandbox-decoy" && chmod 700 "$ALIAS" "$ALIAS/sandbox-decoy"
echo "buildcage-decoy-secret-$$" >"$ALIAS/sandbox-decoy/secret"

RUN_INPUT=$(cat <<'SANDBOX'
fail=0
ALIAS="/tmp/buildcage-$(id -u)"
ls -la "$ALIAS" 2>&1 || true
if [ -e "$ALIAS/sandbox-decoy" ]; then
  echo "LEAK: the scratch base is visible through $ALIAS"
  fail=1
fi
if [ -n "$(find "$ALIAS" -name run-script.sh 2>/dev/null)" ]; then
  echo "LEAK: this run's bundle is visible through $ALIAS"
  fail=1
fi
if { echo x >"$ALIAS/planted"; } 2>/dev/null; then
  echo "LEAK: the scratch base is writable through $ALIAS"
  fail=1
fi
exit "$fail"
SANDBOX
)

for mode in persistent ephemeral; do
  touch "$WORKDIR/state.env" "$WORKDIR/summary.md"
  GITHUB_WORKSPACE="$WORKDIR" \
  GITHUB_STATE="$WORKDIR/state.env" \
  GITHUB_STEP_SUMMARY="$WORKDIR/summary.md" \
  BUILDCAGE_BUILD_TEST_HOOKS=1 \
  BUILDCAGE_LOCAL_IMAGE_REF="$BUILDCAGE_LOCAL_IMAGE_REF" \
  INPUT_FILESYSTEM_MODE="$mode" \
  INPUT_RUN="$RUN_INPUT" \
    node dist/main.cjs
  check_status "$mode: the scratch base is hidden at its /tmp alias too" "$?" 0
  if [ -e "$ALIAS/planted" ]; then
    fail "$mode: a file planted through the alias reached the host"
    rm -f "$ALIAS/planted"
  fi
done

echo ""
echo "=== Sandbox Scratch-Base Alias Assertions ==="
assert_results

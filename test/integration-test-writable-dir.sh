#!/bin/bash
# Verifies write-through: by driving dist/main.cjs directly, without the real
# action wrapper; see test-e2e.yml's enforcement steps for the one
# case that does exercise the real action. Covers an existing path and a
# missing one (created as the runner and kept, written to or not). `/` on its
# own is checked in integration-test-file-commands.sh.
set -uo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/driver-helpers.sh"

require_local_image

WORKDIR=$(mktemp -d)
# Outside every always-writable path ($GITHUB_WORKSPACE/$HOME/tmp/$RUNNER_TEMP),
# so writing under it proves write-through did something, but runner-owned,
# so the runner can create a missing directory under it.
PARENT=/opt/buildcage-write-through-test
sudo -n mkdir -p "$PARENT"
sudo -n chown "$(id -u):$(id -g)" "$PARENT"
cleanup() {
  sudo -n rm -rf "$PARENT"
  rm -rf "$WORKDIR"
}
trap cleanup EXIT
touch "$WORKDIR/state.env" "$WORKDIR/summary.md"

GITHUB_WORKSPACE="$WORKDIR" \
GITHUB_STATE="$WORKDIR/state.env" \
GITHUB_STEP_SUMMARY="$WORKDIR/summary.md" \
BUILDCAGE_LOCAL_IMAGE_REF="$BUILDCAGE_LOCAL_IMAGE_REF" \
INPUT_WRITE_THROUGH="/opt
${PARENT}/created-kept
${PARENT}/created-empty" \
INPUT_RUN="touch /opt/.buildcage-writable-test
rm -f /opt/.buildcage-writable-test
echo built > ${PARENT}/created-kept/marker" \
  node dist/main.cjs
CODE=$?

echo ""
echo "=== Sandbox write-through: Assertions ==="
echo ""

if [ "$CODE" = "0" ]; then
  pass "listed paths were writable (existing /opt and a created directory)"
else
  fail "a listed path was not writable (exit $CODE)"
fi

if [ -f "${PARENT}/created-kept/marker" ]; then
  pass "a created directory the command wrote to is kept"
else
  fail "${PARENT}/created-kept/marker is missing"
fi

OWNER=$(stat -c '%u:%g' "${PARENT}/created-kept" 2>/dev/null)
if [ "$OWNER" = "$(id -u):$(id -g)" ]; then
  pass "the created directory is the runner's"
else
  fail "expected owner $(id -u):$(id -g) on ${PARENT}/created-kept, got ${OWNER:-<none>}"
fi

if [ -d "${PARENT}/created-empty" ]; then
  pass "a created directory left empty is kept too"
else
  fail "${PARENT}/created-empty was removed after the step"
fi

assert_results

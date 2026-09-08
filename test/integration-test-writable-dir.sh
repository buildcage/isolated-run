#!/bin/bash
# Verifies write_through: by driving dist/main.cjs directly, without the real
# action wrapper -- see test-e2e.yml's test_sandbox_enforcement for the one
# case that does exercise the real action. Covers an existing path, a missing
# one (created with the parent's ownership, then given back only if the
# command left it empty), and the deprecated writable: spelling.
set -uo pipefail

: "${BUILDCAGE_LOCAL_IMAGE_REF:?BUILDCAGE_LOCAL_IMAGE_REF must be set to the locally built proxy image}"

WORKDIR=$(mktemp -d)
# Outside every always-writable path ($GITHUB_WORKSPACE/$HOME/tmp/$RUNNER_TEMP),
# so writing under it proves write_through did something -- but runner-owned,
# so a directory created under it inherits an ownership the sandbox can use.
PARENT=/opt/buildcage-write-through-test
sudo -n mkdir -p "$PARENT"
sudo -n chown "$(id -u):$(id -g)" "$PARENT"
cleanup() {
  sudo -n rm -rf "$PARENT"
  rm -rf "$WORKDIR"
}
trap cleanup EXIT
touch "$WORKDIR/state.env" "$WORKDIR/summary.md"

FAILURES=0

GITHUB_WORKSPACE="$WORKDIR" \
GITHUB_STATE="$WORKDIR/state.env" \
GITHUB_STEP_SUMMARY="$WORKDIR/summary.md" \
BUILDCAGE_BUILD_TEST_HOOKS=1 \
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
echo "=== Sandbox write_through: Assertions ==="
echo ""

if [ "$CODE" = "0" ]; then
  echo "  PASS  listed paths were writable (existing /opt and a created directory)"
else
  echo "  FAIL  a listed path was not writable (exit $CODE)"
  FAILURES=$((FAILURES + 1))
fi

if [ -f "${PARENT}/created-kept/marker" ]; then
  echo "  PASS  a created directory the command wrote to is kept"
else
  echo "  FAIL  ${PARENT}/created-kept/marker is missing"
  FAILURES=$((FAILURES + 1))
fi

OWNER=$(stat -c '%u:%g' "${PARENT}/created-kept" 2>/dev/null)
if [ "$OWNER" = "$(id -u):$(id -g)" ]; then
  echo "  PASS  the created directory inherited its parent's ownership"
else
  echo "  FAIL  expected owner $(id -u):$(id -g) on ${PARENT}/created-kept, got ${OWNER:-<none>}"
  FAILURES=$((FAILURES + 1))
fi

if [ -e "${PARENT}/created-empty" ]; then
  echo "  FAIL  ${PARENT}/created-empty was left behind despite being empty"
  FAILURES=$((FAILURES + 1))
else
  echo "  PASS  a created directory left empty is removed again"
fi

# The pre-rename spelling has to keep working (see resolveWriteThroughInput).
GITHUB_WORKSPACE="$WORKDIR" \
GITHUB_STATE="$WORKDIR/state.env" \
GITHUB_STEP_SUMMARY="$WORKDIR/summary.md" \
BUILDCAGE_BUILD_TEST_HOOKS=1 \
BUILDCAGE_LOCAL_IMAGE_REF="$BUILDCAGE_LOCAL_IMAGE_REF" \
INPUT_WRITABLE="/opt" \
INPUT_RUN="touch /opt/.buildcage-writable-test
rm -f /opt/.buildcage-writable-test" \
  node dist/main.cjs
ALIAS_CODE=$?

if [ "$ALIAS_CODE" = "0" ]; then
  echo "  PASS  the deprecated writable: spelling still works"
else
  echo "  FAIL  writable: no longer works as an alias (exit $ALIAS_CODE)"
  FAILURES=$((FAILURES + 1))
fi

echo ""
if [ "$FAILURES" -gt 0 ]; then
  echo "❌ FAILED: $FAILURES assertion(s) failed"
  exit 1
fi
echo "✅ All assertions passed."
echo ""

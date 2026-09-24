#!/bin/bash
# Verifies the sandbox does not re-expose a writable copy of the whole host
# `/` through the scratch dir's `mount --rbind /` rootfs. That rootfs lives
# under the scratch dir at /var/tmp/buildcage-<uid>/sandbox-*/rootfs; that
# base isn't one of the writable exceptions, so the recursive writable
# rbinds never re-expose it. Drives dist/main.cjs directly, like the other
# run integration tests.
set -uo pipefail

: "${BUILDCAGE_LOCAL_IMAGE_REF:?BUILDCAGE_LOCAL_IMAGE_REF must be set to the locally built proxy image}"

WORKDIR=$(mktemp -d)
WORKDIR2=$(mktemp -d)
trap 'rm -rf "$WORKDIR" "$WORKDIR2"' EXIT
touch "$WORKDIR/state.env" "$WORKDIR/summary.md"

GITHUB_WORKSPACE="$WORKDIR" \
GITHUB_STATE="$WORKDIR/state.env" \
GITHUB_STEP_SUMMARY="$WORKDIR/summary.md" \
BUILDCAGE_BUILD_TEST_HOOKS=1 \
BUILDCAGE_LOCAL_IMAGE_REF="$BUILDCAGE_LOCAL_IMAGE_REF" \
INPUT_RUN='set -e
echo "=== the scratch rootfs must not re-expose host / ==="
escaped=0
for d in /var/tmp/buildcage-$(id -u)/sandbox-*/rootfs; do
  [ -e "$d" ] || continue
  if [ -e "$d/etc" ] || [ -e "$d/bin" ] || [ -e "$d/usr" ]; then
    echo "ESCAPE: host / reachable via $d"
    ls -la "$d" 2>/dev/null
    escaped=1
  fi
  if echo x > "$d/etc/.buildcage-escape-test" 2>/dev/null; then
    echo "ESCAPE: wrote to host / via $d"
    escaped=1
  fi
done
[ "$escaped" = "0" ] || exit 1
echo "OK: no writable host / re-exposure under any scratch rootfs"

echo "=== the real host / stays visible but read-only (nested mounts included) ==="
[ -r /etc/hostname ] || { echo "UNEXPECTED: /etc not readable via normal path"; exit 1; }
if echo x > /etc/.buildcage-escape-etc 2>/dev/null; then
  echo "UNEXPECTED: /etc writable"
  exit 1
fi
echo "OK: /etc readable, read-only"

echo "=== /tmp itself stays host-shared and writable ==="
echo x > /tmp/.buildcage-escape-tmp-test
rm -f /tmp/.buildcage-escape-tmp-test
echo "OK: /tmp writable"
' \
  node dist/main.cjs
CODE=$?

echo ""
echo "=== Sandbox Filesystem-Escape Assertions ==="
echo ""
if [ "$CODE" = "0" ]; then
  echo "  PASS  no writable host / re-exposure; host / stays read-only; /tmp writable"
else
  echo "  FAIL  filesystem-escape assertion check failed (exit $CODE)"
  exit 1
fi
echo ""

# Misconfiguration guard: `write_through: /var/tmp/buildcage-<uid>` (or an
# ancestor of it) would recursively re-expose the sandbox's own rootfs
# read-write, so assertScratchBaseNotWritable in sandbox/paths.ts must
# fail the step closed rather than silently running with that hole open.
touch "$WORKDIR2/state.env" "$WORKDIR2/summary.md"
SCRATCH_BASE="/var/tmp/buildcage-$(id -u)"

GITHUB_WORKSPACE="$WORKDIR2" \
GITHUB_STATE="$WORKDIR2/state.env" \
GITHUB_STEP_SUMMARY="$WORKDIR2/summary.md" \
BUILDCAGE_BUILD_TEST_HOOKS=1 \
BUILDCAGE_LOCAL_IMAGE_REF="$BUILDCAGE_LOCAL_IMAGE_REF" \
INPUT_WRITE_THROUGH="$SCRATCH_BASE" \
INPUT_RUN="true" \
  node dist/main.cjs
GUARD_CODE=$?

echo "=== Sandbox write_through:$SCRATCH_BASE Fail-Closed Assertion ==="
echo ""
if [ "$GUARD_CODE" != "0" ]; then
  echo "  PASS  write_through: $SCRATCH_BASE was rejected (fails closed)"
else
  echo "  FAIL  write_through: $SCRATCH_BASE was accepted (should fail closed, exit 0)"
  exit 1
fi
echo ""

# An earlier step could plant a runner-owned symlink under write_through, so an
# entry through one must fail before the command runs.
WORKDIR3=$(mktemp -d)
TARGET3=$(mktemp -d)
trap 'rm -rf "$WORKDIR" "$WORKDIR2" "$WORKDIR3" "$TARGET3"' EXIT
touch "$WORKDIR3/state.env" "$WORKDIR3/summary.md"
ln -s "$TARGET3" "$WORKDIR3/cache"

LINK_OUTPUT=$(
  GITHUB_WORKSPACE="$WORKDIR3" \
  GITHUB_STATE="$WORKDIR3/state.env" \
  GITHUB_STEP_SUMMARY="$WORKDIR3/summary.md" \
  BUILDCAGE_BUILD_TEST_HOOKS=1 \
  BUILDCAGE_LOCAL_IMAGE_REF="$BUILDCAGE_LOCAL_IMAGE_REF" \
  INPUT_FILESYSTEM_MODE=ephemeral \
  INPUT_WRITE_THROUGH="./cache" \
  INPUT_RUN="echo planted > ./cache/written" \
    node dist/main.cjs 2>&1
)
LINK_CODE=$?
echo "$LINK_OUTPUT"

echo "=== Sandbox write_through: through a runner-owned symlink Fail-Closed Assertion ==="
echo ""
if [ "$LINK_CODE" != "0" ] && echo "$LINK_OUTPUT" | grep -q "a symlink" && [ ! -e "$TARGET3/written" ]; then
  echo "  PASS  write_through: ./cache -> $TARGET3 was rejected before the command ran"
else
  echo "  FAIL  write_through: through a runner-owned symlink was not rejected (exit $LINK_CODE)"
  exit 1
fi
echo ""

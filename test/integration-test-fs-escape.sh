#!/bin/bash
# Verifies that a write-through: entry which would open a way out of the
# sandbox fails the step before the command runs. Drives dist/main.cjs
# directly, like the other run integration tests.
set -uo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/driver-helpers.sh"

require_local_image

WORKDIR=$(mktemp -d)
trap 'rm -rf "$WORKDIR"' EXIT

# Misconfiguration guard: `write-through: /var/tmp/buildcage-<uid>` (or an
# ancestor of it) would recursively re-expose the sandbox's own rootfs
# read-write, so assertScratchBaseNotWritable in sandbox/paths.ts must
# fail the step closed rather than silently running with that hole open.
touch "$WORKDIR/state.env" "$WORKDIR/summary.md"
SCRATCH_BASE="/var/tmp/buildcage-$(id -u)"

GITHUB_WORKSPACE="$WORKDIR" \
GITHUB_STATE="$WORKDIR/state.env" \
GITHUB_STEP_SUMMARY="$WORKDIR/summary.md" \
BUILDCAGE_LOCAL_IMAGE_REF="$BUILDCAGE_LOCAL_IMAGE_REF" \
INPUT_WRITE_THROUGH="$SCRATCH_BASE" \
INPUT_RUN="true" \
  node dist/main.cjs
GUARD_CODE=$?

echo "=== Sandbox write-through:$SCRATCH_BASE Fail-Closed Assertion ==="
echo ""
if [ "$GUARD_CODE" != "0" ]; then
  echo "  PASS  write-through: $SCRATCH_BASE was rejected (fails closed)"
else
  echo "  FAIL  write-through: $SCRATCH_BASE was accepted (should fail closed, exit 0)"
  exit 1
fi
echo ""

# An earlier step could plant a symlink under write-through, so an entry
# through one must fail before the command runs.
LINK_WORKDIR=$(mktemp -d)
LINK_TARGET=$(mktemp -d)
trap 'rm -rf "$WORKDIR" "$LINK_WORKDIR" "$LINK_TARGET"' EXIT
touch "$LINK_WORKDIR/state.env" "$LINK_WORKDIR/summary.md"
ln -s "$LINK_TARGET" "$LINK_WORKDIR/cache"

LINK_OUTPUT=$(
  GITHUB_WORKSPACE="$LINK_WORKDIR" \
  GITHUB_STATE="$LINK_WORKDIR/state.env" \
  GITHUB_STEP_SUMMARY="$LINK_WORKDIR/summary.md" \
  BUILDCAGE_LOCAL_IMAGE_REF="$BUILDCAGE_LOCAL_IMAGE_REF" \
  INPUT_FILESYSTEM_MODE=ephemeral \
  INPUT_WRITE_THROUGH="./cache" \
  INPUT_RUN="echo planted > ./cache/written" \
    node dist/main.cjs 2>&1
)
LINK_CODE=$?
echo "$LINK_OUTPUT"

echo "=== Sandbox write-through: through a symlink Fail-Closed Assertion ==="
echo ""
if [ "$LINK_CODE" != "0" ] && echo "$LINK_OUTPUT" | grep -q "a symlink" && [ ! -e "$LINK_TARGET/written" ]; then
  echo "  PASS  write-through: ./cache -> $LINK_TARGET was rejected before the command ran"
else
  echo "  FAIL  write-through: through a symlink was not rejected (exit $LINK_CODE)"
  exit 1
fi
echo ""

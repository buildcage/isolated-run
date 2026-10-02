#!/bin/bash
# Verifies that a SIGTERM reaching run-isolated.sh's own process while the
# command runs neither replaces the command's exit status nor runs the
# teardown twice, which warned about unmounting the already-unmounted rootfs.
# Drives dist/main.cjs directly, like integration-test-die-with-parent.sh,
# so this script can reach in and signal run-isolated.sh mid-run.
set -uo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/helpers.sh"

: "${BUILDCAGE_LOCAL_IMAGE_REF:?BUILDCAGE_LOCAL_IMAGE_REF must be set to the locally built proxy image}"

WORKDIR=$(mktemp -d)
touch "$WORKDIR/state.env" "$WORKDIR/summary.md"
trap 'rm -rf "$WORKDIR"' EXIT

GITHUB_WORKSPACE="$WORKDIR" \
GITHUB_STATE="$WORKDIR/state.env" \
GITHUB_STEP_SUMMARY="$WORKDIR/summary.md" \
BUILDCAGE_BUILD_TEST_HOOKS=1 \
BUILDCAGE_LOCAL_IMAGE_REF="$BUILDCAGE_LOCAL_IMAGE_REF" \
INPUT_RUN='sleep 4.25; exit 5' \
  node dist/main.cjs > "$WORKDIR/out.log" 2>&1 &
NODE_PID=$!

FOUND=0
for _ in $(seq 1 60); do
  if pgrep -f "sleep 4.25" >/dev/null 2>&1; then
    FOUND=1
    break
  fi
  sleep 0.5
done

echo ""
echo "=== Sandbox signal Assertions ==="
echo ""
if [ "$FOUND" != "1" ]; then
  fail "sandboxed process never started"
  cat "$WORKDIR/out.log"
  wait "$NODE_PID"
  assert_results
fi

# The bash running the script, not sudo, whose argv names it too.
sudo -n kill -TERM "$(pgrep -f "/bin/bash .*/run-isolated.sh")"
wait "$NODE_PID"
CODE=$?

if [ "$CODE" = "5" ]; then
  pass "the command's own exit status survives a SIGTERM to run-isolated.sh"
else
  fail "the step exited $CODE after a SIGTERM to run-isolated.sh, not the command's 5"
  cat "$WORKDIR/out.log"
fi
if grep -q "WARNING: failed to unmount" "$WORKDIR/out.log"; then
  fail "the teardown ran twice and warned about an unmount"
  cat "$WORKDIR/out.log"
else
  pass "the teardown ran once, without an unmount warning"
fi

assert_results

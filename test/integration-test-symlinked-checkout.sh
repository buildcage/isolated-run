#!/bin/bash
# Verifies the action starts when the runner reaches its checkout through a
# symlink, as on a self-hosted runner whose work directory links to another
# disk. Node resolves the symlink in the bundle's own path but not in argv, so
# an entry guard comparing the two as written would skip the step and exit 0.
# The link sits in /var/tmp, where the sandbox cannot write, so the checkout
# is protected at its target rather than refused.
set -uo pipefail

: "${BUILDCAGE_LOCAL_IMAGE_REF:?BUILDCAGE_LOCAL_IMAGE_REF must be set to the locally built proxy image}"

source "$(dirname "$0")/helpers.sh"

WORKDIR=$(mktemp -d)
LINK="/var/tmp/buildcage-test-checkout-$$"
trap 'rm -rf "$WORKDIR" "$LINK"' EXIT
touch "$WORKDIR/state.env" "$WORKDIR/summary.md"
ln -s "$(pwd -P)" "$LINK"

GITHUB_WORKSPACE="$WORKDIR" \
GITHUB_STATE="$WORKDIR/state.env" \
GITHUB_STEP_SUMMARY="$WORKDIR/summary.md" \
BUILDCAGE_BUILD_TEST_HOOKS=1 \
BUILDCAGE_LOCAL_IMAGE_REF="$BUILDCAGE_LOCAL_IMAGE_REF" \
INPUT_RUN='touch "$GITHUB_WORKSPACE/ran"' \
  node "$LINK/dist/main.cjs"
CODE=$?

echo ""
echo "=== Symlinked Checkout Assertions ==="
echo ""
check_status "the step started through the symlinked checkout" "$CODE" 0
if [ -e "$WORKDIR/ran" ]; then
  pass "the command ran"
else
  fail "the command never ran"
fi
assert_results

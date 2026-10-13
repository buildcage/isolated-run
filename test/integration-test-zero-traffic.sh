#!/bin/bash
# A `run:` step that makes no outbound connection at all must still pass in
# restrict mode. Drives dist/main.cjs directly, without the real action
# wrapper; see test-e2e.yml's enforcement steps for the one case
# that does exercise the real action.
set -uo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/helpers.sh"

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

: "${BUILDCAGE_LOCAL_IMAGE_REF:?BUILDCAGE_LOCAL_IMAGE_REF must be set to the locally built proxy image}"

WORKDIR=$(mktemp -d)
trap 'rm -rf "$WORKDIR"' EXIT
touch "$WORKDIR/state.env" "$WORKDIR/summary.md"

GITHUB_WORKSPACE="$WORKDIR" \
GITHUB_STATE="$WORKDIR/state.env" \
GITHUB_STEP_SUMMARY="$WORKDIR/summary.md" \
BUILDCAGE_BUILD_TEST_HOOKS=1 \
BUILDCAGE_LOCAL_IMAGE_REF="$BUILDCAGE_LOCAL_IMAGE_REF" \
INPUT_PROXY_MODE="restrict" \
INPUT_ALLOWED_HTTPS_RULES="" \
INPUT_ALLOWED_HTTP_RULES="" \
INPUT_ALLOWED_IP_RULES="" \
INPUT_FAIL_ON_BLOCKED="true" \
INPUT_RUN="echo no network here; true" \
  node "$REPO_ROOT/dist/main.cjs" > "$WORKDIR/out.log" 2>&1
CODE=$?

echo ""
echo "=== Zero-Traffic Restrict-Mode Assertions ==="
echo ""

if [ "$CODE" = "0" ]; then
  pass "a step with no outbound connections at all succeeds in restrict mode"
else
  fail "a step with no outbound connections failed (exit $CODE) -- see out.log"
fi

# Both annotations the head check can produce: the blocked-connection one and
# the incomplete-log one it is replaced by when the marker is missing. Matched
# on the part that outlives a rewording of what is counted: the check fires on
# absence, where a pattern that quietly stops matching would pass.
if ! grep -Eq "detected by buildcage|logs are incomplete" "$WORKDIR/out.log"; then
  pass "no false-positive blocked or incomplete-log annotation from the head check"
else
  fail "the head check misfired despite the guaranteed startup marker -- see out.log"
fi

if [ -s "$WORKDIR/summary.md" ]; then
  pass "a Job Summary report was still generated"
else
  fail "no Job Summary report was generated"
fi

if [ "$FAILURES" -gt 0 ]; then
  echo "--- out.log ---"
  cat "$WORKDIR/out.log"
fi

assert_results

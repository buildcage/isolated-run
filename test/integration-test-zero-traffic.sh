#!/bin/bash
# A `run:` step that makes no outbound connection at all must still pass in
# restrict mode with fail_on_blocked=true. The report's plausibility check
# treats a completely empty haproxy log as a wholesale-erasure tamper (see
# R-H2), so the universal image emits a guaranteed startup line to keep a
# genuinely silent run from being confused with one -- see
# docker/universal/files/s6-rc.d/haproxy/run and haproxy.ts. Drives
# dist/main.cjs directly, without the real action wrapper -- see
# test-e2e.yml's test_sandbox_enforcement for the one case that does
# exercise the real action.
set -uo pipefail

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

FAILURES=0

if [ "$CODE" = "0" ]; then
  echo "  PASS  a step with no outbound connections at all succeeds in restrict mode"
else
  echo "  FAIL  a step with no outbound connections failed (exit $CODE) -- see out.log"
  FAILURES=$((FAILURES + 1))
fi

if ! grep -q "blocked connection(s) detected" "$WORKDIR/out.log"; then
  echo "  PASS  no false-positive 'blocked connection(s) detected' from the plausibility check"
else
  echo "  FAIL  the plausibility check misfired despite the guaranteed startup marker -- see out.log"
  FAILURES=$((FAILURES + 1))
fi

if [ -s "$WORKDIR/summary.md" ]; then
  echo "  PASS  a Job Summary report was still generated"
else
  echo "  FAIL  no Job Summary report was generated"
  FAILURES=$((FAILURES + 1))
fi

echo ""
if [ "$FAILURES" -gt 0 ]; then
  echo "❌ FAILED: $FAILURES assertion(s) failed"
  echo "--- out.log ---"
  cat "$WORKDIR/out.log"
  exit 1
fi
echo "✅ All assertions passed."
echo ""

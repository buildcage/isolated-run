#!/bin/bash
# Drives dist/main.cjs directly against a real universal-engine proxy
# container and a fixture origin network (compose.test-universal.yaml),
# proving allow/block/wildcard/port/direct-IP/dns-failed/internal-address
# enforcement end-to-end (see test/universal-restrict-scenarios.sh for the
# scenario list itself).
set -uo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
FAILURES=0

: "${BUILDCAGE_LOCAL_IMAGE_REF:?BUILDCAGE_LOCAL_IMAGE_REF must be set to a locally built universal-engine image}"

pass() { echo "  PASS  $1"; }
fail() {
  echo "  FAIL  $1"
  FAILURES=$((FAILURES + 1))
}

echo ""
echo "=== Universal Engine Integration Test (restrict) ==="
echo ""

echo "--- bringing up fixture origin (compose.test-universal.yaml) ---"
cleanup() {
  docker compose -f "$REPO_ROOT/compose.test-universal.yaml" down -v >/dev/null 2>&1 || true
}
trap cleanup EXIT
docker compose -f "$REPO_ROOT/compose.test-universal.yaml" up -d --build --wait

TMPDIR=$(mktemp -d)
touch "$TMPDIR/state.env"
SUMMARY_FILE="$TMPDIR/summary.md"
touch "$SUMMARY_FILE"

echo "--- running the sandboxed step (proxy_engine: universal, restrict mode) ---"
GITHUB_WORKSPACE="$TMPDIR" \
GITHUB_STATE="$TMPDIR/state.env" \
GITHUB_STEP_SUMMARY="$SUMMARY_FILE" \
BUILDCAGE_RUN_DEBUG_SUMMARY_FILE="$SUMMARY_FILE" \
BUILDCAGE_LOCAL_IMAGE_REF="$BUILDCAGE_LOCAL_IMAGE_REF" \
BUILDCAGE_TEST_COMPOSE_FILE="$REPO_ROOT/docker/compose.action.test-universal.yaml" \
EXTERNAL_RESOLVER="10.200.0.53" \
INPUT_PROXY_ENGINE="universal" \
INPUT_PROXY_MODE="restrict" \
INPUT_ALLOWED_HTTPS_RULES="allowed.example.com:443 allowed.example.com:8443 *.wildcard.example.com:443 *.wildcard.example.com:8443" \
INPUT_ALLOWED_HTTP_RULES="allowed.example.com:80 allowed.example.com:8080 *.wildcard.example.com:80 *.wildcard.example.com:8080" \
INPUT_ALLOWED_IP_RULES="" \
INPUT_FAIL_ON_BLOCKED="false" \
INPUT_RUN="bash $REPO_ROOT/test/universal-restrict-scenarios.sh" \
  node "$REPO_ROOT/dist/main.cjs" 2>&1 | tee "$TMPDIR/out.log"
RUN_EXIT=${PIPESTATUS[0]}

echo ""
echo "--- scenario exit code: $RUN_EXIT ---"
if [ "$RUN_EXIT" != "0" ]; then
  fail "one or more in-sandbox scenarios failed (see log above)"
else
  pass "all in-sandbox scenarios passed"
fi

echo ""
echo "--- report assertions (Job Summary) ---"
SUMMARY=$(cat "$SUMMARY_FILE")

assert_summary_contains() {
  local pattern="$1" label="$2"
  if grep -qF -- "$pattern" <<< "$SUMMARY"; then
    pass "$label"
  else
    fail "$label -- not found in report"
  fi
}

assert_summary_contains "| allowed.example.com:443 | HTTPS |" "allowed.example.com:443 recorded as allowed"
assert_summary_contains "| allowed.example.com:80 | HTTP |" "allowed.example.com:80 recorded as allowed"
assert_summary_contains "| sub.wildcard.example.com:443 | HTTPS |" "wildcard-matched name recorded as allowed"
assert_summary_contains "| blocked.example.com:443 | HTTPS | not-allowed |" "blocked.example.com:443 recorded as blocked, reason not-allowed"
assert_summary_contains "| 10.200.0.100:80 | IP | ip-not-allowed |" "direct IP recorded as blocked, reason ip-not-allowed"
assert_summary_contains "| nxdomain.wildcard.example.com:443 | HTTPS | dns-failed |" "unresolvable allowlisted name recorded as dns-failed"
assert_summary_contains "| internal.wildcard.example.com:443 | HTTPS | internal-address |" "SSRF via allowlisted name recorded as blocked, reason internal-address"
assert_summary_contains "| internal.wildcard.example.com:80 | HTTP | internal-address |" "SSRF via allowlisted name (HTTP) recorded as blocked, reason internal-address"

rm -rf "$TMPDIR"

echo ""
if [ "$FAILURES" -gt 0 ]; then
  echo "❌ FAILED: $FAILURES assertion(s) failed"
  exit 1
fi
echo "✅ All assertions passed."
echo ""

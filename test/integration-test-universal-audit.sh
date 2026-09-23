#!/bin/bash
# Audit-mode counterpart to integration-test-universal-restrict.sh: with no
# rules configured, everything must be allowed and recorded, except what fails
# for a reason that has nothing to do with rules: the internal-address guard,
# an unresolvable name, or no name to judge at all.
set -uo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/helpers.sh"

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

: "${BUILDCAGE_LOCAL_IMAGE_REF:?BUILDCAGE_LOCAL_IMAGE_REF must be set to a locally built universal-engine image}"

echo ""
echo "=== Universal Engine Integration Test (audit) ==="
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

echo "--- running the sandboxed step (proxy_engine: universal, audit mode) ---"
GITHUB_WORKSPACE="$TMPDIR" \
GITHUB_STATE="$TMPDIR/state.env" \
GITHUB_STEP_SUMMARY="$SUMMARY_FILE" \
BUILDCAGE_RUN_DEBUG_SUMMARY_FILE="$SUMMARY_FILE" \
BUILDCAGE_LOCAL_IMAGE_REF="$BUILDCAGE_LOCAL_IMAGE_REF" \
BUILDCAGE_TEST_COMPOSE_FILE="$REPO_ROOT/docker/compose.action.test-universal.yaml" \
INPUT_PROXY_ENGINE="universal" \
INPUT_PROXY_MODE="audit" \
INPUT_FAIL_ON_BLOCKED="false" \
INPUT_RUN="bash $REPO_ROOT/test/universal-audit-scenarios.sh" \
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
assert_report_complete

assert_summary_contains "| blocked.example.com:443 | HTTPS |" "any domain recorded as audited"
assert_summary_contains "| 10.200.0.100:80 | IP |" "direct IP recorded as audited (audit passes it through)"
assert_summary_contains "| internal.wildcard.example.com:443 | HTTPS | internal-address |" "internal-address guard stays active in audit mode"
assert_summary_contains "| internal.wildcard.example.com:80 | HTTP | internal-address |" "internal-address guard (HTTP) stays active in audit mode"
assert_summary_contains "| runner.wildcard.example.com:443 | HTTPS | internal-address |" "the runner's own addresses stay guarded in audit mode"
assert_summary_contains "| runner.wildcard.example.com:80 | HTTP | internal-address |" "the runner's own addresses stay guarded (HTTP) in audit mode"
assert_summary_contains "### ⚠️ Failed Connections" "audit tables an unresolvable name apart too"
assert_summary_contains "| nxdomain.wildcard.example.com:443 | HTTPS | dns-failed |" "unresolvable name still recorded as dns-failed"
assert_summary_contains "| HTTPS | missing-sni |" "a TLS ClientHello with no SNI is blocked in audit mode too, reason missing-sni"
assert_summary_contains "| HTTP | missing-host-header |" "an HTTP request with no Host header is blocked in audit mode too, reason missing-host-header"

rm -rf "$TMPDIR"

assert_results

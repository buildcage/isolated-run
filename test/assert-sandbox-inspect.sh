#!/bin/bash
# Verifies the run action's report output for the proxy_engine: inspect e2e
# job (test-e2e.yml's test_sandbox_inspect_enforcement). Reads
# BUILDCAGE_RUN_DEBUG_SUMMARY_FILE for the same reason as assert-sandbox.sh.
set -euo pipefail

echo ""
echo "=== Sandbox Report Assertions (inspect engine) ==="
echo ""

FAILURES=0
SUMMARY=$(cat "$BUILDCAGE_RUN_DEBUG_SUMMARY_FILE")

assert_summary_contains() {
  local pattern="$1"
  local label="$2"
  if grep -qF -- "$pattern" <<< "$SUMMARY"; then
    echo "  PASS  $label"
  else
    echo "  FAIL  $label -- not found in sandbox report"
    FAILURES=$((FAILURES + 1))
  fi
}

assert_summary_contains "example.com:443" "allowed URL-rule host recorded in report"
assert_summary_contains "not-allowed" "the out-of-rule POST recorded with its refusal reason"
assert_summary_contains "neverssl.com:443" "host outside allowed_url_rules recorded as blocked"
assert_summary_contains "TLS github.com:443" "the allow_tls_rules passthrough recorded, never decrypted"

echo ""
if [ "$FAILURES" -gt 0 ]; then
  echo "❌ FAILED: $FAILURES assertion(s) failed"
  exit 1
fi
echo "✅ All assertions passed."
echo ""

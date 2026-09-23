#!/bin/bash
# Verifies the run action's report output for the proxy_engine: inspect e2e
# job (test-e2e.yml's test_sandbox_inspect_enforcement). Reads
# BUILDCAGE_RUN_DEBUG_SUMMARY_FILE for the same reason as assert-sandbox.sh.
set -euo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/helpers.sh"

echo ""
echo "=== Sandbox Report Assertions (inspect engine) ==="
echo ""

SUMMARY=$(cat "$BUILDCAGE_RUN_DEBUG_SUMMARY_FILE")
assert_report_complete

assert_summary_contains "example.com:443" "allowed URL-rule host recorded in report"
assert_summary_contains "not-allowed" "the out-of-rule POST recorded with its refusal reason"
assert_summary_contains "neverssl.com:443" "host outside allowed_url_rules recorded as blocked"
assert_summary_contains "TLS github.com:443" "the allowed_tls_rules passthrough recorded, never decrypted"

assert_results

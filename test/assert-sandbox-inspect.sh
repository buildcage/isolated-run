#!/bin/bash
# Verifies the run action's report output for the proxy-engine: inspect e2e
# job (test-e2e.yml's test_sandbox_inspect). Reads
# BUILDCAGE_RUN_DEBUG_SUMMARY_FILE for the same reason as assert-sandbox.sh.
set -euo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/helpers.sh"

echo ""
echo "=== Sandbox Report Assertions (inspect engine) ==="
echo ""

SUMMARY=$(cat "$BUILDCAGE_RUN_DEBUG_SUMMARY_FILE")
assert_report_complete

# example.com:443 is in the blocked table too, for the out-of-rule POST.
assert_section_contains "Allowed Hosts" "| \`example.com:443\` |" "allowed URL-rule host recorded in report"
assert_summary_contains "not-allowed" "the out-of-rule POST recorded with its block reason"
assert_section_contains "🚫 Blocked" "| \`neverssl.com:443\` |" "host outside allowed-url-rules recorded as blocked"
assert_summary_contains "TLS github.com:443" "the allowed-tls-rules passthrough recorded, never decrypted"

assert_results

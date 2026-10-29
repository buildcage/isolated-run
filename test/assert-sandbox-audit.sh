#!/bin/bash
# Verifies audit mode's report: audited-hosts table plus the
# auto-generated restrict-mode example.
set -euo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/helpers.sh"

echo ""
echo "=== Sandbox Audit-Mode Report Assertions ==="
echo ""

SUMMARY=$(cat "$BUILDCAGE_RUN_DEBUG_SUMMARY_FILE")
assert_report_complete

assert_summary_contains "example.com:80" "Audited HTTP host recorded in report"
assert_summary_contains "example.com:443" "Audited HTTPS host recorded in report"
assert_summary_contains "Switch to restrict mode" "Restrict-mode example section present"
assert_summary_contains "uses: buildcage/isolated-run@v2" "Restrict-mode example uses the run action"
assert_summary_contains "run: |" "Restrict-mode example preserves the run: command"
assert_summary_contains "proxy-mode: restrict" "Restrict-mode example sets proxy-mode: restrict"
assert_summary_contains "proxy-engine: universal" "Restrict-mode example names the non-default engine"
assert_summary_contains "allowed-https-rules: >-" "Restrict-mode example includes allowed-https-rules"
assert_summary_contains "allowed-http-rules: >-" "Restrict-mode example includes allowed-http-rules"

assert_results

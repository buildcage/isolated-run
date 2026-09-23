#!/bin/bash
# Verifies audit mode's report: audited-hosts table plus the
# auto-generated restrict-mode example.
set -euo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/helpers.sh"

echo ""
echo "=== Sandbox Audit-Mode Report Assertions ==="
echo ""

SUMMARY=$(cat "$BUILDCAGE_RUN_DEBUG_SUMMARY_FILE")

assert_summary_contains "example.com:80" "Audited HTTP host recorded in report"
assert_summary_contains "example.com:443" "Audited HTTPS host recorded in report"
assert_summary_contains "Switch to restrict mode" "Restrict-mode example section present"
assert_summary_contains "uses: buildcage/isolated-run@v1" "Restrict-mode example uses the run action"
assert_summary_contains "run: |" "Restrict-mode example preserves the run: command"
assert_summary_contains "proxy_mode: restrict" "Restrict-mode example sets proxy_mode: restrict"
assert_summary_contains "proxy_engine: universal" "Restrict-mode example names the non-default engine"
assert_summary_contains "allowed_https_rules: >-" "Restrict-mode example includes allowed_https_rules"
assert_summary_contains "allowed_http_rules: >-" "Restrict-mode example includes allowed_http_rules"

assert_results

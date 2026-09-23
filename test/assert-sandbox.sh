#!/bin/bash
# Verifies the run action's report output. Reads
# BUILDCAGE_RUN_DEBUG_SUMMARY_FILE rather than GITHUB_STEP_SUMMARY:
# GitHub silently ignores attempts to reassign that reserved env var, and it
# is unique per step anyway, so a later step could never read an earlier
# step's copy back through it. The run action itself stops its own
# throwaway proxy container before this script runs, so there is no
# long-lived container left to `docker compose exec` into either.
set -euo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/helpers.sh"

echo ""
echo "=== Sandbox Report Assertions ==="
echo ""

SUMMARY=$(cat "$BUILDCAGE_RUN_DEBUG_SUMMARY_FILE")
assert_report_complete

# One row per verdict, which is as much as this layer is for: the real
# action's own report carries what the proxy decided. Which names, ports and
# protocols are decided which way is the fixture-based integration tests'
# subject, against an origin this suite controls (see
# test/universal-restrict-scenarios.sh).
assert_summary_contains "example.com:443" "Allowed host recorded in report"
assert_summary_contains "example.org:443" "Blocked host recorded in report"

assert_results

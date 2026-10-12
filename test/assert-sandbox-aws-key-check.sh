#!/bin/bash
# Verifies the run action's report for test-e2e.yml's AWS access key check job,
# which calls the real STS. Usage: assert-sandbox-aws-key-check.sh restrict|audit
# with ACCOUNT_ID set to the account of the job's roles. Reads
# BUILDCAGE_RUN_DEBUG_SUMMARY_FILE for the same reason as assert-sandbox.sh.
set -euo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/helpers.sh"

MODE="$1"
: "${ACCOUNT_ID:?ACCOUNT_ID must be set}"

echo ""
echo "=== Sandbox Report Assertions (AWS access key check, $MODE) ==="
echo ""

SUMMARY=$(cat "$BUILDCAGE_RUN_DEBUG_SUMMARY_FILE")
assert_report_complete

case "$MODE" in
  restrict)
    assert_summary_contains "POST https://sts.us-east-1.amazonaws.com/ -> aws-key-not-allowed" \
      "a call signed with a key from outside the step is refused as aws-key-not-allowed"
    ;;
  audit)
    assert_summary_contains "(restrict would refuse: aws-key-not-allowed" \
      "the call signed with the switched role's key is one restrict would refuse"
    assert_summary_contains "allowed_aws_role_accounts: \"$ACCOUNT_ID\" # assumed in this run, check it is yours" \
      "the restrict example names the switched role's account, read from the real STS answer"
    assert_summary_contains "aws_key_check: true" "the restrict example carries aws_key_check over"
    ;;
  *)
    echo "unknown mode: $MODE" >&2
    exit 2
    ;;
esac

assert_results

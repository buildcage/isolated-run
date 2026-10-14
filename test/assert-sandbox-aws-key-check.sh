#!/bin/bash
# Checks the report of test-e2e.yml's AWS access key check job.
# Usage: assert-sandbox-aws-key-check.sh restrict|audit (audit needs SWITCHED_ACCOUNT)
set -euo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/helpers.sh"

MODE="$1"

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
    : "${SWITCHED_ACCOUNT:?SWITCHED_ACCOUNT must be set}"
    assert_summary_contains "(restrict would block: aws-key-not-allowed" \
      "the call signed with the switched role's key is one restrict would block"
    # A single account is quoted on one line.
    if grep -A1 -F "aws_key_check: true" <<< "$SUMMARY" |
      grep -qF "allowed_aws_role_accounts: \"$SWITCHED_ACCOUNT\" # assumed in this run, check it is yours"; then
      pass "the restrict example carries aws_key_check and the switched role's account"
    else
      fail "the restrict example does not carry aws_key_check followed by the switched role's account"
    fi
    ;;
  *)
    echo "unknown mode: $MODE" >&2
    exit 2
    ;;
esac

assert_results

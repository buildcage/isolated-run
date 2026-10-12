#!/bin/bash
# Verifies the run action's report for test-e2e.yml's AWS access key check job,
# which calls the real STS. Usage: assert-sandbox-aws-key-check.sh restrict|audit,
# audit with SWITCHED_ACCOUNT set to the account of the role the step switched
# to. Reads BUILDCAGE_RUN_DEBUG_SUMMARY_FILE for the same reason as
# assert-sandbox.sh.
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
    assert_summary_contains "(restrict would refuse: aws-key-not-allowed" \
      "the call signed with the switched role's key is one restrict would refuse"
    # One account is written on one quoted line, right after aws_key_check.
    if grep -A1 -F "aws_key_check: true" <<< "$SUMMARY" |
      grep -qF "allowed_aws_role_accounts: \"$SWITCHED_ACCOUNT\" # assumed in this run, check it is yours"; then
      pass "the restrict example carries aws_key_check and the switched role's account, read from the real STS answer"
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

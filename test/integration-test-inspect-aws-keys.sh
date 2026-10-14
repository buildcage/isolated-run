#!/bin/bash
# Drives dist/main.cjs against a real inspect-engine proxy with the AWS access
# key check on: restrict refuses what the check refuses (scenarios in
# test/inspect-aws-keys-scenarios.sh), audit lets it through and notes it, and
# a step with no key to start from, or under proxy_engine: universal, fails
# before the proxy starts.
set -uo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/driver-helpers.sh"

require_local_image inspect

echo ""
echo "=== Inspect Engine Integration Test (AWS access key check) ==="
echo ""

trap 'fixture_down inspect' EXIT
fixture_up inspect

TMPDIR=$(mktemp -d)

# One step with the shared fixture inputs, which the caller's VARs override.
aws_step() {
  local name="$1"
  shift
  run_step inspect "$TMPDIR/$name" \
    INPUT_AWS_KEY_CHECK="true" \
    INPUT_ALLOWED_AWS_ROLE_ACCOUNTS="111111111111" \
    INPUT_ALLOWED_URL_RULES="* https://**.amazonaws.com/**
POST http://sts.us-east-1.amazonaws.com/sts/**
GET https://allowed.example.com/public/**" \
    INPUT_FAIL_ON_BLOCKED="false" \
    "$@"
}

echo "--- restrict: the scenarios ---"
aws_step restrict \
  AWS_ACCESS_KEY_ID="${AKIA}TESTSTARTKEY0001" \
  INPUT_PROXY_MODE="restrict" \
  INPUT_RUN="bash $REPO_ROOT/test/inspect-aws-keys-scenarios.sh"
RUN_EXIT=$?
cat "$TMPDIR/restrict.log"
if [ "$RUN_EXIT" = "0" ]; then
  pass "all in-sandbox scenarios passed"
else
  fail "one or more in-sandbox scenarios failed (exit $RUN_EXIT)"
fi
SUMMARY=$(cat "$TMPDIR/restrict.md")
assert_report_complete
assert_summary_contains "https://cloudformation.us-east-1.amazonaws.com/ -> aws-key-not-allowed" \
  "a request signed with a key of the build's own is refused as aws-key-not-allowed"
assert_summary_contains "POST https://sts.us-east-1.amazonaws.com/ -> aws-no-credential" \
  "an unsigned STS call is refused as aws-no-credential"
assert_summary_contains "-> aws-ambiguous-credential" "a request with two credentials is refused as aws-ambiguous-credential"
assert_summary_contains "-> aws-role-not-allowed" "a web identity call for another account's role is refused as aws-role-not-allowed"
assert_summary_contains "-> aws-unreadable" "a body the check cannot read through is refused as aws-unreadable"
assert_summary_contains "-> aws-unsupported-credential" \
  "a credential other than SigV4's is refused as aws-unsupported-credential"
if grep -qF "${AKIA}TESTSTARTKEY0001" "$TMPDIR/restrict.log"; then
  fail "the starting key reached the step's log"
else
  pass "the starting key stayed out of the step's log"
fi

echo ""
echo "--- audit: let through, and noted ---"
aws_step audit \
  AWS_ACCESS_KEY_ID="${AKIA}TESTSTARTKEY0001" \
  INPUT_PROXY_MODE="audit" \
  INPUT_RUN="curl -sS --max-time 10 -o /dev/null -X POST -H 'Authorization: AWS4-HMAC-SHA256 Credential=${AKIA}TESTSTARTKEY0001/x' https://sts.us-east-1.amazonaws.com/sts/other-account &&
    curl -sS --max-time 10 -o /dev/null -X POST -H 'Authorization: AWS4-HMAC-SHA256 Credential=${AKIA}TESTATTACKER0001/x' https://sts.us-east-1.amazonaws.com/sts/same-account &&
    curl -sS --max-time 10 -o /dev/null -X POST -H 'Authorization: AWS4-HMAC-SHA256 Credential=${ASIA}TESTLEARNEDKEY01/x' https://cloudformation.us-east-1.amazonaws.com/ &&
    curl -sS --max-time 10 -o /dev/null -X POST -H 'Authorization: AWS4-HMAC-SHA256 Credential=${ASIA}TESTFOREIGNKEY01/x' https://ssm.us-east-1.amazonaws.com/ &&
    curl -sS --max-time 10 -o /dev/null -X POST -H 'Authorization: AWS4-HMAC-SHA256 Credential=${ASIA}TESTFOREIGNKEY01/x' https://sqs.us-east-1.amazonaws.com/"
RUN_EXIT=$?
if [ "$RUN_EXIT" = "0" ]; then
  pass "audit refused nothing"
else
  fail "the step failed in audit mode (exit $RUN_EXIT)"
  cat "$TMPDIR/audit.log"
fi
SUMMARY=$(cat "$TMPDIR/audit.md")
assert_summary_contains "(restrict would block: aws-key-not-allowed, key 1)" \
  "the timeline says restrict would have refused the request"
assert_summary_matches "POST https://cloudformation\.us-east-1\.amazonaws\.com/ -> .*\(restrict would block: aws-key-not-allowed, key 2 from a role in 111111111111\)" \
  "an AssumeRole answer to a key restrict would block taught no key" \
  "an AssumeRole answer to a key restrict would block taught its key"
assert_summary_contains "| key 3 from a role in 999999999999 | ssm.us-east-1.amazonaws.com, sqs.us-east-1.amazonaws.com | 2 |" \
  "the requests signed with a key an AssumeRole answer issued are one row, naming the role's account"
assert_summary_contains "allowed_aws_role_accounts: |" "the restrict example lists the accounts one to a line"
assert_summary_matches "^ +111111111111$" \
  "the restrict example names the account given, unmarked" \
  "the restrict example does not name the account given on a line of its own"
assert_summary_contains "999999999999 # assumed in this run, check it is yours" \
  "the restrict example marks the account a role was assumed in"
if grep -qF "restrict mode would block" "$TMPDIR/audit.log"; then
  pass "a warning counts the requests restrict would block"
else
  fail "no warning counted the requests restrict would block"
fi

echo ""
echo "--- aws_key_check alone: the step's own key, and no role's ---"
aws_step keyonly \
  AWS_ACCESS_KEY_ID="${AKIA}TESTSTARTKEY0001" \
  INPUT_PROXY_MODE="restrict" \
  INPUT_ALLOWED_AWS_ROLE_ACCOUNTS="" \
  INPUT_RUN="bash $REPO_ROOT/test/inspect-aws-key-only-scenarios.sh"
RUN_EXIT=$?
cat "$TMPDIR/keyonly.log"
if [ "$RUN_EXIT" = "0" ]; then
  pass "all key-only scenarios passed"
else
  fail "one or more key-only scenarios failed (exit $RUN_EXIT)"
fi

echo ""
echo "--- aws_key_check alone, audited: every account a role was assumed in ---"
aws_step keyonlyaudit \
  AWS_ACCESS_KEY_ID="${AKIA}TESTSTARTKEY0001" \
  INPUT_PROXY_MODE="audit" \
  INPUT_ALLOWED_AWS_ROLE_ACCOUNTS="" \
  INPUT_RUN="curl -sS --max-time 10 -o /dev/null -X POST -H 'Authorization: AWS4-HMAC-SHA256 Credential=${AKIA}TESTSTARTKEY0001/x' https://sts.us-east-1.amazonaws.com/sts/same-account &&
    curl -sS --max-time 10 -o /dev/null -X POST -H 'Authorization: AWS4-HMAC-SHA256 Credential=${ASIA}TESTLEARNEDKEY01/x' https://sts.us-east-1.amazonaws.com/sts/other-account &&
    curl -sS --max-time 10 -X POST -H 'Authorization: AWS4-HMAC-SHA256 Credential=${AKIA}TESTSTARTKEY0001/x' http://sts.us-east-1.amazonaws.com/sts/plain-other-account | grep -qF ${ASIA}TESTPLAINKEY0002"
RUN_EXIT=$?
if [ "$RUN_EXIT" != "0" ]; then
  fail "the key-only audit step failed (exit $RUN_EXIT)"
  cat "$TMPDIR/keyonlyaudit.log"
fi
SUMMARY=$(cat "$TMPDIR/keyonlyaudit.md")
assert_summary_contains "111111111111 # assumed in this run, check it is yours" \
  "with no account named, the restrict example names the first role of a chain"
assert_summary_contains "999999999999 # assumed in this run, check it is yours" \
  "with no account named, the restrict example names the second role of a chain"
if grep -qF "333333333333" <<< "$SUMMARY"; then
  fail "the restrict example names the account of an AssumeRole answer over plaintext"
else
  pass "the restrict example leaves out the account of an AssumeRole answer over plaintext"
fi

echo ""
echo "--- no key to start from ---"
aws_step nokey \
  INPUT_PROXY_MODE="audit" \
  INPUT_RUN="true"
RUN_EXIT=$?
if [ "$RUN_EXIT" != "0" ] && grep -qF "AWS_ACCESS_KEY_ID is unset" "$TMPDIR/nokey.log"; then
  pass "a step with no AWS_ACCESS_KEY_ID fails in audit too, naming it"
else
  fail "a step with no AWS_ACCESS_KEY_ID did not fail in audit (exit $RUN_EXIT)"
  cat "$TMPDIR/nokey.log"
fi
if grep -qF "proxy image:" "$TMPDIR/nokey.log"; then
  fail "the step got as far as the proxy image before failing"
else
  pass "the step failed before any setup"
fi

echo ""
echo "--- under proxy_engine: universal ---"
aws_step universal \
  AWS_ACCESS_KEY_ID="${AKIA}TESTSTARTKEY0001" \
  INPUT_PROXY_ENGINE="universal" \
  INPUT_PROXY_MODE="audit" \
  INPUT_ALLOWED_URL_RULES="" \
  INPUT_RUN="true"
RUN_EXIT=$?
if [ "$RUN_EXIT" != "0" ] && grep -qF "has no effect with proxy_engine: universal" "$TMPDIR/universal.log"; then
  pass "a universal step with the check on fails in audit too, naming the engine"
else
  fail "a universal step with the check on did not fail in audit (exit $RUN_EXIT)"
  cat "$TMPDIR/universal.log"
fi
if grep -qF "proxy image:" "$TMPDIR/universal.log"; then
  fail "the universal step got as far as the proxy image before failing"
else
  pass "the universal step failed before any setup"
fi

rm -rf "$TMPDIR"

assert_results

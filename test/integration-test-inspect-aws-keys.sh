#!/bin/bash
# Drives dist/main.cjs against a real inspect-engine proxy with the AWS access
# key check on: restrict refuses what the check refuses (scenarios in
# test/inspect-aws-keys-scenarios.sh), audit lets it through and notes it, and
# a step with no key to start from fails before the proxy starts.
set -uo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/helpers.sh"

# Assembled at runtime: a literal shaped like an AWS access key ID trips secret
# scanning on push.
AKIA="AK""IA"
ASIA="AS""IA"

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

: "${BUILDCAGE_LOCAL_IMAGE_REF:?BUILDCAGE_LOCAL_IMAGE_REF must be set to a locally built inspect-engine image (BUILDCAGE_TEST_HOOKS=1 PROXY_ENGINE=inspect docker compose build proxy)}"

echo ""
echo "=== Inspect Engine Integration Test (AWS access key check) ==="
echo ""

echo "--- bringing up fixture origins (compose.test-inspect.yaml) ---"
cleanup() {
  docker compose -f "$REPO_ROOT/compose.test-inspect.yaml" down -v >/dev/null 2>&1 || true
}
trap cleanup EXIT
docker compose -f "$REPO_ROOT/compose.test-inspect.yaml" up -d --build --wait

TMPDIR=$(mktemp -d)

# One step: a fresh state and summary file, the shared fixture inputs, and
# whatever the caller adds. Prints the step's output to $TMPDIR/<name>.log.
run_step() {
  local name="$1"
  shift
  touch "$TMPDIR/$name.state" "$TMPDIR/$name.md"
  env \
    GITHUB_WORKSPACE="$TMPDIR" \
    GITHUB_STATE="$TMPDIR/$name.state" \
    GITHUB_STEP_SUMMARY="$TMPDIR/$name.md" \
    BUILDCAGE_RUN_DEBUG_SUMMARY_FILE="$TMPDIR/$name.md" \
    BUILDCAGE_LOCAL_IMAGE_REF="$BUILDCAGE_LOCAL_IMAGE_REF" \
    BUILDCAGE_TEST_COMPOSE_FILE="$REPO_ROOT/docker/compose.action.test-inspect.yaml" \
    BUILDCAGE_TEST_CERT_PATH="$REPO_ROOT/test/test-server-inspect/cert.pem" \
    INPUT_PROXY_ENGINE="inspect" \
    INPUT_AWS_KEY_CHECK="true" \
    INPUT_ALLOWED_AWS_ROLE_ACCOUNTS="111111111111" \
    INPUT_ALLOWED_URL_RULES="* https://**.amazonaws.com/**
GET https://allowed.example.com/public/**" \
    INPUT_FAIL_ON_BLOCKED="false" \
    "$@" \
    node "$REPO_ROOT/dist/main.cjs" > "$TMPDIR/$name.log" 2>&1
}

echo "--- restrict: the scenarios ---"
run_step restrict \
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
run_step audit \
  AWS_ACCESS_KEY_ID="${AKIA}TESTSTARTKEY0001" \
  INPUT_PROXY_MODE="audit" \
  INPUT_RUN="curl -sS --max-time 10 -o /dev/null -X POST -H 'Authorization: AWS4-HMAC-SHA256 Credential=${AKIA}TESTSTARTKEY0001/x' https://sts.us-east-1.amazonaws.com/sts/other-account &&
    curl -sS --max-time 10 -o /dev/null -X POST -H 'Authorization: AWS4-HMAC-SHA256 Credential=${AKIA}TESTATTACKER0001/x' https://sts.us-east-1.amazonaws.com/sts/same-account &&
    curl -sS --max-time 10 -o /dev/null -X POST -H 'Authorization: AWS4-HMAC-SHA256 Credential=${ASIA}TESTLEARNEDKEY01/x' https://cloudformation.us-east-1.amazonaws.com/"
RUN_EXIT=$?
if [ "$RUN_EXIT" = "0" ]; then
  pass "audit refused nothing"
else
  fail "the step failed in audit mode (exit $RUN_EXIT)"
  cat "$TMPDIR/audit.log"
fi
SUMMARY=$(cat "$TMPDIR/audit.md")
assert_summary_contains "(restrict would refuse: aws-key-not-allowed)" \
  "the timeline says restrict would have refused the request"
if grep -qE "POST https://cloudformation\.us-east-1\.amazonaws\.com/ -> .*\(restrict would refuse: aws-key-not-allowed\)" <<< "$SUMMARY"; then
  pass "an AssumeRole answer to a key restrict would refuse taught no key"
else
  fail "an AssumeRole answer to a key restrict would refuse taught its key"
fi
assert_summary_contains "allowed_aws_role_accounts: |" "the restrict example lists the accounts one to a line"
if grep -qE "^ +111111111111$" <<< "$SUMMARY"; then
  pass "the restrict example names the account given, unmarked"
else
  fail "the restrict example does not name the account given on a line of its own"
fi
assert_summary_contains "999999999999 # assumed in this run, check it is yours" \
  "the restrict example marks the account a role was assumed in"
if grep -qF "restrict mode would refuse" "$TMPDIR/audit.log"; then
  pass "a warning counts the requests restrict would refuse"
else
  fail "no warning counted the requests restrict would refuse"
fi

echo ""
echo "--- aws_key_check alone: the step's own key, and no role's ---"
run_step keyonly \
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
run_step keyonlyaudit \
  AWS_ACCESS_KEY_ID="${AKIA}TESTSTARTKEY0001" \
  INPUT_PROXY_MODE="audit" \
  INPUT_ALLOWED_AWS_ROLE_ACCOUNTS="" \
  INPUT_RUN="curl -sS --max-time 10 -o /dev/null -X POST -H 'Authorization: AWS4-HMAC-SHA256 Credential=${AKIA}TESTSTARTKEY0001/x' https://sts.us-east-1.amazonaws.com/sts/same-account &&
    curl -sS --max-time 10 -o /dev/null -X POST -H 'Authorization: AWS4-HMAC-SHA256 Credential=${ASIA}TESTLEARNEDKEY01/x' https://sts.us-east-1.amazonaws.com/sts/other-account"
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

echo ""
echo "--- no key to start from ---"
run_step nokey \
  INPUT_PROXY_MODE="restrict" \
  INPUT_RUN="true"
RUN_EXIT=$?
if [ "$RUN_EXIT" != "0" ] && grep -qF "AWS_ACCESS_KEY_ID is unset" "$TMPDIR/nokey.log"; then
  pass "a step with no AWS_ACCESS_KEY_ID fails, naming it"
else
  fail "a step with no AWS_ACCESS_KEY_ID did not fail as expected (exit $RUN_EXIT)"
  cat "$TMPDIR/nokey.log"
fi
if grep -qF "proxy image:" "$TMPDIR/nokey.log"; then
  fail "the step got as far as the proxy image before failing"
else
  pass "the step failed before any setup"
fi

rm -rf "$TMPDIR"

assert_results

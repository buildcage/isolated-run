#!/bin/bash
# Drives dist/main.cjs directly against a real proxy container/HAProxy
# log, proving the INPUT_KNOWN_BLOCKED_RULES -> report -> pass/fail wiring
# end-to-end (the matching logic itself is already unit-tested).
#
# blocked.example.com is a name in the fixture origin's resolver
# (compose.test-universal.yaml), so the blocked request this is built on stays
# inside the fixture's own zone: no rule permits it, and the proxy refuses it
# without ever asking an upstream resolver about it.
set -uo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/driver-helpers.sh"

require_local_image

run_instance() {
  local tmpdir="$1" known_blocked_rules="$2"
  run_step universal "$tmpdir/step" \
    INPUT_ALLOWED_HTTPS_RULES="allowed.example.com:443" \
    INPUT_ALLOWED_HTTP_RULES="allowed.example.com:80" \
    INPUT_ALLOWED_IP_RULES="" \
    INPUT_KNOWN_BLOCKED_RULES="$known_blocked_rules" \
    INPUT_FAIL_ON_BLOCKED="true" \
    INPUT_RUN="wget -q -T 5 -O /dev/null http://blocked.example.com/ || true"
  echo $? > "$tmpdir/exit_code"
}

echo ""
echo "=== Sandbox known_blocked_rules Assertions ==="
echo ""

trap 'fixture_down universal' EXIT
fixture_up universal

# Case 1: the only blocked connection matches known_blocked_rules -> the
# step must succeed despite fail_on_blocked defaulting to true.
TMP_MATCH=$(mktemp -d)
run_instance "$TMP_MATCH" "blocked.example.com:80"
CODE_MATCH=$(cat "$TMP_MATCH/exit_code")
if [ "$CODE_MATCH" = "0" ]; then
  pass "matching known_blocked_rules kept the step from failing"
else
  fail "matching known_blocked_rules did not prevent failure -- exit code $CODE_MATCH, see log below"
  cat "$TMP_MATCH/step.log"
fi
rm -rf "$TMP_MATCH"

# Case 2: known_blocked_rules is set but doesn't match the blocked
# connection -> the step must still fail as normal (known_blocked_rules
# isn't a backdoor allowlist).
TMP_MISMATCH=$(mktemp -d)
run_instance "$TMP_MISMATCH" "some-other-domain.example.com:443"
CODE_MISMATCH=$(cat "$TMP_MISMATCH/exit_code")
if [ "$CODE_MISMATCH" != "0" ]; then
  pass "a non-matching known_blocked_rules entry still failed the step"
else
  fail "the step unexpectedly succeeded despite no known_blocked_rules match -- see log below"
  cat "$TMP_MISMATCH/step.log"
fi
rm -rf "$TMP_MISMATCH"

assert_results

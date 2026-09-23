#!/bin/bash
# Drives dist/main.cjs directly against a real universal-engine proxy
# container and a fixture origin network (compose.test-universal.yaml),
# proving allow/block/wildcard/port/direct-IP/dns-failed/internal-address
# enforcement end-to-end (see test/universal-restrict-scenarios.sh for the
# scenario list itself).
set -uo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/helpers.sh"

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

: "${BUILDCAGE_LOCAL_IMAGE_REF:?BUILDCAGE_LOCAL_IMAGE_REF must be set to a locally built universal-engine image}"

echo ""
echo "=== Universal Engine Integration Test (restrict) ==="
echo ""

echo "--- bringing up fixture origin (compose.test-universal.yaml) ---"
cleanup() {
  docker compose -f "$REPO_ROOT/compose.test-universal.yaml" down -v >/dev/null 2>&1 || true
}
trap cleanup EXIT
docker compose -f "$REPO_ROOT/compose.test-universal.yaml" up -d --build --wait

TMPDIR=$(mktemp -d)
touch "$TMPDIR/state.env"
SUMMARY_FILE="$TMPDIR/summary.md"
touch "$SUMMARY_FILE"

echo "--- running the sandboxed step (proxy_engine: universal, restrict mode) ---"
GITHUB_WORKSPACE="$TMPDIR" \
GITHUB_STATE="$TMPDIR/state.env" \
GITHUB_STEP_SUMMARY="$SUMMARY_FILE" \
BUILDCAGE_RUN_DEBUG_SUMMARY_FILE="$SUMMARY_FILE" \
BUILDCAGE_LOCAL_IMAGE_REF="$BUILDCAGE_LOCAL_IMAGE_REF" \
BUILDCAGE_TEST_COMPOSE_FILE="$REPO_ROOT/docker/compose.action.test-universal.yaml" \
INPUT_PROXY_ENGINE="universal" \
INPUT_PROXY_MODE="restrict" \
INPUT_ALLOWED_HTTPS_RULES="allowed.example.com:443 allowed.example.com:8443 *.wildcard.example.com:443 *.wildcard.example.com:8443 ~ok\\.regex\\.example\\.com:443 ~^ports\\.regex\\.example\\.com:(443|8443)\$" \
INPUT_ALLOWED_HTTP_RULES="allowed.example.com:80 allowed.example.com:8080 *.wildcard.example.com:80 *.wildcard.example.com:8080" \
INPUT_ALLOWED_IP_RULES="10.200.0.100:8443" \
INPUT_FAIL_ON_BLOCKED="false" \
INPUT_RUN="bash $REPO_ROOT/test/universal-restrict-scenarios.sh" \
  node "$REPO_ROOT/dist/main.cjs" 2>&1 | tee "$TMPDIR/out.log"
RUN_EXIT=${PIPESTATUS[0]}

echo ""
echo "--- scenario exit code: $RUN_EXIT ---"
if [ "$RUN_EXIT" != "0" ]; then
  fail "one or more in-sandbox scenarios failed (see log above)"
else
  pass "all in-sandbox scenarios passed"
fi

echo ""
echo "--- report assertions (Job Summary) ---"
SUMMARY=$(cat "$SUMMARY_FILE")

assert_summary_contains "| allowed.example.com:443 | HTTPS |" "allowed.example.com:443 recorded as allowed"
assert_summary_contains "| allowed.example.com:80 | HTTP |" "allowed.example.com:80 recorded as allowed"
# Case and a trailing dot survive only on the Host-header path, so that is
# where the scenarios ask for both forms. The row below is the uppercase one;
# the trailing-dot request is normalized into the allowed.example.com:80 row
# above, and the scenario's own 200 is what asserts it.
assert_summary_contains "| ALLOWED.example.com:80 | HTTP |" "uppercase host (HTTP) recorded as allowed"
assert_summary_contains "| sub.wildcard.example.com:443 | HTTPS |" "wildcard-matched name recorded as allowed"
# Each of these is the near miss for a rule the scenarios also request on its
# matching side. From inside the sandbox every one of them looks the same,
# "not 200", so the reason is what tells a rule that refused the name from a
# fixture that was never reachable in the first place.
assert_summary_contains "| not-ok.regex.example.com:443 | HTTPS | not-allowed |" "an anchorless regex did not match a name merely containing it, reason not-allowed"
assert_summary_contains "| deep.sub.wildcard.example.com:443 | HTTPS | not-allowed |" "a wildcard did not reach a nested subdomain, reason not-allowed"
assert_summary_contains "| ports.regex.example.com:80 | HTTP | not-allowed |" "a regex naming https ports only did not cover :80, reason not-allowed"
assert_summary_contains "| blocked.example.com:443 | HTTPS | not-allowed |" "blocked.example.com:443 recorded as blocked, reason not-allowed"
# The same name on the three other ports the scenarios request it on. The
# keep-alive check further down reads blocked.example.com:80 out of the Allowed
# Hosts table only, so it and the row below are about different tables.
assert_summary_contains "| blocked.example.com:80 | HTTP | not-allowed |" "blocked.example.com:80 recorded as blocked, reason not-allowed"
assert_summary_contains "| blocked.example.com:8443 | HTTPS | not-allowed |" "blocked.example.com:8443 recorded as blocked, reason not-allowed"
assert_summary_contains "| blocked.example.com:8080 | HTTP | not-allowed |" "blocked.example.com:8080 recorded as blocked, reason not-allowed"
assert_summary_contains "| 10.200.0.100:80 | IP | ip-not-allowed |" "direct IP recorded as blocked, reason ip-not-allowed"
assert_summary_contains "| 10.200.0.100:8443 | IP |" "an allowed address recorded as allowed, whatever name its SNI carried"
assert_summary_contains "| 10.200.0.101:8443 | IP | ip-not-allowed |" "an address no rule allows recorded as blocked, though its SNI named an allowed one"
# No rule refused these and none can clear them, so they are tabled apart.
assert_summary_contains "### ⚠️ Failed Connections" "a name that resolved nowhere is tabled apart from what the rules refused"
assert_summary_contains "| nxdomain.wildcard.example.com:443 | HTTPS | dns-failed |" "unresolvable allowlisted name recorded as dns-failed"
assert_summary_contains "| nxdomain.wildcard.example.com:80 | HTTP | dns-failed |" "unresolvable allowlisted name recorded as dns-failed on the HTTP path too"
assert_summary_contains "| v6only.wildcard.example.com:443 | HTTPS | dns-failed |" "allowlisted name with AAAA records only recorded as dns-failed"
assert_summary_contains "| v6only.wildcard.example.com:80 | HTTP | dns-failed |" "allowlisted name with AAAA records only recorded as dns-failed on the HTTP path too"
assert_summary_contains "| internal.wildcard.example.com:443 | HTTPS | internal-address |" "SSRF via allowlisted name recorded as blocked, reason internal-address"
assert_summary_contains "| internal.wildcard.example.com:80 | HTTP | internal-address |" "SSRF via allowlisted name (HTTP) recorded as blocked, reason internal-address"
assert_summary_contains "| runner.wildcard.example.com:443 | HTTPS | internal-address |" "a name resolving to an address the runner holds recorded as blocked, reason internal-address"
assert_summary_contains "| runner.wildcard.example.com:80 | HTTP | internal-address |" "a name resolving to an address the runner holds (HTTP) recorded as blocked, reason internal-address"
# Neither of these names a host, so the row carries whatever address the
# connection was headed for, the proxy's own. The reason is the assertion.
assert_summary_contains "| HTTPS | missing-sni |" "a TLS ClientHello with no SNI recorded as blocked, reason missing-sni"
assert_summary_contains "| HTTP | missing-host-header |" "an HTTP request with no Host header recorded as blocked, reason missing-host-header"
# The crafted SNI arrives as one row whose host cell is the sanitized name.
assert_summary_contains "x__-__T__buildcage__ALLOWED___HTTPS___forged.example.com:443" \
  "the forged SNI was sanitized into a single blocked row"

# The Allowed Hosts table never shows a reason column, so a plain substring
# search for "| blocked.example.com:80 | HTTP |" would also match the start
# of its correct Blocked Hosts row ("| blocked.example.com:80 | HTTP |
# not-allowed |"). Scope the search to just the Allowed Hosts section instead.
ALLOWED_SECTION=$(awk '
  /^### / { in_section = (index($0, "Allowed Hosts") > 0) ? 1 : 0; next }
  in_section { print }
' <<< "$SUMMARY")

assert_absent_in_allowed() {
  local pattern="$1" label="$2"
  if grep -qF -- "$pattern" <<< "$ALLOWED_SECTION"; then
    fail "$label -- found in the Allowed Hosts table"
  else
    pass "$label"
  fi
}

assert_absent_in_allowed "| blocked.example.com:80 | HTTP |" \
  "keep-alive: second (blocked) request on a reused connection did not inherit the first request's ALLOWED verdict"

assert_absent_in_summary() {
  local pattern="$1" label="$2"
  if grep -qF -- "$pattern" <<< "$SUMMARY"; then
    fail "$label"
  else
    pass "$label"
  fi
}

# A bare, unsanitized row would only exist if the crafted SNI had broken out
# of its log line and been read back as an ALLOWED entry of its own.
assert_absent_in_summary "| forged.example.com:443 | HTTPS |" \
  "the forged SNI produced no unsanitized row of its own"

assert_present_in_allowed() {
  local pattern="$1" label="$2"
  if grep -qF -- "$pattern" <<< "$ALLOWED_SECTION"; then
    pass "$label"
  else
    fail "$label -- not found in the Allowed Hosts table"
  fi
}

# The other direction: keepalive.wildcard.example.com is requested once, as
# the second request on a connection whose first was refused. Scoped to the
# Allowed Hosts table, since a blocked row for it would start with the same
# text.
assert_present_in_allowed "| keepalive.wildcard.example.com:80 | HTTP |" \
  "keep-alive: second (allowed) request on a reused connection did not inherit the first request's BLOCKED verdict"

rm -rf "$TMPDIR"

assert_results

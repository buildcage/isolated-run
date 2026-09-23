#!/bin/bash
# Drives dist/main.cjs directly against a real inspect-engine proxy container
# and a fixture origin network (compose.test-inspect.yaml), proving
# method/path enforcement, DNS non-leak, SSRF/forged-Host guards, TLS
# passthrough and CA trust end-to-end (see
# test/inspect-restrict-scenarios.sh for the scenario list itself).
#
# Also checks the CA-injection design (see
# src/lib/sandbox/ca-trust.ts): this sandbox's rootfs is the real host `/`,
# so CA trust is injected as mounts, torn down with the rest of the
# sandbox's mount namespace, never written to the host. That is a
# regression risk unique to this repo, so it is checked here rather than
# only in theory.
set -uo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/helpers.sh"

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

: "${BUILDCAGE_LOCAL_IMAGE_REF:?BUILDCAGE_LOCAL_IMAGE_REF must be set to a locally built inspect-engine image (BUILDCAGE_TEST_HOOKS=1 PROXY_ENGINE=inspect docker compose build proxy)}"

echo ""
echo "=== Inspect Engine Integration Test (restrict) ==="
echo ""

echo "--- bringing up fixture origins (compose.test-inspect.yaml) ---"
cleanup() {
  docker compose -f "$REPO_ROOT/compose.test-inspect.yaml" down -v >/dev/null 2>&1 || true
}
trap cleanup EXIT
docker compose -f "$REPO_ROOT/compose.test-inspect.yaml" up -d --build --wait

SYSTEM_CA=/etc/ssl/certs/ca-certificates.crt
HASH_BEFORE=$(sha256sum "$SYSTEM_CA" | awk '{print $1}')

TMPDIR=$(mktemp -d)
touch "$TMPDIR/state.env"
SUMMARY_FILE="$TMPDIR/summary.md"
touch "$SUMMARY_FILE"

echo "--- running the sandboxed step (proxy_engine: inspect, restrict mode) ---"
GITHUB_WORKSPACE="$TMPDIR" \
GITHUB_STATE="$TMPDIR/state.env" \
GITHUB_STEP_SUMMARY="$SUMMARY_FILE" \
BUILDCAGE_RUN_DEBUG_SUMMARY_FILE="$SUMMARY_FILE" \
BUILDCAGE_LOCAL_IMAGE_REF="$BUILDCAGE_LOCAL_IMAGE_REF" \
BUILDCAGE_TEST_COMPOSE_FILE="$REPO_ROOT/docker/compose.action.test-inspect.yaml" \
BUILDCAGE_TEST_CERT_PATH="$REPO_ROOT/test/test-server-inspect/cert.pem" \
INPUT_PROXY_ENGINE="inspect" \
INPUT_PROXY_MODE="restrict" \
INPUT_ALLOWED_HTTPS_RULES="sub.wildcard.example.com:443 absent.example.com:443 v6only.example.com:443 metadata.example.com:443 runner.example.com:443 deadend.example.com:443" \
INPUT_ALLOWED_HTTP_RULES="allowed.example.com:80 deadend.example.com:80" \
INPUT_ALLOWED_TLS_RULES="tlspass.example.com:443 ~^tlspass\.example\.com:8443$" \
INPUT_ALLOWED_IP_RULES="~^10\.200\.0\.\d+:9080$ 10.200.0.53:53" \
INPUT_ALLOWED_URL_RULES="GET https://allowed.example.com/public/**
GET https://allowed.example.com:9443/public/**
GET|POST https://api.example.com/v1/*
GET http://10.200.0.100/pub-by-addr/**
GET https://*.wildcard.example.com/public/**
GET ~^https://blocked\.example\.com:9443/public/.*$
GET ~^https://blocked\.example\.com/defaultport/.*$
GET ~https://ok\.wildcard\.example\.com/regexpub/
GET ~^https://ok\.wildcard\.example\.com/regexexact$
# Never requested: this puts a character haproxy's own config parser
# folds in front of real haproxy. Unescaped, the ' would open a quoted
# string, so haproxy refuses the config and this test fails, which is the
# point. A pattern that stayed valid when cut short would regress in
# silence. (A '#' is rejected at input as a comment written without its
# space, so it never reaches the config.)
GET ~^https://blocked\.example\.com/frag(x|'z)$" \
INPUT_FAIL_ON_BLOCKED="false" \
INPUT_RUN="bash $REPO_ROOT/test/inspect-restrict-scenarios.sh" \
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
assert_report_complete

assert_summary_contains "| allowed.example.com:443 | HTTPS |" "allowed.example.com:443 recorded as allowed"
assert_summary_contains "| allowed.example.com:80 | HTTP |" "allowed.example.com:80 recorded as allowed"
assert_summary_contains "| blocked.example.com:443 | HTTPS |" "blocked.example.com:443 recorded as blocked"
assert_summary_contains "| blocked.example.com:9443 | HTTPS |" "the ~regex rule's blocked.example.com:9443 recorded as allowed"
assert_summary_contains "| 10.200.0.100:9080 | IP |" "the ~regex allowed_ip_rules entry recorded as allowed"
assert_summary_contains "| 10.200.0.53:53 | IP |" "DNS over TCP to a resolver an ip rule allows recorded as allowed"
# No rule refused this one and none can clear it, so it is tabled apart.
assert_summary_contains "### ⚠️ Failed Connections" "a name that resolved nowhere is tabled apart from what the rules refused"
assert_summary_contains "| absent.example.com:443 | HTTPS | dns-failed |" "absent.example.com:443 recorded as failed, reason dns-failed"
# The opposite case: a connection that never completed is a refusal, because
# nothing on it was ever authenticated. It reads like an outage and is counted
# anyway.
assert_summary_contains "| deadend.example.com:443 | HTTPS | origin-connect-failed |" \
  "a connection that never completed is in the blocked table, not the failed one"
# The same host over plaintext, where no certificate was ever going to be
# checked, so nothing was hidden by the connection failing.
assert_summary_contains "| deadend.example.com:80 | HTTP | origin-unreachable |" \
  "a plaintext connection that failed is a failure, not a refusal"
assert_summary_contains "POST https://allowed.example.com/public/pkg.tgz -> not-allowed" "out-of-rule POST recorded with its reason"
# `OPTIONS *` carries no path, so no URL can spell what it asked for and the
# row names the method and the host instead. The host is the point: built from
# the logged URL it would read as the nonexistent `allowed.example.com-`.
assert_summary_contains "OPTIONS HTTPS allowed.example.com:443 -> not-allowed" "a target that is not a path is recorded against the host the request carried"
assert_summary_contains "https://absent.example.com/ -> dns-failed" "unresolvable allowlisted name recorded as dns-failed"
assert_summary_contains "https://v6only.example.com/ -> dns-failed" "allowlisted name with AAAA records only recorded as dns-failed"
assert_summary_contains "exfil?token=*** -> not-allowed" "the refused URL's credential parameter was replaced"
# The summary is as readable as the run; the traffic artifact is where the
# value itself survives.
if grep -qF "token=SECRET-VALUE" <<< "$SUMMARY"; then
  fail "a credential parameter's value reached the report"
else
  pass "a credential parameter's value was replaced"
fi
# The marker is last on the log line the report is built from, so finding it
# proves nothing was cut.
assert_summary_contains "end=TAIL-MARKER -> not-allowed" "the ~1.3KB refused URL was recorded whole"
assert_summary_contains "TLS tlspass.example.com:443" "the TLS passthrough is in the timeline, never decrypted"
assert_summary_contains "DNS secret-in-a-name.attacker.example -> dns-not-allowed" "the DNS-only exfiltration attempt was refused and recorded"
# No rule can name an address backwards, so a row for one could never be taken
# away by writing a rule. The resolver records it under a verb of its own
# instead. An invented name under the same zone is judged like any other, or
# appending `.in-addr.arpa` would be a way out of the report.
if grep -qF "1.0.20.172.in-addr.arpa" <<< "$SUMMARY"; then
  fail "a reverse lookup reached the report"
else
  pass "a reverse lookup is left out of the report entirely"
fi
assert_summary_contains "DNS secret-in-a-name.in-addr.arpa -> dns-not-allowed" \
  "an invented name under the reverse zone still reaches the report"
# No discovery record is ever served, so no rule could make this lookup
# succeed and a blocked row for it would name a remedy that does not exist.
assert_summary_contains "DNS SRV _http._tcp.allowed.example.com -> no data" \
  "the service-discovery lookup is in the timeline, with its type"
if grep -qE '_http\._tcp\.allowed\.example\.com.*dns-(service-)?not-allowed' <<< "$SUMMARY"; then
  fail "a service-discovery lookup under an allowed host was reported as blocked"
else
  pass "a service-discovery lookup under an allowed host was not reported as blocked"
fi
# Only a service name under a host the rules allow is treated that way. The
# refusal names its own remedy: the host below the name, which is what a rule
# can be written against.
if grep -qiE '_mongodb\._tcp\.secret-in-a-name\.attacker\.example.*dns-service-not-allowed' <<< "$SUMMARY"; then
  pass "a service name under a host no rule allows was refused with a reason of its own"
else
  fail "a service name under a host no rule allows was not reported as refused"
fi
if grep -qE 'DNS allowed\.example\.com ->' <<< "$SUMMARY"; then
  fail "a name that merely resolved is in the timeline (should be dropped as redundant)"
else
  pass "a name that merely resolved is left out of the timeline"
fi
# A connection the client left before sending a request. No rule decided it and
# nothing else reached this host, so its close is kept; it belongs in neither
# table, and the timeline is the only place it can appear. Its host is the SNI,
# the only name it ever gave.
if grep -qE "⚠️ .*: HTTPS aborted\.example\.com:443 -> client-(aborted|timeout)$" <<< "$SUMMARY"; then
  pass "a connection the client left is in the timeline, with a mark of its own"
else
  fail "the aborted connection is missing from the timeline"
fi
if grep -qF "| aborted.example.com:443 | HTTPS |" <<< "$SUMMARY"; then
  fail "the aborted connection was put in one of the host tables"
else
  pass "the aborted connection is in neither host table"
fi
# No rule takes the row above away, so the refused lookup for the same name has
# to survive: it is the only row a reader can act on.
assert_summary_contains "| aborted.example.com | DNS | dns-not-allowed |" \
  "the refused lookup for the same name is still its own Blocked row"
# A refusal made before a whole request arrived is still a refusal, so it is in
# the table and in fail_on_blocked. The plain stage has no SNI to name it by,
# hence the host both rows carry.
if grep -qE '^\| \(unknown\):[0-9]+ \| HTTP \| bad-request \|' <<< "$SUMMARY" \
  && grep -qE '^\| \(unknown\):[0-9]+ \| HTTP \| missing-host-header \|' <<< "$SUMMARY"; then
  pass "both refusals that named no host are in the Blocked Hosts table"
else
  fail "the Blocked Hosts table is missing the rows for requests that named no host"
fi

echo ""
echo "--- positive control: the UDP echo server is reachable from beside the cage ---"
UDP_REPLY=$(docker compose -f "$REPO_ROOT/compose.test-inspect.yaml" exec -T test-dns sh -c \
  'echo probe | nc -u -w 3 10.200.0.102 9999' 2>/dev/null | tr -d '\r\n' || true)
if [ "$UDP_REPLY" = "probe" ]; then
  pass "the echo server answers on test-net, so the scenario script's silence was the cage, not a dead fixture"
else
  fail "the echo server did not answer from test-net either (got \"$UDP_REPLY\")"
fi

echo ""
echo "--- CA-injection residue check (novel to this repo's host-rootfs design) ---"
HASH_AFTER=$(sha256sum "$SYSTEM_CA" | awk '{print $1}')
if [ "$HASH_BEFORE" = "$HASH_AFTER" ]; then
  pass "the host's own system CA store ($SYSTEM_CA) is byte-identical before and after the step"
else
  fail "the host's system CA store changed -- CA injection leaked onto the real host filesystem"
fi
if [ -e /etc/buildcage-ca.pem ]; then
  fail "/etc/buildcage-ca.pem exists on the host after the step"
else
  pass "no /etc/buildcage-ca.pem left on the host"
fi

echo ""
echo "--- CA trust survives a write_through: entry containing its mount points ---"
WT_TMPDIR=$(mktemp -d)
touch "$WT_TMPDIR/state.env" "$WT_TMPDIR/summary.md"
GITHUB_WORKSPACE="$WT_TMPDIR" \
GITHUB_STATE="$WT_TMPDIR/state.env" \
GITHUB_STEP_SUMMARY="$WT_TMPDIR/summary.md" \
BUILDCAGE_LOCAL_IMAGE_REF="$BUILDCAGE_LOCAL_IMAGE_REF" \
BUILDCAGE_TEST_COMPOSE_FILE="$REPO_ROOT/docker/compose.action.test-inspect.yaml" \
BUILDCAGE_TEST_CERT_PATH="$REPO_ROOT/test/test-server-inspect/cert.pem" \
INPUT_PROXY_ENGINE="inspect" \
INPUT_PROXY_MODE="restrict" \
INPUT_WRITE_THROUGH="/etc" \
INPUT_ALLOWED_URL_RULES="GET https://allowed.example.com/public/**" \
INPUT_RUN="curl -sS --max-time 10 -o /dev/null https://allowed.example.com/public/pkg.tgz" \
  node "$REPO_ROOT/dist/main.cjs" > "$WT_TMPDIR/out.log" 2>&1
WT_EXIT=$?
if [ "$WT_EXIT" = "0" ]; then
  pass "an allowed HTTPS GET still verifies against the injected CA under write_through: /etc"
else
  fail "write_through: /etc broke CA trust or DNS (exit $WT_EXIT; see $WT_TMPDIR/out.log)"
  cat "$WT_TMPDIR/out.log"
fi
if [ "$HASH_BEFORE" = "$(sha256sum "$SYSTEM_CA" | awk '{print $1}')" ]; then
  pass "the host's system CA store is still untouched after the write_through: /etc step"
else
  fail "the host's system CA store changed during the write_through: /etc step"
fi
if [ -e /etc/buildcage-ca.pem ]; then
  fail "/etc/buildcage-ca.pem was left on the host by the write_through: /etc step"
else
  pass "no /etc/buildcage-ca.pem left on the host after the write_through: /etc step"
fi

rm -rf "$TMPDIR" "$WT_TMPDIR"

assert_results

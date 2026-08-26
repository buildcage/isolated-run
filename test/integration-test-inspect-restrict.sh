#!/bin/bash
# Drives dist/main.cjs directly against a real inspect-engine proxy container
# and a fixture origin network (compose.test-inspect.yaml), proving
# method/path enforcement, DNS non-leak, SSRF/forged-Host guards, TLS
# passthrough and CA trust end-to-end -- ported from buildcage/docker's
# test/Dockerfile.inspect-restrict + test/assert-inspect-restrict.sh, adapted
# to a `run:` step instead of a buildkit build (see
# test/inspect-restrict-scenarios.sh for the scenario list itself).
#
# Also checks the CA-injection design this port introduces (see
# src/lib/sandbox/ca-trust.ts): unlike buildkit-runc's disposable-layer
# approach, this sandbox's rootfs is the real host `/`, so CA trust is
# injected as mounts, torn down with the rest of the sandbox's mount
# namespace -- never written to the host. That is a regression risk unique to
# this repo, so it is checked here rather than only in theory.
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
EXTERNAL_RESOLVER="10.200.0.53" \
INPUT_PROXY_ENGINE="inspect" \
INPUT_PROXY_MODE="restrict" \
INPUT_ALLOWED_HTTPS_RULES="sub.wildcard.example.com:443 absent.example.com:443 metadata.example.com:443" \
INPUT_ALLOWED_HTTP_RULES="allowed.example.com:80" \
INPUT_ALLOW_TLS_RULES="tlspass.example.com:443" \
INPUT_ALLOWED_URL_RULES="GET https://allowed.example.com/public/**
GET https://allowed.example.com:9443/public/**
GET|POST https://api.example.com/v1/*
GET http://10.200.0.100/pub-by-addr/**
GET https://*.wildcard.example.com/public/**" \
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

assert_summary_contains() {
  local pattern="$1" label="$2"
  if grep -qF -- "$pattern" <<< "$SUMMARY"; then
    pass "$label"
  else
    fail "$label -- not found in report"
  fi
}

assert_summary_contains "| allowed.example.com:443 | HTTPS |" "allowed.example.com:443 recorded as allowed"
assert_summary_contains "| allowed.example.com:80 | HTTP |" "allowed.example.com:80 recorded as allowed"
assert_summary_contains "| blocked.example.com:443 | HTTPS |" "blocked.example.com:443 recorded as blocked"
assert_summary_contains "| absent.example.com:443 | HTTPS |" "absent.example.com:443 recorded as blocked"
assert_summary_contains "POST https://allowed.example.com/public/pkg.tgz -> not-allowed" "out-of-rule POST recorded with its reason"
assert_summary_contains "https://absent.example.com/ -> dns-failed" "unresolvable allowlisted name recorded as dns-failed"
assert_summary_contains "token=SECRET-VALUE" "the refused URL's query string was recorded intact"
assert_summary_contains "TLS tlspass.example.com:443" "the TLS passthrough is in the timeline, never decrypted"
# Regression for the port-scoping bug: the same SNI on a port allow_tls_rules
# does not name must be inspected (HTTPS request, refused by the ordinary
# URL rules), not treated as an undecrypted passthrough.
assert_summary_contains "GET https://tlspass.example.com:9443/public/x -> not-allowed" "wrong-port TLS request was inspected and refused, not passed through"
if grep -qF "TLS tlspass.example.com:9443" <<< "$SUMMARY"; then
  fail "the wrong-port TLS request was recorded as a passthrough"
else
  pass "the wrong-port TLS request was not recorded as a passthrough"
fi
assert_summary_contains "DNS secret-in-a-name.attacker.example -> dns-not-allowed" "the DNS-only exfiltration attempt was refused and recorded"
if grep -qE 'DNS allowed\.example\.com ->' <<< "$SUMMARY"; then
  fail "a name that merely resolved is in the timeline (should be dropped as redundant)"
else
  pass "a name that merely resolved is left out of the timeline"
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

rm -rf "$TMPDIR"

echo ""
if [ "$FAILURES" -gt 0 ]; then
  echo "❌ FAILED: $FAILURES assertion(s) failed"
  exit 1
fi
echo "✅ All assertions passed."
echo ""

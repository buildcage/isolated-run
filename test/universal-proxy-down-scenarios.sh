#!/bin/bash
# Runs inside the sandbox, as the `run:` input of the step
# test/integration-test-proxy-down.sh drives. That driver stops the proxy's
# services between the phases below, and each phase waits for the marker the
# driver writes into the workspace, which is this script's working directory.
set -uo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/helpers.sh"

C="curl -sS -k -o /dev/null -w %{http_code} --max-time 10"

# Bounded, so a driver that never writes the marker ends the step instead of
# hanging it.
wait_for() {
  for _ in $(seq 1 240); do
    [ -e "$1" ] && return 0
    sleep 0.5
  done
  return 1
}

# udp_lookup_answered <server>: whether <server> answers an A query for
# allowed.example.com sent straight to its UDP port 53. The reply opens with
# the query's own id.
udp_lookup_answered() {
  local id
  id=$(printf '\253\315\001\000\000\001\000\000\000\000\000\000\007allowed\007example\003com\000\000\001\000\001' |
    timeout 10 nc -u -w 3 "$1" 53 2>/dev/null | od -An -tx1 | tr -d ' \n' | cut -c1-4)
  [ "$id" = abcd ]
}

# 000 is curl's code for a request that got no HTTP answer at all.
assert_unreachable() {
  local label="$1"
  shift
  check_status "$label" "$($C "$@" 2>/dev/null)" "000"
}

echo "=== [proxy up: the allowed origin is reachable] ==="
check_status "allowed.example.com HTTP" "$($C http://allowed.example.com/)" "200"
check_status "allowed.example.com HTTPS" "$($C https://allowed.example.com/)" "200"
# Shows the probe the coredns phase relies on can see an answer.
if udp_lookup_answered 198.19.255.1; then
  pass "the cage's resolver answers a UDP lookup"
else
  fail "the cage's resolver did not answer a UDP lookup"
fi
# The driver reports this phase on its own, and the count below is the
# stopped phases' alone.
echo "$FAILURES" > serving.done
FAILURES=0

echo "=== [haproxy stopped: nothing gets through] ==="
if ! wait_for haproxy.down; then
  fail "the driver never stopped haproxy"
  scenario_results "proxy-down scenarios"
fi
# The resolver still answers, so the failures below are the listener's.
if timeout 20 getent ahostsv4 allowed.example.com >/dev/null; then
  pass "allowed.example.com still resolves with only haproxy stopped"
else
  fail "allowed.example.com stopped resolving with only haproxy stopped"
fi
assert_unreachable "allowed.example.com HTTP fails with haproxy stopped" http://allowed.example.com/
assert_unreachable "allowed.example.com HTTPS fails with haproxy stopped" https://allowed.example.com/
assert_unreachable "the origin's address fails with haproxy stopped" http://10.200.0.100/
touch haproxy-phase.done

echo "=== [coredns stopped too: no lookups, still nothing gets through] ==="
if ! wait_for coredns.down; then
  fail "the driver never stopped coredns"
  scenario_results "proxy-down scenarios"
fi
if timeout 20 getent ahostsv4 allowed.example.com >/dev/null; then
  fail "allowed.example.com still resolved with coredns stopped"
else
  pass "allowed.example.com no longer resolves with coredns stopped"
fi
if udp_lookup_answered 198.19.255.1; then
  fail "the cage's resolver still answered a UDP lookup with coredns stopped"
else
  pass "the cage's resolver no longer answers a UDP lookup"
fi
# With the cage's own resolver gone, a lookup must not reach another one.
if udp_lookup_answered 10.200.0.53; then
  fail "a UDP lookup reached the fixture's resolver with coredns stopped"
else
  pass "a UDP lookup to the fixture's resolver got no answer"
fi

scenario_results "proxy-down scenarios"

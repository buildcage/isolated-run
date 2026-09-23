#!/bin/bash
# Runs inside the sandbox, as the `run:` input of a real proxy_engine:
# universal step in audit mode (see test/integration-test-universal-audit.sh).
#
# ---------------------------------------------------------------------------
# Rules under test: none. Audit mode records but does not enforce the
# allowlist, so a connection only fails here for a reason that has nothing to
# do with rules: the internal-address guard, an unresolvable name, or no name
# to judge at all.
# ---------------------------------------------------------------------------
set -uo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/helpers.sh"

C="curl -sS -k -o /dev/null -w %{http_code} --max-time 10"

echo "=== [HTTPS - any domain] ==="
check_status "blocked.example.com" "$($C https://blocked.example.com/)" "200"

echo "=== [HTTP - any domain] ==="
check_status "blocked.example.com HTTP" "$($C http://blocked.example.com/)" "200"

echo "=== [Port 8443 - any domain] ==="
check_status "blocked.example.com:8443" "$($C https://blocked.example.com:8443/)" "200"

echo "=== [Port 8080 - any domain] ==="
check_status "blocked.example.com:8080" "$($C http://blocked.example.com:8080/)" "200"

echo "=== [Direct IP - audit mode passes it through] ==="
check_status "10.200.0.100 direct" "$($C http://10.200.0.100/)" "200"

# [SSRF - internal address, blocked even though audit otherwise allows everything]
echo "=== [HTTPS - SSRF via internal address] ==="
CODE=$($C --max-time 5 https://internal.wildcard.example.com/ 2>/dev/null || echo "000")
if [ "$CODE" != "200" ]; then
  pass "internal.wildcard.example.com blocked (got $CODE)"
else
  fail "internal.wildcard.example.com reached an internal address"
fi

echo "=== [HTTP - SSRF via internal address] ==="
CODE=$($C --max-time 5 http://internal.wildcard.example.com/ 2>/dev/null || echo "000")
if [ "$CODE" != "200" ]; then
  pass "internal.wildcard.example.com HTTP blocked (got $CODE)"
else
  fail "internal.wildcard.example.com HTTP reached an internal address"
fi

# [SSRF - the runner itself, blocked in audit too]
echo "=== [HTTPS - SSRF back to the runner] ==="
CODE=$($C --max-time 5 https://runner.wildcard.example.com/ 2>/dev/null || echo "000")
if [ "$CODE" != "200" ]; then
  pass "runner.wildcard.example.com blocked (got $CODE)"
else
  fail "runner.wildcard.example.com reached the runner"
fi

echo "=== [HTTP - SSRF back to the runner] ==="
CODE=$($C --max-time 5 http://runner.wildcard.example.com/ 2>/dev/null || echo "000")
if [ "$CODE" != "200" ]; then
  pass "runner.wildcard.example.com HTTP blocked (got $CODE)"
else
  fail "runner.wildcard.example.com HTTP reached the runner"
fi

echo "=== [HTTPS - dns-failed (NXDOMAIN)] ==="
CODE=$($C --max-time 5 https://nxdomain.wildcard.example.com/ 2>/dev/null || echo "000")
if [ "$CODE" != "200" ]; then
  pass "nxdomain.wildcard.example.com blocked (got $CODE)"
else
  fail "nxdomain.wildcard.example.com reached the origin"
fi

echo "=== [HTTP - dns-failed (NXDOMAIN)] ==="
CODE=$($C --max-time 5 http://nxdomain.wildcard.example.com/ 2>/dev/null || echo "000")
if [ "$CODE" != "200" ]; then
  pass "nxdomain.wildcard.example.com HTTP blocked (got $CODE)"
else
  fail "nxdomain.wildcard.example.com HTTP reached the origin"
fi

# [TLS ClientHello with no SNI extension at all. There is no name to judge, so
# the connection is refused on that alone, audit mode or not; the report
# records the address it was headed for, which is the proxy's own.]
echo "=== [HTTPS - missing-sni] ==="
(printf '\x16\x03\x01\x00\x2d\x01\x00\x00\x29\x03\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x02\x00\xff\x01\x00' \
 | nc -w 5 blocked.example.com 443 > /dev/null 2>&1 || true)
echo "  request sent (blocked expected in the report)"

# [HTTP/1.0 request with no Host header, the plaintext counterpart of the
# case above.]
echo "=== [HTTP - missing-host-header] ==="
((printf 'GET / HTTP/1.0\r\n\r\n'; sleep 1) | nc -w 5 blocked.example.com 80 > /dev/null 2>&1 || true)
echo "  request sent (blocked expected in the report)"

# [What a resolver does when a UDP answer comes back truncated. The query has
# to reach the resolver itself, not the proxy, which cannot read one. The
# reply opens with its length, then the query's own id.]
echo "=== [DNS over TCP] ==="
ANSWER=$(timeout 5 bash -c '
  exec 3<>/dev/tcp/198.19.255.1/53 || exit 1
  printf "\x00\x1d\xab\xcd\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x07example\x03com\x00\x00\x01\x00\x01" >&3
  head -c 4 <&3 | od -An -tx1' 2>/dev/null | tr -d ' \n')
if [ "${ANSWER:4:4}" = "abcd" ]; then
  pass "a TCP lookup at the resolver was answered"
else
  fail "a TCP lookup at the resolver went unanswered (got '$ANSWER')"
fi

scenario_results

#!/bin/bash
# Runs inside the sandbox, as the `run:` input of a real proxy_engine:
# universal step (see test/integration-test-universal-restrict.sh).
#
# ---------------------------------------------------------------------------
# Rules under test (set by test/integration-test-universal-restrict.sh):
#   allowed_https_rules: allowed.example.com:443 allowed.example.com:8443
#                        *.wildcard.example.com:443 *.wildcard.example.com:8443
#                        ~ok\.regex\.example\.com:443        (no anchors)
#                        ~^ports\.regex\.example\.com:(443|8443)$
#   allowed_http_rules:  allowed.example.com:80 allowed.example.com:8080
#                        *.wildcard.example.com:80 *.wildcard.example.com:8080
#   allowed_ip_rules:    10.200.0.100:8443
# ---------------------------------------------------------------------------
set -uo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/helpers.sh"

C="curl -sS -k -o /dev/null -w %{http_code} --max-time 10"

echo "=== [HTTPS - allowed - exact match] ==="
check_status "allowed.example.com" "$($C https://allowed.example.com/)" "200"

# curl lowercases the host and drops its trailing dot before the TLS
# handshake, so an HTTPS version of either check below would send the SNI the
# exact match above already sends. Only a Host header carries both forms
# through untouched.
echo "=== [HTTP - allowed - uppercase host (DNS names are case-insensitive)] ==="
check_status "ALLOWED.example.com HTTP" "$($C http://ALLOWED.example.com/)" "200"

echo "=== [HTTP - allowed - trailing dot (a trailing dot is the same DNS name)] ==="
check_status "allowed.example.com. HTTP" "$($C http://allowed.example.com./)" "200"

echo "=== [HTTPS - allowed - wildcard] ==="
check_status "sub.wildcard.example.com" "$($C https://sub.wildcard.example.com/)" "200"

echo "=== [HTTPS - regex rule written without anchors] ==="
check_status "ok.regex.example.com" "$($C https://ok.regex.example.com/)" "200"

echo "=== [HTTPS - regex rule must not match a name merely containing it] ==="
CODE=$($C --max-time 5 https://not-ok.regex.example.com/ 2>/dev/null || echo "000")
if [ "$CODE" != "200" ]; then
  pass "not-ok.regex.example.com blocked (got $CODE)"
else
  fail "not-ok.regex.example.com reached the origin"
fi

echo "=== [HTTPS - regex rule with a grouped port alternation] ==="
check_status "ports.regex.example.com:443" "$($C https://ports.regex.example.com/)" "200"
check_status "ports.regex.example.com:8443" "$($C https://ports.regex.example.com:8443/)" "200"

echo "=== [HTTP - regex rule names https ports only] ==="
CODE=$($C --max-time 5 http://ports.regex.example.com/ 2>/dev/null || echo "000")
if [ "$CODE" != "200" ]; then
  pass "ports.regex.example.com:80 blocked (got $CODE)"
else
  fail "ports.regex.example.com:80 reached the origin"
fi

echo "=== [HTTPS - blocked - nested subdomain] ==="
CODE=$($C --max-time 5 https://deep.sub.wildcard.example.com/ 2>/dev/null || echo "000")
if [ "$CODE" != "200" ]; then
  pass "deep.sub.wildcard.example.com blocked (got $CODE)"
else
  fail "deep.sub.wildcard.example.com reached the origin"
fi

echo "=== [HTTPS - blocked] ==="
CODE=$($C --max-time 5 https://blocked.example.com/ 2>/dev/null || echo "000")
if [ "$CODE" != "200" ]; then
  pass "blocked.example.com blocked (got $CODE)"
else
  fail "blocked.example.com reached the origin"
fi

echo "=== [HTTP - allowed] ==="
check_status "allowed.example.com HTTP" "$($C http://allowed.example.com/)" "200"

echo "=== [HTTP - blocked] ==="
CODE=$($C --max-time 5 http://blocked.example.com/ 2>/dev/null || echo "000")
if [ "$CODE" != "200" ]; then
  pass "blocked.example.com HTTP blocked (got $CODE)"
else
  fail "blocked.example.com HTTP reached the origin"
fi

echo "=== [HTTP - allowed - wildcard] ==="
check_status "sub.wildcard.example.com HTTP" "$($C http://sub.wildcard.example.com/)" "200"

echo "=== [Port 8443 - allowed] ==="
check_status "allowed.example.com:8443" "$($C https://allowed.example.com:8443/)" "200"

echo "=== [Port 8080 - allowed] ==="
check_status "allowed.example.com:8080" "$($C http://allowed.example.com:8080/)" "200"

echo "=== [Port 8443 - blocked] ==="
CODE=$($C --max-time 5 https://blocked.example.com:8443/ 2>/dev/null || echo "000")
if [ "$CODE" != "200" ]; then
  pass "blocked.example.com:8443 blocked (got $CODE)"
else
  fail "blocked.example.com:8443 reached the origin"
fi

echo "=== [Port 8080 - blocked] ==="
CODE=$($C --max-time 5 http://blocked.example.com:8080/ 2>/dev/null || echo "000")
if [ "$CODE" != "200" ]; then
  pass "blocked.example.com:8080 blocked (got $CODE)"
else
  fail "blocked.example.com:8080 reached the origin"
fi

echo "=== [Direct IP - blocked (no allowed_ip_rules entry for the port)] ==="
CODE=$($C --max-time 5 http://10.200.0.100/ 2>/dev/null || echo "000")
if [ "$CODE" != "200" ]; then
  pass "10.200.0.100 blocked (got $CODE)"
else
  fail "10.200.0.100 reached the origin directly"
fi

# The SNI is the client's to choose, so it must decide neither way: a name there
# must not refuse the allowed address, and the allowed address there must not
# open another one. curl never sends an address as SNI; openssl does.
echo "=== [Direct IP - allowed, SNI names a host] ==="
check_status "10.200.0.100:8443 with SNI allowed.example.com" \
  "$($C --resolve allowed.example.com:8443:10.200.0.100 https://allowed.example.com:8443/)" "200"

echo "=== [Direct IP - blocked, SNI names an allowed address] ==="
if timeout 10 openssl s_client -connect 10.200.0.101:8443 -servername 10.200.0.100 \
  < /dev/null 2>/dev/null | grep -q '^New, '; then
  fail "10.200.0.101:8443 completed a handshake under SNI 10.200.0.100"
else
  pass "10.200.0.101:8443 blocked"
fi

echo "=== [HTTPS - dns-failed (NXDOMAIN)] ==="
CODE=$($C --max-time 5 https://nxdomain.wildcard.example.com/ 2>/dev/null || echo "000")
if [ "$CODE" != "200" ]; then
  pass "nxdomain.wildcard.example.com blocked (got $CODE)"
else
  fail "nxdomain.wildcard.example.com reached the origin"
fi

echo "=== [HTTPS - dns-failed (AAAA only, no A record)] ==="
CODE=$($C --max-time 5 https://v6only.wildcard.example.com/ 2>/dev/null || echo "000")
if [ "$CODE" != "200" ]; then
  pass "v6only.wildcard.example.com blocked (got $CODE)"
else
  fail "v6only.wildcard.example.com reached the origin"
fi

echo "=== [HTTP - dns-failed (AAAA only, no A record)] ==="
# The HTTP path resolves through a do-resolve pair of its own, so the HTTPS
# case above says nothing about it.
CODE=$($C --max-time 5 http://v6only.wildcard.example.com/ 2>/dev/null || echo "000")
if [ "$CODE" != "200" ]; then
  pass "v6only.wildcard.example.com HTTP blocked (got $CODE)"
else
  fail "v6only.wildcard.example.com HTTP reached the origin"
fi

echo "=== [HTTP - dns-failed (NXDOMAIN)] ==="
CODE=$($C --max-time 5 http://nxdomain.wildcard.example.com/ 2>/dev/null || echo "000")
if [ "$CODE" != "200" ]; then
  pass "nxdomain.wildcard.example.com HTTP blocked (got $CODE)"
else
  fail "nxdomain.wildcard.example.com HTTP reached the origin"
fi

# [SSRF - allowlisted name resolving to an internal address (169.254.169.254)]
# internal.wildcard.example.com matches the *.wildcard.example.com allowlist
# rule but resolves to a link-local address; the name passes the rules, but
# the resolved address must not.
echo "=== [HTTPS - SSRF via allowlisted name] ==="
CODE=$($C --max-time 5 https://internal.wildcard.example.com/ 2>/dev/null || echo "000")
if [ "$CODE" != "200" ]; then
  pass "internal.wildcard.example.com blocked (got $CODE)"
else
  fail "internal.wildcard.example.com reached an internal address"
fi

echo "=== [HTTP - SSRF via allowlisted name] ==="
CODE=$($C --max-time 5 http://internal.wildcard.example.com/ 2>/dev/null || echo "000")
if [ "$CODE" != "200" ]; then
  pass "internal.wildcard.example.com HTTP blocked (got $CODE)"
else
  fail "internal.wildcard.example.com HTTP reached an internal address"
fi

# [SSRF - allowlisted name resolving to a runner address]
# RFC1918 is exempt on purpose, so only the runner's address list refuses it.
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

# [HTTP keep-alive - allowed then blocked: a second request on a reused
# HTTP/1.1 keep-alive connection must be judged on its own merits, not
# inherit the first request's decision. Verified against the report by
# test/integration-test-universal-restrict.sh, since this script only sees
# curl/nc exit status, not the proxy's log.]
echo "=== [HTTP keep-alive - allowed then blocked] ==="
((printf 'GET / HTTP/1.1\r\nHost: allowed.example.com\r\n\r\n'; sleep 1; \
  printf 'GET / HTTP/1.1\r\nHost: blocked.example.com\r\nConnection: close\r\n\r\n'; sleep 1) \
 | nc -w 5 allowed.example.com 80 > /dev/null 2>&1 || true)
echo "  requests sent over one keep-alive connection (checked against the report)"

# The other direction, which the pair above cannot show: a refusal must not
# carry over either. keepalive.wildcard.example.com is requested here and
# nowhere else, so the report showing it as allowed is this connection's
# second request and nothing else.
echo "=== [HTTP keep-alive - blocked then allowed] ==="
((printf 'GET / HTTP/1.1\r\nHost: blocked.example.com\r\n\r\n'; sleep 1; \
  printf 'GET / HTTP/1.1\r\nHost: keepalive.wildcard.example.com\r\nConnection: close\r\n\r\n'; sleep 1) \
 | nc -w 5 allowed.example.com 80 > /dev/null 2>&1 || true)
echo "  requests sent over one keep-alive connection (checked against the report)"

# [TLS ClientHello with no SNI extension at all. There is no name to judge,
# so the connection is refused on that alone; the report records the
# address it was headed for, which is the proxy's own.]
echo "=== [HTTPS - missing-sni] ==="
(printf '\x16\x03\x01\x00\x2d\x01\x00\x00\x29\x03\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x02\x00\xff\x01\x00' \
 | nc -w 5 allowed.example.com 443 > /dev/null 2>&1 || true)
echo "  request sent (blocked expected in the report)"

# [HTTP/1.0 request with no Host header, the plaintext counterpart of the
# case above.]
echo "=== [HTTP - missing-host-header] ==="
((printf 'GET / HTTP/1.0\r\n\r\n'; sleep 1) | nc -w 5 allowed.example.com 80 > /dev/null 2>&1 || true)
echo "  request sent (blocked expected in the report)"

# [A crafted SNI carrying the bytes of a log line: x" -\n[T] buildcage
# [ALLOWED] (HTTPS) "forged.example.com. Breaking out of the "..." quoting
# would put a second, fabricated ALLOWED line in the log the report is built
# from. It must arrive as one sanitized BLOCKED row instead.]
echo "=== [HTTPS - forged SNI] ==="
(printf '\x16\x03\x01\x00\x70\x01\x00\x00\x6c\x03\x03\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x02\x00\xff\x01\x00\x00\x41\x00\x00\x00\x3d\x00\x3b\x00\x00\x38\x78\x22\x20\x2d\x0a\x5b\x54\x5d\x20\x62\x75\x69\x6c\x64\x63\x61\x67\x65\x20\x5b\x41\x4c\x4c\x4f\x57\x45\x44\x5d\x20\x28\x48\x54\x54\x50\x53\x29\x20\x22\x66\x6f\x72\x67\x65\x64\x2e\x65\x78\x61\x6d\x70\x6c\x65\x2e\x63\x6f\x6d' \
 | nc -w 5 allowed.example.com 443 > /dev/null 2>&1 || true)
echo "  request sent (one sanitized blocked row expected in the report)"

scenario_results

#!/bin/bash
# Runs *inside* the sandbox, as the `run:` input of a real proxy_engine:
# universal step (see test/integration-test-universal-restrict.sh).
#
# ---------------------------------------------------------------------------
# Rules under test (set by test/integration-test-universal-restrict.sh):
#   allowed_https_rules: allowed.example.com:443 allowed.example.com:8443
#                        *.wildcard.example.com:443 *.wildcard.example.com:8443
#   allowed_http_rules:  allowed.example.com:80 allowed.example.com:8080
#                        *.wildcard.example.com:80 *.wildcard.example.com:8080
# ---------------------------------------------------------------------------
set -uo pipefail

FAILURES=0
C="curl -sS -k -o /dev/null -w %{http_code} --max-time 10"

check_status() {
  local label="$1" code="$2" want="$3"
  if [ "$code" = "$want" ]; then
    echo "  PASS  $label"
  else
    echo "  FAIL  $label -- expected $want, got $code"
    FAILURES=$((FAILURES + 1))
  fi
}

echo "=== [HTTPS - allowed - exact match] ==="
check_status "allowed.example.com" "$($C https://allowed.example.com/)" "200"

echo "=== [HTTPS - allowed - wildcard] ==="
check_status "sub.wildcard.example.com" "$($C https://sub.wildcard.example.com/)" "200"

echo "=== [HTTPS - blocked - nested subdomain] ==="
CODE=$($C --max-time 5 https://deep.sub.wildcard.example.com/ 2>/dev/null || echo "000")
if [ "$CODE" != "200" ]; then
  echo "  PASS  deep.sub.wildcard.example.com blocked (got $CODE)"
else
  echo "  FAIL  deep.sub.wildcard.example.com reached the origin"
  FAILURES=$((FAILURES + 1))
fi

echo "=== [HTTPS - blocked] ==="
CODE=$($C --max-time 5 https://blocked.example.com/ 2>/dev/null || echo "000")
if [ "$CODE" != "200" ]; then
  echo "  PASS  blocked.example.com blocked (got $CODE)"
else
  echo "  FAIL  blocked.example.com reached the origin"
  FAILURES=$((FAILURES + 1))
fi

echo "=== [HTTP - allowed] ==="
check_status "allowed.example.com HTTP" "$($C http://allowed.example.com/)" "200"

echo "=== [HTTP - blocked] ==="
CODE=$($C --max-time 5 http://blocked.example.com/ 2>/dev/null || echo "000")
if [ "$CODE" != "200" ]; then
  echo "  PASS  blocked.example.com HTTP blocked (got $CODE)"
else
  echo "  FAIL  blocked.example.com HTTP reached the origin"
  FAILURES=$((FAILURES + 1))
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
  echo "  PASS  blocked.example.com:8443 blocked (got $CODE)"
else
  echo "  FAIL  blocked.example.com:8443 reached the origin"
  FAILURES=$((FAILURES + 1))
fi

echo "=== [Port 8080 - blocked] ==="
CODE=$($C --max-time 5 http://blocked.example.com:8080/ 2>/dev/null || echo "000")
if [ "$CODE" != "200" ]; then
  echo "  PASS  blocked.example.com:8080 blocked (got $CODE)"
else
  echo "  FAIL  blocked.example.com:8080 reached the origin"
  FAILURES=$((FAILURES + 1))
fi

echo "=== [Direct IP - blocked (no allowed_ip_rules configured)] ==="
CODE=$($C --max-time 5 http://10.200.0.100/ 2>/dev/null || echo "000")
if [ "$CODE" != "200" ]; then
  echo "  PASS  10.200.0.100 blocked (got $CODE)"
else
  echo "  FAIL  10.200.0.100 reached the origin directly"
  FAILURES=$((FAILURES + 1))
fi

echo "=== [HTTPS - dns-failed (NXDOMAIN)] ==="
CODE=$($C --max-time 5 https://nxdomain.wildcard.example.com/ 2>/dev/null || echo "000")
if [ "$CODE" != "200" ]; then
  echo "  PASS  nxdomain.wildcard.example.com blocked (got $CODE)"
else
  echo "  FAIL  nxdomain.wildcard.example.com reached the origin"
  FAILURES=$((FAILURES + 1))
fi

echo "=== [HTTP - dns-failed (NXDOMAIN)] ==="
CODE=$($C --max-time 5 http://nxdomain.wildcard.example.com/ 2>/dev/null || echo "000")
if [ "$CODE" != "200" ]; then
  echo "  PASS  nxdomain.wildcard.example.com HTTP blocked (got $CODE)"
else
  echo "  FAIL  nxdomain.wildcard.example.com HTTP reached the origin"
  FAILURES=$((FAILURES + 1))
fi

# [SSRF - allowlisted name resolving to an internal address (169.254.169.254)]
# internal.wildcard.example.com matches the *.wildcard.example.com allowlist
# rule but resolves to a link-local address; the name passes the rules, the
# resolved address must not.
echo "=== [HTTPS - SSRF via allowlisted name] ==="
CODE=$($C --max-time 5 https://internal.wildcard.example.com/ 2>/dev/null || echo "000")
if [ "$CODE" != "200" ]; then
  echo "  PASS  internal.wildcard.example.com blocked (got $CODE)"
else
  echo "  FAIL  internal.wildcard.example.com reached an internal address"
  FAILURES=$((FAILURES + 1))
fi

echo "=== [HTTP - SSRF via allowlisted name] ==="
CODE=$($C --max-time 5 http://internal.wildcard.example.com/ 2>/dev/null || echo "000")
if [ "$CODE" != "200" ]; then
  echo "  PASS  internal.wildcard.example.com HTTP blocked (got $CODE)"
else
  echo "  FAIL  internal.wildcard.example.com HTTP reached an internal address"
  FAILURES=$((FAILURES + 1))
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

echo "=== End of scenarios: $FAILURES failure(s) ==="
exit "$FAILURES"

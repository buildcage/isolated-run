#!/bin/bash
# Runs *inside* the sandbox, as the `run:` input of a real proxy_engine:
# universal step in audit mode (see test/integration-test-universal-audit.sh).
#
# ---------------------------------------------------------------------------
# Rules under test: none -- audit mode records but does not enforce the
# allowlist, so every name-based connection is expected to succeed except
# the internal-address guard, which stays active unconditionally.
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
  echo "  PASS  internal.wildcard.example.com blocked (got $CODE)"
else
  echo "  FAIL  internal.wildcard.example.com reached an internal address"
  FAILURES=$((FAILURES + 1))
fi

echo "=== [HTTP - SSRF via internal address] ==="
CODE=$($C --max-time 5 http://internal.wildcard.example.com/ 2>/dev/null || echo "000")
if [ "$CODE" != "200" ]; then
  echo "  PASS  internal.wildcard.example.com HTTP blocked (got $CODE)"
else
  echo "  FAIL  internal.wildcard.example.com HTTP reached an internal address"
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

echo "=== End of scenarios: $FAILURES failure(s) ==="
exit "$FAILURES"

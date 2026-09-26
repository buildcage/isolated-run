#!/bin/bash
# Chromium on Linux trusts the Chrome Root Store compiled into it and the NSS
# database in $HOME, and reads neither the system CA store nor any variable, so
# none of the other CA-trust mounts reach it. The action mounts a database
# holding only the proxy CA over the one Chromium would read (see
# src/lib/sandbox/nss-db.ts). Each step here loads a page through the proxy in
# chrome-headless-shell, the minimal build Puppeteer, Playwright and Remotion
# download, and checks what the step left in $HOME afterwards. The last two
# check that a command writing to the database fails the step, pointing at
# fail_on_ca_residue, and only warns when that is false.
set -uo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/helpers.sh"

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

: "${BUILDCAGE_LOCAL_IMAGE_REF:?BUILDCAGE_LOCAL_IMAGE_REF must be set to a locally built inspect-engine image (BUILDCAGE_TEST_HOOKS=1 PROXY_ENGINE=inspect docker compose build proxy)}"

PUPPETEER_VERSION=25.12.0
CHROME_VERSION=154.0.8037.57

echo ""
echo "=== Inspect Engine Integration Test (Chromium's NSS database) ==="
echo ""

echo "--- bringing up fixture origins (compose.test-inspect.yaml) ---"
cleanup() {
  docker compose -f "$REPO_ROOT/compose.test-inspect.yaml" down -v >/dev/null 2>&1 || true
}
trap cleanup EXIT
docker compose -f "$REPO_ROOT/compose.test-inspect.yaml" up -d --build --wait

TMPDIR=$(mktemp -d)

# Outside the sandbox, straight from the registry and Chrome for Testing: what
# is under test is the browser inside it, not how it got there. Chrome for
# Testing ships chrome-headless-shell for x86-64 Linux only.
echo "--- installing puppeteer-core and chrome-headless-shell $CHROME_VERSION ---"
mkdir -p "$TMPDIR/check"
cp "$REPO_ROOT/test/chromium-check.js" "$TMPDIR/check/"
(cd "$TMPDIR/check" && npm install --silent --no-audit --no-fund "puppeteer-core@$PUPPETEER_VERSION" &&
  npx --no-install browsers install "chrome-headless-shell@$CHROME_VERSION" --path "$TMPDIR/chrome") >/dev/null ||
  { fail "could not install chrome-headless-shell"; assert_results; }
CHROME="$TMPDIR/chrome/chrome-headless-shell/linux-$CHROME_VERSION/chrome-headless-shell-linux64/chrome-headless-shell"
CHECK="CHROME_HEADLESS_SHELL=$CHROME node $TMPDIR/check/chromium-check.js https://allowed.example.com/public/chromium"
# What the command sees where Chromium looks, printed ahead of each check so a
# failure shows whether the database was mounted and what was in it.
SHOW="grep nssdb /proc/self/mountinfo || echo 'no nssdb mount'; ls -la \$HOME/.pki/nssdb \$HOME/.local/share/pki/nssdb 2>&1 || true"

# show_home <home>: what the step left in a home, for a failed assertion.
show_home() { find "$1" -ls | sed 's/^/    /'; }

# run_step <home> <run> [VAR=value...]: the action, with HOME pointed at a
# directory of the test's own so the runner's real one is neither read nor
# written. Leaves the output in $OUT and the exit code in $RUN_EXIT.
run_step() {
  local home=$1 run=$2
  shift 2
  touch "$TMPDIR/state.env" "$TMPDIR/summary.md"
  OUT=$(env "$@" \
    HOME="$home" \
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
echo "--- a home with no database ---"
HOME_A="$TMPDIR/home-a"
mkdir -p "$HOME_A"
# The control first: pointed at a home the action did not mount a database
# into, the same browser must refuse the proxy's certificate, or the check
# below could pass for a reason of its own.
run_step "$HOME_A" "
$SHOW
HOME=/tmp/chromium-control $CHECK untrusted
rm -rf /tmp/chromium-control
$CHECK"
if [ "$RUN_EXIT" = "0" ]; then
  pass "refused the proxy's certificate without the database, trusted it with"
else
  fail "the step failed (exit $RUN_EXIT)"
fi
if [ -e "$HOME_A/.local/share/pki" ]; then
  fail "the directories made to mount the database over are still in \$HOME"
  show_home "$HOME_A"
else
  pass "the directories made to mount the database over were taken back"
fi

echo ""
echo "--- a home with its own legacy database ---"
HOME_B="$TMPDIR/home-b"
mkdir -p "$HOME_B/.pki/nssdb"
run_step "$HOME_B" "
$SHOW
$CHECK"
if [ "$RUN_EXIT" = "0" ]; then
  pass "trusted the proxy CA over the runner's own ~/.pki/nssdb"
else
  fail "the step failed (exit $RUN_EXIT)"
fi
if [ -z "$(ls -A "$HOME_B/.pki/nssdb")" ] && [ ! -e "$HOME_B/.local/share/pki" ]; then
  pass "the runner's own database is untouched, and nothing was created beside it"
else
  fail "the runner's own database changed, or something was created beside it"
  show_home "$HOME_B"
fi

echo ""
echo "--- a command that writes to the database ---"
HOME_C="$TMPDIR/home-c"
mkdir -p "$HOME_C"
run_step "$HOME_C" "touch \$HOME/.local/share/pki/nssdb/written-by-the-command"
if [ "$RUN_EXIT" != "0" ]; then
  pass "the step failed"
else
  fail "the step succeeded, so the write was dropped silently"
fi
if grep -q "changed the NSS database at $HOME_C/.local/share/pki/nssdb" <<<"$OUT" &&
  grep -q "fail_on_ca_residue: false" <<<"$OUT"; then
  pass "the failure names the database and points at fail_on_ca_residue"
else
  fail "the output does not name the database, or does not point at fail_on_ca_residue"
fi

echo ""
echo "--- the same command under fail_on_ca_residue: false ---"
run_step "$HOME_C" "touch \$HOME/.local/share/pki/nssdb/written-by-the-command" INPUT_FAIL_ON_CA_RESIDUE=false
if [ "$RUN_EXIT" = "0" ]; then
  pass "the step carried on"
else
  fail "the step failed (exit $RUN_EXIT)"
fi
if grep -q "changed the NSS database at $HOME_C/.local/share/pki/nssdb.*fail_on_ca_residue is false" <<<"$OUT"; then
  pass "a warning names the database"
else
  fail "no warning names the database"
fi
if [ -e "$HOME_C/.local/share/pki" ]; then
  fail "the write reached \$HOME"
  show_home "$HOME_C"
else
  pass "the write was discarded, and the directories taken back"
fi

rm -rf "$TMPDIR"

assert_results

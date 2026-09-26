#!/bin/bash
# chrome-headless-shell must trust the proxy CA through the NSS database the
# action mounts over ~/.pki/nssdb, leave $HOME as it found it, and fail the step
# on a write to the database unless fail_on_ca_residue is false.
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

# Installed outside the sandbox. Chrome for Testing ships chrome-headless-shell
# for x86-64 Linux only.
echo "--- installing puppeteer-core and chrome-headless-shell $CHROME_VERSION ---"
mkdir -p "$TMPDIR/check"
cp "$REPO_ROOT/test/chromium-check.js" "$TMPDIR/check/"
(cd "$TMPDIR/check" && npm install --silent --no-audit --no-fund "puppeteer-core@$PUPPETEER_VERSION" &&
  npx --no-install browsers install "chrome-headless-shell@$CHROME_VERSION" --path "$TMPDIR/chrome") >/dev/null ||
  { fail "could not install chrome-headless-shell"; assert_results; }
CHROME="$TMPDIR/chrome/chrome-headless-shell/linux-$CHROME_VERSION/chrome-headless-shell-linux64/chrome-headless-shell"
CHECK="CHROME_HEADLESS_SHELL=$CHROME node $TMPDIR/check/chromium-check.js https://allowed.example.com/public/chromium"
# Printed before each check so a failure shows what was mounted.
SHOW="grep nssdb /proc/self/mountinfo || echo 'no nssdb mount'; ls -la \$HOME/.pki/nssdb 2>&1 || true"

show_home() { find "$1" -ls | sed 's/^/    /'; }

# run_step <home> <run> [VAR=value...]: runs the action with HOME pointed away
# from the runner's real one. Sets $OUT and $RUN_EXIT.
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
# Control: without the database the same browser must refuse the proxy.
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
if [ -e "$HOME_A/.pki" ]; then
  fail "the directories made to mount the database over are still in \$HOME"
  show_home "$HOME_A"
else
  pass "the directories made to mount the database over were taken back"
fi

echo ""
echo "--- a home with its own XDG database ---"
HOME_B="$TMPDIR/home-b"
mkdir -p "$HOME_B/.local/share/pki/nssdb"
run_step "$HOME_B" "
$SHOW
$CHECK"
if [ "$RUN_EXIT" = "0" ]; then
  pass "trusted the proxy CA beside the runner's own XDG database"
else
  fail "the step failed (exit $RUN_EXIT)"
fi
if [ -z "$(ls -A "$HOME_B/.local/share/pki/nssdb")" ] && [ ! -e "$HOME_B/.pki" ]; then
  pass "the runner's own database is untouched, and ~/.pki was taken back"
else
  fail "the runner's own database changed, or ~/.pki was left behind"
  show_home "$HOME_B"
fi

echo ""
echo "--- a home with its own ~/.pki/nssdb ---"
HOME_D="$TMPDIR/home-d"
mkdir -p "$HOME_D/.pki/nssdb"
run_step "$HOME_D" "
$SHOW
$CHECK"
if [ "$RUN_EXIT" = "0" ]; then
  pass "trusted the proxy CA over the runner's own ~/.pki/nssdb"
else
  fail "the step failed (exit $RUN_EXIT)"
fi
if [ -z "$(ls -A "$HOME_D/.pki/nssdb")" ]; then
  pass "the runner's own database is untouched"
else
  fail "the runner's own database changed"
  show_home "$HOME_D"
fi

echo ""
echo "--- a command that writes to the database ---"
HOME_C="$TMPDIR/home-c"
mkdir -p "$HOME_C"
run_step "$HOME_C" "touch \$HOME/.pki/nssdb/written-by-the-command"
if [ "$RUN_EXIT" != "0" ]; then
  pass "the step failed"
else
  fail "the step succeeded, so the write was dropped silently"
fi
if grep -q "changed the NSS database at $HOME_C/.pki/nssdb" <<<"$OUT" &&
  grep -q "fail_on_ca_residue: false" <<<"$OUT"; then
  pass "the failure names the database and points at fail_on_ca_residue"
else
  fail "the output does not name the database, or does not point at fail_on_ca_residue"
fi

echo ""
echo "--- the same command under fail_on_ca_residue: false ---"
run_step "$HOME_C" "touch \$HOME/.pki/nssdb/written-by-the-command" INPUT_FAIL_ON_CA_RESIDUE=false
if [ "$RUN_EXIT" = "0" ]; then
  pass "the step carried on"
else
  fail "the step failed (exit $RUN_EXIT)"
fi
if grep -q "changed the NSS database at $HOME_C/.pki/nssdb.*fail_on_ca_residue is false" <<<"$OUT"; then
  pass "a warning names the database"
else
  fail "no warning names the database"
fi
if [ -e "$HOME_C/.pki" ]; then
  fail "the write reached \$HOME"
  show_home "$HOME_C"
else
  pass "the write was discarded, and the directories taken back"
fi

rm -rf "$TMPDIR"

assert_results

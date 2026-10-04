#!/bin/bash
# chrome-headless-shell must trust the proxy CA through the slot the action adds
# to the runner's own NSS database. What the command writes to that database is
# kept where filesystem_mode keeps writes, below a write_through: entry under
# ephemeral included, less the slot; a copy of the CA left there fails the step
# unless fail_on_ca_residue is false. A database the runner user cannot write
# is left alone with a warning. Directories made for a new database are removed
# afterwards, and removing one on the host mid-command gives a warning.
set -uo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/helpers.sh"

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

: "${BUILDCAGE_LOCAL_IMAGE_REF:?BUILDCAGE_LOCAL_IMAGE_REF must be set to a locally built inspect-engine image (BUILDCAGE_TEST_HOOKS=1 PROXY_ENGINE=inspect docker compose build proxy)}"

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
cp -R "$REPO_ROOT/test/chromium" "$TMPDIR/check"
(cd "$TMPDIR/check" && npm ci --silent --no-audit --no-fund &&
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

# no_slot <dir>: the database holds nothing of the slot once the step is over.
no_slot() {
  ! grep -rqs buildcage "$1"
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
if [ -e "$HOME_A/.pki/nssdb/cert9.db" ] && no_slot "$HOME_A/.pki/nssdb"; then
  pass "the database Chromium created is kept, without the slot"
else
  fail "the database Chromium created is missing, or still holds the slot"
  show_home "$HOME_A"
fi

echo ""
echo "--- a home with its own XDG database ---"
HOME_B="$TMPDIR/home-b"
mkdir -p "$HOME_B/.local/share/pki/nssdb"
run_step "$HOME_B" "
$SHOW
$CHECK"
if [ "$RUN_EXIT" = "0" ]; then
  pass "trusted the proxy CA through the runner's own XDG database"
else
  fail "the step failed (exit $RUN_EXIT)"
fi
if no_slot "$HOME_B/.local/share/pki/nssdb" && [ ! -e "$HOME_B/.pki" ]; then
  pass "the XDG database holds no slot, and no ~/.pki was made"
else
  fail "the XDG database still holds the slot, or ~/.pki was made"
  show_home "$HOME_B"
fi

echo ""
echo "--- a command that writes to the database ---"
HOME_C="$TMPDIR/home-c"
mkdir -p "$HOME_C/.pki/nssdb"
printf 'library=\nname=the runner'"'"'s own\n' >"$HOME_C/.pki/nssdb/pkcs11.txt"
run_step "$HOME_C" "
grep -q buildcage \$HOME/.pki/nssdb/pkcs11.txt
touch \$HOME/.pki/nssdb/written-by-the-command"
if [ "$RUN_EXIT" = "0" ]; then
  pass "the step carried on"
else
  fail "the step failed (exit $RUN_EXIT)"
fi
if [ -e "$HOME_C/.pki/nssdb/written-by-the-command" ] &&
  [ "$(cat "$HOME_C/.pki/nssdb/pkcs11.txt")" = "$(printf 'library=\nname=the runner'"'"'s own')" ]; then
  pass "the write reached \$HOME, and pkcs11.txt is as the runner left it"
else
  fail "the write did not reach \$HOME, or pkcs11.txt changed"
  show_home "$HOME_C"
fi

echo ""
echo "--- the same command under filesystem_mode: ephemeral ---"
HOME_E="$TMPDIR/home-e"
mkdir -p "$HOME_E"
run_step "$HOME_E" "touch \$HOME/.pki/nssdb/written-by-the-command" INPUT_FILESYSTEM_MODE=ephemeral
if [ "$RUN_EXIT" = "0" ]; then
  pass "the step carried on"
else
  fail "the step failed (exit $RUN_EXIT)"
fi
if [ -e "$HOME_E/.pki" ]; then
  fail "the write reached \$HOME"
  show_home "$HOME_E"
else
  pass "the write was discarded, and the directories taken back"
fi

echo ""
echo "--- a command that leaves the database alone ---"
HOME_I="$TMPDIR/home-i"
mkdir -p "$HOME_I"
run_step "$HOME_I" "true"
if [ "$RUN_EXIT" = "0" ] && [ ! -e "$HOME_I/.pki" ]; then
  pass "the directories made for the database were taken back"
else
  fail "the step failed, or left ~/.pki behind (exit $RUN_EXIT)"
  show_home "$HOME_I"
fi

echo ""
echo "--- the database's directory removed outside the sandbox while the command runs ---"
HOME_J="$TMPDIR/home-j"
mkdir -p "$HOME_J"
rm -f "$TMPDIR/started-j"
(
  for _ in $(seq 600); do
    [ -e "$TMPDIR/started-j" ] && break
    sleep 0.1
  done
  rm -rf "$HOME_J/.pki"
) &
REMOVER=$!
run_step "$HOME_J" "touch $TMPDIR/started-j; sleep 3"
wait "$REMOVER"
if [ "$RUN_EXIT" = "0" ] &&
  grep -q "$HOME_J/.pki/nssdb was removed or replaced on the runner while the command ran" <<<"$OUT"; then
  pass "the step warned, naming the database, and carried on"
else
  fail "the step failed, or gave no warning (exit $RUN_EXIT)"
fi

echo ""
echo "--- the same under filesystem_mode: ephemeral, below a write_through: entry ---"
HOME_H="$TMPDIR/home-h"
mkdir -p "$HOME_H/.pki/nssdb"
printf 'library=\nname=the runner'"'"'s own\n' >"$HOME_H/.pki/nssdb/pkcs11.txt"
# The module is appended after the slot, as modutil does.
run_step "$HOME_H" "
$SHOW
$CHECK
touch \$HOME/.pki/nssdb/written-by-the-command
printf 'library=added.so\nname=added\n\n' >>\$HOME/.pki/nssdb/pkcs11.txt" \
  INPUT_FILESYSTEM_MODE=ephemeral INPUT_WRITE_THROUGH="$HOME_H/.pki"
if [ "$RUN_EXIT" = "0" ]; then
  pass "trusted the proxy CA through the slot under ephemeral"
else
  fail "the step failed (exit $RUN_EXIT)"
fi
if [ -e "$HOME_H/.pki/nssdb/written-by-the-command" ] &&
  [ "$(cat "$HOME_H/.pki/nssdb/pkcs11.txt")" = "$(printf 'library=\nname=the runner'"'"'s own\n\nlibrary=added.so\nname=added')" ]; then
  pass "the write reached \$HOME, and the added module is an entry of its own without the slot"
else
  fail "the write did not reach \$HOME, or pkcs11.txt is not the runner's plus the added module"
  show_home "$HOME_H"
  cat "$HOME_H/.pki/nssdb/pkcs11.txt"
fi

echo ""
echo "--- a command that copies the CA into the database ---"
HOME_F="$TMPDIR/home-f"
mkdir -p "$HOME_F/.pki/nssdb"
run_step "$HOME_F" "cp /dev/buildcage-nssdb/cert9.db \$HOME/.pki/nssdb/copy.db"
if [ "$RUN_EXIT" != "0" ] && grep -q "copied the proxy CA into the NSS database at $HOME_F/.pki/nssdb" <<<"$OUT" &&
  grep -q "fail_on_ca_residue: false" <<<"$OUT"; then
  pass "the step failed, naming the database and pointing at fail_on_ca_residue"
else
  fail "the step did not fail on the copy (exit $RUN_EXIT)"
fi
if [ -e "$HOME_F/.pki/nssdb/copy.db" ]; then
  fail "the copy of the CA reached \$HOME"
else
  pass "the copy of the CA was not written back"
fi

echo ""
echo "--- a database the runner user cannot write ---"
HOME_G="$TMPDIR/home-g"
mkdir -p "$HOME_G/.pki/nssdb"
chmod 555 "$HOME_G/.pki/nssdb"
run_step "$HOME_G" "
$SHOW
$CHECK untrusted"
if [ "$RUN_EXIT" = "0" ] && grep -q "the runner user cannot write $HOME_G/.pki/nssdb" <<<"$OUT" &&
  grep -q "use proxy_engine: universal" <<<"$OUT" && grep -q "no nssdb mount" <<<"$OUT"; then
  pass "the step warned, naming the database and pointing at universal, and mounted nothing"
else
  fail "the step failed, gave no warning, or mounted over the database (exit $RUN_EXIT)"
fi
chmod 755 "$HOME_G/.pki/nssdb"
if [ -z "$(ls -A "$HOME_G/.pki/nssdb")" ]; then
  pass "the database is untouched"
else
  fail "the database changed"
  show_home "$HOME_G"
fi

rm -rf "$TMPDIR"

assert_results

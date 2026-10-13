#!/bin/bash
# Verifies filesystem_mode: ephemeral / write_through: end-to-end by driving
# dist/main.cjs directly, without the real action wrapper; test-e2e.yml's
# enforcement steps cover write_through: through the real action, and
# nothing there sets filesystem_mode: at all.
# The mount-composition/path-resolution rules themselves are already
# unit-tested (ephemeral-fs.test.ts, oci-config.test.ts); this proves runc
# actually honors them. The mediated $GITHUB_OUTPUT and $GITHUB_STEP_SUMMARY
# are checked in integration-test-file-commands.sh.
#
# One case is left out on purpose: the clear error an overlay probe failure
# raises isn't exercised here, because it needs an environment where
# overlayfs itself doesn't work, which contradicts everything else in this file
# running successfully. Covered instead by the mac-only dev loop
# (`make test_sandbox_dev`), where overlayfs-on-overlayfs is known to fail
# (see overlayfs-preflight.ts's REQUIREMENT message).
set -uo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/driver-helpers.sh"

require_local_image

# Runs dist/main.cjs with filesystem_mode: ephemeral against a fresh
# $GITHUB_WORKSPACE/$RUNNER_TEMP (both under mktemp's default, i.e. /tmp,
# never inside the real $HOME, so $HOME survives folding as its own overlay
# root instead of being subsumed by GITHUB_WORKSPACE/RUNNER_TEMP; see
# determineOverlayRoots). $1=workdir (already created) $2=write_through input
# $3=run script. Writes $workdir/out.log and $workdir/exit_code.
run_ephemeral() {
  local workdir="$1" write_through="$2" run_script="$3"
  local runner_temp
  runner_temp=$(mktemp -d)
  touch "$workdir/state.env" "$workdir/summary.md"
  GITHUB_WORKSPACE="$workdir" \
  GITHUB_STATE="$workdir/state.env" \
  GITHUB_STEP_SUMMARY="$workdir/summary.md" \
  RUNNER_TEMP="$runner_temp" \
  BUILDCAGE_LOCAL_IMAGE_REF="$BUILDCAGE_LOCAL_IMAGE_REF" \
  INPUT_FILESYSTEM_MODE="ephemeral" \
  INPUT_WRITE_THROUGH="$write_through" \
  INPUT_RUN="$run_script" \
    node "$REPO_ROOT/dist/main.cjs" >"$workdir/out.log" 2>&1
  echo $? >"$workdir/exit_code"
  rm -rf "$runner_temp"
}

echo ""
echo "=== Sandbox filesystem_mode: ephemeral / write_through: Assertions ==="
echo ""

# A fresh runner has no scratch base at all, which is the state this test
# has to cover: earlier runs in the same Makefile target (all persistent
# mode) leave one behind at 0700, masking a preflight that only works
# because the base already exists in the right shape.
sudo rm -rf "/var/tmp/buildcage-$(id -u)"

# --- Without write_through, one sandbox for every check, since a start is not
# cheap; the UNEXPECTED lines in out.log say which in-sandbox check gave way.
# - $HOME writes (create + delete) never reach the host.
# - A host mount nested under an overlay root, here the workspace under /tmp,
#   is seen with its contents and written to without the writes reaching the
#   host. Both a separate filesystem and a bind of the same one, since
#   overlayfs hides either, plus a mount whose path is longer than one file
#   name may be.
# - /tmp and $HOME keep the host's owner and mode, /tmp's root 1777 included,
#   and a file made under /tmp does not reach the host.
# - The setup log shows the folded ephemeral paths and a discard line.
# - The scratch dir (including the overlay upper/work dirs) is fully cleaned
#   up, compared by listing rather than by the randomly generated name.
HOME_MARKER="$HOME/.buildcage-ephemeral-test-marker"
HOME_PRELOADED="$HOME/.buildcage-ephemeral-test-preloaded"
rm -f "$HOME_MARKER" "$HOME_PRELOADED"
echo "pre-existing-on-host" >"$HOME_PRELOADED"
TMP_MARKER="/tmp/.buildcage-ephemeral-tmp-marker-$$"
HOST_ATTRS="$(stat -c '%u:%g %a' /tmp) $(stat -c '%u:%g %a' "$HOME")"
NONE=$(mktemp -d)
BIND_SRC=$(mktemp -d)
DEEP=$(printf 'd%.0s' {1..100})
DEEP="$DEEP/$DEEP/$DEEP/deep"
mkdir -p "$NONE/tool" "$NONE/bound" "$NONE/$DEEP"
sudo -n mount -t tmpfs -o "mode=0777" tmpfs "$NONE/tool"
sudo -n mount -t tmpfs -o "mode=0777" tmpfs "$NONE/$DEEP"
echo tool >"$NONE/tool/present"
echo deep >"$NONE/$DEEP/present"
echo bound >"$BIND_SRC/present"
sudo -n mount --bind "$BIND_SRC" "$NONE/bound"
SCRATCH_BASE="/var/tmp/buildcage-$(id -u)"
BEFORE=$(sudo -n find "$SCRATCH_BASE" -maxdepth 1 -mindepth 1 2>/dev/null | sort)
BC_DEEP="$DEEP" BC_HOST_ATTRS="$HOST_ATTRS" BC_TMP_MARKER="$TMP_MARKER" \
  run_ephemeral "$NONE" "" 'rc=0
touch "$HOME/.buildcage-ephemeral-test-marker"
rm -f "$HOME/.buildcage-ephemeral-test-preloaded"
for dir in "$GITHUB_WORKSPACE/tool" "$GITHUB_WORKSPACE/bound" "$GITHUB_WORKSPACE/$BC_DEEP"; do
  [ -f "$dir/present" ] || { echo "UNEXPECTED: $dir/present not visible"; rc=1; }
  echo x >"$dir/written" || { echo "UNEXPECTED: $dir not writable"; rc=1; }
done
attrs="$(stat -c "%u:%g %a" /tmp) $(stat -c "%u:%g %a" "$HOME")"
[ "$attrs" = "$BC_HOST_ATTRS" ] || { echo "UNEXPECTED: $attrs, host has $BC_HOST_ATTRS"; rc=1; }
echo x >"$BC_TMP_MARKER"
exit $rc'
CODE_NONE=$(cat "$NONE/exit_code")
AFTER=$(sudo -n find "$SCRATCH_BASE" -maxdepth 1 -mindepth 1 2>/dev/null | sort)
LOG_NONE="$NONE/out.log"
FAILURES_BEFORE_NONE=$FAILURES
# The leak checks below need the command to have run, or an absent marker
# would pass them untested.
if [ "$CODE_NONE" = "0" ]; then
  pass "a host mount under an overlay root is visible and writable, and /tmp and \$HOME keep the host's owner and mode"
else
  fail "a check inside the sandbox gave way (exit $CODE_NONE)"
fi
if [ "$CODE_NONE" = "0" ] && [ ! -e "$HOME_MARKER" ]; then
  pass "a file created under \$HOME during the step is not on the host afterwards"
else
  fail "a file created under \$HOME during the step leaked to the host"
fi
if [ "$CODE_NONE" = "0" ] && [ -f "$HOME_PRELOADED" ] &&
  [ "$(cat "$HOME_PRELOADED")" = "pre-existing-on-host" ]; then
  pass "deleting a pre-existing \$HOME file inside the sandbox does not delete it on the host"
else
  fail "a pre-existing \$HOME file was actually removed from the host by an in-sandbox delete"
fi
if [ "$CODE_NONE" = "0" ] && [ ! -e "$NONE/tool/written" ] && [ ! -e "$BIND_SRC/written" ] &&
  [ ! -e "$NONE/$DEEP/written" ]; then
  pass "writes to a host mount under an overlay root are discarded"
else
  fail "a write to a host mount under an overlay root reached the host"
fi
if [ "$CODE_NONE" = "0" ] && [ ! -e "$TMP_MARKER" ]; then
  pass "a write to /tmp is discarded"
else
  fail "a write to /tmp reached the host"
fi
if grep -q "^Filesystem mode: ephemeral$" "$LOG_NONE" &&
  grep -q "^Ephemeral (writes discarded at step end): $HOME$" "$LOG_NONE"; then
  pass "setup log shows the folded ephemeral paths"
else
  fail "setup log is missing the expected filesystem-mode lines"
fi
if grep -q "^Discarded ephemeral writes under .*$HOME" "$LOG_NONE"; then
  pass "a discard line is logged for the ephemeral overlay roots"
else
  fail "no discard line was logged for the ephemeral overlay roots"
fi
if [ "$BEFORE" = "$AFTER" ]; then
  pass "the run's scratch dir (including overlay upper/work) is fully cleaned up afterwards"
else
  fail "the run's scratch dir was not fully cleaned up -- before/after $SCRATCH_BASE listings differ"
  echo "before: $BEFORE"
  echo "after:  $AFTER"
fi
if [ "$FAILURES" != "$FAILURES_BEFORE_NONE" ]; then
  cat "$LOG_NONE"
fi
sudo -n umount "$NONE/tool" "$NONE/bound" "$NONE/$DEEP"
rm -rf "$NONE" "$BIND_SRC"
rm -f "$HOME_MARKER" "$HOME_PRELOADED" "$TMP_MARKER"

# --- write_through: a missing target under a runner-owned tree
# ($GITHUB_WORKSPACE) is created runner-owned, and an existing directory the
# runner can already write that is not one of the fixed overlay candidates
# (CI images make /opt writable by the runner user) persists writes too.
THROUGH=$(mktemp -d)
rm -f /opt/.buildcage-ephemeral-allow-write-test
run_ephemeral "$THROUGH" "./dist
/opt" 'rc=0
echo "built" > "$GITHUB_WORKSPACE/dist/output.txt" || rc=1
echo x > /opt/.buildcage-ephemeral-allow-write-test || rc=1
exit $rc'
CODE_THROUGH=$(cat "$THROUGH/exit_code")
LOG_THROUGH="$THROUGH/out.log"
FAILURES_BEFORE_THROUGH=$FAILURES
check_status "write_through: ./dist and /opt: the step held" "$CODE_THROUGH" 0
# A file on the host is itself the proof it persisted, so each entry is judged
# on its own whatever the other did.
if [ -f "$THROUGH/dist/output.txt" ]; then
  pass "write_through: ./dist creates the missing dir runner-owned and persists writes under it"
else
  fail "write_through: ./dist did not persist the write"
fi
if [ -f /opt/.buildcage-ephemeral-allow-write-test ]; then
  pass "write_through: /opt persists a write to an existing, already-writable directory"
else
  fail "write_through: /opt did not persist the write"
fi
if grep -q "^Writable (persisted): *$THROUGH/dist$" "$LOG_THROUGH" &&
  grep -q "^Writable (persisted): */opt$" "$LOG_THROUGH"; then
  pass "setup log shows the persisted paths"
else
  fail "setup log is missing the persisted paths"
fi
if [ "$FAILURES" != "$FAILURES_BEFORE_THROUGH" ]; then
  cat "$LOG_THROUGH"
fi
rm -f /opt/.buildcage-ephemeral-allow-write-test
rm -rf "$THROUGH"

# --- A missing write_through target under a tree the runner can't write fails
# the step before the command runs, and nothing is created. Uses a throwaway
# /etc subdirectory; needs sudo to clean up in case a failure leaves it behind.
ETC_TARGET="/etc/buildcage-ephemeral-test-$$"
sudo -n rm -rf "$ETC_TARGET" 2>/dev/null
REFUSED=$(mktemp -d)
run_ephemeral "$REFUSED" "$ETC_TARGET" 'echo UNEXPECTED: the command ran'
CODE_REFUSED=$(cat "$REFUSED/exit_code")
if [ "$CODE_REFUSED" != "0" ] && [ ! -e "$ETC_TARGET" ] &&
  grep -q "the runner can't create it under \"/etc\"" "$REFUSED/out.log" &&
  ! grep -q "UNEXPECTED" "$REFUSED/out.log"; then
  pass "write_through: a missing target under a tree the runner can't write fails the step and creates nothing"
else
  fail "write_through: a root-owned missing target did not behave as expected (exit $CODE_REFUSED) -- see $REFUSED/out.log"
  cat "$REFUSED/out.log"
fi
sudo -n rm -rf "$ETC_TARGET" 2>/dev/null
rm -rf "$REFUSED"

assert_results

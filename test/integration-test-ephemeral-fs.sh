#!/bin/bash
# Verifies filesystem_mode: ephemeral / write_through: end-to-end by driving
# dist/main.cjs directly, without the real action wrapper -- see
# test-e2e.yml for the one case that does exercise the real action.
# The mount-composition/path-resolution rules themselves are already
# unit-tested (ephemeral-fs.test.ts, oci-config.test.ts); this proves runc
# actually honors them, matching the real-host smoke test performed during
# development (see isolated-run-spec-filesystem.md and the R-H1 plan).
#
# Case 10 from the spec's own test plan (§12: overlay probe failure ->
# clear error) isn't exercised here -- it needs an environment where
# overlayfs itself doesn't work, which contradicts everything else in this
# file running successfully. Covered instead by the mac-only dev loop
# (`make test_sandbox_dev`), where overlayfs-on-overlayfs is known to fail
# (see overlayfs-preflight.ts's own doc comment).
set -uo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
FAILURES=0

: "${BUILDCAGE_LOCAL_IMAGE_REF:?BUILDCAGE_LOCAL_IMAGE_REF must be set to the locally built proxy image}"

pass() { echo "  PASS  $1"; }
fail() {
  echo "  FAIL  $1"
  FAILURES=$((FAILURES + 1))
}

# Runs dist/main.cjs with filesystem_mode: ephemeral against a fresh
# $GITHUB_WORKSPACE/$RUNNER_TEMP (both under mktemp's default, i.e. /tmp --
# never inside the real $HOME, so $HOME survives folding as its own overlay
# root instead of being subsumed by GITHUB_WORKSPACE/RUNNER_TEMP -- see
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
  BUILDCAGE_BUILD_TEST_HOOKS=1 \
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

# --- Case 1+6: $HOME writes (create + delete) during the step never reach
# the host, whether or not the sandbox itself observes them mid-step.
HOME_MARKER="$HOME/.buildcage-ephemeral-test-marker"
HOME_PRELOADED="$HOME/.buildcage-ephemeral-test-preloaded"
rm -f "$HOME_MARKER" "$HOME_PRELOADED"
echo "pre-existing-on-host" >"$HOME_PRELOADED"
CASE1=$(mktemp -d)
run_ephemeral "$CASE1" "" '
touch "$HOME/.buildcage-ephemeral-test-marker"
rm -f "$HOME/.buildcage-ephemeral-test-preloaded"
'
CODE1=$(cat "$CASE1/exit_code")
if [ "$CODE1" = "0" ] && [ ! -e "$HOME_MARKER" ]; then
  pass "a file created under \$HOME during the step is not on the host afterwards"
else
  fail "a file created under \$HOME during the step leaked to the host (exit $CODE1) -- see $CASE1/out.log"
  cat "$CASE1/out.log"
fi
if [ -f "$HOME_PRELOADED" ] && [ "$(cat "$HOME_PRELOADED")" = "pre-existing-on-host" ]; then
  pass "deleting a pre-existing \$HOME file inside the sandbox does not delete it on the host"
else
  fail "a pre-existing \$HOME file was actually removed from the host by an in-sandbox delete"
fi
rm -f "$HOME_MARKER" "$HOME_PRELOADED"
rm -rf "$CASE1"

# --- Case 2+3: the runner's own generated files are discarded by default
# and persisted when named in write_through:. Placed under RUNNER_TEMP (as
# they are for real) so they're covered by RUNNER_TEMP's own overlay in the
# default case.
CASE2=$(mktemp -d)
GITHUB_ENV_FILE2=$(mktemp)
touch "$CASE2/state.env" "$CASE2/summary.md"
# Not via run_ephemeral -- GITHUB_ENV/RUNNER_TEMP need to be set together
# below, unlike its fixed default env.
GITHUB_ENV="$GITHUB_ENV_FILE2" \
GITHUB_WORKSPACE="$CASE2" \
GITHUB_STATE="$CASE2/state.env" \
GITHUB_STEP_SUMMARY="$CASE2/summary.md" \
RUNNER_TEMP="$(dirname "$GITHUB_ENV_FILE2")" \
BUILDCAGE_BUILD_TEST_HOOKS=1 \
BUILDCAGE_LOCAL_IMAGE_REF="$BUILDCAGE_LOCAL_IMAGE_REF" \
INPUT_FILESYSTEM_MODE="ephemeral" \
INPUT_WRITE_THROUGH="" \
INPUT_RUN='echo "SHOULD_NOT_PERSIST=1" >> "$GITHUB_ENV"' \
  node "$REPO_ROOT/dist/main.cjs" >"$CASE2/out.log" 2>&1
CODE2=$?
if [ "$CODE2" = "0" ] && ! grep -q SHOULD_NOT_PERSIST "$GITHUB_ENV_FILE2"; then
  pass "an append to \$GITHUB_ENV during the step is not reflected afterwards (default)"
else
  fail "an append to \$GITHUB_ENV during the step was reflected afterwards despite no write_through: entry (exit $CODE2) -- see $CASE2/out.log"
  cat "$CASE2/out.log"
fi
rm -rf "$CASE2" "$GITHUB_ENV_FILE2"

# Case 3 covers all three files a step realistically produces output
# through, since the README tells readers to name any of them.
CASE3=$(mktemp -d)
GITHUB_ENV_FILE3=$(mktemp)
GITHUB_OUTPUT_FILE3=$(mktemp)
GITHUB_SUMMARY_FILE3=$(mktemp)
touch "$CASE3/state.env"
FAILURES_BEFORE3=$FAILURES
GITHUB_ENV="$GITHUB_ENV_FILE3" \
GITHUB_OUTPUT="$GITHUB_OUTPUT_FILE3" \
GITHUB_WORKSPACE="$CASE3" \
GITHUB_STATE="$CASE3/state.env" \
GITHUB_STEP_SUMMARY="$GITHUB_SUMMARY_FILE3" \
RUNNER_TEMP="$(dirname "$GITHUB_ENV_FILE3")" \
BUILDCAGE_BUILD_TEST_HOOKS=1 \
BUILDCAGE_LOCAL_IMAGE_REF="$BUILDCAGE_LOCAL_IMAGE_REF" \
INPUT_FILESYSTEM_MODE="ephemeral" \
INPUT_WRITE_THROUGH='$GITHUB_ENV
$GITHUB_OUTPUT
$GITHUB_STEP_SUMMARY' \
INPUT_RUN='echo "SHOULD_PERSIST=1" >> "$GITHUB_ENV"
echo "persisted_output=1" >> "$GITHUB_OUTPUT"
echo "SHOULD_PERSIST_SUMMARY" >> "$GITHUB_STEP_SUMMARY"' \
  node "$REPO_ROOT/dist/main.cjs" >"$CASE3/out.log" 2>&1
CODE3=$?
if [ "$CODE3" != "0" ]; then
  fail "the write_through: step itself failed (exit $CODE3) -- see $CASE3/out.log"
fi
if [ "$CODE3" = "0" ] && grep -q SHOULD_PERSIST "$GITHUB_ENV_FILE3"; then
  pass "write_through: \$GITHUB_ENV persists an append to it"
else
  fail "write_through: \$GITHUB_ENV did not persist the append"
fi
if [ "$CODE3" = "0" ] && grep -q "persisted_output=1" "$GITHUB_OUTPUT_FILE3"; then
  pass "write_through: \$GITHUB_OUTPUT persists a step output the command sets"
else
  fail "write_through: \$GITHUB_OUTPUT did not persist the step output"
fi
# Also asserts this action's own report is in the same file: it is written
# from the host after the sandbox exits, so naming $GITHUB_STEP_SUMMARY
# puts the command's markdown alongside it rather than in place of it.
if [ "$CODE3" = "0" ] && grep -q SHOULD_PERSIST_SUMMARY "$GITHUB_SUMMARY_FILE3" && grep -q "^## " "$GITHUB_SUMMARY_FILE3"; then
  pass "write_through: \$GITHUB_STEP_SUMMARY persists the command's markdown next to this action's report"
else
  fail "write_through: \$GITHUB_STEP_SUMMARY did not persist the command's markdown next to the report"
fi
if [ "$FAILURES" != "$FAILURES_BEFORE3" ]; then
  cat "$CASE3/out.log"
fi
rm -rf "$CASE3" "$GITHUB_ENV_FILE3" "$GITHUB_OUTPUT_FILE3" "$GITHUB_SUMMARY_FILE3"

# --- Case 4: a missing write_through target under a runner-owned tree
# ($GITHUB_WORKSPACE) is created runner-owned, and the write persists.
CASE4=$(mktemp -d)
run_ephemeral "$CASE4" "./dist" '
mkdir -p "$GITHUB_WORKSPACE/dist"
echo "built" > "$GITHUB_WORKSPACE/dist/output.txt"
'
CODE4=$(cat "$CASE4/exit_code")
if [ "$CODE4" = "0" ] && [ -f "$CASE4/dist/output.txt" ]; then
  pass "write_through: ./dist creates the missing dir runner-owned and persists writes under it"
else
  fail "write_through: ./dist did not persist the write (exit $CODE4) -- see $CASE4/out.log"
  cat "$CASE4/out.log"
fi
rm -rf "$CASE4"

# --- Case 4b: a missing write_through target under a root-owned, non-runner
# tree is still created (via sudo mkdir -p), but mirrors its nearest
# existing ancestor's owner/mode -- so it stays unwritable by the
# (non-root) sandboxed process, exactly as naming the existing ancestor
# directly would. The denied write is what proves that ownership; the
# directory is then empty, so the end-of-step cleanup gives it back.
# Uses a throwaway /etc subdirectory; needs sudo to clean up in case a
# failure leaves it behind.
ETC_TARGET="/etc/buildcage-ephemeral-test-$$"
sudo -n rm -rf "$ETC_TARGET" 2>/dev/null
CASE4B=$(mktemp -d)
run_ephemeral "$CASE4B" "$ETC_TARGET" '
if echo x > "'"$ETC_TARGET"'/should-fail.txt" 2>/dev/null; then
  echo "UNEXPECTED: write into a root-owned write_through target succeeded"
  exit 1
fi
'
CODE4B=$(cat "$CASE4B/exit_code")
if [ "$CODE4B" = "0" ] && [ ! -e "$ETC_TARGET" ]; then
  pass "write_through: a missing target under a root-owned tree stays unwritable by the sandbox, and is given back empty"
else
  fail "write_through: a root-owned missing target did not behave as expected (exit $CODE4B) -- see $CASE4B/out.log"
  cat "$CASE4B/out.log"
fi
sudo -n rm -rf "$ETC_TARGET" 2>/dev/null
rm -rf "$CASE4B"

# --- Case 5: an existing, already-writable-by-the-runner directory named
# in write_through: (not one of the fixed overlay candidates) persists writes.
# Matches integration-test-writable-dir.sh's own use of /opt as a directory
# CI images make writable by the runner user.
CASE5=$(mktemp -d)
rm -f /opt/.buildcage-ephemeral-allow-write-test
run_ephemeral "$CASE5" "/opt" '
echo x > /opt/.buildcage-ephemeral-allow-write-test
'
CODE5=$(cat "$CASE5/exit_code")
if [ "$CODE5" = "0" ] && [ -f /opt/.buildcage-ephemeral-allow-write-test ]; then
  pass "write_through: /opt persists a write to an existing, already-writable directory"
else
  fail "write_through: /opt did not persist the write (exit $CODE5) -- see $CASE5/out.log"
  cat "$CASE5/out.log"
fi
rm -f /opt/.buildcage-ephemeral-allow-write-test
rm -rf "$CASE5"

# --- Case 7+8: setup log shows the folded ephemeral/persisted paths, and a
# discard line is logged before the scratch dir (incl. its upper/work
# dirs) is removed.
CASE7=$(mktemp -d)
run_ephemeral "$CASE7" "\$GITHUB_WORKSPACE" 'true'
CODE7=$(cat "$CASE7/exit_code")
LOG7="$CASE7/out.log"
if [ "$CODE7" = "0" ] &&
  grep -q "^Filesystem mode: ephemeral$" "$LOG7" &&
  grep -q "^Ephemeral (writes discarded at step end): $HOME$" "$LOG7" &&
  grep -q "^Writable (persisted): *$CASE7$" "$LOG7"; then
  pass "setup log shows the folded ephemeral and persisted paths"
else
  fail "setup log is missing the expected filesystem-mode lines (exit $CODE7) -- see $LOG7"
  cat "$LOG7"
fi
if grep -q "^Discarded ephemeral writes under .*$HOME" "$LOG7"; then
  pass "a discard line is logged for the ephemeral overlay roots"
else
  fail "no discard line was logged for the ephemeral overlay roots -- see $LOG7"
fi
rm -rf "$CASE7"

# --- Case 9: the scratch dir (including the overlay upper/work dirs) is
# fully cleaned up afterwards -- no directory left behind under
# SANDBOX_SCRATCH_BASE from this run. Compares the directory listing
# before/after rather than relying on knowing the (randomly generated)
# container name.
SCRATCH_BASE="/var/tmp/buildcage-$(id -u)"
BEFORE=$(sudo -n find "$SCRATCH_BASE" -maxdepth 1 -mindepth 1 2>/dev/null | sort)
CASE9=$(mktemp -d)
run_ephemeral "$CASE9" "" 'true'
CODE9=$(cat "$CASE9/exit_code")
AFTER=$(sudo -n find "$SCRATCH_BASE" -maxdepth 1 -mindepth 1 2>/dev/null | sort)
if [ "$CODE9" = "0" ] && [ "$BEFORE" = "$AFTER" ]; then
  pass "the run's scratch dir (including overlay upper/work) is fully cleaned up afterwards"
else
  fail "the run's scratch dir was not fully cleaned up -- before/after $SCRATCH_BASE listings differ"
  echo "before: $BEFORE"
  echo "after:  $AFTER"
fi
rm -rf "$CASE9"

echo ""
if [ "$FAILURES" -gt 0 ]; then
  echo "$FAILURES assertion(s) failed."
  exit 1
fi
echo "All assertions passed."

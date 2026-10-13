#!/bin/bash
# Verifies the sandbox hands the command the same process environment an
# unwrapped `run:` step gets, rather than runc's container defaults (see
# buildOciConfig), and that the command is not the sandbox's PID 1 (see
# env-loader.ts). Drives dist/main.cjs directly, like integration-test-defaults.sh.
set -uo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/driver-helpers.sh"

require_local_image

WORKDIR=$(mktemp -d)
trap 'rm -rf "$WORKDIR"' EXIT
touch "$WORKDIR/state.env" "$WORKDIR/summary.md"

run_sandboxed() {
  GITHUB_WORKSPACE="$WORKDIR" \
  GITHUB_STATE="$WORKDIR/state.env" \
  GITHUB_STEP_SUMMARY="$WORKDIR/summary.md" \
  BUILDCAGE_LOCAL_IMAGE_REF="$BUILDCAGE_LOCAL_IMAGE_REF" \
  INPUT_RUN="$1" \
    node dist/main.cjs
}

# This script runs on the runner host, so its own values are the baseline.
# /proc/sys/kernel/hostname rather than hostname(1) to avoid depending on a
# binary being installed.
#
# The soft limit is deliberately below the hard one. Node raises its own soft
# RLIMIT_NOFILE to the hard limit at startup, so reading the action's own
# /proc/self/limits would report the raised value and hand the sandbox more than
# the step would have had. A GitHub-hosted runner sets soft = hard, which hides
# that.
(
  ulimit -Sn 4096 || exit 1
  EXPECT_NOFILE_SOFT=$(ulimit -Sn)
  EXPECT_NOFILE_HARD=$(ulimit -Hn)
  EXPECT_HOSTNAME=$(cat /proc/sys/kernel/hostname)
  EXPECT_SHM_KB=$(df -k --output=size /dev/shm | tail -1 | tr -d ' ')
  export EXPECT_NOFILE_SOFT EXPECT_NOFILE_HARD EXPECT_HOSTNAME EXPECT_SHM_KB
  echo "host baseline: nofile ${EXPECT_NOFILE_SOFT}/${EXPECT_NOFILE_HARD}, /dev/shm ${EXPECT_SHM_KB}k, hostname ${EXPECT_HOSTNAME}"
  # shellcheck disable=SC2016 # expands in the sandbox
  run_sandboxed 'fail() { echo "UNEXPECTED: $1"; exit 1; }
[ "$(ulimit -Sn)" = "$EXPECT_NOFILE_SOFT" ] || fail "soft RLIMIT_NOFILE is $(ulimit -Sn), the runner has $EXPECT_NOFILE_SOFT"
[ "$(ulimit -Hn)" = "$EXPECT_NOFILE_HARD" ] || fail "hard RLIMIT_NOFILE is $(ulimit -Hn), the runner has $EXPECT_NOFILE_HARD"
[ "$(cat /proc/sys/kernel/hostname)" = "$EXPECT_HOSTNAME" ] || fail "hostname is $(cat /proc/sys/kernel/hostname), the runner is $EXPECT_HOSTNAME"
SHM_KB=$(df -k --output=size /dev/shm | tail -1 | tr -d " ")
[ "$SHM_KB" = "$EXPECT_SHM_KB" ] || fail "/dev/shm is ${SHM_KB}k, the runner has ${EXPECT_SHM_KB}k"'
)
PARITY_CODE=$?

# One sandbox for the process checks, since a start is not cheap: the command
# is not PID 1, an orphan is reaped (python, which would never reap one itself,
# leaves its grandchild to PID 1), and `kill -TERM $$` ends the command with
# 143. Any other exit status is one of the first two failing, which the
# UNEXPECTED line in the log names. The self-kill also stands for a command
# that exits non-zero on its own, which must not read as a launch failure.
START=$SECONDS
run_sandboxed '[ $$ -ne 1 ] || { echo "UNEXPECTED: the command is PID 1"; exit 1; }
python3 - <<"EOF" || exit 1
import glob, os, sys, time
child = os.fork()
if child == 0:
    if os.fork() == 0:
        time.sleep(0.2)
    os._exit(0)
os.waitpid(child, 0)
time.sleep(1)
zombies = []
for stat in glob.glob("/proc/[0-9]*/stat"):
    try:
        with open(stat) as f:
            state = f.read().rsplit(")", 1)[1].split()[0]
    except OSError:
        continue
    if state == "Z":
        zombies.append(stat)
if zombies:
    print("UNEXPECTED: unreaped zombies:", zombies)
    sys.exit(1)
EOF
( sleep 1; kill -TERM $$ ) & sleep 30' >"$WORKDIR/process.log" 2>&1
PROCESS_CODE=$?
PROCESS_SECONDS=$((SECONDS - START))
cat "$WORKDIR/process.log"

FAILED=0
echo ""
echo "=== Sandbox Host Environment Parity Assertions ==="
echo ""
if [ "$PARITY_CODE" = "0" ]; then
  echo "  PASS  open-file limits, /dev/shm size and hostname match the runner's own"
else
  echo "  FAIL  sandbox environment diverges from the runner (exit $PARITY_CODE)"
  FAILED=1
fi
if [ "$PROCESS_CODE" = "143" ] && [ "$PROCESS_SECONDS" -lt 30 ]; then
  echo "  PASS  the command is not the sandbox's PID 1, an orphan is reaped, and kill -TERM \$\$ ends the command with 143"
else
  echo "  FAIL  exit $PROCESS_CODE after ${PROCESS_SECONDS}s, expected 143 well under 30s"
  FAILED=1
fi
if grep -q "buildcage: command exited with code 143" "$WORKDIR/process.log" &&
  ! grep -q "sandbox launch failed" "$WORKDIR/process.log"; then
  echo "  PASS  a command that exits non-zero is reported as the command's exit"
else
  echo "  FAIL  a command that exits non-zero was not reported as the command's exit"
  FAILED=1
fi
echo ""
exit "$FAILED"

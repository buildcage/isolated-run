#!/bin/bash
# Verifies the sandbox hands the command the same process environment an
# unwrapped `run:` step gets, rather than runc's container defaults (see
# buildOciConfig), and that the command is not the sandbox's PID 1 (see
# env-loader.ts). Drives dist/main.cjs directly, like integration-test-defaults.sh.
set -uo pipefail

: "${BUILDCAGE_LOCAL_IMAGE_REF:?BUILDCAGE_LOCAL_IMAGE_REF must be set to the locally built proxy image}"

WORKDIR=$(mktemp -d)
trap 'rm -rf "$WORKDIR"' EXIT
touch "$WORKDIR/state.env" "$WORKDIR/summary.md"

# This script runs on the runner host, so its own values are the baseline.
# /proc/sys/kernel/hostname rather than hostname(1) to avoid depending on a
# binary being installed.
run_parity_check() {
  local label="$1"
  local expect_nofile_soft expect_nofile_hard expect_hostname expect_shm_kb
  expect_nofile_soft=$(ulimit -Sn)
  expect_nofile_hard=$(ulimit -Hn)
  expect_hostname=$(cat /proc/sys/kernel/hostname)
  expect_shm_kb=$(df -k --output=size /dev/shm | tail -1 | tr -d ' ')
  export EXPECT_NOFILE_SOFT="$expect_nofile_soft" EXPECT_NOFILE_HARD="$expect_nofile_hard"
  export EXPECT_HOSTNAME="$expect_hostname" EXPECT_SHM_KB="$expect_shm_kb"

  echo "[$label] host baseline: nofile ${expect_nofile_soft}/${expect_nofile_hard}, /dev/shm ${expect_shm_kb}k, hostname ${expect_hostname}"

  GITHUB_WORKSPACE="$WORKDIR" \
  GITHUB_STATE="$WORKDIR/state.env" \
  GITHUB_STEP_SUMMARY="$WORKDIR/summary.md" \
  BUILDCAGE_BUILD_TEST_HOOKS=1 \
  BUILDCAGE_LOCAL_IMAGE_REF="$BUILDCAGE_LOCAL_IMAGE_REF" \
  INPUT_RUN='fail() { echo "UNEXPECTED: $1"; exit 1; }
[ "$(ulimit -Sn)" = "$EXPECT_NOFILE_SOFT" ] || fail "soft RLIMIT_NOFILE is $(ulimit -Sn), the runner has $EXPECT_NOFILE_SOFT"
[ "$(ulimit -Hn)" = "$EXPECT_NOFILE_HARD" ] || fail "hard RLIMIT_NOFILE is $(ulimit -Hn), the runner has $EXPECT_NOFILE_HARD"
[ "$(cat /proc/sys/kernel/hostname)" = "$EXPECT_HOSTNAME" ] || fail "hostname is $(cat /proc/sys/kernel/hostname), the runner is $EXPECT_HOSTNAME"
SHM_KB=$(df -k --output=size /dev/shm | tail -1 | tr -d " ")
[ "$SHM_KB" = "$EXPECT_SHM_KB" ] || fail "/dev/shm is ${SHM_KB}k, the runner has ${EXPECT_SHM_KB}k"' \
    node dist/main.cjs
}

run_parity_check "inherited limits"
CODE=$?

# Again with the soft limit deliberately below the hard one. Node raises its own
# soft RLIMIT_NOFILE to the hard limit at startup, so reading the action's own
# /proc/self/limits would report the raised value and hand the sandbox more than
# the step would have had. A GitHub-hosted runner sets soft = hard, which hides
# that; this pass is what makes it visible.
if [ "$CODE" = "0" ]; then
  ( ulimit -Sn 4096 && run_parity_check "soft limit below hard" )
  CODE=$?
fi

PARITY_CODE=$CODE

run_sandboxed() {
  GITHUB_WORKSPACE="$WORKDIR" \
  GITHUB_STATE="$WORKDIR/state.env" \
  GITHUB_STEP_SUMMARY="$WORKDIR/summary.md" \
  BUILDCAGE_BUILD_TEST_HOOKS=1 \
  BUILDCAGE_LOCAL_IMAGE_REF="$BUILDCAGE_LOCAL_IMAGE_REF" \
  INPUT_RUN="$1" \
    node dist/main.cjs
}

run_sandboxed '[ $$ -ne 1 ] || { echo "UNEXPECTED: the command is PID 1"; exit 1; }'
NOT_PID1_CODE=$?

START=$SECONDS
run_sandboxed '( sleep 1; kill -TERM $$ ) & sleep 30'
SELF_KILL_CODE=$?
SELF_KILL_SECONDS=$((SECONDS - START))

# The grandchild is orphaned onto PID 1, which python would never reap.
run_sandboxed '#!/usr/bin/env python3
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
    sys.exit(1)'
ORPHAN_CODE=$?

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
if [ "$NOT_PID1_CODE" = "0" ]; then
  echo "  PASS  the command is not the sandbox's PID 1"
else
  echo "  FAIL  the command runs as the sandbox's PID 1 (exit $NOT_PID1_CODE)"
  FAILED=1
fi
if [ "$SELF_KILL_CODE" = "143" ] && [ "$SELF_KILL_SECONDS" -lt 30 ]; then
  echo "  PASS  kill -TERM \$\$ ends the command with 143"
else
  echo "  FAIL  kill -TERM \$\$ gave exit $SELF_KILL_CODE after ${SELF_KILL_SECONDS}s, expected 143 well under 30s"
  FAILED=1
fi
if [ "$ORPHAN_CODE" = "0" ]; then
  echo "  PASS  an orphan exiting under a python command is reaped"
else
  echo "  FAIL  an orphan was left a zombie (exit $ORPHAN_CODE)"
  FAILED=1
fi
echo ""
exit "$FAILED"

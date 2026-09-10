#!/bin/bash
# Verifies the sandbox hands the command the same process environment an
# unwrapped `run:` step gets, rather than runc's container defaults (see
# buildOciConfig). Drives dist/main.cjs directly, like integration-test-defaults.sh.
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

echo ""
echo "=== Sandbox Host Environment Parity Assertions ==="
echo ""
if [ "$CODE" = "0" ]; then
  echo "  PASS  open-file limits, /dev/shm size and hostname match the runner's own"
else
  echo "  FAIL  sandbox environment diverges from the runner (exit $CODE)"
  exit 1
fi
echo ""

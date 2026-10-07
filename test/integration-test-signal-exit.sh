#!/bin/bash
# Verifies what a cancelled step does: the runner sends SIGINT to the action's
# node process alone, and the action has to stop the sandbox, write the report
# and tear everything down before the runner's SIGKILL 10 seconds later.
# Drives dist/main.cjs directly, like integration-test-die-with-parent.sh,
# so this script can send that SIGINT itself.
set -uo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/helpers.sh"

: "${BUILDCAGE_LOCAL_IMAGE_REF:?BUILDCAGE_LOCAL_IMAGE_REF must be set to the locally built proxy image}"

WORKDIR=$(mktemp -d)

cleanup() {
  sudo -n pkill -9 -f "sudo -n -- .*/run-isolated.sh" >/dev/null 2>&1
  rm -rf "$WORKDIR"
}
trap cleanup EXIT

# Runs INPUT_RUN as a step, sends the step SIGINT once `marker` is running,
# and leaves the step's exit code in CODE, how long it took to exit after the
# SIGINT in ELAPSED, and its log and summary under WORKDIR/<name>.
cancel_step() {
  local name="$1" run="$2" marker="$3"
  local dir="$WORKDIR/$name"
  mkdir -p "$dir"
  touch "$dir/state.env" "$dir/summary.md"

  GITHUB_WORKSPACE="$dir" \
  GITHUB_STATE="$dir/state.env" \
  GITHUB_STEP_SUMMARY="$dir/summary.md" \
  BUILDCAGE_BUILD_TEST_HOOKS=1 \
  BUILDCAGE_LOCAL_IMAGE_REF="$BUILDCAGE_LOCAL_IMAGE_REF" \
  INPUT_RUN="$run" \
    node dist/main.cjs > "$dir/out.log" 2>&1 &
  local node_pid=$!

  local found=0
  for _ in $(seq 1 60); do
    if pgrep -f "$marker" >/dev/null 2>&1; then
      found=1
      break
    fi
    sleep 0.5
  done
  if [ "$found" != "1" ]; then
    fail "$name: sandboxed process never started"
    cat "$dir/out.log"
    kill -9 "$node_pid" >/dev/null 2>&1
    CODE=-1
    return
  fi

  local start=$SECONDS
  kill -INT "$node_pid"
  wait "$node_pid"
  CODE=$?
  ELAPSED=$((SECONDS - start))
}

# What every cancelled step must leave behind, whatever its command did.
assert_cancelled_cleanly() {
  local name="$1" marker="$2"
  local dir="$WORKDIR/$name"
  if [ "$ELAPSED" -lt 10 ]; then
    pass "$name: the step exited ${ELAPSED}s after the SIGINT, before the runner's SIGKILL"
  else
    fail "$name: the step took ${ELAPSED}s to exit after the SIGINT"
  fi
  if grep -q "Outbound Traffic Report" "$dir/summary.md"; then
    pass "$name: the traffic report was written"
  else
    fail "$name: no traffic report in the summary"
    cat "$dir/out.log"
  fi
  if pgrep -f "$marker" >/dev/null 2>&1; then
    fail "$name: the sandboxed command outlived the step"
  else
    pass "$name: the sandboxed command did not outlive the step"
  fi
  local container
  container=$(awk '/^container_name<</{getline; print; exit}' "$dir/state.env" 2>/dev/null)
  if [ -n "$container" ] && docker inspect "$container" >/dev/null 2>&1; then
    fail "$name: the proxy container $container is still there"
    docker rm -f "$container" >/dev/null 2>&1
  else
    pass "$name: the proxy container was stopped"
  fi
}

echo ""
echo "=== Cancelled step Assertions ==="
echo ""

# The run script is the process the sandbox forwards SIGTERM to, so its own
# trap decides the exit code.
cancel_step handles "trap 'exit 5' TERM; sleep 301 & wait" "sleep 301"
if [ "$CODE" != "-1" ]; then
  check_status "handles: the command's own exit status is the step's" "$CODE" 5
  assert_cancelled_cleanly handles "sleep 301"
fi

# The SIGTERM reaches what the run script started too, and the step waits for
# it to finish its own cleanup after the script itself has died of the signal.
cancel_step command \
  "bash -c 'trap \"sleep 1; touch cleaned-up; exit 0\" TERM; sleep 303 & wait'" "sleep 303"
if [ "$CODE" != "-1" ]; then
  check_status "command: the run script died of the SIGTERM" "$CODE" 143
  if [ -e "$WORKDIR/command/cleaned-up" ]; then
    pass "command: the command the script ran finished its cleanup"
  else
    fail "command: the command the script ran was killed before its cleanup finished"
    cat "$WORKDIR/command/out.log"
  fi
  assert_cancelled_cleanly command "sleep 303"
fi

# A process the command moved out of its process group with setsid gets the
# SIGTERM too, and the step waits for its cleanup the same way.
cancel_step detached \
  "setsid bash -c 'trap \"sleep 1; touch cleaned-up; exit 0\" TERM; sleep 304 & wait' & wait" "sleep 304"
if [ "$CODE" != "-1" ]; then
  check_status "detached: the run script died of the SIGTERM" "$CODE" 143
  if [ -e "$WORKDIR/detached/cleaned-up" ]; then
    pass "detached: the setsid process finished its cleanup"
  else
    fail "detached: the setsid process was killed before its cleanup finished"
    cat "$WORKDIR/detached/out.log"
  fi
  assert_cancelled_cleanly detached "sleep 304"
fi

cancel_step ignores "trap '' TERM; sleep 302" "sleep 302"
if [ "$CODE" != "-1" ]; then
  check_status "ignores: a command that ignores SIGTERM is killed" "$CODE" 137
  assert_cancelled_cleanly ignores "sleep 302"
fi

assert_results

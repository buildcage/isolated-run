#!/bin/bash
# Verifies the setpriv --pdeathsig chain (see run-isolated.sh and
# sandbox/oci-config.ts's buildOciConfig): SIGKILL-ing run-isolated.sh's own
# process must tear down the whole sandboxed process tree rather than
# leaving it running as an orphan. Drives dist/main.cjs directly, not
# through the real action wrapper, so this script can reach in and kill
# run-isolated.sh mid-run.
set -uo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/driver-helpers.sh"

require_local_image

WORKDIR=$(mktemp -d)
touch "$WORKDIR/state.env" "$WORKDIR/summary.md"

cleanup() {
  [ -n "${NODE_PID:-}" ] && kill -9 "$NODE_PID" >/dev/null 2>&1
  # sudo itself (setuid root) and everything under it run as root, so
  # this needs the same privilege too.
  sudo -n pkill -9 -f "sudo -n -- .*/run-isolated.sh" >/dev/null 2>&1
  # A bare buildcage-proxy-* sweep would take down another git worktree's
  # proxy. sandbox-step.ts writes the name to GITHUB_STATE before creating
  # the container, so nothing it started escapes this narrower one.
  local name project
  name=$(state_container_name "$WORKDIR/state.env")
  if [ -n "$name" ]; then
    project=$(docker inspect "$name" \
      --format '{{index .Config.Labels "com.docker.compose.project"}}' 2>/dev/null)
    docker rm -f "$name" >/dev/null 2>&1
    [ -n "$project" ] && docker network ls --filter "label=com.docker.compose.project=$project" -q |
      xargs -r docker network rm >/dev/null 2>&1
  fi
  rm -rf "$WORKDIR"
}
trap cleanup EXIT

GITHUB_WORKSPACE="$WORKDIR" \
GITHUB_STATE="$WORKDIR/state.env" \
GITHUB_STEP_SUMMARY="$WORKDIR/summary.md" \
BUILDCAGE_LOCAL_IMAGE_REF="$BUILDCAGE_LOCAL_IMAGE_REF" \
INPUT_RUN='echo sandboxed-process-started; sleep 297' \
  node dist/main.cjs > "$WORKDIR/out.log" 2>&1 &
NODE_PID=$!

echo "waiting for the sandboxed 'sleep 297' to start..." >&2
FOUND=0
for _ in $(seq 1 60); do
  if pgrep -f "^sleep 297" >/dev/null 2>&1; then
    FOUND=1
    break
  fi
  sleep 0.5
done
if [ "$FOUND" != "1" ]; then
  echo "  FAIL  sandboxed process never started; see log below"
  cat "$WORKDIR/out.log"
  exit 1
fi
sleep 0.5

# The sandbox's cgroup is a child of this script's, the runner's stand-in, so
# whatever limits the runner's service has reach the command too. Read from
# here, since the sandbox sees only its own cgroup namespace.
OWN_CGROUP=$(sed -n 's/^0:://p' /proc/self/cgroup)
SLEEP_PID=$(pgrep -f -n "^sleep 297")
SANDBOX_CGROUP=$(sed -n 's/^0:://p' "/proc/$SLEEP_PID/cgroup" 2>/dev/null)
echo "runner cgroup: ${OWN_CGROUP}, sandbox cgroup: ${SANDBOX_CGROUP}" >&2

# sudo's own argv also names run-isolated.sh, so this must target the bash
# running it, not sudo.
mapfile -t BASH_PIDS < <(pgrep -f "/bin/bash .*/run-isolated.sh")
if [ "${#BASH_PIDS[@]}" != "1" ]; then
  echo "  FAIL  expected exactly 1 run-isolated.sh bash process, found ${#BASH_PIDS[@]}: ${BASH_PIDS[*]:-<none>}"
  exit 1
fi
BASH_PID="${BASH_PIDS[0]}"

# run-isolated.sh runs as root (via sudo -n), so killing it requires the
# same privilege.
sudo -n kill -9 "$BASH_PID"
for _ in $(seq 1 20); do
  pgrep -f "^sleep 297" >/dev/null 2>&1 || break
  sleep 0.1
done

echo ""
echo "=== Sandbox die-with-parent Assertions ==="
echo ""
case "$SANDBOX_CGROUP" in
  "${OWN_CGROUP%/}/buildcage-proxy-"*)
    pass "the sandbox's cgroup is a child of the runner's own" ;;
  *)
    fail "the sandbox's cgroup is ${SANDBOX_CGROUP:-unknown}, not under ${OWN_CGROUP}" ;;
esac
if pgrep -f "^sleep 297" >/dev/null 2>&1; then
  fail "sandboxed process survived as an orphan after run-isolated.sh was killed"
else
  pass "entire sandbox process tree died with run-isolated.sh"
fi

wait "$NODE_PID"
CODE=$?
if [ "$CODE" != "0" ] && grep -q "The sandbox was ended by SIGKILL" "$WORKDIR/out.log"; then
  pass "the step fails, saying the sandbox was killed (exit $CODE)"
else
  fail "the step did not report the sandbox being killed (exit $CODE)"
  cat "$WORKDIR/out.log"
fi

assert_results

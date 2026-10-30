#!/bin/bash
# Stops the proxy's haproxy, then its coredns, while a sandboxed command is
# still running, and checks that the command's traffic then fails instead of
# finding a way around the proxy, and that the step does not pass on a report
# the stopped proxy can no longer vouch for.
#
# The command and this driver take turns through marker files in the
# workspace: the command writes one when it is done with a phase, and waits
# for the one this driver writes once a service is down (see
# test/universal-proxy-down-scenarios.sh for the phases).
set -uo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/driver-helpers.sh"

require_local_image universal

WORKDIR=$(mktemp -d)
STEP_PID=""

# Bounded, so a step that hangs fails this driver instead of the job's timeout.
STEP_END_TIMEOUT=120

# wait_step_gone <seconds>: whether the backgrounded step ended in time.
wait_step_gone() {
  for _ in $(seq 1 $(($1 * 2))); do
    kill -0 "$STEP_PID" 2>/dev/null || return 0
    sleep 0.5
  done
  return 1
}

# stop_step: cancels the step as the runner would, with SIGTERM to node alone
# (the backgrounded run_step is a subshell around it), then kills what is
# left, and removes whatever of the proxy the step did not get to.
stop_step() {
  if [ -n "$STEP_PID" ]; then
    local node="$STEP_PID"
    [ "$(ps -o comm= -p "$node" 2>/dev/null)" = node ] || node=$(pgrep -P "$STEP_PID" -x node)
    [ -n "$node" ] && kill -TERM "$node" 2>/dev/null
    if ! wait_step_gone 30; then
      [ -n "$node" ] && kill -KILL "$node" 2>/dev/null
      kill -KILL "$STEP_PID" 2>/dev/null
    fi
    STEP_PID=""
  fi
  local name
  name=$(state_container_name "$WORKDIR/step.state")
  if [ -n "$name" ]; then
    docker rm -f "$name" >/dev/null 2>&1
    docker network ls -q --filter "label=com.docker.compose.project=$(proxy_project "$name")" |
      xargs -r docker network rm >/dev/null 2>&1
  fi
}

cleanup() {
  stop_step
  fixture_down universal
  rm -rf "$WORKDIR"
}
trap cleanup EXIT

echo ""
echo "=== Proxy stopped mid-step Assertions ==="
echo ""

fixture_up universal

run_step universal "$WORKDIR/step" \
  INPUT_PROXY_MODE="restrict" \
  INPUT_ALLOWED_HTTPS_RULES="allowed.example.com:443" \
  INPUT_ALLOWED_HTTP_RULES="allowed.example.com:80" \
  INPUT_ALLOWED_IP_RULES="" \
  INPUT_FAIL_ON_BLOCKED="false" \
  INPUT_RUN="status=0
bash $(printf '%q' "$REPO_ROOT/test/universal-proxy-down-scenarios.sh") || status=\$?
echo \$status > scenarios.exit" &
STEP_PID=$!

# wait_for_step_marker <name>: false if the step ended or never wrote it.
wait_for_step_marker() {
  for _ in $(seq 1 600); do
    [ -e "$WORKDIR/$1" ] && return 0
    kill -0 "$STEP_PID" 2>/dev/null || return 1
    sleep 0.5
  done
  return 1
}

# stop_service <service>: brings the s6 service down for good, as a crash the
# supervisor was told not to recover from would.
stop_service() {
  local svc="$1"
  if docker exec "$CONTAINER" s6-svc -wd -T 20000 -d "/run/service/$svc" &&
    docker exec "$CONTAINER" s6-svstat "/run/service/$svc" | grep -q '^down'; then
    pass "$svc stopped in the proxy container"
  else
    fail "could not stop $svc in the proxy container"
  fi
}

CONTAINER=""
if wait_for_step_marker serving.done; then
  CONTAINER=$(state_container_name "$WORKDIR/step.state")
  stop_service haproxy
  touch "$WORKDIR/haproxy.down"
  if wait_for_step_marker haproxy-phase.done; then
    stop_service coredns
  else
    fail "the command never finished its haproxy phase"
  fi
  touch "$WORKDIR/coredns.down"
else
  fail "the command never reached the proxy"
fi

if wait_step_gone "$STEP_END_TIMEOUT"; then
  wait "$STEP_PID"
  STEP_EXIT=$?
  STEP_PID=""
else
  fail "the step did not end within ${STEP_END_TIMEOUT}s of its last phase"
  stop_step
  STEP_EXIT="timeout"
fi

echo ""
echo "--- in-sandbox scenarios ---"
# The command writes its proxy-up phase's failure count into serving.done, and
# the stopped phases' into scenarios.exit.
UP_FAILURES=$(cat "$WORKDIR/serving.done" 2>/dev/null || echo "missing")
check_status "the allowed origin was reachable with the proxy up" "$UP_FAILURES" 0
SCENARIOS_EXIT=$(cat "$WORKDIR/scenarios.exit" 2>/dev/null || echo "missing")
check_status "every request made after a service stopped failed" "$SCENARIOS_EXIT" 0

echo ""
echo "--- the step's outcome ---"
# The run script records the scenarios' result and exits 0, so a failure
# here is the report's. fail-on-blocked is off: a stopped proxy is not a rule
# the command broke, so it fails the step regardless.
check_status "the step failed on the report the stopped proxy left" "$STEP_EXIT" 1
assert_file_has "$WORKDIR/step.log" "the step's error says the logs are incomplete" \
  "^::error::buildcage sandbox logs are incomplete"
assert_file_has "$WORKDIR/step.log" "the step's error says the proxy did not answer" \
  "The proxy did not answer the report"

SUMMARY=$(cat "$WORKDIR/step.md")
assert_summary_contains "This report is incomplete" "the report marks itself incomplete"
assert_summary_contains "| \`allowed.example.com:80\` | HTTP |" \
  "the report still lists the request made before the proxy stopped"

CONTAINER=$(state_container_name "$WORKDIR/step.state")
if [ -z "$CONTAINER" ]; then
  fail "the step wrote no container_name to GITHUB_STATE"
else
  if docker ps -aq --filter "name=$CONTAINER" | grep -q .; then
    fail "the proxy container $CONTAINER was left behind"
  else
    pass "the proxy container was removed"
  fi
  if docker network ls -q --filter "label=com.docker.compose.project=$(proxy_project "$CONTAINER")" | grep -q .; then
    fail "the proxy's network was left behind"
  else
    pass "the proxy's network was removed"
  fi
fi

if [ "$FAILURES" -gt 0 ]; then
  echo ""
  echo "--- step log ---"
  cat "$WORKDIR/step.log"
fi

assert_results

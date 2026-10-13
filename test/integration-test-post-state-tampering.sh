#!/bin/bash
# Verifies post.ts validates values read back from $GITHUB_STATE instead of
# trusting them. The sandboxed command cannot write the file (see
# integration-test-file-commands.sh), but a process outside the sandbox, such
# as one an earlier step left running, can, and the runner keeps only the last
# value written for a repeated key, so it can overwrite container_name and
# ephemeral_overlay_roots before post.ts reads them back.
#
# @actions/core's getState reads STATE_<name> env vars directly, which is
# how the real runner invokes a post step, so this drives dist/post.cjs
# directly with those env vars for the tampering case below, rather than
# going through dist/main.cjs.
#
# One tampering case, not one per malformed shape: which values resolvePostState
# refuses is src/lib/post-state.test.ts's subject, and it covers traversal
# names, malformed ephemeral_overlay_roots and the rest against the same
# inputs. What only a real post step can show is that the refusal is wired
# through dist/post.cjs to the sudo and rm that would otherwise run.
set -uo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/driver-helpers.sh"

require_local_image

FAKE_BIN=$(mktemp -d)
SUDO_LOG="$FAKE_BIN/sudo.log"
cat >"$FAKE_BIN/sudo" <<'EOS'
#!/bin/bash
echo "$@" >>"$SUDO_LOG"
exit 0
EOS
chmod +x "$FAKE_BIN/sudo"
export SUDO_LOG

# A bare buildcage-proxy-* sweep would remove another git worktree's proxy
# while it is still in use.
CREATED_CONTAINERS=()

remove_own_container() {
  local name="$1" project
  project=$(docker inspect "$name" \
    --format '{{index .Config.Labels "com.docker.compose.project"}}' 2>/dev/null)
  docker rm -f "$name" >/dev/null 2>&1
  [ -n "$project" ] && docker network ls --filter "label=com.docker.compose.project=$project" -q |
    xargs -r docker network rm >/dev/null 2>&1
  return 0
}

cleanup() {
  rm -rf "$FAKE_BIN" "${CANARY_DIR:-}" "${VICTIM_DIR:-}"
  local name
  for name in "${CREATED_CONTAINERS[@]+"${CREATED_CONTAINERS[@]}"}"; do
    remove_own_container "$name"
  done
}
trap cleanup EXIT

echo "=== 1. a path-traversal container_name must not reach umount/rm ==="
CANARY_DIR=$(mktemp -d)
touch "$CANARY_DIR/keep"
TRAVERSAL="buildcage-proxy-x/../../../..${CANARY_DIR}"
OUT=$(PATH="$FAKE_BIN:$PATH" STATE_container_name="$TRAVERSAL" node dist/post.cjs 2>&1)

if [ -f "$CANARY_DIR/keep" ]; then
  pass "canary file survived the traversal"
else
  fail "canary file was deleted -- the traversal reached rm"
fi
if echo "$OUT" | grep -q "::error::"; then
  pass "post step logged ::error:: instead of cleaning up silently"
else
  fail "no ::error:: was logged; output was:"
  echo "$OUT"
fi
if [ -s "$SUDO_LOG" ]; then
  fail "sudo was invoked despite the traversal: $(cat "$SUDO_LOG")"
else
  pass "sudo was never invoked"
fi

echo ""
echo "=== 2. a concurrent step's own container name must not reach its proxy or its scratch dir ==="
# The two steps differ only in $GITHUB_ACTION, which the runner numbers per
# use within a job, the same shape as two `uses:` of this action side by
# side. The attacker names the victim's container, which is well-formed and
# therefore passes every check that looks at the name alone.
: >"$SUDO_LOG"
VICTIM_DIR=$(mktemp -d)
touch "$VICTIM_DIR/state.env" "$VICTIM_DIR/summary.md"
GITHUB_WORKSPACE="$VICTIM_DIR" \
  GITHUB_STATE="$VICTIM_DIR/state.env" \
  GITHUB_STEP_SUMMARY="$VICTIM_DIR/summary.md" \
  GITHUB_RUN_ID=1 GITHUB_RUN_ATTEMPT=1 GITHUB_JOB=test GITHUB_ACTION=buildcage RUNNER_TEMP="$VICTIM_DIR" \
  BUILDCAGE_LOCAL_IMAGE_REF="$BUILDCAGE_LOCAL_IMAGE_REF" \
  INPUT_RUN="sleep 300" \
  node dist/main.cjs >"$VICTIM_DIR/out.log" 2>&1 &
VICTIM_PID=$!

VICTIM_NAME=""
for _ in $(seq 1 60); do
  if grep -q '^container_name<<' "$VICTIM_DIR/state.env" 2>/dev/null; then
    VICTIM_NAME=$(awk '/^container_name<</{getline; print; exit}' "$VICTIM_DIR/state.env")
    CREATED_CONTAINERS+=("$VICTIM_NAME")
    break
  fi
  sleep 0.5
done
VICTIM_SCRATCH="/var/tmp/buildcage-$(id -u)/sandbox-${VICTIM_NAME#buildcage-proxy-}"
for _ in $(seq 1 60); do
  [ -n "$VICTIM_NAME" ] && [ -e "$VICTIM_SCRATCH" ] && break
  sleep 0.5
done

if [ -z "$VICTIM_NAME" ] || [ ! -e "$VICTIM_SCRATCH" ]; then
  fail "the victim step never reached a running sandbox; see log:"
  cat "$VICTIM_DIR/out.log"
else
  OUT=$(PATH="$FAKE_BIN:$PATH" \
    GITHUB_RUN_ID=1 GITHUB_RUN_ATTEMPT=1 GITHUB_JOB=test GITHUB_ACTION=buildcage_2 RUNNER_TEMP="$VICTIM_DIR" \
    STATE_container_name="$VICTIM_NAME" node dist/post.cjs 2>&1)

  if [ -e "$VICTIM_SCRATCH" ]; then
    pass "the concurrent step's scratch dir survived"
  else
    fail "the concurrent step's scratch dir $VICTIM_SCRATCH was deleted"
  fi
  if docker ps -q --filter "name=$VICTIM_NAME" | grep -q .; then
    pass "the concurrent step's proxy container is still running"
  else
    fail "the concurrent step's proxy container $VICTIM_NAME was torn down"
  fi
  if echo "$OUT" | grep -q "::error::"; then
    pass "post step logged ::error:: instead of cleaning up silently"
  else
    fail "no ::error:: was logged; output was:"
    echo "$OUT"
  fi
  if [ -s "$SUDO_LOG" ]; then
    fail "sudo was invoked against the concurrent step: $(cat "$SUDO_LOG")"
  else
    pass "sudo was never invoked"
  fi

  # The same container, from its own step: the check must not stand in the
  # way of the hard-kill cleanup this post step exists for.
  kill -9 "$VICTIM_PID" >/dev/null 2>&1
  sudo -n pkill -9 -f "sudo -n -- .*/run-isolated.sh" >/dev/null 2>&1
  sleep 1
  GITHUB_RUN_ID=1 GITHUB_RUN_ATTEMPT=1 GITHUB_JOB=test GITHUB_ACTION=buildcage RUNNER_TEMP="$VICTIM_DIR" \
    STATE_container_name="$VICTIM_NAME" node dist/post.cjs
  if [ -e "$VICTIM_SCRATCH" ]; then
    fail "the owning step's own post left $VICTIM_SCRATCH behind"
  else
    pass "the owning step's own post still cleans up its scratch dir"
  fi
  if docker ps -aq --filter "name=$VICTIM_NAME" | grep -q .; then
    fail "the owning step's own post left the proxy container behind"
  else
    pass "the owning step's own post still tears down its proxy container"
  fi
fi
kill -9 "$VICTIM_PID" >/dev/null 2>&1
rm -rf "$VICTIM_DIR"

assert_results

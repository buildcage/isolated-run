#!/bin/bash
# Verifies post.ts validates values read back from $GITHUB_STATE instead of
# trusting them. In persistent mode, $RUNNER_TEMP (where $GITHUB_STATE
# lives) stays writable inside the sandbox, and the runner keeps only the
# last value written for a repeated key, so the sandboxed command itself can
# overwrite container_name and ephemeral_overlay_roots before post.ts reads
# them back.
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
source "$(dirname "${BASH_SOURCE[0]}")/helpers.sh"

: "${BUILDCAGE_LOCAL_IMAGE_REF:?BUILDCAGE_LOCAL_IMAGE_REF must be set to the locally built proxy image}"

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
  rm -rf "$FAKE_BIN" "${CANARY_DIR:-}" "${WORKDIR:-}" "${VICTIM_DIR:-}"
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
echo "=== 2/3. normal-path cleanup after a hard kill, with and without a spoofed project_name ==="

run_hard_kill_and_post() {
  local label="$1"
  local workdir container_name scratch_dir
  workdir=$(mktemp -d)
  touch "$workdir/state.env" "$workdir/summary.md"

  GITHUB_WORKSPACE="$workdir" \
    GITHUB_STATE="$workdir/state.env" \
    GITHUB_STEP_SUMMARY="$workdir/summary.md" \
    BUILDCAGE_BUILD_TEST_HOOKS=1 \
    BUILDCAGE_LOCAL_IMAGE_REF="$BUILDCAGE_LOCAL_IMAGE_REF" \
    INPUT_RUN="sleep 300" \
    node dist/main.cjs >"$workdir/out.log" 2>&1 &
  local node_pid=$!

  local found=0
  for _ in $(seq 1 60); do
    if grep -q '^container_name<<' "$workdir/state.env" 2>/dev/null; then
      found=1
      break
    fi
    sleep 0.5
  done
  if [ "$found" != "1" ]; then
    fail "[$label] container_name never appeared in GITHUB_STATE; see log:"
    cat "$workdir/out.log"
    kill -9 "$node_pid" >/dev/null 2>&1
    rm -rf "$workdir"
    return
  fi
  container_name=$(awk '/^container_name<</{getline; print; exit}' "$workdir/state.env")
  CREATED_CONTAINERS+=("$container_name")
  scratch_dir="/var/tmp/buildcage-$(id -u)/sandbox-${container_name#buildcage-proxy-}"

  for _ in $(seq 1 60); do
    [ -e "$scratch_dir" ] && break
    sleep 0.5
  done

  kill -9 "$node_pid" >/dev/null 2>&1
  sudo -n pkill -9 -f "sudo -n -- .*/run-isolated.sh" >/dev/null 2>&1
  sleep 1

  if [ "$label" = "with-spoofed-project-name" ]; then
    STATE_container_name="$container_name" STATE_project_name="buildcage-deadbeefcafe" node dist/post.cjs
  else
    STATE_container_name="$container_name" node dist/post.cjs
  fi

  if [ -e "$scratch_dir" ]; then
    fail "[$label] scratch dir $scratch_dir still exists after post cleanup"
  else
    pass "[$label] scratch dir removed"
  fi
  if docker ps -aq --filter "name=$container_name" | grep -q .; then
    fail "[$label] proxy container $container_name still exists after post cleanup"
  else
    pass "[$label] proxy container removed"
  fi

  remove_own_container "$container_name"
  rm -rf "$workdir"
}

# STATE_project_name is deliberately never given here: post-state.ts derives
# projectName from container_name, so this proves it's no longer read.
run_hard_kill_and_post "plain"
# Given anyway in the second case, to prove it is ignored rather than merely
# unused.
run_hard_kill_and_post "with-spoofed-project-name"

echo ""
echo "=== 4. premise check: a persistent-mode step can actually append to \$GITHUB_STATE ==="
WORKDIR=$(mktemp -d)
touch "$WORKDIR/state.env" "$WORKDIR/summary.md"
GITHUB_WORKSPACE="$WORKDIR" \
  GITHUB_STATE="$WORKDIR/state.env" \
  GITHUB_STEP_SUMMARY="$WORKDIR/summary.md" \
  BUILDCAGE_BUILD_TEST_HOOKS=1 \
  BUILDCAGE_LOCAL_IMAGE_REF="$BUILDCAGE_LOCAL_IMAGE_REF" \
  INPUT_RUN='cat >> "$GITHUB_STATE" <<EOF
container_name<<BUILDCAGE_EOF
forged-from-inside-the-sandbox
BUILDCAGE_EOF
EOF' \
  node dist/main.cjs
if grep -q "forged-from-inside-the-sandbox" "$WORKDIR/state.env"; then
  pass "the sandboxed command was able to append to \$GITHUB_STATE (this is the premise the fix above defends against)"
else
  fail "the append never landed in \$GITHUB_STATE -- the premise for this whole test no longer holds; if that's expected, this test needs revisiting"
fi
rm -rf "$WORKDIR"

echo ""
echo "=== 5. a concurrent step's own container name must not reach its proxy or its scratch dir ==="
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
  GITHUB_RUN_ID=1 GITHUB_RUN_ATTEMPT=1 GITHUB_JOB=test GITHUB_ACTION=buildcage \
  BUILDCAGE_BUILD_TEST_HOOKS=1 \
  BUILDCAGE_LOCAL_IMAGE_REF="$BUILDCAGE_LOCAL_IMAGE_REF" \
  INPUT_RUN="sleep 300" \
  node dist/main.cjs >"$VICTIM_DIR/out.log" 2>&1 &
VICTIM_PID=$!

VICTIM_NAME=""
for _ in $(seq 1 60); do
  if grep -q '^container_name<<' "$VICTIM_DIR/state.env" 2>/dev/null; then
    VICTIM_NAME=$(awk '/^container_name<</{getline; print; exit}' "$VICTIM_DIR/state.env")
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
    GITHUB_RUN_ID=1 GITHUB_RUN_ATTEMPT=1 GITHUB_JOB=test GITHUB_ACTION=buildcage_2 \
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
  GITHUB_RUN_ID=1 GITHUB_RUN_ATTEMPT=1 GITHUB_JOB=test GITHUB_ACTION=buildcage \
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

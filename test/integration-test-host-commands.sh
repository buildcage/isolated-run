#!/bin/bash
# Verifies, in persistent mode, that a `docker` under $HOME earlier on PATH is
# never run, and that the docker config directory and this action's checkout
# are read-only inside the sandbox and cannot be renamed away, while a
# write_through entry inside the config directory stays writable. See
# sandbox/host-commands.ts. The stand-in only leaves a marker file.
#
# A second sandbox puts the config directory inside a workspace nested in
# $HOME, as on a hosted runner, where the directories between the workspace
# and $HOME are writable through $HOME and must not be renamable either.
#
# Two more reach the config directory through a symlink. One placed in $HOME,
# which the command could replace, refuses to start; one placed where the
# sandbox cannot write is followed, and its target is what becomes read-only.
set -uo pipefail

: "${BUILDCAGE_LOCAL_IMAGE_REF:?BUILDCAGE_LOCAL_IMAGE_REF must be set to the locally built proxy image}"

source "$(dirname "$0")/helpers.sh"

ACTION_ROOT=$(pwd -P)
WORKDIR=$(mktemp -d)
STANDIN_DIR="$HOME/.buildcage-test-bin-$$"
MARKER="$WORKDIR/standin-docker-ran"
DOCKER_CONFIG_DIR="$HOME/.docker"
NESTED_WRITABLE="$DOCKER_CONFIG_DIR/buildcage-test-$$"

NESTED_BASE="$HOME/.buildcage-test-ws-$$"
NESTED_WORKSPACE="$NESTED_BASE/repo/repo"
LINK_IN_HOME="$HOME/.buildcage-test-cfg-link-$$"
LINK_OUTSIDE="/var/tmp/buildcage-test-cfg-link-$$"
LINKED_CONFIG="$HOME/.buildcage-test-cfg-$$"

cleanup() {
  rm -rf "$WORKDIR" "$STANDIN_DIR" "$NESTED_WRITABLE" "$NESTED_BASE" "$NESTED_BASE.moved"
  rm -rf "$LINK_IN_HOME" "$LINK_OUTSIDE" "$LINKED_CONFIG"
  rm -f "$DOCKER_CONFIG_DIR/.buildcage-probe" "$ACTION_ROOT/.buildcage-probe"
}
trap cleanup EXIT

mkdir -p "$STANDIN_DIR"
printf '#!/bin/sh\ntouch %q\nexit 1\n' "$MARKER" >"$STANDIN_DIR/docker"
chmod +x "$STANDIN_DIR/docker"
touch "$WORKDIR/state.env" "$WORKDIR/summary.md"

# Only a checkout under $HOME is protected; the dev container keeps it elsewhere.
case "$ACTION_ROOT/" in
  "$HOME"/*) CHECK_ACTION_ROOT=1 ;;
  *) CHECK_ACTION_ROOT=0 ;;
esac
ACTION_PARENT=$(dirname "$ACTION_ROOT")

PATH="$STANDIN_DIR:$PATH" \
GITHUB_WORKSPACE="$WORKDIR" \
GITHUB_STATE="$WORKDIR/state.env" \
GITHUB_STEP_SUMMARY="$WORKDIR/summary.md" \
BUILDCAGE_BUILD_TEST_HOOKS=1 \
BUILDCAGE_LOCAL_IMAGE_REF="$BUILDCAGE_LOCAL_IMAGE_REF" \
INPUT_WRITE_THROUGH="$NESTED_WRITABLE" \
INPUT_RUN="rc=0

if touch '$DOCKER_CONFIG_DIR/.buildcage-probe' 2>/dev/null; then
  echo 'UNEXPECTED: the docker config directory was writable'
  rc=1
else
  echo 'OK: the docker config directory is read-only'
fi

if touch '$NESTED_WRITABLE/probe' 2>/dev/null; then
  echo 'OK: a write_through entry inside it stays writable'
else
  echo 'UNEXPECTED: a write_through entry inside it was not writable'
  rc=1
fi

if touch \"\$HOME/.buildcage-home-probe\" 2>/dev/null; then
  rm -f \"\$HOME/.buildcage-home-probe\"
  echo 'OK: \$HOME around it stays writable'
else
  echo 'UNEXPECTED: \$HOME was not writable'
  rc=1
fi

if [ '$CHECK_ACTION_ROOT' = 1 ]; then
  if touch '$ACTION_ROOT/.buildcage-probe' 2>/dev/null; then
    echo 'UNEXPECTED: the action checkout was writable'
    rc=1
  else
    echo 'OK: the action checkout is read-only'
  fi
  # $HOME is writable through to the host, so a rename that succeeds is undone.
  if mv '$ACTION_PARENT' '$ACTION_PARENT.moved' 2>/dev/null; then
    echo 'UNEXPECTED: a parent of the action checkout could be renamed'
    mv '$ACTION_PARENT.moved' '$ACTION_PARENT' 2>/dev/null || true
    rc=1
  else
    echo 'OK: a parent of the action checkout cannot be renamed'
  fi
fi

exit \$rc
" \
  node dist/main.cjs
CODE=$?

mkdir -p "$NESTED_WORKSPACE/.docker-config"
GITHUB_WORKSPACE="$NESTED_WORKSPACE" \
GITHUB_STATE="$WORKDIR/state.env" \
GITHUB_STEP_SUMMARY="$WORKDIR/summary.md" \
DOCKER_CONFIG="$NESTED_WORKSPACE/.docker-config" \
BUILDCAGE_BUILD_TEST_HOOKS=1 \
BUILDCAGE_LOCAL_IMAGE_REF="$BUILDCAGE_LOCAL_IMAGE_REF" \
INPUT_RUN="rc=0
for dir in '$NESTED_BASE/repo' '$NESTED_BASE'; do
  if mv \"\$dir\" \"\$dir.moved\" 2>/dev/null; then
    echo \"UNEXPECTED: \$dir, above the workspace, could be renamed\"
    mv \"\$dir.moved\" \"\$dir\" 2>/dev/null || true
    rc=1
  else
    echo \"OK: \$dir, above the workspace, cannot be renamed\"
  fi
done
exit \$rc
" \
  node dist/main.cjs
NESTED_CODE=$?

mkdir -p "$LINKED_CONFIG"
ln -s "$LINKED_CONFIG" "$LINK_IN_HOME"
ln -s "$LINKED_CONFIG" "$LINK_OUTSIDE"

run_with_config() {
  GITHUB_WORKSPACE="$WORKDIR" \
  GITHUB_STATE="$WORKDIR/state.env" \
  GITHUB_STEP_SUMMARY="$WORKDIR/summary.md" \
  DOCKER_CONFIG="$1" \
  BUILDCAGE_BUILD_TEST_HOOKS=1 \
  BUILDCAGE_LOCAL_IMAGE_REF="$BUILDCAGE_LOCAL_IMAGE_REF" \
  INPUT_RUN="if touch '$LINKED_CONFIG/probe' 2>/dev/null; then
  echo 'UNEXPECTED: the linked config directory was writable'
  exit 1
fi
echo 'OK: the linked config directory is read-only'" \
    node dist/main.cjs 2>&1
}

LINK_IN_HOME_OUT=$(run_with_config "$LINK_IN_HOME")
LINK_IN_HOME_CODE=$?
echo "$LINK_IN_HOME_OUT"
run_with_config "$LINK_OUTSIDE"
LINK_OUTSIDE_CODE=$?

echo ""
echo "=== Sandbox Host Command Assertions ==="
echo ""
check_status "the step ran with the stand-in docker first on PATH" "$CODE" 0
check_status "nothing between a nested workspace and \$HOME could be renamed" "$NESTED_CODE" 0
if [ "$LINK_IN_HOME_CODE" != 0 ] && echo "$LINK_IN_HOME_OUT" | grep -q "a symlink the sandboxed command can replace"; then
  pass "a config directory reached through a symlink in \$HOME refuses to start"
else
  fail "a config directory reached through a symlink in \$HOME did not refuse to start (exit $LINK_IN_HOME_CODE)"
fi
check_status "a config directory reached through a symlink outside \$HOME is read-only at its target" "$LINK_OUTSIDE_CODE" 0
if [ -e "$MARKER" ]; then
  fail "the stand-in docker under \$HOME was run in place of the real one"
else
  pass "the stand-in docker under \$HOME was never run"
fi
if [ "$CHECK_ACTION_ROOT" != 1 ]; then
  echo "  SKIP  the action checkout is not under \$HOME here, so no parent guard applies"
fi
assert_results

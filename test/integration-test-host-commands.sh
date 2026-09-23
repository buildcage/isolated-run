#!/bin/bash
# Verifies that what the step runs on the host after the command exits stays
# out of the command's reach in persistent mode (see sandbox/host-commands.ts):
# a `docker` earlier on PATH under $HOME is never run in place of the real one,
# and the docker CLI's config directory and this action's own checkout are
# read-only inside the sandbox even though $HOME around them is writable.
#
# The stand-in `docker` only leaves a marker file behind, and is in place
# before the step starts, which is the harder case: pinning has to skip it,
# not merely resolve before the command could plant one.
set -uo pipefail

: "${BUILDCAGE_LOCAL_IMAGE_REF:?BUILDCAGE_LOCAL_IMAGE_REF must be set to the locally built proxy image}"

source "$(dirname "$0")/helpers.sh"

ACTION_ROOT=$(pwd -P)
WORKDIR=$(mktemp -d)
STANDIN_DIR="$HOME/.buildcage-test-bin-$$"
MARKER="$WORKDIR/standin-docker-ran"
DOCKER_CONFIG_DIR="$HOME/.docker"

cleanup() {
  rm -rf "$WORKDIR" "$STANDIN_DIR"
  rm -f "$DOCKER_CONFIG_DIR/.buildcage-probe" "$ACTION_ROOT/.buildcage-probe"
}
trap cleanup EXIT

mkdir -p "$STANDIN_DIR"
printf '#!/bin/sh\ntouch %q\nexit 1\n' "$MARKER" >"$STANDIN_DIR/docker"
chmod +x "$STANDIN_DIR/docker"
touch "$WORKDIR/state.env" "$WORKDIR/summary.md"

# The checkout is only a read-only candidate when $HOME holds it, as it does on
# a hosted runner; the dev container keeps it elsewhere.
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
INPUT_RUN="rc=0

if touch '$DOCKER_CONFIG_DIR/.buildcage-probe' 2>/dev/null; then
  echo 'UNEXPECTED: the docker config directory was writable'
  rc=1
else
  echo 'OK: the docker config directory is read-only'
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
  # The read-only mount is on the checkout itself; renaming a parent would move
  # it aside and free the original path. Each parent is a mount point, so this
  # must fail. Nothing moves on the host either way, since the guard is in the
  # sandbox's mount namespace only.
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

echo ""
echo "=== Sandbox Host Command Assertions ==="
echo ""
check_status "the step ran with the stand-in docker first on PATH" "$CODE" 0
if [ -e "$MARKER" ]; then
  fail "the stand-in docker under \$HOME was run in place of the real one"
else
  pass "the stand-in docker under \$HOME was never run"
fi
if [ "$CHECK_ACTION_ROOT" != 1 ]; then
  echo "  SKIP  the action checkout is not under \$HOME here, so no parent guard applies"
fi
assert_results

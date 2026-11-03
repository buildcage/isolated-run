#!/bin/bash
# Verifies working-directory: by driving dist/main.cjs directly. The command
# starts there with PWD set to it, a relative write-through path and config-file
# resolve against its real path, and a directory that is missing or that the
# sandbox mounts over fails the step, the missing one left uncreated, as does a
# `..` after the input's start.
set -uo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/driver-helpers.sh"

require_local_image

WORKDIR=$(mktemp -d)
# Outside every always-writable path, so a write under it proves the relative
# write-through entry resolved against it.
OUTSIDE=/opt/buildcage-working-directory-test
SHM=/dev/shm/buildcage-working-directory-test
sudo -n mkdir -p "$OUTSIDE/out"
sudo -n chown -R "$(id -u):$(id -g)" "$OUTSIDE"
mkdir -p "$SHM" "$WORKDIR/app"
cleanup() {
  sudo -n rm -rf "$OUTSIDE"
  rm -rf "$WORKDIR" "$SHM"
}
trap cleanup EXIT

# step <name> VAR=value...: runs one step in $WORKDIR, its output in <name>.log.
step() {
  local name="$1"
  shift
  : >"$WORKDIR/$name.state"
  : >"$WORKDIR/$name.md"
  env \
    GITHUB_WORKSPACE="$WORKDIR" \
    GITHUB_STATE="$WORKDIR/$name.state" \
    GITHUB_STEP_SUMMARY="$WORKDIR/$name.md" \
    BUILDCAGE_LOCAL_IMAGE_REF="$BUILDCAGE_LOCAL_IMAGE_REF" \
    "$@" \
    node dist/main.cjs >"$WORKDIR/$name.log" 2>&1
}

echo ""
echo "=== Sandbox working-directory: Assertions ==="
echo ""

step outside \
  INPUT_WORKING_DIRECTORY="$OUTSIDE" \
  INPUT_WRITE_THROUGH="out" \
  INPUT_RUN="pwd >\"$WORKDIR/pwd\"
printf '%s\n' \"\$PWD\" >\"$WORKDIR/pwd-env\"
echo built >out/marker"
CODE=$?
if [ "$CODE" = "0" ] && [ "$(cat "$WORKDIR/pwd" 2>/dev/null)" = "$OUTSIDE" ]; then
  pass "the command starts in working-directory"
else
  fail "expected the command to start in $OUTSIDE (exit $CODE, pwd $(cat "$WORKDIR/pwd" 2>/dev/null))"
  cat "$WORKDIR/outside.log"
fi
if [ "$(cat "$WORKDIR/pwd-env" 2>/dev/null)" = "$OUTSIDE" ]; then
  pass "PWD names working-directory"
else
  fail "expected PWD $OUTSIDE, got $(cat "$WORKDIR/pwd-env" 2>/dev/null)"
fi
if [ -f "$OUTSIDE/out/marker" ]; then
  pass "a relative write-through path resolves against working-directory"
else
  fail "$OUTSIDE/out/marker is missing: write-through: out did not reach $OUTSIDE/out"
fi

printf 'label: from-app\n' >"$WORKDIR/app/buildcage.yml"
step config \
  INPUT_WORKING_DIRECTORY="app" \
  INPUT_CONFIG_FILE="buildcage.yml" \
  INPUT_RUN="true"
CODE=$?
if [ "$CODE" = "0" ] && grep -q "from-app" "$WORKDIR/config.md"; then
  pass "config-file resolves against working-directory"
else
  fail "expected app/buildcage.yml to label the report (exit $CODE)"
  cat "$WORKDIR/config.log"
fi

step missing INPUT_WORKING_DIRECTORY="missing" INPUT_RUN="true"
CODE=$?
if [ "$CODE" != "0" ] && grep -q 'working-directory "missing" .* does not exist' "$WORKDIR/missing.log" &&
  [ ! -e "$WORKDIR/missing" ]; then
  pass "a missing working-directory fails the step without being created"
else
  fail "expected a missing working-directory to fail and stay missing (exit $CODE)"
  cat "$WORKDIR/missing.log"
fi

# Under $OUTSIDE, so only write-through makes the two directories writable.
mkdir -p "$OUTSIDE/releases/v2"
ln -s releases/v2 "$OUTSIDE/current"
REAL_OUTSIDE=$(cd "$OUTSIDE" && pwd -P)
step linked INPUT_WORKING_DIRECTORY="$OUTSIDE/current" INPUT_WRITE_THROUGH="../out
dist" \
  INPUT_RUN="printf '%s\n' \"\$PWD\" >../out/pwd-env
cd .. && echo built >out/marker && echo built >v2/dist/marker"
CODE=$?
if [ "$CODE" = "0" ] && [ -f "$OUTSIDE/releases/out/marker" ] && [ -f "$OUTSIDE/releases/v2/dist/marker" ]; then
  pass "relative write-through paths, a leading .. included, resolve against a symlinked working-directory's real path"
else
  fail "expected ../out and dist to land under $OUTSIDE/releases (exit $CODE)"
  cat "$WORKDIR/linked.log"
fi
if [ "$(cat "$OUTSIDE/releases/out/pwd-env" 2>/dev/null)" = "$REAL_OUTSIDE/releases/v2" ]; then
  pass "PWD names a symlinked working-directory by its real path"
else
  fail "expected PWD $REAL_OUTSIDE/releases/v2, got $(cat "$OUTSIDE/releases/out/pwd-env" 2>/dev/null)"
fi

ln -s releases/v2 "$WORKDIR/current"
step dotdot INPUT_WORKING_DIRECTORY="current/.." INPUT_RUN="touch \"$WORKDIR/dotdot-ran\""
CODE=$?
if [ "$CODE" != "0" ] && [ ! -e "$WORKDIR/dotdot-ran" ] &&
  grep -q 'working-directory "current/.." has a ".." after its start' "$WORKDIR/dotdot.log"; then
  pass "a .. after the start of working-directory fails the step"
else
  fail "expected working-directory: current/.. to be refused (exit $CODE)"
  cat "$WORKDIR/dotdot.log"
fi

step shm INPUT_WORKING_DIRECTORY="$SHM" INPUT_RUN="true"
CODE=$?
if [ "$CODE" != "0" ] && grep -q "the sandbox mounts its own /dev/shm" "$WORKDIR/shm.log"; then
  pass "a working-directory the sandbox mounts over fails the step"
else
  fail "expected a working-directory under /dev/shm to fail (exit $CODE)"
  cat "$WORKDIR/shm.log"
fi

assert_results

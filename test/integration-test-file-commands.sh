#!/bin/bash
# Verifies that the runner's GITHUB_ENV, GITHUB_PATH and GITHUB_STATE files are
# read-only inside the sandbox in both filesystem modes and cannot be renamed
# away, and that write_through naming GITHUB_ENV or GITHUB_PATH opens that one
# file only. Under write_through: / nothing above them is a mount point, so the
# third run also tries to move $RUNNER_TEMP aside. See
# sandboxReadonlyFileCommands and renameGuardDirs in sandbox/host-commands.ts.
set -uo pipefail

: "${BUILDCAGE_LOCAL_IMAGE_REF:?BUILDCAGE_LOCAL_IMAGE_REF must be set to the locally built proxy image}"

source "$(dirname "$0")/helpers.sh"

WORKDIR=$(mktemp -d)
trap 'rm -rf "$WORKDIR"' EXIT
COMMANDS="$WORKDIR/_temp/_runner_file_commands"
mkdir -p "$COMMANDS"
touch "$WORKDIR/summary.md"

# The step script: each file is written to and renamed, and the one named in
# write_through is expected to take the write.
PROBE_SCRIPT='rc=0
for name in GITHUB_ENV GITHUB_PATH GITHUB_STATE; do
  file=$(printenv "$name")
  if [ "$name" = "$OPENED" ]; then
    if echo "probe-$MODE" >>"$file" 2>/dev/null; then
      echo "OK: $name, named in write_through, is writable"
    else
      echo "UNEXPECTED: $name, named in write_through, was not writable"
      rc=1
    fi
    continue
  fi
  if echo "probe-$MODE" >>"$file" 2>/dev/null; then
    echo "UNEXPECTED: $name was writable"
    rc=1
  else
    echo "OK: $name is read-only"
  fi
  if mv "$file" "$file.moved" 2>/dev/null; then
    echo "UNEXPECTED: $name could be renamed"
    rc=1
  else
    echo "OK: $name cannot be renamed"
  fi
done
# Only a writable parent can be renamed, and only persistent mode keeps the
# rename, so only there is the directory guarded.
if [ "$MODE" = persistent ]; then
  if mv "$RUNNER_TEMP" "$RUNNER_TEMP.moved" 2>/dev/null; then
    echo "UNEXPECTED: \$RUNNER_TEMP could be renamed"
    mv "$RUNNER_TEMP.moved" "$RUNNER_TEMP" 2>/dev/null || true
    rc=1
  else
    echo "OK: \$RUNNER_TEMP cannot be renamed"
  fi
  dir=$(dirname "$GITHUB_ENV")
  if mv "$dir" "$dir.moved" 2>/dev/null; then
    echo "UNEXPECTED: the file command directory could be renamed"
    mv "$dir.moved" "$dir" 2>/dev/null || true
    rc=1
  else
    echo "OK: the file command directory cannot be renamed"
  fi
fi
exit $rc'

# Runs one sandbox, named $1, in mode $2 with write_through $3, which opens
# the file named in $4 (none for write_through: /).
run_probe() {
  local tag="$1" mode="$2" write_through="$3" opened="$4"
  local env_file="$COMMANDS/set_env_$tag" path_file="$COMMANDS/add_path_$tag"
  local state_file="$COMMANDS/save_state_$tag"
  touch "$env_file" "$path_file" "$state_file"
  echo "=== $mode, write_through: $write_through ==="
  RUNNER_TEMP="$WORKDIR/_temp" \
  GITHUB_WORKSPACE="$WORKDIR" \
  GITHUB_ENV="$env_file" \
  GITHUB_PATH="$path_file" \
  GITHUB_STATE="$state_file" \
  GITHUB_STEP_SUMMARY="$WORKDIR/summary.md" \
  BUILDCAGE_BUILD_TEST_HOOKS=1 \
  BUILDCAGE_LOCAL_IMAGE_REF="$BUILDCAGE_LOCAL_IMAGE_REF" \
  INPUT_FILESYSTEM_MODE="$mode" \
  INPUT_WRITE_THROUGH="$write_through" \
  INPUT_RUN="MODE=$mode OPENED=$opened; $PROBE_SCRIPT" \
    node dist/main.cjs
}

run_probe persistent persistent '$GITHUB_PATH' GITHUB_PATH
PERSISTENT_CODE=$?
run_probe ephemeral ephemeral '$GITHUB_ENV' GITHUB_ENV
EPHEMERAL_CODE=$?
run_probe whole persistent / none
WHOLE_CODE=$?

echo ""
echo "=== Sandbox File Command Assertions ==="
echo ""
check_status "persistent: every probe inside the sandbox held" "$PERSISTENT_CODE" 0
check_status "ephemeral: every probe inside the sandbox held" "$EPHEMERAL_CODE" 0
check_status "write_through: /: every probe inside the sandbox held" "$WHOLE_CODE" 0

# What reached the host: only the write to the file write_through named.
check_host_file() {
  local label="$1" file="$2" want="$3"
  if [ -z "$want" ] && ! grep -q probe "$file" 2>/dev/null; then
    pass "$label"
  elif [ -n "$want" ] && grep -qx "$want" "$file" 2>/dev/null; then
    pass "$label"
  else
    fail "$label -- got: $(cat "$file" 2>/dev/null)"
  fi
}
check_host_file "persistent: GITHUB_PATH took the write" "$COMMANDS/add_path_persistent" probe-persistent
check_host_file "persistent: GITHUB_ENV is untouched" "$COMMANDS/set_env_persistent" ""
check_host_file "persistent: GITHUB_STATE carries no probe" "$COMMANDS/save_state_persistent" ""
check_host_file "ephemeral: GITHUB_ENV took the write" "$COMMANDS/set_env_ephemeral" probe-ephemeral
check_host_file "ephemeral: GITHUB_PATH is untouched" "$COMMANDS/add_path_ephemeral" ""
check_host_file "write_through: /: GITHUB_ENV is untouched" "$COMMANDS/set_env_whole" ""
assert_results

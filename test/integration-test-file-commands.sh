#!/bin/bash
# Verifies that the runner's GITHUB_ENV, GITHUB_PATH and GITHUB_STATE files are
# read-only inside the sandbox in both filesystem modes and cannot be renamed
# away, and that write_through naming GITHUB_ENV or GITHUB_PATH opens that one
# file only. Under write_through: / nothing above them is a mount point, so the
# third run also tries to move $RUNNER_TEMP aside, and writes to /opt, which
# no other entry opens. The fourth reaches the files through a bind mount that
# write_through names. See sandboxReadonlyFileCommands and renameGuardDirs in
# sandbox/host-commands.ts.
#
# The ephemeral run also checks the other half: GITHUB_OUTPUT, named in
# write_through, is mediated, so the command writes a backing copy it can
# rewrite in place (sed -i, which would EBUSY against a bind-mounted file), and
# the host writes the real file from it. GITHUB_STEP_SUMMARY, not named, stays
# under the overlay and is discarded, while this action's report still lands.
# The persistent run's GITHUB_STEP_SUMMARY is mediated too, and lands after the
# report. See runner-output-files.ts.
set -uo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/driver-helpers.sh"

require_local_image

WORKDIR=$(mktemp -d)
trap 'rm -rf "$WORKDIR"' EXIT
COMMANDS="$WORKDIR/_temp/_runner_file_commands"
mkdir -p "$COMMANDS"
touch "$WORKDIR/summary.md"

# The step script: each file is written to and renamed, and the one named in
# write_through is expected to take the write.
# shellcheck disable=SC2016 # expands in the sandbox
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
  echo "COMMAND_SUMMARY" >>"$GITHUB_STEP_SUMMARY" || rc=1
fi
if [ "$MODE" = ephemeral ]; then
  if echo "mediated_key=initial" >>"$GITHUB_OUTPUT" && sed -i "s/initial/final/" "$GITHUB_OUTPUT"; then
    echo "OK: GITHUB_OUTPUT can be rewritten in place"
  else
    echo "UNEXPECTED: GITHUB_OUTPUT could not be rewritten in place"
    rc=1
  fi
  if echo "DISCARDED_SUMMARY" >>"$GITHUB_STEP_SUMMARY"; then
    echo "OK: GITHUB_STEP_SUMMARY is writable"
  else
    echo "UNEXPECTED: GITHUB_STEP_SUMMARY was not writable"
    rc=1
  fi
fi
if [ "$OPENED" = none ]; then
  if touch /opt/.buildcage-whole-test 2>/dev/null; then
    rm -f /opt/.buildcage-whole-test
    echo "OK: /opt is writable"
  else
    echo "UNEXPECTED: /opt was not writable"
    rc=1
  fi
fi
exit $rc'

# Runs one sandbox, named $1, in mode $2 with write_through $3, which opens
# the file named in $4 (none for write_through: /).
run_probe() {
  local tag="$1" mode="$2" write_through="$3" opened="$4"
  local env_file="$COMMANDS/set_env_$tag" path_file="$COMMANDS/add_path_$tag"
  local state_file="$COMMANDS/save_state_$tag" output_file="$COMMANDS/set_output_$tag"
  local summary_file="$WORKDIR/summary_$tag.md"
  touch "$env_file" "$path_file" "$state_file" "$output_file" "$summary_file"
  echo "=== $mode, write_through: $write_through ==="
  RUNNER_TEMP="$WORKDIR/_temp" \
  GITHUB_WORKSPACE="$WORKDIR" \
  GITHUB_ENV="$env_file" \
  GITHUB_PATH="$path_file" \
  GITHUB_STATE="$state_file" \
  GITHUB_OUTPUT="$output_file" \
  GITHUB_STEP_SUMMARY="$summary_file" \
  BUILDCAGE_LOCAL_IMAGE_REF="$BUILDCAGE_LOCAL_IMAGE_REF" \
  INPUT_FILESYSTEM_MODE="$mode" \
  INPUT_WRITE_THROUGH="$write_through" \
  INPUT_RUN="MODE=$mode OPENED=$opened; $PROBE_SCRIPT" \
    node dist/main.cjs
}

# shellcheck disable=SC2016 # the action expands write_through
run_probe persistent persistent '$GITHUB_PATH' GITHUB_PATH
PERSISTENT_CODE=$?
# shellcheck disable=SC2016
run_probe ephemeral ephemeral '$GITHUB_ENV
$GITHUB_OUTPUT' GITHUB_ENV
EPHEMERAL_CODE=$?
run_probe whole persistent / none
WHOLE_CODE=$?

# The same files through a bind mount of the work directory that write_through
# names: what is read-only at one path has to be at the other too.
ALIAS="/mnt/buildcage-test-alias-$$"
if ! sudo -n mkdir -p "$ALIAS" || ! sudo -n mount --bind "$WORKDIR" "$ALIAS"; then
  echo "  FAIL  could not bind-mount the work directory onto $ALIAS"
  exit 1
fi
trap 'sudo -n umount "$ALIAS"; sudo -n rmdir "$ALIAS"; rm -rf "$WORKDIR"' EXIT
for name in env path state; do touch "$COMMANDS/${name}_alias"; done
echo "=== persistent, write_through: $ALIAS ==="
RUNNER_TEMP="$WORKDIR/_temp" \
GITHUB_WORKSPACE="$WORKDIR" \
GITHUB_ENV="$COMMANDS/env_alias" \
GITHUB_PATH="$COMMANDS/path_alias" \
GITHUB_STATE="$COMMANDS/state_alias" \
GITHUB_STEP_SUMMARY="$WORKDIR/summary.md" \
BUILDCAGE_LOCAL_IMAGE_REF="$BUILDCAGE_LOCAL_IMAGE_REF" \
INPUT_WRITE_THROUGH="$ALIAS" \
INPUT_RUN="rc=0
for name in env path state; do
  file='$ALIAS/_temp/_runner_file_commands/'\${name}_alias
  if echo probe-alias >>\"\$file\" 2>/dev/null; then
    echo \"UNEXPECTED: \$file was writable\"
    rc=1
  else
    echo \"OK: \$file is read-only\"
  fi
done
exit \$rc" \
  node dist/main.cjs
ALIAS_CODE=$?

echo ""
echo "=== Sandbox File Command Assertions ==="
echo ""
check_status "persistent: every probe inside the sandbox held" "$PERSISTENT_CODE" 0
check_status "ephemeral: every probe inside the sandbox held" "$EPHEMERAL_CODE" 0
check_status "write_through: /: every probe inside the sandbox held" "$WHOLE_CODE" 0
check_status "an alias in write_through: every probe inside the sandbox held" "$ALIAS_CODE" 0

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
check_host_file "an alias in write_through: GITHUB_ENV is untouched" "$COMMANDS/env_alias" ""

PERSISTENT_SUMMARY="$WORKDIR/summary_persistent.md"
report_line=$(grep -n -m1 "^## " "$PERSISTENT_SUMMARY" | cut -d: -f1)
command_line=$(grep -nx -m1 "COMMAND_SUMMARY" "$PERSISTENT_SUMMARY" | cut -d: -f1)
if [ -n "$report_line" ] && [ -n "$command_line" ] && [ "$report_line" -lt "$command_line" ]; then
  pass "persistent: GITHUB_STEP_SUMMARY has the command's markdown after this action's report"
else
  fail "persistent: GITHUB_STEP_SUMMARY -- got: $(cat "$PERSISTENT_SUMMARY" 2>/dev/null)"
fi

OUTPUT_FILE="$COMMANDS/set_output_ephemeral"
SUMMARY_FILE="$WORKDIR/summary_ephemeral.md"
if grep -qx "mediated_key=final" "$OUTPUT_FILE" 2>/dev/null; then
  pass "ephemeral: GITHUB_OUTPUT written back after an in-place edit"
else
  fail "ephemeral: GITHUB_OUTPUT -- got: $(cat "$OUTPUT_FILE" 2>/dev/null)"
fi
# The report is written from the host after the sandbox exits, outside the
# overlay that took the command's markdown.
if ! grep -q "DISCARDED_SUMMARY" "$SUMMARY_FILE" 2>/dev/null && grep -q "^## " "$SUMMARY_FILE"; then
  pass "ephemeral: GITHUB_STEP_SUMMARY, not named in write_through, has this action's report and not the command's markdown"
else
  fail "ephemeral: GITHUB_STEP_SUMMARY -- got: $(cat "$SUMMARY_FILE" 2>/dev/null)"
fi
assert_results

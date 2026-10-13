#!/bin/bash
# Checks the recording test-e2e.yml's filesystem audit step uploaded.
# Usage: assert-filesystem-audit-artifact.sh <the downloaded artifact's directory>
set -euo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/helpers.sh"

shopt -s nullglob
recordings=("$1"/*.jsonl)
if [ "${#recordings[@]}" -ne 1 ]; then
  echo "::error::expected one recording in $1, found ${#recordings[@]}"
  exit 1
fi
f="${recordings[0]}"

# holds/holds_not <label> <jq filter over the events as one array>
holds() {
  if jq -se "$2" "$f" > /dev/null; then pass "$1"; else fail "$1"; fi
}
holds_not() {
  if jq -se "($2) | not" "$f" > /dev/null; then pass "$1"; else fail "$1"; fi
}

echo ""
echo "=== Filesystem Audit Artifact Assertions ==="
echo ""

if [ ! -s "$f" ]; then
  fail "The recording is not empty"
  assert_results
fi
echo "::group::Recorded events (first lines)"
head -20 "$f"
echo "::endgroup::"

assert_file_has "$f" "A write is recorded" '"kind":"write"'
# overlayfs opens a layer's directories with O_NOATIME (0o1000000) on its own
# behalf; none of those may pass for the step's.
holds_not "No O_NOATIME open is recorded" \
  'any(.[]; .kind == "open" and ((.flags // 0) / 262144 | floor) % 2 == 1)'
# buildcage's own exec wrappers and scratch files must not leak.
assert_file_lacks "$f" "buildcage's own wrappers are left out" -E '"comm":"(setpriv|buildcage-init|run-script\.sh)"'
assert_file_lacks "$f" "buildcage's scratch files are left out" '/var/tmp/buildcage-'
assert_file_lacks "$f" "A program's arguments are not recorded" 'buildcage-audit-sentinel-arg'

# A program run by a relative name is recorded under the file it resolved to,
# the script itself rather than its interpreter, with the name it was run by
# beside it.
assert_file_has "$f" "run.sh is recorded under its path and the name it was run by" \
  -E '"kind":"exec",[^}]*"path":"/[^"]*/A/run\.sh","name":"\./run\.sh"'
holds "run.sh's interpreter is recorded as the image its exec mapped" \
  'any(.[]; .kind == "mmap" and .path == "/usr/bin/dash" and .image == true)'

# A mkdir the read-only root refused before the tracer's path hook is recorded
# (the summary folds it into /usr/**), one on a name already there is not.
holds "A mkdir the read-only root refused is recorded with EROFS" \
  'any(.[]; .kind == "mkdir" and .path == "/usr/local/buildcage-ro-probe" and .err == 30)'
holds_not "A mkdir on a name already there is not recorded" \
  'any(.[]; .kind == "mkdir" and .err == 17)'
holds "A refused chmod is recorded with its mode" \
  'any(.[]; .kind == "chmod" and .failed and .mode == "0777" and (.path | endswith("/root-owned.txt")))'
holds "A refused chown is recorded with its owner" \
  'any(.[]; .kind == "chown" and .failed and .owner == "1:2" and (.path | endswith("/root-owned.txt")))'
holds "A symlink's longest target is recorded whole" \
  'any(.[]; .kind == "symlink" and (.path | endswith("/long-link")) and (.to | length) == 4095)'

# Refused after the tracer's hook: no mapping, and only the failed open.
holds_not "A refused mapping is not recorded" \
  'any(.[]; .kind == "mmap" and (.path // "" | endswith("/ro-mapped.bin")))'
holds "A refused FIFO open is recorded once, as failed" \
  '[.[] | select(.kind == "open" and (.path // "" | endswith("/fifo")))] | length == 1 and .[0].failed'

holds "The refused unshare is recorded with EPERM" \
  'any(.[]; .kind == "syscall" and .syscall == "unshare" and .err == 1 and .failed)'
if [ "$(uname -m)" = x86_64 ]; then
  holds "The killed 32-bit getpid is recorded" \
    'any(.[]; .kind == "syscall" and .syscall == "getpid" and .compat and .killed)'
fi

assert_results

#!/bin/bash
# Checks the Job Summary of test-e2e.yml's filesystem audit step. Run on the
# runner host from the checkout the step wrote its files in.
# The backticks in the patterns are the summary's Markdown code spans.
# shellcheck disable=SC2016
set -euo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/helpers.sh"

f="$BUILDCAGE_RUN_DEBUG_SUMMARY_FILE"
sections=$(mktemp -d)
trap 'rm -rf "$sections"' EXIT
sed -n '/^#### Executed/,/^#### Accessed/p' "$f" > "$sections/executed.md"
sed -n '/^#### Accessed/,/<details>/p' "$f" > "$sections/accessed.md"

# The line a row is first on, or nothing.
line_of() { grep -nE -m1 "$1" "$f" | cut -d: -f1 || true; }

echo ""
echo "=== Filesystem Audit Summary Assertions ==="
echo ""

assert_file_has "$f" "The summary has the Process Activity section" "Process Activity"
# The tracer stopped on SIGTERM and wrote its whole record.
assert_file_lacks "$f" "The record is not marked incomplete" "This record is incomplete"
# The probe writes show as a flagged, command-tagged line under the
# workspace, led by its elapsed time (MM:SS.mmm) and a colon.
t='[0-9]{2}:[0-9]{2}\.[0-9]{3}'
assert_file_has "$f" "A probe line is led by its elapsed time" -E "^$t(-$t)?: +[RWXMLDArwxmlda!]+ +\S+ +\./probe"

# Rows run in the order they were first touched: write, move, delete.
w=$(line_of ' W +bash +\./probe\.txt$')
m=$(line_of ' M +mv +\./probe\.txt$')
d=$(line_of ' D +rm +\./probe2\.txt$')
if [ -n "$w" ] && [ -n "$m" ] && [ -n "$d" ] && [ "$w" -lt "$m" ] && [ "$m" -lt "$d" ]; then
  pass "The probe's write, move and delete rows run in that order"
else
  fail "The probe's write, move and delete rows run in that order -- lines: '$w' '$m' '$d'"
fi

# The tables list what ran and how often, and what was touched, across
# commands. python3 is a symlink, so it shows as the versioned file it runs.
assert_file_has "$f" "python3 is listed as the versioned file it runs" -E '^\| `/usr/bin/python3[.0-9]*` \| [0-9]+ \|$'
assert_file_has "$f" "run.sh is listed as run once" -F '| `./A/run.sh` | 1 |'
# Running a program is left to the executed table.
assert_file_lacks "$sections/accessed.md" "The accessed table has no run flag" -E '\| [A-Za-z!]*X[A-Za-z!]* \|$'
assert_file_has "$f" "futimens.txt is in the accessed table" -F '| `./futimens.txt` | WA |'
assert_file_has "$f" "empty-name.txt is in the accessed table" -F '| `./empty-name.txt` | WA |'
assert_file_has "$f" "The summary has the process details" '<summary>🔍 Process details</summary>'
assert_file_has "$f" "futimens.txt has a details row" -E ' WA +python3 +\./futimens\.txt$'
assert_file_has "$f" "empty-name.txt has a details row" -E ' WA +python3 +\./empty-name\.txt$'

# A subshell's command still counts as the step's. GNU touch then sets the
# new file's times through the descriptor; uutils' does not.
a=
if [[ "$(touch --version)" == *'GNU coreutils'* ]]; then a=A; fi
assert_file_has "$f" "A subshell's write is in the accessed table" -F "| \`./subshell.txt\` | W$a |"
assert_file_has "$f" "A subshell's write has a details row" -E " W$a +touch +\./subshell\.txt$"

# Relative names show under the directory they resolved against.
assert_file_has "$f" "A failed read against a changed working directory shows under it" -E ' r +bash +\./sub/missing\.txt$'
assert_file_has "$f" "A failed delete against a directory descriptor shows under it" -E ' d +python3 +\./sub/gone$'
assert_file_has "$f" "A failed open against a directory descriptor shows under it" -E ' r +python3 +\./sub/absent$'

# A refused syscall: noted under the heading, and a details row.
assert_file_has "$f" "Refused syscalls are noted under the heading" -E '^> 🚫 Refused system calls: '
assert_file_has "$f" "The refused unshare has a details row" -E ' ! +python3 +syscall:unshare$'
if [ "$(uname -m)" = x86_64 ]; then
  assert_file_has "$f" "The killed 32-bit syscall is noted under the heading" -E '^> 🚫 .*illed for a 32-bit system call: .*`int80`'
  assert_file_has "$f" "The killed 32-bit syscall has a details row" -E ' ! +int80 +syscall:32-bit getpid \(killed\)$'
fi

# A refused change shows only as failed.
assert_file_has "$f" "A refused chmod shows as failed" -E ' a!? +chmod +\./root-owned\.txt$'
# Each program sharing a descriptor gets its own row.
assert_file_has "$f" "bash's write through a shared descriptor has its row" -E ' W +bash +\./shared\.txt$'
assert_file_has "$f" "sh's write through a shared descriptor has its row" -E ' W +sh +\./shared\.txt$'
assert_file_has "$f" "bash's write before exec has its row" -E ' W +bash +\./execd\.txt$'
assert_file_has "$f" "cat's write after exec has its row" -E ' W +cat +\./execd\.txt$'
assert_file_has "$f" "A refused mkdir shows as failed" -E ' w!? +mkdir +\./root-owned/x$'
assert_file_has "$f" "A hard link's new name shows as written" -E ' W +ln +\./link-dst\.txt$'
assert_file_has "$f" "A hard link's source shows as linked" -E ' L +ln +\./link-src\.txt$'
assert_file_has "$f" "A hard link across mounts shows as failed" -E ' l +ln +/etc/hostname$'

# A file mapped executable shows as read unless it is a library or an exec
# mapped it, as it does run.sh's interpreter.
assert_file_has "$f" "A file mapped executable shows as read" -E ' R +python3 +\./mapped\.bin$'
# A mapping the kernel refused after the tracer's hook is not a write.
assert_file_lacks "$f" "A refused mapping is not a write" -E ' [A-Za-z!]*[Ww][A-Za-z!]* +python3 +\./ro-mapped\.bin$'
# Shared anonymous memory names no file.
assert_file_has "$f" "A shared mapping made writable shows as read and written" -E ' RW +python3 +\./mprotected\.bin$'
assert_file_has "$f" "A shared mapping made writable and executable shows as read and written" -E ' RW +python3 +\./mprotected-rwx\.bin$'
assert_file_lacks "$f" "Shared anonymous memory names no file" '/dev/zero'
assert_file_lacks "$f" "run.sh's interpreter, mapped by its exec, is not a read" -E ' [A-Z]*R[A-Z!]* +\S+ +/usr/bin/dash$'

# Run without a path: a memfd by its quoted name, a deleted file marked.
assert_file_has "$sections/executed.md" "A memfd runs under its quoted name" -F '| `memfd:"probe-memfd"` |'
assert_file_has "$sections/executed.md" "A deleted program is marked" -F '| `./gone-bin` (deleted) |'
# buildcage's own wrappers must never reach the summary.
assert_file_lacks "$f" "buildcage's own wrappers are left out" -E ' (setpriv|buildcage-init|run-script\.sh) '

assert_results

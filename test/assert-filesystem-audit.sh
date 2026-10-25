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
sed -n '/^### 📂 Accessed/,/^<details>/p' "$f" > "$sections/accessed.md"

# The line a row is first on, or nothing.
line_of() { grep -nE -m1 "$1" "$f" | cut -d: -f1 || true; }

echo ""
echo "=== Filesystem Audit Summary Assertions ==="
echo ""

assert_file_has "$f" "The summary has the Filesystem Activity section" "^## Filesystem Activity Report"
# The tracer stopped on SIGTERM and wrote its whole record.
assert_file_lacks "$f" "The record is not marked incomplete" "This record is incomplete"
# The probe writes show as a flagged, command-tagged line under the
# workspace, led by its elapsed time (MM:SS.mmm) and a colon.
t='[0-9]{2}:[0-9]{2}\.[0-9]{3}'
assert_file_has "$f" "A probe line is led by its elapsed time" -E "^$t(-$t)?: +[RWXMLDArwxmlda!]+ +\S+ +\./probe"

# Rows run in the order they were first touched: write, move, delete. A row
# names the file run, which is gnumv or gnurm where mv and rm link to them.
w=$(line_of ' W +bash +\./probe\.txt$')
m=$(line_of ' M +(gnu)?mv +\./probe\.txt$')
d=$(line_of ' D +(gnu)?rm +\./probe2\.txt$')
if [ -n "$w" ] && [ -n "$m" ] && [ -n "$d" ] && [ "$w" -lt "$m" ] && [ "$m" -lt "$d" ]; then
  pass "The probe's write, move and delete rows run in that order"
else
  fail "The probe's write, move and delete rows run in that order -- lines: '$w' '$m' '$d'"
fi

# The table lists, open, what each program touched, and what it ran as an X
# under the program that ran it. python3 is a symlink, so it shows as the
# versioned file it runs.
assert_file_has "$f" "The accessed table is open" -E '^### 📂 Accessed Paths \([0-9]+\)$'
assert_file_has "$sections/accessed.md" "python3 is run by bash as the versioned file it runs" -E '^\| `bash` \| `bash` \| X \| `/usr/bin/python3[.0-9]*` \|$'
assert_file_has "$sections/accessed.md" "run.sh is written and run by bash" -F '| `bash` | `bash` | WX | `./A/run.sh` |'
assert_file_has "$sections/accessed.md" "The step's shell goes by bash" -F '| `bash` | `bash` | W | `./probe.txt` |'
assert_file_has "$sections/accessed.md" "futimens.txt is under python3 in the accessed table" -E '^\| `/usr/bin/python3[.0-9]*` \| `python3[.0-9]*` \| WA \| `\./futimens\.txt` \|$'
assert_file_has "$sections/accessed.md" "empty-name.txt is under python3 in the accessed table" -E '^\| `/usr/bin/python3[.0-9]*` \| `python3[.0-9]*` \| WA \| `\./empty-name\.txt` \|$'
assert_file_has "$f" "The summary has the file access details" '<summary>🔍 File access details</summary>'
assert_file_has "$f" "A process's own /proc directory shows as /proc/self" -E ' R +cat +/proc/self/status$'
assert_file_has "$f" "Another process's /proc directory shows as /proc/<pid>" -E ' R +cat +/proc/<pid>/stat$'
assert_file_has "$f" "futimens.txt has a details row" -E ' WA +python3\.[0-9]+ +\./futimens\.txt$'
assert_file_has "$f" "empty-name.txt has a details row" -E ' WA +python3\.[0-9]+ +\./empty-name\.txt$'

# A subshell's command still counts as the step's. GNU touch then sets the
# new file's times through the descriptor; uutils' does not.
a=
if [[ "$(touch --version)" == *'GNU coreutils'* ]]; then a=A; fi
assert_file_has "$sections/accessed.md" "A subshell's write is under touch in the accessed table" -E "^\\| \`[^\`]*/touch\` \\| \`[^\`]*\` \\| W$a \\| \`\\./subshell\\.txt\` \\|$"
assert_file_has "$f" "A subshell's write has a details row" -E " W$a +touch +\./subshell\.txt$"

# Relative names show under the directory they resolved against.
assert_file_has "$f" "A failed read against a changed working directory shows under it" -E ' r +bash +\./sub/missing\.txt$'
assert_file_has "$f" "A failed delete against a directory descriptor shows under it" -E ' d +python3\.[0-9]+ +\./sub/gone$'
assert_file_has "$f" "A failed open against a directory descriptor shows under it" -E ' r +python3\.[0-9]+ +\./sub/absent$'

# A refused syscall is left to the artifact, unless it killed the command.
assert_file_lacks "$f" "The refused unshare has no details row" 'syscall:unshare'
if [ "$(uname -m)" = x86_64 ]; then
  assert_file_has "$f" "The killed 32-bit syscall is noted under the heading" -E '^> 🚫 Killed for a 32-bit system call: .*`int80`'
  assert_file_has "$f" "The killed 32-bit syscall has a details row" -E ' ! +int80 +syscall:32-bit getpid \(killed\)$'
fi

# A refused change shows only as failed.
assert_file_has "$f" "A refused chmod shows as failed" -E ' a!? +chmod +\./root-owned\.txt$'
# Each program sharing a descriptor gets its own row.
assert_file_has "$f" "bash's write through a shared descriptor has its row" -E ' W +bash +\./shared\.txt$'
assert_file_has "$f" "sh's write through a shared descriptor has its row, under dash, which it runs" -E ' W +dash +\./shared\.txt$'
assert_file_has "$f" "bash's write before exec has its row" -E ' W +bash +\./execd\.txt$'
assert_file_has "$f" "cat's write after exec has its row" -E ' W +cat +\./execd\.txt$'
assert_file_has "$f" "A refused truncate through a descriptor shows as failed" -E ' [A-Za-z]*w[A-Za-z!]* +python3\.[0-9]+ +\./fd-truncate\.txt$'
assert_file_has "$f" "An xattr set through a descriptor shows as an attribute change" -Ei ' [A-Za-z]*a[A-Za-z!]* +python3\.[0-9]+ +\./fd-xattr\.txt$'
assert_file_has "$f" "A refused mkdir shows as failed" -E ' w!? +mkdir +\./root-owned/x$'
assert_file_has "$f" "A hard link's new name shows as written" -E ' W +ln +\./link-dst\.txt$'
assert_file_has "$f" "A hard link's source shows as linked" -E ' L +ln +\./link-src\.txt$'
assert_file_has "$f" "A hard link across mounts shows as failed" -E ' l +ln +/etc/hostname$'

# A file mapped executable shows as read unless it is a library or an exec
# mapped it, as it does run.sh's interpreter.
assert_file_has "$f" "A file mapped executable shows as read" -E ' R +python3\.[0-9]+ +\./mapped\.bin$'
# A mapping the kernel refused after the tracer's hook is not a write.
assert_file_lacks "$f" "A refused mapping is not a write" -E ' [A-Za-z!]*[Ww][A-Za-z!]* +python3\.[0-9]+ +\./ro-mapped\.bin$'
# Shared anonymous memory names no file.
assert_file_has "$f" "A shared mapping made writable shows as read and written" -E ' RW +python3\.[0-9]+ +\./mprotected\.bin$'
assert_file_has "$f" "A shared mapping made writable and executable shows as read and written" -E ' RW +python3\.[0-9]+ +\./mprotected-rwx\.bin$'
assert_file_lacks "$f" "Shared anonymous memory names no file" '/dev/zero'
assert_file_lacks "$f" "run.sh's interpreter, mapped by its exec, is not a read" -E ' [A-Z]*R[A-Z!]* +.+ +/usr/bin/dash$'

# Run without a path: a memfd by its quoted name, a deleted file marked.
assert_file_has "$sections/accessed.md" "A memfd runs under its quoted name" -E '\| W?X \| `memfd:"probe-memfd"` \|$'
assert_file_has "$sections/accessed.md" "A deleted program is marked" -E '\| X \| `\./gone-bin` \(deleted\) \|$'
# buildcage's own wrappers must never reach the summary.
assert_file_lacks "$f" "buildcage's own wrappers are left out" -E ' (setpriv|buildcage-init|run-script\.sh) '

assert_results

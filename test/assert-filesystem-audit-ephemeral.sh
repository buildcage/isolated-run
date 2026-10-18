#!/bin/bash
# Checks the Job Summary of test-e2e.yml's ephemeral filesystem audit step and
# what the step left on the host. Run on the runner host from the checkout the
# step wrote its files in.
# shellcheck disable=SC2016
set -euo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/helpers.sh"

f="$BUILDCAGE_RUN_DEBUG_SUMMARY_FILE"

# overlayfs calls the inode hooks again for each layer it touches, so a change
# recorded twice would show as a second details row.
assert_one_row() {
  local label="$1" pattern="$2" n
  n=$(grep -cE "$pattern" "$f" || true)
  if [ "$n" = 1 ]; then pass "$label"; else fail "$label -- $n rows"; fi
}

echo ""
echo "=== Ephemeral Filesystem Audit Summary Assertions ==="
echo ""

assert_file_has "$f" "The summary has the Process Activity section" "^## Process Activity Report"
assert_file_lacks "$f" "The record is not marked incomplete" "This record is incomplete"

assert_one_row "An append to a lower-layer file has one row" ' W +bash +\./README\.md$'
assert_one_row "A chmod of a lower-layer file has one row" ' A +chmod +\./LICENSE$'
assert_one_row "A move of a lower-layer file has one row" ' M +mv +\./SECURITY\.md$'
assert_one_row "A delete of a lower-layer file has one row" ' D +rm +\./MAINTAINERS\.md$'
assert_one_row "A lower-layer file mapped shared and made writable has one row" ' RW +python3 +\./renovate\.json$'

assert_one_row "A discarded write has one row" ' W +bash +\./discarded\.txt$'
assert_one_row "A write under write_through has one row" ' W +bash +\./kept/written\.txt$'

# $GITHUB_OUTPUT is written back and $GITHUB_STEP_SUMMARY discarded; both go
# by name.
assert_one_row "\$GITHUB_OUTPUT has one row under its name" ' W +bash +\$GITHUB_OUTPUT$'
assert_one_row "\$GITHUB_STEP_SUMMARY has one row under its name" ' W +bash +\$GITHUB_STEP_SUMMARY$'
assert_file_lacks "$f" "No path names the backing copy" '/dev/buildcage-runner-files'
assert_file_lacks "$f" "No path names the runner's real files" '_runner_file_commands'

assert_file_lacks "$f" "No path names the scratch dir" '/var/tmp/buildcage-'
assert_file_lacks "$f" "buildcage's own wrappers are left out" -E ' (setpriv|buildcage-init|run-script\.sh) '

echo ""
echo "=== Ephemeral Step Host Assertions ==="
echo ""

check_status "The write under write_through reached the host" "$(test -f kept/written.txt && echo yes || echo no)" yes
check_status "The discarded write did not" "$(test -e discarded.txt && echo yes || echo no)" no
check_status "The lower-layer files are as checked out" \
  "$(git diff --quiet -- README.md LICENSE SECURITY.md MAINTAINERS.md renovate.json && echo yes || echo no)" yes
check_status "The moved file's new name did not reach the host" "$(test -e SECURITY.moved && echo yes || echo no)" no
check_status "The step's output went through write_through" "$PROBE_OUTPUT" kept

assert_results

#!/bin/bash
# Refreshes the filesystem audit golden fixtures from a run of the
# filesystem_audit e2e job: its raw recording, with the runner's uid in the
# scratch base normalized to 0, then the stripped recording and the summary
# rendered from it by the golden test.
#
#   dev/update-filesystem-audit-fixture.sh <run id of "Test / E2E">
set -euo pipefail

run=${1:?usage: dev/update-filesystem-audit-fixture.sh <run id of "Test / E2E">}
cd "$(dirname "$0")/.."
fixture=src/lib/__fixtures__/filesystem-audit/recording.jsonl
job="e2e: test (filesystem_audit, ubuntu-latest)"
step="Verify the Job Summary has the filesystem audit"

# Log lines are "<job>\t<step>\t<timestamp> <text>". The step prints the raw
# recording in a "Raw recording" group; the closing marker can share a line
# with a last record that lacks its newline. awk reads to the end, since
# stopping early would kill gh with SIGPIPE.
tmp=$(mktemp)
trap 'rm -f "$tmp"' EXIT
gh run view "$run" -R buildcage/isolated-run --log |
  awk -F'\t' -v job="$job" -v step="$step" '
    $1 != job || $2 != step { next }
    { sub(/^[^ ]+ /, "", $3); line = $3 }
    !seen && line == "##[group]Raw recording" { seen = inside = 1; next }
    inside {
      inside = !sub(/::endgroup::$|^##\[endgroup\]$/, "", line)
      gsub(/\/var\/tmp\/buildcage-[0-9]+/, "/var/tmp/buildcage-0", line)
      if (line != "") print line
    }' >"$tmp"

if [ ! -s "$tmp" ]; then
  echo "no raw recording in run $run under job \"$job\", step \"$step\"" >&2
  exit 1
fi
mv "$tmp" "$fixture"
UPDATE_GOLDEN=1 vp test run src/lib/filesystem-audit-golden.test.ts

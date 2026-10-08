#!/bin/bash
# Refreshes the filesystem audit golden fixtures from a passing filesystem_audit
# e2e job: its raw recording, runner uid normalized, then the stripped
# recording and summary the golden test renders from it.
#
#   dev/update-filesystem-audit-fixture.sh <run id of "Test / E2E">
set -euo pipefail

run=${1:?usage: dev/update-filesystem-audit-fixture.sh <run id of "Test / E2E">}
cd "$(dirname "$0")/.."
dir=src/lib/__fixtures__/filesystem-audit
job="e2e: test (filesystem_audit, ubuntu-latest)"
step="Verify the Job Summary has the filesystem audit"

read -r job_id conclusion < <(gh run view "$run" --json jobs \
  --jq ".jobs[] | select(.name == \"$job\") | \"\(.databaseId) \(.conclusion)\"") || true
if [ -z "${job_id:-}" ]; then
  echo "run $run has no job \"$job\"; its jobs are:" >&2
  gh run view "$run" --json jobs --jq '.jobs[].name' >&2
  exit 1
fi
if [ "$conclusion" != "success" ]; then
  echo "job \"$job\" in run $run did not pass ($conclusion); take the recording from a passing run" >&2
  exit 1
fi

# Log lines are "<job>\t<step>\t<timestamp> <text>". The recording is the
# step's "Raw recording" group, whose closing marker can share its last line.
# awk reads to the end: stopping early would kill gh with SIGPIPE.
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
gh run view "$run" --job "$job_id" --log |
  awk -F'\t' -v step="$step" '
    $2 != step { next }
    { sub(/^[^ ]+ ?/, "", $3); line = $3 }
    !seen && line == "##[group]Raw recording" { seen = inside = 1; next }
    inside {
      inside = !sub(/::endgroup::$|^##\[endgroup\]$/, "", line)
      gsub(/\/var\/tmp\/buildcage-[0-9]+/, "/var/tmp/buildcage-0", line)
      if (line != "") print line
    }' >"$tmp/recording.jsonl"

if [ ! -s "$tmp/recording.jsonl" ]; then
  echo "no raw recording in run $run under step \"$step\"" >&2
  exit 1
fi
cp "$dir/recording.jsonl" "$tmp/previous.jsonl"
mv "$tmp/recording.jsonl" "$dir/recording.jsonl"
# A failed run rewrites no golden, so restore the recording to keep the three
# files in step.
if ! UPDATE_GOLDEN=1 vp test run src/lib/filesystem-audit-golden.test.ts; then
  cp "$tmp/previous.jsonl" "$dir/recording.jsonl"
  echo "regenerating the goldens failed; recording.jsonl is restored" >&2
  exit 1
fi

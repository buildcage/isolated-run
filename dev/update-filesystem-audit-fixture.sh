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
step="Verify the Job Summary has the filesystem audit"

# The matrix values that pick the job; others in its name come and go.
# shellcheck disable=SC2016 # $values is jq's
matches=$(gh run view "$run" --json jobs --jq '
  .jobs[]
  | select((.name | capture("\\((?<m>.*)\\)$").m | split(", ")) as $values
      | ["filesystem_audit", "persistent", "audit mode", "enforcement", "ubuntu-24.04"] - $values == [])
  | "\(.databaseId) \(.conclusion) \(.name)"')
if [ "$(printf '%s' "$matches" | grep -c '^')" -ne 1 ]; then
  echo "run $run has no single filesystem_audit fixture job; its jobs are:" >&2
  gh run view "$run" --json jobs --jq '.jobs[].name' >&2
  exit 1
fi
read -r job_id conclusion job <<<"$matches"
if [ "$conclusion" != "success" ]; then
  echo "job \"$job\" in run $run did not pass ($conclusion); take the recording from a passing run" >&2
  exit 1
fi

# Log lines are "<job>\t<step>\t<timestamp> <text>". The recording is the
# step's "Raw recording" group, whose closing marker can share its last line.
# gh may print "UNKNOWN STEP" in place of a step's name, so each group is kept
# apart by where it came from, and one under that name is taken only if it is
# the only one.
# awk reads to the end: stopping early would kill gh with SIGPIPE.
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
gh run view "$run" --job "$job_id" --log |
  awk -F'\t' -v step="$step" -v out="$tmp" '
    $2 != step && $2 != "UNKNOWN STEP" { next }
    { sub(/^[^ ]+ ?/, "", $3); line = $3 }
    line == "##[group]Raw recording" {
      src = $2 == step ? "named" : "unknown"
      file = out "/" src "." (++groups[src]) ".jsonl"
      printf "" >file
      inside = 1
      next
    }
    inside {
      inside = !sub(/::endgroup::$|^##\[endgroup\]$/, "", line)
      gsub(/\/var\/tmp\/buildcage-[0-9]+/, "/var/tmp/buildcage-0", line)
      if (line != "") print line >file
    }'

# Takes the one group from src, failing if there are more.
pick() {
  local src=$1
  set -- "$tmp/$src".*.jsonl
  [ -e "$1" ] || return 1
  if [ $# -ne 1 ]; then
    echo "run $run has $# \"Raw recording\" groups that could be the step's; can't tell which" >&2
    exit 1
  fi
  mv "$1" "$tmp/recording.jsonl"
}
pick named || pick unknown || true
if [ ! -s "$tmp/recording.jsonl" ]; then
  echo "no raw recording in run $run under step \"$step\"" >&2
  exit 1
fi
cp "$dir/recording.jsonl" "$tmp/previous.jsonl"
mv "$tmp/recording.jsonl" "$dir/recording.jsonl"
# A failed run rewrites no golden, so restore the recording to keep the three
# files in step.
if ! UPDATE_GOLDEN=1 vp test run src/lib/filesystem-audit/golden.test.ts; then
  cp "$tmp/previous.jsonl" "$dir/recording.jsonl"
  echo "regenerating the goldens failed; recording.jsonl is restored" >&2
  exit 1
fi

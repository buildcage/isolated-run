#!/bin/bash
# Refreshes the filesystem audit golden fixtures from a run of the
# filesystem_audit e2e job: its raw recording, with the runner's uid in the
# scratch base normalized to 0, then the stripped recording and the summary
# rendered from it by the golden test.
#
#   dev/update-filesystem-audit-fixture.sh <run id of "Test / E2E">
set -euo pipefail

run=${1:?usage: dev/update-filesystem-audit-fixture.sh <run id of "Test / E2E">}
dir=src/lib/__fixtures__/filesystem-audit

# Log lines are "<job>\t<step>\t<timestamp> <text>"; the step prints the raw
# recording inside a "Raw recording" group.
gh run view "$run" -R buildcage/isolated-run --log |
  awk -F'\t' '$1 == "e2e: test (filesystem_audit, ubuntu-latest)" { sub(/^[^ ]+ /, "", $3); print $3 }' |
  sed -n '/^##\[group\]Raw recording$/,/^##\[endgroup\]$/p' | sed '1d;$d' |
  sed -E 's#/var/tmp/buildcage-[0-9]+#/var/tmp/buildcage-0#g' >"$dir/recording.jsonl"

if [ ! -s "$dir/recording.jsonl" ]; then
  echo "no raw recording found in run $run" >&2
  exit 1
fi
UPDATE_GOLDEN=1 vp test run src/lib/filesystem-audit-golden.test.ts

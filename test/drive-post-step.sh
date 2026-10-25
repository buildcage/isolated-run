#!/bin/bash
# Runs the action's post step for each filesystem audit recording left on the
# runner, with the state it would be handed, and checks it removed the audit's
# files. The real post step runs only once the job ends (see
# integration-test-post-state-tampering.sh).
set -euo pipefail

base="/var/tmp/buildcage-$(id -u)"
post="$(dirname "${BASH_SOURCE[0]}")/../dist/post.cjs"

shopt -s nullglob
recordings=("$base"/filesystem-audit-*.jsonl)
# A step that ran its command always leaves one, so none means the post step
# would have nothing to prove it removes.
if [ "${#recordings[@]}" -eq 0 ]; then
  echo "::error::no recording left for the post step"
  exit 1
fi
for rec in "${recordings[@]}"; do
  suffix=$(basename "$rec" | sed -nE 's/^filesystem-audit-([0-9a-f]{8})\.jsonl$/\1/p')
  if [ -z "$suffix" ]; then
    echo "::error::$rec is not named like a recording"
    exit 1
  fi
  STATE_container_name="buildcage-proxy-$suffix" node "$post"
done

left=("$base"/filesystem-audit-*)
if [ "${#left[@]}" -gt 0 ]; then
  printf '%s\n' "${left[@]}"
  echo "::error::the post step left the audit's files"
  exit 1
fi

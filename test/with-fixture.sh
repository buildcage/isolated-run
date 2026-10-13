#!/bin/bash
# with-fixture.sh <engine> <driver>...: runs each driver against one fixture of
# compose.test-<engine>.yaml, started once rather than by every driver. Runs
# them all, and fails if any did.
set -uo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/driver-helpers.sh"

engine=$1
shift
trap 'fixture_down "$engine"' EXIT
fixture_up "$engine" || exit 1
export BUILDCAGE_SHARED_FIXTURE=$engine
status=0
for driver in "$@"; do
  "$driver" || status=1
done
exit "$status"

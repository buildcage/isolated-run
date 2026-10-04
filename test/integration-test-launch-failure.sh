#!/bin/bash
# A `runc run` that fails before the command starts must not read as the
# command exiting: run-isolated.sh annotates it as a launch failure. A command
# that does start and exits non-zero must still read as the command's own exit.
#
# The command's exit goes through dist/main.cjs and the real runc. The launch
# failure drives scripts/run-isolated.sh directly, with /bin/false standing in
# for a runc that cannot create the container, and a throwaway container
# standing in for the buildcage-proxy image, as integration-test-proxy-gone.sh
# does.
set -uo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/helpers.sh"

: "${BUILDCAGE_LOCAL_IMAGE_REF:?BUILDCAGE_LOCAL_IMAGE_REF must be set to the locally built proxy image}"

# renovate: datasource=docker depName=alpine
ALPINE_IMAGE="alpine:3.24.2@sha256:294b683cb724975bec92580e1e685676bd4b50bda910ddb8c51d4cabeaec77e6"

SUFFIX="launch-test-$$"
CONTAINER_NAME="buildcage-proxy-${SUFFIX}"
NETNS_NAME="buildcage-sandbox-${SUFFIX}"
ROOTFS_BIND_DIR="/tmp/buildcage-${SUFFIX}-rootfs"
WORKDIR=$(mktemp -d)

cleanup() {
  docker rm -f "$CONTAINER_NAME" >/dev/null 2>&1
  sudo -n ip netns del "$NETNS_NAME" >/dev/null 2>&1
  sudo -n rm -f "/var/run/netns/${NETNS_NAME}-proxy" >/dev/null 2>&1
  sudo -n rm -rf "$ROOTFS_BIND_DIR" "$WORKDIR" >/dev/null 2>&1
}
trap cleanup EXIT

echo ""
echo "=== Sandbox launch failure Assertions ==="
echo ""

mkdir -p "$WORKDIR/step"
touch "$WORKDIR/step/state.env" "$WORKDIR/step/summary.md"
GITHUB_WORKSPACE="$WORKDIR/step" \
GITHUB_STATE="$WORKDIR/step/state.env" \
GITHUB_STEP_SUMMARY="$WORKDIR/step/summary.md" \
BUILDCAGE_BUILD_TEST_HOOKS=1 \
BUILDCAGE_LOCAL_IMAGE_REF="$BUILDCAGE_LOCAL_IMAGE_REF" \
INPUT_RUN="exit 3" \
  node dist/main.cjs >"$WORKDIR/step.log" 2>&1
check_status "a command that exits 3 ends the step with 3" "$?" 3
if grep -q "buildcage: command exited with code 3" "$WORKDIR/step.log" &&
  ! grep -q "sandbox launch failed" "$WORKDIR/step.log"; then
  pass "a command that exits 3 is reported as the command's exit"
else
  fail "a command that exits 3 was not reported as the command's exit; see log below"
  cat "$WORKDIR/step.log"
fi

if ! docker run -d --name "$CONTAINER_NAME" "$ALPINE_IMAGE" sleep 300 >/dev/null; then
  fail "could not start the throwaway container"
  assert_results
fi
PROXY_NETNS=$(docker inspect --format '{{.NetworkSettings.SandboxKey}}' "$CONTAINER_NAME")

mkdir -p "$WORKDIR/bundle"
echo '{}' >"$WORKDIR/bundle/config.json"
sudo -n ./scripts/run-isolated.sh \
  --proxy-netns "$PROXY_NETNS" \
  --runc /bin/false \
  --bundle "$WORKDIR/bundle" \
  --container-id "buildcage-sandbox-${SUFFIX}" \
  --netns-name "$NETNS_NAME" \
  --rootfs-bind-dir "$ROOTFS_BIND_DIR" \
  --gateway 198.19.255.1 \
  --target-ip 198.19.255.101 \
  </dev/null >"$WORKDIR/launch.log" 2>&1
CODE=$?

if [ "$CODE" != "0" ] &&
  grep -q "^::error::buildcage: sandbox launch failed (runc exit 1)" "$WORKDIR/launch.log" &&
  ! grep -q "command exited with code" "$WORKDIR/launch.log"; then
  pass "a runc that fails before the command starts is annotated as a launch failure (exit $CODE)"
else
  fail "expected a launch failure annotation, got exit $CODE; see log below"
  cat "$WORKDIR/launch.log"
fi

if ip netns list 2>/dev/null | grep -q "^${NETNS_NAME}\b"; then
  fail "sandbox netns ${NETNS_NAME} was left behind"
else
  pass "no leftover sandbox netns"
fi

assert_results

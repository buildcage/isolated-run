#!/bin/bash
# A `runc run` that fails before the command starts must not read as the
# command exiting: run-isolated.sh annotates it as a launch failure. The other
# half, a command that starts and exits non-zero reading as its own exit, is
# checked in integration-test-host-parity.sh. Once the proxy container is gone,
# the same call must fail closed before setting anything up.
#
# Drives scripts/run-isolated.sh directly, with /bin/false standing in for a
# runc that cannot create the container, and a throwaway container standing in
# for the buildcage-proxy image.
set -uo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/driver-helpers.sh"

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

if ! docker run -d --name "$CONTAINER_NAME" "$ALPINE_IMAGE" sleep 300 >/dev/null; then
  fail "could not start the throwaway container"
  assert_results
fi
PROXY_NETNS=$(docker inspect --format '{{.NetworkSettings.SandboxKey}}' "$CONTAINER_NAME")

mkdir -p "$WORKDIR/bundle"
echo '{}' >"$WORKDIR/bundle/config.json"
# shellcheck disable=SC2024 # the log is the caller's own file
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

check_no_leftovers() {
  local label="$1"
  if ip netns list 2>/dev/null | grep -q "^${NETNS_NAME}\b"; then
    fail "$label: sandbox netns ${NETNS_NAME} was left behind"
  else
    pass "$label: no leftover sandbox netns"
  fi
  if [ -e "/var/run/netns/${NETNS_NAME}-proxy" ]; then
    fail "$label: leftover proxy netns bind at /var/run/netns/${NETNS_NAME}-proxy"
  else
    pass "$label: no leftover proxy netns bind"
  fi
}
check_no_leftovers "launch failure"

# The same call once the container behind --proxy-netns is gone must fail
# closed before setting anything up.
docker rm -f "$CONTAINER_NAME" >/dev/null
# shellcheck disable=SC2024 # the log is the caller's own file
sudo -n ./scripts/run-isolated.sh \
  --proxy-netns "$PROXY_NETNS" \
  --runc /bin/false \
  --bundle "$WORKDIR/bundle" \
  --container-id "buildcage-sandbox-${SUFFIX}" \
  --netns-name "$NETNS_NAME" \
  --rootfs-bind-dir "$ROOTFS_BIND_DIR" \
  --gateway 198.19.255.1 \
  --target-ip 198.19.255.101 \
  </dev/null >"$WORKDIR/gone.log" 2>&1
CODE=$?

if [ "$CODE" != "0" ] &&
  grep -q "^::error::buildcage: sandbox setup failed: proxy netns not found" "$WORKDIR/gone.log"; then
  pass "a proxy netns that is already gone fails closed with an annotated error (exit $CODE)"
else
  fail "expected an annotated 'proxy netns not found' failure, got exit $CODE; see log below"
  cat "$WORKDIR/gone.log"
fi
check_no_leftovers "proxy gone"

assert_results

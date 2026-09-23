#!/bin/bash
# When the container behind --proxy-netns is already gone by the time the
# script checks it, run-isolated.sh must fail closed: no host-side
# buildcage0, no leftover /var/run/netns entries.
#
# Drives scripts/run-isolated.sh directly, not through dist/main.cjs: the
# property under test is entirely about its own --proxy-netns check, so a
# throwaway container stands in for the real buildcage-proxy image.
set -uo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/helpers.sh"

# The throwaway container. Pinned like every fixture Dockerfile, so a moving
# tag can't fail a run for a reason run-isolated.sh had no part in.
# renovate: datasource=docker depName=alpine
ALPINE_IMAGE="alpine:3.24.1@sha256:28bd5fe8b56d1bd048e5babf5b10710ebe0bae67db86916198a6eec434943f8b"

SUFFIX="gone-test-$$"
CONTAINER_NAME="buildcage-proxy-${SUFFIX}"
NETNS_NAME="buildcage-sandbox-${SUFFIX}"
ROOTFS_BIND_DIR="/tmp/buildcage-${SUFFIX}-rootfs"
WORKDIR=$(mktemp -d)

cleanup() {
  docker rm -f "$CONTAINER_NAME" >/dev/null 2>&1
  sudo -n ip netns del "$NETNS_NAME" >/dev/null 2>&1
  sudo -n rm -f "/var/run/netns/${NETNS_NAME}-proxy" >/dev/null 2>&1
  sudo -n rm -rf "$ROOTFS_BIND_DIR" >/dev/null 2>&1
  rm -rf "$WORKDIR"
}
trap cleanup EXIT

echo "starting a throwaway container to obtain a real SandboxKey..." >&2
if ! docker run -d --name "$CONTAINER_NAME" "$ALPINE_IMAGE" sleep 300 >/dev/null; then
  echo "  FAIL  could not start the throwaway container"
  exit 1
fi

PROXY_NETNS=$(docker inspect --format '{{.NetworkSettings.SandboxKey}}' "$CONTAINER_NAME")
if [ -z "$PROXY_NETNS" ]; then
  echo "  FAIL  could not read SandboxKey from the throwaway container"
  exit 1
fi
echo "SandboxKey: ${PROXY_NETNS}" >&2

echo "stopping the container before run-isolated.sh ever sees it..." >&2
docker rm -f "$CONTAINER_NAME" >/dev/null

sudo -n ./scripts/run-isolated.sh \
  --proxy-netns "$PROXY_NETNS" \
  --runc /bin/true \
  --bundle /nonexistent-bundle-dir \
  --container-id "buildcage-sandbox-${SUFFIX}" \
  --netns-name "$NETNS_NAME" \
  --rootfs-bind-dir "$ROOTFS_BIND_DIR" \
  --gateway 198.19.255.1 \
  --dns 198.19.255.1 \
  --target-ip 198.19.255.101 \
  >"$WORKDIR/out.log" 2>&1
CODE=$?

echo ""
echo "=== Sandbox proxy-gone Assertions ==="
echo ""

if [ "$CODE" != "0" ] && grep -q "proxy netns not found" "$WORKDIR/out.log"; then
  pass "run-isolated.sh failed closed with a clear error (exit $CODE)"
else
  fail "expected a clear 'proxy netns not found' failure, got exit $CODE; see log below"
  cat "$WORKDIR/out.log"
fi

if ip netns list 2>/dev/null | grep -q "^${NETNS_NAME}\b"; then
  fail "sandbox netns ${NETNS_NAME} was left behind"
else
  pass "no leftover sandbox netns"
fi

if [ -e "/var/run/netns/${NETNS_NAME}-proxy" ]; then
  fail "leftover proxy netns bind at /var/run/netns/${NETNS_NAME}-proxy"
else
  pass "no leftover proxy netns bind"
fi

assert_results

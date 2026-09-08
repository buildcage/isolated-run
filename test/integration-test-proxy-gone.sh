#!/bin/bash
# run-isolated.sh must fail closed -- no host-side buildcage0, no leftover
# /var/run/netns entries -- when the container behind --proxy-netns is
# already gone by the time the script checks it.
#
# Drives scripts/run-isolated.sh directly, not through dist/main.cjs: the
# property under test is entirely about its own --proxy-netns check, so a
# throwaway container stands in for the real buildcage-proxy image.
set -uo pipefail

FAILURES=0
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
if ! docker run -d --name "$CONTAINER_NAME" alpine:3 sleep 300 >/dev/null; then
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
  --gateway 172.20.0.1 \
  --dns 172.20.0.1 \
  --target-ip 172.20.0.101 \
  >"$WORKDIR/out.log" 2>&1
CODE=$?

echo ""
echo "=== Sandbox proxy-gone Assertions ==="
echo ""

if [ "$CODE" != "0" ] && grep -q "proxy netns not found" "$WORKDIR/out.log"; then
  echo "  PASS  run-isolated.sh failed closed with a clear error (exit $CODE)"
else
  echo "  FAIL  expected a clear 'proxy netns not found' failure, got exit $CODE; see log below"
  cat "$WORKDIR/out.log"
  FAILURES=$((FAILURES + 1))
fi

if ip netns list 2>/dev/null | grep -q "^${NETNS_NAME}\b"; then
  echo "  FAIL  sandbox netns ${NETNS_NAME} was left behind"
  FAILURES=$((FAILURES + 1))
else
  echo "  PASS  no leftover sandbox netns"
fi

if [ -e "/var/run/netns/${NETNS_NAME}-proxy" ]; then
  echo "  FAIL  leftover proxy netns bind at /var/run/netns/${NETNS_NAME}-proxy"
  FAILURES=$((FAILURES + 1))
else
  echo "  PASS  no leftover proxy netns bind"
fi

echo ""
if [ "$FAILURES" -gt 0 ]; then
  echo "❌ FAILED: $FAILURES assertion(s) failed"
  exit 1
fi
echo "✅ All assertions passed."
echo ""

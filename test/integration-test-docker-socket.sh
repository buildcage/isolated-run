#!/bin/bash
# Regression check for the docker-socket hardening: if the sandboxed
# command's primary GID were left privileged, it could reach
# /var/run/docker.sock. See identity.ts and oci-config.ts's maskedPaths
# for the two independent layers that close this. Drives dist/main.cjs
# directly, without the real action wrapper -- see test-e2e.yml's
# test_sandbox_enforcement for the one case that does exercise the real
# action.
set -uo pipefail

: "${BUILDCAGE_LOCAL_IMAGE_REF:?BUILDCAGE_LOCAL_IMAGE_REF must be set to the locally built proxy image}"

if [ ! -S /var/run/docker.sock ]; then
  echo "SKIP: /var/run/docker.sock doesn't exist on this host -- nothing to regress against"
  exit 0
fi
HOST_SOCKET_GID=$(stat -c %g /var/run/docker.sock)

WORKDIR=$(mktemp -d)
trap 'rm -rf "$WORKDIR"' EXIT
touch "$WORKDIR/state.env" "$WORKDIR/summary.md"

GITHUB_WORKSPACE="$WORKDIR" \
GITHUB_STATE="$WORKDIR/state.env" \
GITHUB_STEP_SUMMARY="$WORKDIR/summary.md" \
BUILDCAGE_BUILD_TEST_HOOKS=1 \
BUILDCAGE_LOCAL_IMAGE_REF="$BUILDCAGE_LOCAL_IMAGE_REF" \
INPUT_RUN='echo "SANDBOX_GID=$(id -g)"
if [ -S /var/run/docker.sock ]; then echo "SOCKET_IS_SOCKET=yes"; else echo "SOCKET_IS_SOCKET=no"; fi
DOCKER_PS_EXIT=0
docker ps >/dev/null 2>&1 || DOCKER_PS_EXIT=$?
echo "DOCKER_PS_EXIT=$DOCKER_PS_EXIT"
DOCKER_RUN_PRIVILEGED_EXIT=0
docker run --rm --privileged --net=host -v /:/host alpine true >/dev/null 2>&1 || DOCKER_RUN_PRIVILEGED_EXIT=$?
echo "DOCKER_RUN_PRIVILEGED_EXIT=$DOCKER_RUN_PRIVILEGED_EXIT"' \
  node dist/main.cjs > "$WORKDIR/out.log" 2>&1

echo ""
echo "=== Docker Socket Escape Assertions ==="
echo ""

FAILURES=0

SANDBOX_GID=$(grep -oP '(?<=^SANDBOX_GID=)\d+' "$WORKDIR/out.log" || true)
if [ -n "$SANDBOX_GID" ] && [ "$SANDBOX_GID" != "$HOST_SOCKET_GID" ]; then
  echo "  PASS  sandbox GID ($SANDBOX_GID) does not match the docker.sock owner GID ($HOST_SOCKET_GID)"
else
  echo "  FAIL  sandbox GID ($SANDBOX_GID) matches the docker.sock owner GID ($HOST_SOCKET_GID) -- see out.log"
  FAILURES=$((FAILURES + 1))
fi

if grep -q '^SOCKET_IS_SOCKET=no$' "$WORKDIR/out.log"; then
  echo "  PASS  /var/run/docker.sock is not a socket inside the sandbox (masked)"
else
  echo "  FAIL  /var/run/docker.sock is still a live socket inside the sandbox -- see out.log"
  FAILURES=$((FAILURES + 1))
fi

DOCKER_PS_EXIT=$(grep -oP '(?<=^DOCKER_PS_EXIT=)\d+' "$WORKDIR/out.log" || true)
if [ -n "$DOCKER_PS_EXIT" ] && [ "$DOCKER_PS_EXIT" != "0" ]; then
  echo "  PASS  \`docker ps\` fails inside the sandbox (exit $DOCKER_PS_EXIT)"
else
  echo "  FAIL  \`docker ps\` succeeded inside the sandbox -- see out.log"
  FAILURES=$((FAILURES + 1))
fi

DOCKER_RUN_EXIT=$(grep -oP '(?<=^DOCKER_RUN_PRIVILEGED_EXIT=)\d+' "$WORKDIR/out.log" || true)
if [ -n "$DOCKER_RUN_EXIT" ] && [ "$DOCKER_RUN_EXIT" != "0" ]; then
  echo "  PASS  a privileged sibling container fails to launch (exit $DOCKER_RUN_EXIT)"
else
  echo "  FAIL  a privileged sibling container was launched from inside the sandbox -- see out.log"
  FAILURES=$((FAILURES + 1))
fi

echo ""
if [ "$FAILURES" -gt 0 ]; then
  echo "❌ FAILED: $FAILURES assertion(s) failed"
  echo "--- out.log ---"
  cat "$WORKDIR/out.log"
  exit 1
fi
echo "✅ All assertions passed."
echo ""

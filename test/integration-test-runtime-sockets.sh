#!/bin/bash
# Regression check for the runtime-socket hardening: if the sandboxed
# command's primary GID were left privileged, or a Unix domain socket
# under /run were left reachable, either would let it escape the isolation
# (docker.sock -> a sibling privileged container; a systemd --user bus ->
# a unit that runs entirely outside every namespace the sandbox creates).
# See identity.ts (GID substitution) and oci-config.ts's maskedPaths (the
# per-path and per-user-runtime-dir masking) for the two independent
# layers that close this. Drives dist/main.cjs directly, without the real
# action wrapper -- see test-e2e.yml's test_sandbox_enforcement for the
# one case that does exercise the real action.
set -uo pipefail

: "${BUILDCAGE_LOCAL_IMAGE_REF:?BUILDCAGE_LOCAL_IMAGE_REF must be set to the locally built proxy image}"

HOST_UID=$(id -u)
RUN_DOCKER_SOCKET_CHECKS=0
RUN_USER_RUNTIME_DIR_CHECKS=0
RUN_SYSTEMD_USER_CHECK=0

if [ -S /var/run/docker.sock ]; then
  RUN_DOCKER_SOCKET_CHECKS=1
  HOST_SOCKET_GID=$(stat -c %g /var/run/docker.sock)
fi
if [ -d "/run/user/${HOST_UID}" ]; then
  RUN_USER_RUNTIME_DIR_CHECKS=1
fi
if command -v systemd-run >/dev/null 2>&1; then
  RUN_SYSTEMD_USER_CHECK=1
fi

if [ "$RUN_DOCKER_SOCKET_CHECKS" -eq 0 ] && [ "$RUN_USER_RUNTIME_DIR_CHECKS" -eq 0 ]; then
  echo "SKIP: neither /var/run/docker.sock nor /run/user/${HOST_UID} exist on this host -- nothing to regress against"
  exit 0
fi

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
echo "DOCKER_RUN_PRIVILEGED_EXIT=$DOCKER_RUN_PRIVILEGED_EXIT"
if [ -d "/run/user/$(id -u)" ]; then echo "RUNTIME_DIR_EXISTS=yes"; else echo "RUNTIME_DIR_EXISTS=no"; fi
if [ -n "$(ls -A "/run/user/$(id -u)" 2>/dev/null)" ]; then echo "RUNTIME_DIR_EMPTY=no"; else echo "RUNTIME_DIR_EMPTY=yes"; fi
if [ -S "/run/user/$(id -u)/bus" ]; then echo "USER_BUS_IS_SOCKET=yes"; else echo "USER_BUS_IS_SOCKET=no"; fi
if [ -S /run/dbus/system_bus_socket ]; then echo "SYSTEM_BUS_IS_SOCKET=yes"; else echo "SYSTEM_BUS_IS_SOCKET=no"; fi
SYSTEMD_RUN_USER_EXIT=0
systemd-run --user --wait -- true >/dev/null 2>&1 || SYSTEMD_RUN_USER_EXIT=$?
echo "SYSTEMD_RUN_USER_EXIT=$SYSTEMD_RUN_USER_EXIT"' \
  node dist/main.cjs > "$WORKDIR/out.log" 2>&1

echo ""
echo "=== Runtime Socket Escape Assertions ==="
echo ""

FAILURES=0

# --- always run: sandbox must start regardless of what exists on the host
# (in particular, /run/user/<uid> not existing at all -- masking a path
# runc can't find is a no-op, not a failure -- see oci-config.ts)
if grep -q '^SANDBOX_GID=' "$WORKDIR/out.log"; then
  echo "  PASS  sandbox started successfully"
else
  echo "  FAIL  sandbox failed to start -- see out.log"
  FAILURES=$((FAILURES + 1))
fi

if [ "$RUN_DOCKER_SOCKET_CHECKS" -eq 1 ]; then
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
else
  echo "  SKIP  docker.sock checks (/var/run/docker.sock doesn't exist on this host)"
fi

if grep -q '^SYSTEM_BUS_IS_SOCKET=no$' "$WORKDIR/out.log"; then
  echo "  PASS  /run/dbus/system_bus_socket is not a socket inside the sandbox (masked)"
else
  echo "  FAIL  /run/dbus/system_bus_socket is still a live socket inside the sandbox -- see out.log"
  FAILURES=$((FAILURES + 1))
fi

if [ "$RUN_USER_RUNTIME_DIR_CHECKS" -eq 1 ]; then
  if grep -q '^RUNTIME_DIR_EMPTY=yes$' "$WORKDIR/out.log"; then
    echo "  PASS  /run/user/<uid> is an empty directory inside the sandbox (masked)"
  else
    echo "  FAIL  /run/user/<uid> has content inside the sandbox -- see out.log"
    FAILURES=$((FAILURES + 1))
  fi

  if grep -q '^USER_BUS_IS_SOCKET=no$' "$WORKDIR/out.log"; then
    echo "  PASS  /run/user/<uid>/bus is not a socket inside the sandbox (masked)"
  else
    echo "  FAIL  /run/user/<uid>/bus is still a live socket inside the sandbox -- see out.log"
    FAILURES=$((FAILURES + 1))
  fi
else
  echo "  SKIP  /run/user/<uid> checks (/run/user/${HOST_UID} doesn't exist on this host)"
fi

if [ "$RUN_SYSTEMD_USER_CHECK" -eq 1 ]; then
  SYSTEMD_RUN_USER_EXIT=$(grep -oP '(?<=^SYSTEMD_RUN_USER_EXIT=)\d+' "$WORKDIR/out.log" || true)
  if [ -n "$SYSTEMD_RUN_USER_EXIT" ] && [ "$SYSTEMD_RUN_USER_EXIT" != "0" ]; then
    echo "  PASS  \`systemd-run --user\` fails inside the sandbox (exit $SYSTEMD_RUN_USER_EXIT)"
  else
    echo "  FAIL  \`systemd-run --user\` succeeded inside the sandbox -- see out.log"
    FAILURES=$((FAILURES + 1))
  fi
else
  echo "  SKIP  systemd-run --user check (systemd-run not found on this host)"
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

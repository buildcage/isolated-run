#!/bin/bash
# run-isolated.sh: run a command in a network-isolated sandbox via runc.
#
# Creates a network namespace, wires a veth pair directly between it and the
# buildcage-proxy container's own netns (the proxy-side end is renamed to
# "buildcage0" and given the proxy's fixed gateway address, no bridge
# involved, since this is always a 1:1 connection: one sandbox, one proxy),
# bind-mounts the host's own "/" so it can be handed to runc as a read-only
# rootfs, and execs `runc run` against an OCI bundle (config.json) that
# sandbox/oci-config.ts has already fully built: namespaces, capabilities,
# mounts, uid/gid, and the seccomp filter are all declared there. This
# script only sets up what runc itself cannot: the network namespace's veth
# wiring into the proxy, and the rootfs bind-mount runc needs as its
# root.path (pivot_root can't target "/" itself).
#
# Must be run as root (invoked via `sudo -n` from the run action).
set -euo pipefail

# The checks before setup_failed's ERR trap below, annotated the same way.
check_failed() {
  echo "::error::buildcage: sandbox setup failed: ${1//'%'/'%25'}" >&2
  exit 1
}

# Re-exec into a fresh, private mount namespace before doing anything else.
# Every concurrently running `run:` step's own scratch dir lives under the
# same /tmp, so without this, the `mount --rbind /` staging below (and `ip
# netns add`'s own bind-mount of /run/netns) would run in the one mount
# namespace shared by every step on the host, unavoidably nesting a copy
# of each concurrently running step's rootfs tree inside every other's
# snapshot, which races their unmount/rmdir cleanup against each other.
# With this, everything this script mounts is invisible to (and
# unaffected by) every other concurrent invocation from the moment it's
# created. `--propagation private` is `unshare`'s shortcut for "unshare +
# recursively make every mount private" in one step. No `--fork`, so this
# and the subsequent exec replace the current process in place: this
# script's PID stays the same across the re-exec, and its
# /proc/self/cmdline keeps matching the integration tests' pgrep. The
# re-exec is marked by a leading argument, not an environment variable,
# because sudo passes the caller's variables through under
# `Defaults !env_reset`.
if [ "${1:-}" != "--unshared" ]; then
  command -v unshare >/dev/null 2>&1 || check_failed "required command not found: unshare"
  exec unshare --mount --propagation private -- "$0" --unshared "$@"
fi
shift

PROXY_NETNS=""
RUNC_PATH=""
BUNDLE_DIR=""
CONTAINER_ID=""
NETNS_NAME=""
ROOTFS_BIND_DIR=""
GATEWAY=""
TARGET_IP=""

usage() {
  cat >&2 <<'EOF'
Usage: run-isolated.sh --proxy-netns <PATH> --runc <PATH> --bundle <DIR>
         --container-id <ID> --netns-name <NAME> --rootfs-bind-dir <DIR>
         --gateway <IP> --target-ip <IP>
EOF
}

while [ $# -gt 0 ]; do
  case "$1" in
    --proxy-netns) PROXY_NETNS="$2"; shift 2 ;;
    --runc) RUNC_PATH="$2"; shift 2 ;;
    --bundle) BUNDLE_DIR="$2"; shift 2 ;;
    --container-id) CONTAINER_ID="$2"; shift 2 ;;
    --netns-name) NETNS_NAME="$2"; shift 2 ;;
    --rootfs-bind-dir) ROOTFS_BIND_DIR="$2"; shift 2 ;;
    --gateway) GATEWAY="$2"; shift 2 ;;
    --target-ip) TARGET_IP="$2"; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) usage; check_failed "unknown argument: $1" ;;
  esac
done

[ -z "$PROXY_NETNS" ] && { usage; check_failed "--proxy-netns is required"; }
[ -z "$RUNC_PATH" ] && { usage; check_failed "--runc is required"; }
[ -z "$BUNDLE_DIR" ] && { usage; check_failed "--bundle is required"; }
[ -z "$CONTAINER_ID" ] && { usage; check_failed "--container-id is required"; }
[ -z "$NETNS_NAME" ] && { usage; check_failed "--netns-name is required"; }
[ -z "$ROOTFS_BIND_DIR" ] && { usage; check_failed "--rootfs-bind-dir is required"; }
[ -z "$GATEWAY" ] && { usage; check_failed "--gateway is required"; }
[ -z "$TARGET_IP" ] && { usage; check_failed "--target-ip is required"; }

[ "$(id -u)" = "0" ] || check_failed "run-isolated.sh must be run as root (via sudo)"
for cmd in nsenter ip mount setpriv; do
  command -v "$cmd" >/dev/null 2>&1 || check_failed "required command not found: $cmd"
done
[ -e "$PROXY_NETNS" ] || check_failed "proxy netns not found at ${PROXY_NETNS}"
[ -x "$RUNC_PATH" ] || check_failed "runc not found or not executable: ${RUNC_PATH}"
[ -f "${BUNDLE_DIR}/config.json" ] || check_failed "OCI bundle config not found: ${BUNDLE_DIR}/config.json"

RAND_ID=$(od -An -tx1 -N4 /dev/urandom | tr -d ' \n')
VETH_T="sbxt${RAND_ID}"
VETH_P="sbxp${RAND_ID}"
# `ip link set ... netns` takes a name under /var/run/netns/, not a path.
PROXY_NETNS_NAME="${NETNS_NAME}-proxy"

CODE=1

# Tracks whether a ::group:: block is currently open (see group_start/
# group_end below), so cleanup() can force it closed if this script exits
# mid-group (e.g. a failed `ip netns add`); otherwise every line printed
# afterwards (including the WARNING messages below) would stay nested inside
# an unclosed, collapsed group in the Actions UI.
IN_GROUP=0

group_start() {
  echo "::group::$1" >&2
  IN_GROUP=1
}

group_end() {
  echo "::endgroup::" >&2
  IN_GROUP=0
}

cleanup() {
  # Once only: a signal during the teardown, or the exit below, would
  # otherwise run it again.
  trap '' INT TERM
  trap - EXIT
  set +e
  [ "$IN_GROUP" = "1" ] && group_end
  # -f/--force also kills the container's process tree if `runc run` ended
  # abnormally and left it behind, so it must run before the network/mount
  # resources below are torn out from under it.
  "$RUNC_PATH" delete -f "$CONTAINER_ID" >/dev/null 2>&1
  # This bind, like the netns one below, exists only in this script's private
  # mount namespace, which drops it on exit anyway.
  umount -R "$ROOTFS_BIND_DIR" >/dev/null 2>&1
  # The proxy-side veth end (renamed to "buildcage0" below) lives in the
  # long-lived proxy container's netns, so it must be explicitly removed.
  # Unlike the target-side end (torn down for free when the sandbox netns
  # below is deleted), a still-alive namespace doesn't lose its interfaces
  # just because its veth peer's namespace went away.
  nsenter --net="$PROXY_NETNS" -- ip link del buildcage0 >/dev/null 2>&1
  ip netns del "$NETNS_NAME" >/dev/null 2>&1
  # A pair that failed to move out of this netns is still here, both ends.
  ip link del "$VETH_T" >/dev/null 2>&1
  umount "/var/run/netns/${PROXY_NETNS_NAME}" >/dev/null 2>&1
  rm -f "/var/run/netns/${PROXY_NETNS_NAME}" >/dev/null 2>&1
  exit "$CODE"
}
trap cleanup EXIT
trap 'CODE=130; exit' INT
trap 'CODE=143; exit' TERM

# A failed setup command would otherwise end the step with a bare exit 1, the
# same as a command that exits 1. Closes the group first so the annotation is
# not folded away inside it.
setup_failed() {
  # The first line names a multi-line command well enough; $LINENO would
  # give its last.
  local command=${2%%$'\n'*}
  [ "$IN_GROUP" = "1" ] && group_end
  echo "::error::buildcage: sandbox setup failed (exit $1): ${command//'%'/'%25'}" >&2
}
trap 'setup_failed "$?" "$BASH_COMMAND"' ERR

# Bind-mounted first, before any of the network setup below: it has no
# dependency on the netns/veth work that follows, and doing it first
# minimizes the gap between sandbox/mountinfo.ts's listHostMounts() snapshot
# (which config.json's readonlyPaths was computed from) and this rbind
# actually capturing the host's mount table.
group_start "buildcage: preparing sandbox"
echo "Bind-mounting host root for runc's rootfs..." >&2
mkdir -p "$ROOTFS_BIND_DIR"
mount --rbind / "$ROOTFS_BIND_DIR"
# No separate `mount --make-rprivate` needed here: the whole-namespace
# `--propagation private` set up above already makes every mount created
# under it private by default, including this one.

echo "Creating sandbox network namespace..." >&2
ip netns add "$NETNS_NAME"

echo "Creating veth pair ${VETH_T} <-> ${VETH_P}..." >&2
ip link add "$VETH_T" type veth peer name "$VETH_P"
ip link set "$VETH_T" netns "$NETNS_NAME"
# Bind PROXY_NETNS to that name, as `ip netns attach` does internally, minus
# the pid.
mkdir -p /var/run/netns
: > "/var/run/netns/${PROXY_NETNS_NAME}"
mount --bind "$PROXY_NETNS" "/var/run/netns/${PROXY_NETNS_NAME}"
ip link set "$VETH_P" netns "$PROXY_NETNS_NAME"

# stdin carries the step's environment to the sandboxed process (see
# sandbox/env-loader.ts). These nested shells are the only commands here
# that could plausibly consume any of it, hence the /dev/null redirects.
echo "Configuring sandbox namespace network..." >&2
# Positional arguments, so a value can never become shell syntax.
# No link-local address on eth0: it would arrive after the command starts,
# and Chromium fails a request in flight on any address change. A kernel
# without IPv6 gives it none anyway.
ip netns exec "$NETNS_NAME" sh -c '
  set -e
  ip link set "$1" name eth0
  if [ -e /proc/net/if_inet6 ]; then ip link set eth0 addrgenmode none; fi
  ip addr add "$2/24" dev eth0
  ip link set eth0 up
  ip link set lo up
  ip route add default via "$3"
' sh "$VETH_T" "$TARGET_IP" "$GATEWAY" </dev/null

echo "Configuring proxy-side veth as buildcage0..." >&2
# The name is fixed because init-iptables's "-i buildcage0" rule is added at
# container startup, before this device exists, and matches on the name
# whenever it appears.
nsenter --net="$PROXY_NETNS" -- sh -c '
  set -e
  ip link set "$1" name buildcage0
  ip addr add "$2/24" dev buildcage0
  ip link set buildcage0 up
' sh "$VETH_P" "$GATEWAY" </dev/null

echo "Executing isolated command via runc..." >&2
# buildcage-init writes to fd 3 just before it runs the command, so a `runc run`
# that fails before then is told apart from the command exiting.
STARTED_FILE="${BUNDLE_DIR}/started"
exec 3>"$STARTED_FILE"
group_end
trap - ERR
set +e
# No nsenter wrapper needed here: config.json's linux.namespaces network
# entry already points at /var/run/netns/${NETNS_NAME}, so runc joins it
# itself as part of its own container setup.
#
# setpriv --pdeathsig here (targeting this script's own life) is the first
# half of a two-hop die-with-parent chain: `runc run`'s own process, not
# the container process it starts, is this script's direct child, so a
# guard on just the sandboxed process (config.json's process.args, see
# buildOciConfig) would only protect against `runc run` itself dying:
# without this outer hop, SIGKILL-ing this script would leave `runc run`
# (and the sandboxed process under it) as a still-alive orphan.
#
# Known residual gap: killing `sudo -n`, this script's parent, on its own
# leaves this script running as an orphan. With no terminal, as on a
# runner, `use_pty` puts no monitor between the two. Low-severity, since
# the orphan is still fully sandboxed (see docs/security.md), and not
# addressed here.
#
# A signal from here on means the step was cancelled (see sandbox/run.ts):
# the first goes on to `runc run`, which forwards it to the container, and
# any later one kills it. Either way CODE is what `runc run` exits with.
STOPPING=0
stop_sandbox() {
  # $! covers a signal that lands between the fork and the assignment.
  local pid=${RUNC_PID:-${!:-}}
  if [ -z "$pid" ]; then
    # Nothing forked yet, so exit as the traps above would.
    CODE=$1
    exit
  fi
  if [ "$STOPPING" = "0" ]; then
    STOPPING=1
    kill -TERM "$pid" 2>/dev/null
  else
    # Through runc, so `runc run` exits with the container's status rather
    # than being killed itself.
    "$RUNC_PATH" kill "$CONTAINER_ID" KILL 2>/dev/null || kill -KILL "$pid" 2>/dev/null
  fi
}
# Before the fork: once `runc run` has started, killing it rather than letting
# it forward the signal can leave its `runc init` behind.
trap 'stop_sandbox 130' INT
trap 'stop_sandbox 143' TERM
# In the background so the trap runs as soon as a signal arrives: bash defers
# it until a foreground child returns. An asynchronous command starts with
# SIGINT and SIGQUIT ignored and stdin on /dev/null, which the command would
# inherit, hence the reset and the explicit stdin.
( trap - INT QUIT; exec setpriv --pdeathsig=KILL -- "$RUNC_PATH" run --preserve-fds 1 --bundle "$BUNDLE_DIR" "$CONTAINER_ID" ) <&0 &
RUNC_PID=$!
# wait returns early when a trapped signal arrives; the last one returns the
# status bash kept.
while kill -0 "$RUNC_PID" 2>/dev/null; do wait "$RUNC_PID"; done
wait "$RUNC_PID"
CODE=$?
set -e
exec 3>&-

# A cancelled step can stop the sandbox before the command starts; that is not
# a launch failure.
if [ "$STOPPING" = "0" ] && [ ! -s "$STARTED_FILE" ]; then
  echo "::error::buildcage: sandbox launch failed (runc exit ${CODE})" >&2
else
  echo "buildcage: command exited with code ${CODE}" >&2
fi

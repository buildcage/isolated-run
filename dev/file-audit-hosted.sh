#!/bin/bash
# PoC driver for docker/file-audit on a GitHub-hosted runner, run as root.
# Builds an OCI bundle shaped like production's (host / as a read-only
# rbind rootfs, runner uid, no capabilities, noNewPrivileges, cgroup nested
# under the runner's own) without the proxy, and runs WORKLOAD in it with
# and without the tracer.
#
# Usage: file-audit-hosted.sh <tracer> <runc> <uid> <gid> <name> <workload> [trace|none]
# Env: RUNNER_CG (the runner's cgroup, read before sudo), HOME_DIR, WORK_DIR,
# SANDBOX_PATH, SECCOMP (gen-seccomp-profile's output, as production uses).
set -euo pipefail

TRACER_BIN=$1 RUNC=$2 UID_=$3 GID_=$4 NAME=$5 WORKLOAD=$6 MODE=${7:-trace}
BUNDLE=/var/tmp/buildcage-poc/$NAME
OUT=/var/tmp/buildcage-poc/$NAME.jsonl
: "${RUNNER_CG:?}" "${HOME_DIR:?}" "${WORK_DIR:?}" "${SANDBOX_PATH:?}" "${SECCOMP:?}"
CG_REL="${RUNNER_CG%/}/buildcage-poc-$NAME"

# One rootfs bind shared by every run: a fresh rbind of / per run would
# copy the previous runs' binds too and soon hit the mount limit.
ROOTFS=/var/tmp/buildcage-poc-rootfs
if ! mountpoint -q "$ROOTFS"; then
  mkdir -p "$ROOTFS"
  mount --rbind / "$ROOTFS"
  mount --make-rslave "$ROOTFS"
fi
rm -rf "$BUNDLE" && mkdir -p "$BUNDLE"
(cd "$BUNDLE" && "$RUNC" spec)
jq --arg rootfs "$ROOTFS" --arg cg "$CG_REL" --arg wl "$WORKLOAD" --arg home "$HOME_DIR" --arg ws "$WORK_DIR" --arg path "$SANDBOX_PATH" \
  --argjson uid "$UID_" --argjson gid "$GID_" --slurpfile seccomp "$SECCOMP" '
  .root = {"path": $rootfs, "readonly": true} |
  # No network namespace (the proxy is left out), and a fresh sysfs needs one.
  .mounts |= map(if .destination == "/sys" then {"destination":"/sys","type":"none","source":"/sys","options":["rbind","nosuid","noexec","nodev","ro"]} else . end) |
  .mounts += [
    {"destination":"/tmp","type":"tmpfs","source":"tmpfs","options":["nosuid","nodev","mode=1777"]},
    {"destination":$home,"type":"none","source":$home,"options":["rbind","rw"]},
    {"destination":$ws,"type":"none","source":$ws,"options":["rbind","rw"]}
  ] |
  .linux.namespaces = [{"type":"pid"},{"type":"ipc"},{"type":"uts"},{"type":"mount"}] |
  .linux.cgroupsPath = $cg |
  .linux.seccomp = $seccomp[0] |
  .process.terminal = false |
  .process.cwd = $ws |
  .process.env = ["PATH=" + $path, "HOME=" + $home] |
  .process.user = {"uid": $uid, "gid": $gid} |
  .process.args = ["/bin/bash", "-c", $wl] |
  .process.capabilities = {"bounding":[],"effective":[],"permitted":[],"inheritable":[],"ambient":[]} |
  .process.noNewPrivileges = true
  ' "$BUNDLE/config.json" > "$BUNDLE/c.json"
mv "$BUNDLE/c.json" "$BUNDLE/config.json"

TRACER=""
if [ "$MODE" = trace ]; then
  rm -f "$BUNDLE.ready"
  "$TRACER_BIN" --cgroup "/sys/fs/cgroup$CG_REL" --out "$OUT" --ready "$BUNDLE.ready" 2>"$BUNDLE.log" &
  TRACER=$!
  for _ in $(seq 100); do [ -e "$BUNDLE.ready" ] && break; kill -0 $TRACER || { cat "$BUNDLE.log"; exit 1; }; sleep 0.1; done
fi

START=$EPOCHREALTIME
CODE=0
"$RUNC" run --bundle "$BUNDLE" "poc-$NAME" </dev/null || CODE=$?
END=$EPOCHREALTIME
if [ -n "$TRACER" ]; then
  kill -TERM $TRACER
  wait $TRACER || true
fi
echo "--- $NAME ($MODE): exit $CODE, sandbox wall time $(awk "BEGIN{printf \"%.2f\", $END - $START}") s"
[ -n "$TRACER" ] && cat "$BUNDLE.log"
rmdir "/sys/fs/cgroup$CG_REL" 2>/dev/null || true

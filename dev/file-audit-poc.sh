#!/bin/bash
# PoC driver for docker/file-audit, run inside the sandbox-dev runner:
# attaches the tracer to a cgroup nested under the runner's own (as
# oci-config.ts's cgroupsPathFor does), runs SCENARIO in the sandbox, and
# prints what was recorded.
set -euo pipefail

SCENARIO="${1:?usage: file-audit-poc.sh <scenario-script> <proxy-netns>}"
PROXY_NETNS="${2:?}"
BUNDLE=/var/tmp/buildcage/poc-bundle
OUT=/var/tmp/file-audit.jsonl
RUNNER_CG=$(sed -n 's/^0:://p' /proc/self/cgroup)
CG_NAME=buildcage-poc-$$
CG="/sys/fs/cgroup${RUNNER_CG%/}/${CG_NAME}"

rm -f /var/tmp/file-audit.ready /var/tmp/file-audit.log
if [ -n "${NO_TRACE:-}" ]; then
  sleep infinity & TRACER=$!; touch /var/tmp/file-audit.ready
else
/usr/local/bin/file-audit ${BENCH:+--bench "$BENCH"} --cgroup "$CG" --out "$OUT" --ready /var/tmp/file-audit.ready 2>/var/tmp/file-audit.log &
TRACER=$!
fi
for _ in $(seq 100); do [ -e /var/tmp/file-audit.ready ] && break; kill -0 $TRACER || { cat /var/tmp/file-audit.log; exit 1; }; sleep 0.1; done

# Activity outside the sandbox cgroup that must not show up.
( for _ in $(seq 50); do cat /etc/hostname >/dev/null; sleep 0.05; done ) &
NOISE=$!

rm -rf "$BUNDLE"
build-test-bundle.sh --netns-name buildcage-poc --script "$SCENARIO" --bundle "$BUNDLE" >/dev/null
jq --arg cg "${RUNNER_CG%/}/${CG_NAME}" '.linux.cgroupsPath = $cg' "$BUNDLE/config.json" > "$BUNDLE/c.json"
mv "$BUNDLE/c.json" "$BUNDLE/config.json"

START=$EPOCHREALTIME
run-isolated.sh --proxy-netns "$PROXY_NETNS" --runc /usr/local/bin/runc --bundle "$BUNDLE" \
  --container-id buildcage-poc --netns-name buildcage-poc --rootfs-bind-dir "$BUNDLE/rootfs" \
  --gateway 198.19.255.1 --target-ip 198.19.255.101 2>/dev/null || echo "sandbox exit $?"
END=$EPOCHREALTIME
wait $NOISE
kill -TERM $TRACER
wait $TRACER || true
echo "--- sandbox wall time: $(awk "BEGIN{printf \"%.2f\", $END - $START}") s"
cat /var/tmp/file-audit.log 2>/dev/null || true
rmdir "$CG" 2>/dev/null || true

#!/bin/bash
# Verifies that the mounts the action makes for itself survive a write_through:
# entry that contains them, and that naming one of those paths directly (or a
# destination runc mounts itself) is refused. Drives dist/main.cjs directly,
# without the real action wrapper.
#
# Case 1 resolves and fetches a name to show DNS still works through the
# action's own resolv.conf mount. It goes to the fixture origin in
# compose.test-universal.yaml rather than a real site: what is under test is the
# mount, so nothing here should turn on a third party being up.
set -uo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/helpers.sh"

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

: "${BUILDCAGE_LOCAL_IMAGE_REF:?BUILDCAGE_LOCAL_IMAGE_REF must be set to the locally built proxy image}"

WORKDIR=$(mktemp -d)
# Runner-owned, so the sandbox (which keeps the runner's own uid and gains no
# capabilities) can actually write there once /etc is bind-mounted rw.
TESTDIR=/etc/buildcage-reserved-test
sudo -n mkdir -p "$TESTDIR"
sudo -n chown "$(id -u):$(id -g)" "$TESTDIR"
cleanup() {
  docker compose -f "$REPO_ROOT/compose.test-universal.yaml" down -v >/dev/null 2>&1 || true
  sudo -n rm -rf "$TESTDIR"
  rm -rf "$WORKDIR"
}
trap cleanup EXIT
touch "$WORKDIR/state.env" "$WORKDIR/summary.md"
cp /etc/resolv.conf "$WORKDIR/host-resolv-before.conf"


run_instance() {
  local write_through="$1" run_script="$2"
  GITHUB_WORKSPACE="$WORKDIR" \
  GITHUB_STATE="$WORKDIR/state.env" \
  GITHUB_STEP_SUMMARY="$WORKDIR/summary.md" \
  BUILDCAGE_BUILD_TEST_HOOKS=1 \
  BUILDCAGE_LOCAL_IMAGE_REF="$BUILDCAGE_LOCAL_IMAGE_REF" \
  BUILDCAGE_TEST_COMPOSE_FILE="$REPO_ROOT/docker/compose.action.test-universal.yaml" \
  INPUT_PROXY_ENGINE="universal" \
  INPUT_ALLOWED_HTTPS_RULES="allowed.example.com:443" \
  INPUT_WRITE_THROUGH="$write_through" \
  INPUT_RUN="$run_script" \
    node "$REPO_ROOT/dist/main.cjs" > "$WORKDIR/out.log" 2>&1
  echo $? > "$WORKDIR/exit_code"
  cat "$WORKDIR/out.log"
}

echo ""
echo "=== Sandbox reserved-mount Assertions ==="
echo ""

echo "--- bringing up fixture origin (compose.test-universal.yaml) ---"
docker compose -f "$REPO_ROOT/compose.test-universal.yaml" up -d --build --wait

# Case 1: write_through: /etc persists writes under /etc without taking the
# action's own DNS and CA mounts with it. `-k` because the fixture origin's
# certificate is self-signed and the universal engine never terminates TLS.
run_instance "/etc" "curl -fsS -k --max-time 20 -o /dev/null https://allowed.example.com/
cp /etc/resolv.conf \"\$GITHUB_WORKSPACE/sandbox-resolv.conf\"
echo built > ${TESTDIR}/marker
if echo nameserver 1.2.3.4 >> /etc/resolv.conf 2>/dev/null; then
  echo UNEXPECTED: /etc/resolv.conf was writable
  exit 1
fi"
CODE=$(cat "$WORKDIR/exit_code")

if [ "$CODE" = "0" ]; then
  pass "write_through: /etc left DNS working and /etc/resolv.conf read-only"
else
  fail "write_through: /etc broke the step (exit $CODE)"
fi

if [ -f "${TESTDIR}/marker" ]; then
  pass "writes under /etc reached the host"
else
  fail "${TESTDIR}/marker is missing"
fi

if cmp -s "$WORKDIR/host-resolv-before.conf" /etc/resolv.conf; then
  pass "the host's /etc/resolv.conf is unchanged"
else
  fail "the host's /etc/resolv.conf was modified"
fi

if [ -f "$WORKDIR/sandbox-resolv.conf" ] &&
  ! cmp -s "$WORKDIR/sandbox-resolv.conf" "$WORKDIR/host-resolv-before.conf"; then
  pass "the sandbox saw the proxy's resolv.conf, not the host's"
else
  fail "the sandbox saw the host's /etc/resolv.conf"
fi

# Case 2: naming a reserved path itself is refused rather than silently
# overridden by the mount that has to win.
run_instance "/etc/resolv.conf" "true"
CODE=$(cat "$WORKDIR/exit_code")

if [ "$CODE" != "0" ] && grep -q "reserved" "$WORKDIR/out.log"; then
  pass "write_through: /etc/resolv.conf is refused"
else
  fail "write_through: /etc/resolv.conf was accepted (exit $CODE)"
fi

# Case 3: same for a destination runc mounts fresh content at, which would
# otherwise hand the sandbox the host's real procfs.
run_instance "/proc" "true"
CODE=$(cat "$WORKDIR/exit_code")

if [ "$CODE" != "0" ]; then
  pass "write_through: /proc is refused"
else
  fail "write_through: /proc was accepted"
fi

assert_results

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
source "$(dirname "${BASH_SOURCE[0]}")/driver-helpers.sh"

require_local_image

WORKDIR=$(mktemp -d)
# Runner-owned, so the sandbox (which keeps the runner's own uid and gains no
# capabilities) can actually write there once /etc is bind-mounted rw.
TESTDIR=/etc/buildcage-reserved-test
sudo -n mkdir -p "$TESTDIR"
sudo -n chown "$(id -u):$(id -g)" "$TESTDIR"
# A CA store candidate this runner lacks, made a symlink for case 4.
CA_LINK=""
for candidate in /etc/ssl/cert.pem /etc/ssl/ca-bundle.pem; do
  if [ ! -e "$candidate" ] && [ ! -L "$candidate" ]; then
    CA_LINK="$candidate"
    break
  fi
done
CA_LINK_MADE=false
cleanup() {
  fixture_down universal
  if [ "$CA_LINK_MADE" = true ]; then sudo -n rm -f "$CA_LINK"; fi
  sudo -n rm -rf "$TESTDIR"
  rm -rf "$WORKDIR"
}
trap cleanup EXIT
cp /etc/resolv.conf "$WORKDIR/host-resolv-before.conf"

run_instance() {
  local write_through="$1" run_script="$2"
  run_step universal "$WORKDIR/step" \
    INPUT_ALLOWED_HTTPS_RULES="allowed.example.com:443" \
    INPUT_WRITE_THROUGH="$write_through" \
    INPUT_RUN="$run_script"
  echo $? > "$WORKDIR/exit_code"
  cat "$WORKDIR/step.log"
}

echo ""
echo "=== Sandbox reserved-mount Assertions ==="
echo ""

fixture_up universal

# Case 1: write_through: /etc persists writes under /etc without taking the
# action's own resolv.conf mount with it. `-k` because the fixture origin's
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

if [ "$CODE" != "0" ] && grep -q "reserved" "$WORKDIR/step.log"; then
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

# Case 4: the file a CA store candidate is a symlink to, as on RHEL, is
# reserved too: the CA mount lands on it.
if [ -z "$CA_LINK" ]; then
  echo "  SKIP  every candidate a symlink could stand in for already exists"
elif ! touch "$TESTDIR/bundle.pem" || ! sudo -n ln -s "$TESTDIR/bundle.pem" "$CA_LINK"; then
  fail "could not link $CA_LINK to $TESTDIR/bundle.pem"
else
  CA_LINK_MADE=true
  run_instance "$TESTDIR/bundle.pem" "true"
  CODE=$(cat "$WORKDIR/exit_code")

  if [ "$CODE" != "0" ] && grep -q "reserved" "$WORKDIR/step.log"; then
    pass "write_through: the file $CA_LINK links to is refused"
  else
    fail "write_through: the file $CA_LINK links to was accepted (exit $CODE)"
  fi
fi

assert_results

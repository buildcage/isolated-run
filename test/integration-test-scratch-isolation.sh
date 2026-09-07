#!/bin/bash
# Same-uid scratch-dir isolation. Two concurrent `run:` steps on the
# same host, run as the same uid, must not be able to see each other's
# scratch dir (config.json, run-script.sh, env-loader.sh, CA material) via
# the sandboxed rootfs's own `mount --rbind /` -- see oci-config.ts's
# SANDBOX_SCRATCH_BASE mask + own-scratchDir reveal. Also checks that the
# step's env (including anything passed via `env:`) reaches the sandboxed
# command correctly now that it travels over stdin (base64-encoded)
# instead of config.json (env-loader.ts) -- and that it's genuinely absent
# from config.json, not just unreadable because of the mask.
#
# Modeled on integration-test-concurrent.sh's two-parallel-instance harness.
set -uo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
FAILURES=0

TMP_A=$(mktemp -d)
TMP_B=$(mktemp -d)
cleanup() { rm -rf "$TMP_A" "$TMP_B"; }
trap cleanup EXIT

: "${BUILDCAGE_LOCAL_IMAGE_REF:?BUILDCAGE_LOCAL_IMAGE_REF must be set to the locally built proxy image}"
touch "$TMP_A/state.env" "$TMP_A/summary.md" "$TMP_B/state.env" "$TMP_B/summary.md"

SCRATCH_BASE="/var/tmp/buildcage-$(id -u)"

# Held open with `sleep` so both instances are guaranteed to be alive under
# SCRATCH_BASE at the same time -- seeing only one's own entry there while
# the other is running is the whole point of this test. DIR_COUNT=1 and
# UNEXPECTED_ENTRY=no together already prove the other instance's directory
# isn't visible at all (not even as a bare listing entry) -- deliberately
# not also grep'ing for the other instance's secret value here: doing so
# would require embedding that value as a literal string in this instance's
# own run-script.sh (which lives inside its own, legitimately-visible
# scratch dir), making the check trivially "find" itself.
run_instance() {
  local tmpdir="$1" own_secret="$2"
  local run_script='sleep 3
echo "SAW_OWN_SECRET=$([ "$MY_SECRET" = "'"$own_secret"'" ] && echo yes || echo no)"
echo "DIR_COUNT=$(ls "'"$SCRATCH_BASE"'" | wc -l)"
if [ -n "$(ls -A "'"$SCRATCH_BASE"'" | grep -v "^sandbox-")" ]; then
  echo "UNEXPECTED_ENTRY=yes"
else
  echo "UNEXPECTED_ENTRY=no"
fi
if grep -q "'"$own_secret"'" "'"$SCRATCH_BASE"'"/*/config.json 2>/dev/null; then
  echo "OWN_SECRET_IN_CONFIG=yes"
else
  echo "OWN_SECRET_IN_CONFIG=no"
fi
ROOTFS_LEAKED=no
for d in "'"$SCRATCH_BASE"'"/*/rootfs; do
  [ -e "$d" ] || continue
  if [ -e "$d/etc" ] || [ -e "$d/bin" ] || [ -e "$d/usr" ]; then
    ROOTFS_LEAKED=yes
  fi
done
echo "ROOTFS_LEAKED=$ROOTFS_LEAKED"'
  GITHUB_WORKSPACE="$tmpdir" \
  GITHUB_STATE="$tmpdir/state.env" \
  GITHUB_STEP_SUMMARY="$tmpdir/summary.md" \
  BUILDCAGE_BUILD_TEST_HOOKS=1 \
  BUILDCAGE_LOCAL_IMAGE_REF="$BUILDCAGE_LOCAL_IMAGE_REF" \
  INPUT_FAIL_ON_BLOCKED="false" \
  MY_SECRET="$own_secret" \
  INPUT_RUN="$run_script" \
    node "$REPO_ROOT/dist/main.cjs" > "$tmpdir/out.log" 2>&1
  echo $? > "$tmpdir/exit_code"
}

SECRET_A="secret-A-$(od -An -tx1 -N8 /dev/urandom | tr -d ' \n')"
SECRET_B="secret-B-$(od -An -tx1 -N8 /dev/urandom | tr -d ' \n')"

run_instance "$TMP_A" "$SECRET_A" &
PID_A=$!
run_instance "$TMP_B" "$SECRET_B" &
PID_B=$!

wait "$PID_A"
wait "$PID_B"

echo ""
echo "=== Scratch-Dir Isolation Assertions ==="
echo ""

for label_dir in "A:$TMP_A" "B:$TMP_B"; do
  label="${label_dir%%:*}"
  dir="${label_dir#*:}"
  log="$dir/out.log"

  if [ "$(cat "$dir/exit_code")" = "0" ]; then
    echo "  PASS  instance $label's run: step exited 0"
  else
    echo "  FAIL  instance $label -- exit code $(cat "$dir/exit_code"), see log below"
    cat "$log"
    FAILURES=$((FAILURES + 1))
  fi

  if grep -q '^SAW_OWN_SECRET=yes$' "$log"; then
    echo "  PASS  instance $label saw its own env var (env now travels over stdin, not config.json)"
  else
    echo "  FAIL  instance $label did not see its own env var -- see $log"
    FAILURES=$((FAILURES + 1))
  fi

  if grep -q '^DIR_COUNT=1$' "$log"; then
    echo "  PASS  instance $label sees exactly one entry under $SCRATCH_BASE (its own)"
  else
    echo "  FAIL  instance $label sees $(grep -oP '(?<=^DIR_COUNT=)\d+' "$log" || echo '?') entries under $SCRATCH_BASE -- see $log"
    FAILURES=$((FAILURES + 1))
  fi

  if grep -q '^UNEXPECTED_ENTRY=no$' "$log"; then
    echo "  PASS  instance $label sees no non-sandbox-* entry under $SCRATCH_BASE (so the other instance's directory, secret included, is entirely invisible)"
  else
    echo "  FAIL  instance $label sees an unexpected entry under $SCRATCH_BASE -- see $log"
    FAILURES=$((FAILURES + 1))
  fi

  if grep -q '^OWN_SECRET_IN_CONFIG=no$' "$log"; then
    echo "  PASS  instance $label's own config.json does not contain its own secret (env moved to stdin)"
  else
    echo "  FAIL  instance $label's own config.json contains its own secret -- see $log"
    FAILURES=$((FAILURES + 1))
  fi

  if grep -q '^ROOTFS_LEAKED=no$' "$log"; then
    echo "  PASS  instance $label's own scratchDir reveal does not re-expose rootfsBindDir's host-/ content"
  else
    echo "  FAIL  instance $label's own scratchDir reveal exposes rootfsBindDir's content -- see $log"
    FAILURES=$((FAILURES + 1))
  fi
done

LEFTOVER_CONTAINERS=$(docker ps -a --filter "name=buildcage-proxy-" -q)
if [ -z "$LEFTOVER_CONTAINERS" ]; then
  echo "  PASS  no leftover buildcage-proxy-* containers"
else
  echo "  FAIL  leftover buildcage-proxy-* containers: $LEFTOVER_CONTAINERS"
  FAILURES=$((FAILURES + 1))
fi

echo ""
if [ "$FAILURES" -gt 0 ]; then
  echo "❌ FAILED: $FAILURES assertion(s) failed"
  exit 1
fi
echo "✅ All assertions passed."
echo ""

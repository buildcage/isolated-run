#!/bin/bash
# Verifies that one `run:` step cannot read another's scratch directory, and
# that the step environment still arrives intact now that it travels over
# stdin instead of config.json (see sandbox/env-loader.ts).
#
# Uses a decoy scratch directory rather than a second concurrent run, so the
# leak assertion doesn't depend on two runs overlapping in time: a decoy is
# exactly what a crashed run leaves behind, and equally what the sandbox
# must not see.
set -uo pipefail

: "${BUILDCAGE_LOCAL_IMAGE_REF:?BUILDCAGE_LOCAL_IMAGE_REF must be set to the locally built proxy image}"

SCRATCH_BASE="/var/tmp/buildcage-$(id -u)"
DECOY_DIR="$SCRATCH_BASE/sandbox-decoy"
INJECTION_MARKER="/tmp/.buildcage-env-injection-$$"
WORKDIR=$(mktemp -d)
trap 'rm -rf "$WORKDIR" "$DECOY_DIR" "$INJECTION_MARKER"' EXIT
touch "$WORKDIR/state.env" "$WORKDIR/summary.md"

# 0700, since ensureOwnScratchBase refuses a base any other user could have
# tampered with.
mkdir -p "$SCRATCH_BASE" && chmod 700 "$SCRATCH_BASE"
mkdir -p "$DECOY_DIR" && chmod 700 "$DECOY_DIR"
# Only ever named through $BC_DECOY_MARKER below, so the string itself never
# lands in the run script -- which the sandbox *can* see, and which would
# otherwise match the search for it.
DECOY_SECRET="buildcage-decoy-secret-$$"
printf '{"process":{"env":["SECRET=%s"]}}' "$DECOY_SECRET" > "$DECOY_DIR/config.json"
chmod 600 "$DECOY_DIR/config.json"

# Written from here rather than passed as more env vars, so the assertions
# below compare the transported environment against something that did not
# travel with it. The sandbox's cwd is $GITHUB_WORKSPACE, hence the relative
# paths.
BC_MULTILINE=$'-----BEGIN KEY-----\nline two\r\nline three'
BC_EQUALS='a=b=c'
BC_SPACES=' leading and trailing '
BC_DOLLAR="\$(touch $INJECTION_MARKER) \`id\` \${HOME}"
printf '%s' "$PATH" > "$WORKDIR/expected-path"
printf '%s' "$BC_MULTILINE" > "$WORKDIR/expected-multiline"
printf '%s' "$BC_EQUALS" > "$WORKDIR/expected-equals"
printf '%s' "$BC_SPACES" > "$WORKDIR/expected-spaces"
printf '%s' "$BC_DOLLAR" > "$WORKDIR/expected-dollar"

RUN_INPUT=$(cat <<'SANDBOX'
fail=0
BASE="/var/tmp/buildcage-$(id -u)"

echo "=== what the sandbox sees of $BASE ==="
ls -la "$BASE" 2>&1 || true

if [ -e "$BASE/sandbox-decoy" ]; then
  echo "LEAK: another run's scratch directory is visible"
  fail=1
fi
if grep -rq "$BC_DECOY_MARKER" "$BASE" 2>/dev/null; then
  echo "LEAK: another run's secrets are readable"
  fail=1
fi
leaked=$(find "$BASE" -name config.json 2>/dev/null || true)
if [ -n "$leaked" ]; then
  echo "LEAK: an OCI config is reachable at: $leaked"
  fail=1
fi
if echo x > "$BASE/.buildcage-plant-test" 2>/dev/null; then
  echo "LEAK: the masked scratch base is writable"
  rm -f "$BASE/.buildcage-plant-test"
  fail=1
fi
if [ -z "$(find "$BASE" -name run-script.sh 2>/dev/null)" ]; then
  echo "UNEXPECTED: this run's own run-script.sh is not visible"
  fail=1
fi

echo "=== the step environment survived the trip over stdin ==="
check() {
  if [ "$2" = "$3" ]; then
    echo "OK: $1"
  else
    echo "MISMATCH: $1: got [$2]"
    fail=1
  fi
}
check PATH "$PATH" "$(cat ./expected-path)"
check BC_MULTILINE "$BC_MULTILINE" "$(cat ./expected-multiline)"
check BC_EQUALS "$BC_EQUALS" "$(cat ./expected-equals)"
check BC_SPACES "$BC_SPACES" "$(cat ./expected-spaces)"
check BC_DOLLAR "$BC_DOLLAR" "$(cat ./expected-dollar)"
check BC_EMPTY-is-set "${BC_EMPTY+set}" set
check BC_EMPTY "$BC_EMPTY" ""
[ -n "$HOME" ] || { echo "MISMATCH: HOME is empty"; fail=1; }
[ ! -e "$BC_INJECTION_MARKER" ] || { echo "LEAK: a value was evaluated, not exported"; fail=1; }

exit "$fail"
SANDBOX
)

GITHUB_WORKSPACE="$WORKDIR" \
GITHUB_STATE="$WORKDIR/state.env" \
GITHUB_STEP_SUMMARY="$WORKDIR/summary.md" \
BUILDCAGE_BUILD_TEST_HOOKS=1 \
BUILDCAGE_LOCAL_IMAGE_REF="$BUILDCAGE_LOCAL_IMAGE_REF" \
BC_DECOY_MARKER="$DECOY_SECRET" \
BC_INJECTION_MARKER="$INJECTION_MARKER" \
BC_MULTILINE="$BC_MULTILINE" \
BC_EQUALS="$BC_EQUALS" \
BC_SPACES="$BC_SPACES" \
BC_DOLLAR="$BC_DOLLAR" \
BC_EMPTY="" \
INPUT_RUN="$RUN_INPUT" \
  node dist/main.cjs
CODE=$?

echo ""
echo "=== Sandbox Scratch-Dir Isolation Assertions ==="
echo ""
if [ "$CODE" = "0" ]; then
  echo "  PASS  no other run's scratch dir is reachable; the step environment arrived intact"
else
  echo "  FAIL  scratch-dir isolation or environment transfer check failed (exit $CODE)"
  exit 1
fi
echo ""

if [ -f "$DECOY_DIR/config.json" ]; then
  echo "  PASS  the decoy scratch dir survived the run (it was hidden, not deleted)"
else
  echo "  FAIL  the decoy scratch dir was removed by the run"
  exit 1
fi
echo ""

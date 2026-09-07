#!/bin/bash
# Verifies that one `run:` step cannot read another's scratch directory, and
# that the step environment still arrives intact over stdin (see
# sandbox/env-loader.ts).
#
# A decoy scratch dir rather than a second concurrent run: it is what a
# crashed run leaves behind anyway, and the assertion doesn't then depend on
# two runs overlapping in time.
set -uo pipefail

: "${BUILDCAGE_LOCAL_IMAGE_REF:?BUILDCAGE_LOCAL_IMAGE_REF must be set to the locally built proxy image}"

SCRATCH_BASE="/var/tmp/buildcage-$(id -u)"
DECOY_DIR="$SCRATCH_BASE/sandbox-decoy"
INJECTION_MARKER="/tmp/.buildcage-env-injection-$$"
WORKDIR=$(mktemp -d)
trap 'rm -rf "$WORKDIR" "$DECOY_DIR" "$INJECTION_MARKER"' EXIT
touch "$WORKDIR/state.env" "$WORKDIR/summary.md"

# 0700, or ensureOwnScratchBase rejects the base as tampered with.
mkdir -p "$SCRATCH_BASE" && chmod 700 "$SCRATCH_BASE"
mkdir -p "$DECOY_DIR" && chmod 700 "$DECOY_DIR"
# Only ever named through $BC_DECOY_MARKER, so the string itself stays out
# of the run script, which the sandbox can see and would otherwise match.
DECOY_SECRET="buildcage-decoy-secret-$$"
printf '{"process":{"env":["SECRET=%s"]}}' "$DECOY_SECRET" > "$DECOY_DIR/config.json"
chmod 600 "$DECOY_DIR/config.json"

export BC_MULTILINE=$'-----BEGIN KEY-----\nline two\r\nline three'
export BC_EQUALS='a=b=c'
export BC_SPACES=' leading and trailing '
export BC_DOLLAR="\$(touch $INJECTION_MARKER) \`id\` \${HOME}"
export BC_EMPTY=""
# Stands in for an `env:` secret; asserted absent from config.json below.
export BC_STEP_SECRET="buildcage-step-secret-$$"

# Dumped from node, since what has to survive the trip is what the action's
# own process.env holds, not what this shell happens to see. Files rather
# than more env vars, so the assertions compare against something that did
# not travel with the environment; read by relative path below, the sandbox's
# cwd being $GITHUB_WORKSPACE.
node -e '
  const { writeFileSync } = require("node:fs");
  for (const name of process.argv.slice(2)) {
    writeFileSync(`${process.argv[1]}/expected-${name}`, process.env[name] ?? "");
  }
' "$WORKDIR" PATH HOME BC_MULTILINE BC_EQUALS BC_SPACES BC_DOLLAR BC_EMPTY

RUN_INPUT=$(cat <<'SANDBOX'
# Holds the bundle on disk long enough for the host side to grab this run's
# config.json while it still exists (the mask means the sandbox can't reach
# it to check the contents itself).
sleep 2

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
if { echo x > "$BASE/.buildcage-plant-test"; } 2>/dev/null; then
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
    echo "MISMATCH: $1"
    echo "  got      [$2]"
    echo "  expected [$3]"
    fail=1
  fi
}
check PATH "$PATH" "$(cat ./expected-PATH)"
check HOME "$HOME" "$(cat ./expected-HOME)"
check BC_MULTILINE "$BC_MULTILINE" "$(cat ./expected-BC_MULTILINE)"
check BC_EQUALS "$BC_EQUALS" "$(cat ./expected-BC_EQUALS)"
check BC_SPACES "$BC_SPACES" "$(cat ./expected-BC_SPACES)"
check BC_DOLLAR "$BC_DOLLAR" "$(cat ./expected-BC_DOLLAR)"
check BC_EMPTY-is-set "${BC_EMPTY+set}" set
check BC_EMPTY "$BC_EMPTY" "$(cat ./expected-BC_EMPTY)"
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
INPUT_RUN="$RUN_INPUT" \
  node dist/main.cjs &
NODE_PID=$!

# The mask proves the sandbox can't *reach* another run's config.json; this
# proves the environment isn't in one to begin with. Only the host can look,
# and only while the run is live, since the scratch dir is torn down with it.
CAPTURED="$WORKDIR/captured-config.json"
for _ in $(seq 1 300); do
  kill -0 "$NODE_PID" 2>/dev/null || break
  found=$(find "$SCRATCH_BASE" -maxdepth 2 -name config.json -not -path "$DECOY_DIR/*" 2>/dev/null | head -1)
  # Parsed, not just non-empty: the poll can otherwise catch a half-written file.
  if [ -n "$found" ] &&
    node -e 'JSON.parse(require("node:fs").readFileSync(process.argv[1], "utf8"))' "$found" 2>/dev/null
  then
    cp "$found" "$CAPTURED"
    break
  fi
  sleep 0.1
done

wait "$NODE_PID"
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

if [ ! -f "$CAPTURED" ]; then
  echo "  FAIL  could not capture this run's config.json while it existed"
  exit 1
elif grep -q "$BC_STEP_SECRET" "$CAPTURED"; then
  echo "  FAIL  config.json still carries the step environment"
  exit 1
elif ! grep -q '"env":\[\]' "$CAPTURED"; then
  echo "  FAIL  config.json's process.env is not empty"
  exit 1
else
  echo "  PASS  config.json carries no step environment at all"
fi
echo ""

if [ -f "$DECOY_DIR/config.json" ]; then
  echo "  PASS  the decoy scratch dir survived the run (it was hidden, not deleted)"
else
  echo "  FAIL  the decoy scratch dir was removed by the run"
  exit 1
fi
echo ""

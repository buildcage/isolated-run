#!/bin/bash
# Verifies default privilege drop, filesystem policy and sandbox environment by
# driving dist/main.cjs directly, without the real action wrapper -- see
# test-e2e.yml's test_sandbox_enforcement for the one case that does.
set -uo pipefail

: "${BUILDCAGE_LOCAL_IMAGE_REF:?BUILDCAGE_LOCAL_IMAGE_REF must be set to the locally built proxy image}"

WORKDIR=$(mktemp -d)
trap 'rm -rf "$WORKDIR"' EXIT
touch "$WORKDIR/state.env" "$WORKDIR/summary.md"

# Stand-ins for what the runner hands a JavaScript action: the first two are
# withheld from the sandbox because a `run:` step has no such thing, the third
# reaches it because a `run:` step gets one too.
ACTIONS_RUNTIME_TOKEN="fake-runtime-token" \
ACTIONS_RESULTS_URL="https://results.invalid/" \
ACTIONS_ID_TOKEN_REQUEST_URL="https://idtoken.invalid/" \
GITHUB_WORKSPACE="$WORKDIR" \
GITHUB_STATE="$WORKDIR/state.env" \
GITHUB_STEP_SUMMARY="$WORKDIR/summary.md" \
BUILDCAGE_BUILD_TEST_HOOKS=1 \
BUILDCAGE_LOCAL_IMAGE_REF="$BUILDCAGE_LOCAL_IMAGE_REF" \
INPUT_RUN="grep -q '^CapEff:[[:space:]]*0000000000000000\$' /proc/self/status
grep -q '^NoNewPrivs:[[:space:]]*1\$' /proc/self/status
echo x >> \"\$GITHUB_WORKSPACE/.buildcage-writable-test\"
echo x >> \"\$HOME/.buildcage-writable-test\"
echo x >> /tmp/.buildcage-writable-test
if touch /opt/.buildcage-writable-test 2>/dev/null; then
  echo UNEXPECTED: /opt was writable without a write_through: entry
  exit 1
fi
for withheld in ACTIONS_RUNTIME_TOKEN ACTIONS_RESULTS_URL INPUT_RUN; do
  if env | grep -q \"^\${withheld}=\"; then
    echo \"UNEXPECTED: \${withheld} reached the sandbox\"
    exit 1
  fi
done
[ \"\$ACTIONS_ID_TOKEN_REQUEST_URL\" = 'https://idtoken.invalid/' ] || {
  echo 'UNEXPECTED: ACTIONS_ID_TOKEN_REQUEST_URL did not reach the sandbox'
  exit 1
}" \
  node dist/main.cjs
CODE=$?

echo ""
echo "=== Sandbox Default Privilege/Filesystem Assertions ==="
echo ""
if [ "$CODE" = "0" ]; then
  echo "  PASS  capabilities dropped, no_new_privs set, filesystem policy correct, runner-only credentials withheld"
else
  echo "  FAIL  default privilege/filesystem/environment check failed (exit $CODE)"
  exit 1
fi
echo ""

#!/bin/bash
# Verifies default privilege drop, seccomp filter, filesystem policy and
# sandbox environment by driving dist/main.cjs directly, without the real
# action wrapper; see test-e2e.yml's enforcement steps for the one case that
# does.
#
# $RUNNER_TEMP belongs here rather than in a run of its own: it is one more
# writable exception under the default policy. buildOciConfig's own handling of
# it is unit-tested against the generated config.json; what this adds is that
# runc honors it.
#
# The command makes no outbound connection under the default restrict mode and
# fail-on-blocked, so the run also shows such a step passes without a
# misfiring blocked or incomplete-log annotation.
set -uo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/driver-helpers.sh"

require_local_image

WORKDIR=$(mktemp -d)
RUNNER_TEMP_DIR=$(mktemp -d)
trap 'rm -rf "$WORKDIR" "$RUNNER_TEMP_DIR"' EXIT
touch "$WORKDIR/state.env" "$WORKDIR/summary.md"

# The two syscall classes docs/security.md names as motivating examples for
# the Docker-default-profile-derived filter: unprivileged user-namespace
# creation and io_uring.
SECCOMP_SCRIPT='if unshare -U true 2>/dev/null; then
  echo "UNEXPECTED: unshare -U succeeded"
  exit 1
fi
if ! command -v cc >/dev/null 2>&1; then
  echo "SKIP: no C compiler available to exercise io_uring_setup"
else
  # No $ or backticks below, so an unquoted heredoc delimiter is safe (no
  # accidental expansion by the shell that processes it).
  cat > /tmp/io_uring_check.c <<EOF
#include <sys/syscall.h>
#include <unistd.h>
#include <stdio.h>
#include <errno.h>
int main() {
  long ret = syscall(__NR_io_uring_setup, 1, NULL);
  if (ret == -1 && errno == EPERM) { printf("OK: io_uring_setup blocked\n"); return 0; }
  printf("UNEXPECTED: io_uring_setup returned %ld errno=%d\n", ret, errno);
  return 1;
}
EOF
  cc -O0 -o /tmp/io_uring_check /tmp/io_uring_check.c
  /tmp/io_uring_check
fi'

# Stand-ins for what the runner hands a JavaScript action: the first two are
# withheld from the sandbox because a `run:` step has no such thing; the third
# reaches it because a `run:` step gets one too.
ACTIONS_RUNTIME_TOKEN="fake-runtime-token" \
ACTIONS_RESULTS_URL="https://results.invalid/" \
ACTIONS_ID_TOKEN_REQUEST_URL="https://idtoken.invalid/" \
GITHUB_WORKSPACE="$WORKDIR" \
GITHUB_STATE="$WORKDIR/state.env" \
GITHUB_STEP_SUMMARY="$WORKDIR/summary.md" \
RUNNER_TEMP="$RUNNER_TEMP_DIR" \
BUILDCAGE_LOCAL_IMAGE_REF="$BUILDCAGE_LOCAL_IMAGE_REF" \
INPUT_RUN="grep -q '^CapEff:[[:space:]]*0000000000000000\$' /proc/self/status
grep -q '^NoNewPrivs:[[:space:]]*1\$' /proc/self/status
echo x >> \"\$GITHUB_WORKSPACE/.buildcage-writable-test\"
echo x >> \"\$HOME/.buildcage-writable-test\"
echo x >> /tmp/.buildcage-writable-test
echo x >> \"\$RUNNER_TEMP/.buildcage-writable-test\"
if touch /opt/.buildcage-writable-test 2>/dev/null; then
  echo UNEXPECTED: /opt was writable without a write-through: entry
  exit 1
fi
[ -r /etc/hostname ] || { echo UNEXPECTED: /etc was not readable; exit 1; }
if touch /etc/.buildcage-writable-test 2>/dev/null; then
  echo UNEXPECTED: /etc was writable
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
}
$SECCOMP_SCRIPT" \
  node dist/main.cjs >"$WORKDIR/out.log" 2>&1
CODE=$?

echo ""
echo "=== Sandbox Default Privilege/Filesystem Assertions ==="
echo ""
if [ "$CODE" = "0" ]; then
  pass "capabilities dropped, no_new_privs set, seccomp blocks unshare -U and io_uring_setup, filesystem policy correct (\$RUNNER_TEMP included), runner-only credentials withheld"
else
  fail "default privilege/seccomp/filesystem/environment check failed (exit $CODE)"
fi
# The head check's two annotations, for blocked connections and for an
# incomplete log. Matched on their stable part: this assertion passes on
# absence, so a pattern that stopped matching would pass silently.
if ! grep -Eq "detected by buildcage|logs are incomplete" "$WORKDIR/out.log"; then
  pass "no blocked or incomplete-log annotation for a step with no outbound connection"
else
  fail "the head check misfired on a step with no outbound connection"
fi
if [ "$FAILURES" -gt 0 ]; then
  cat "$WORKDIR/out.log"
fi
assert_results

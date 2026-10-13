#!/bin/bash
# Drives two sandbox proxy lifecycles directly against dist/main.cjs
# (rather than through two real `uses: ./` steps) so this test doesn't
# depend on GitHub Actions' `parallel:` step keyword to prove true
# concurrency; see test-e2e.yml's own `parallel:`-based test for the
# Actions-level version of the same check.
#
# Both instances reach the fixture origin in compose.test-universal.yaml, so
# the only thing that decides whether a request succeeds is the instance's own
# allowlist. The two names below resolve to the same origin.
set -uo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/driver-helpers.sh"

require_local_image

TMP_A=$(mktemp -d)
TMP_B=$(mktemp -d)
cleanup() {
  fixture_down universal
  rm -rf "$TMP_A" "$TMP_B"
}
trap cleanup EXIT

# The origin serves a self-signed certificate and the universal engine never
# terminates TLS, so the client validates the origin's own cert; `-k` is what
# makes that a non-issue rather than the subject of this test.
CURL="curl -fsS -k -o /dev/null --max-time 10"

run_instance() {
  local tmpdir="$1" https_rule="$2" own_url="$3" other_url="$4" test_net_addr="$5"
  run_step universal "$tmpdir/step" \
    TEST_NET_ADDR="$test_net_addr" \
    INPUT_ALLOWED_HTTPS_RULES="$https_rule" \
    INPUT_ALLOWED_HTTP_RULES="" \
    INPUT_ALLOWED_IP_RULES="" \
    INPUT_FAIL_ON_BLOCKED="false" \
    INPUT_RUN="$CURL $own_url
if $CURL $other_url 2>&1; then
  echo cross-talk: $other_url was reachable
  exit 1
fi"
  echo $? > "$tmpdir/exit_code"
}

fixture_up universal

# Each proxy adds its own address to the shared fixture network, so the two
# cannot take the default one (docker/compose.action.test-universal.yaml).
run_instance "$TMP_A" "concurrent-a.example.com:443" \
  "https://concurrent-a.example.com/" "https://concurrent-b.example.com/" 10.200.0.2/24 &
PID_A=$!
run_instance "$TMP_B" "concurrent-b.example.com:443" \
  "https://concurrent-b.example.com/" "https://concurrent-a.example.com/" 10.200.0.3/24 &
PID_B=$!

wait "$PID_A"
wait "$PID_B"

echo ""
echo "=== Sandbox Concurrent-Execution Assertions ==="
echo ""

for label_dir in "A:$TMP_A" "B:$TMP_B"; do
  label="${label_dir%%:*}"
  dir="${label_dir#*:}"
  code=$(cat "$dir/exit_code")
  if [ "$code" = "0" ]; then
    pass "instance $label reached only its own allowlisted host"
  else
    fail "instance $label -- exit code $code, see log below"
    cat "$dir/step.log"
  fi
done

# A bare buildcage-proxy-* sweep also matches another git worktree's proxy, and
# would call someone else's running container a leak.
for label_dir in "A:$TMP_A" "B:$TMP_B"; do
  label="${label_dir%%:*}"
  dir="${label_dir#*:}"
  name=$(awk '/^container_name<</{getline; print; exit}' "$dir/step.state")
  if [ -z "$name" ]; then
    fail "instance $label wrote no container_name to GITHUB_STATE"
    continue
  fi

  if [ -z "$(docker ps -aq --filter "name=$name")" ]; then
    pass "instance $label left no proxy container behind"
  else
    fail "instance $label left $name behind"
  fi

  # Mirrors deriveProjectName (src/core/lib/docker/compose-project-name.ts):
  # the container is already gone here, so its Compose labels can't be read.
  project="buildcage-$(printf '%s' "$name" | sha256sum | cut -c1-12)"
  if [ -z "$(docker network ls --filter "label=com.docker.compose.project=$project" -q)" ]; then
    pass "instance $label left no proxy network behind"
  else
    fail "instance $label left $project's network behind"
  fi
done

assert_results

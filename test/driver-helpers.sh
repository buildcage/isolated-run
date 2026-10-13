#!/bin/bash
# Sourced by the integration drivers (integration-test-*.sh) on the runner
# host, and never from inside the sandbox: helpers.sh is the half the scenario
# scripts share, and this file sources it.
source "$(dirname "${BASH_SOURCE[0]}")/helpers.sh"

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

# require_local_image [inspect|universal]: stops the driver unless
# BUILDCAGE_LOCAL_IMAGE_REF names the proxy image to run, built for that engine
# if one is given.
require_local_image() {
  local what="the locally built proxy image"
  case "${1:-}" in
    inspect) what="a locally built inspect-engine image (BUILDCAGE_TEST_HOOKS=1 PROXY_ENGINE=inspect docker compose build proxy)" ;;
    universal) what="a locally built universal-engine image" ;;
  esac
  : "${BUILDCAGE_LOCAL_IMAGE_REF:?BUILDCAGE_LOCAL_IMAGE_REF must be set to $what}"
}

# fixture_up|fixture_down <engine>: the fixture origins of
# compose.test-<engine>.yaml.
fixture_up() {
  echo "--- bringing up fixture origins (compose.test-$1.yaml) ---"
  docker compose -f "$REPO_ROOT/compose.test-$1.yaml" up -d --build --wait
}

fixture_down() {
  docker compose -f "$REPO_ROOT/compose.test-$1.yaml" down -v >/dev/null 2>&1 || true
}

# run_step <engine> <prefix> [VAR=value...]: runs dist/main.cjs as one step
# against the fixture origins, in the workspace <prefix> sits in, with a fresh
# <prefix>.state and <prefix>.md and its output in <prefix>.log. The VARs come
# last, so they override any of these. Returns the step's exit code.
run_step() {
  local engine="$1" prefix="$2"
  shift 2
  local cert=()
  if [ "$engine" = inspect ]; then
    cert=(BUILDCAGE_TEST_CERT_PATH="$REPO_ROOT/test/test-server-inspect/cert.pem")
  fi
  : > "$prefix.state"
  : > "$prefix.md"
  env \
    GITHUB_WORKSPACE="$(dirname "$prefix")" \
    GITHUB_STATE="$prefix.state" \
    GITHUB_STEP_SUMMARY="$prefix.md" \
    BUILDCAGE_LOCAL_IMAGE_REF="$BUILDCAGE_LOCAL_IMAGE_REF" \
    BUILDCAGE_TEST_COMPOSE_FILE="$REPO_ROOT/docker/compose.action.test-$engine.yaml" \
    "${cert[@]}" \
    INPUT_PROXY_ENGINE="$engine" \
    "$@" \
    node "$REPO_ROOT/dist/main.cjs" > "$prefix.log" 2>&1
}

#!/bin/bash
# Sourced by the integration drivers (integration-test-*.sh) on the runner
# host, and never from inside the sandbox: helpers.sh is the half the scenario
# scripts share, and this file sources it.
source "$(dirname "${BASH_SOURCE[0]}")/helpers.sh"

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

# require_local_image [inspect|universal]: stops the driver if
# BUILDCAGE_LOCAL_IMAGE_REF is unset, naming the image it should hold.
require_local_image() {
  local what="the locally built proxy image"
  case "${1:-}" in
    inspect) what="a locally built inspect-engine image (BUILDCAGE_TEST_HOOKS=1 PROXY_ENGINE=inspect docker compose build proxy)" ;;
    universal) what="a locally built universal-engine image" ;;
  esac
  : "${BUILDCAGE_LOCAL_IMAGE_REF:?BUILDCAGE_LOCAL_IMAGE_REF must be set to $what}"
}

# fixture_up|fixture_down <engine>: starts or removes the fixture origins of
# compose.test-<engine>.yaml.
fixture_up() {
  echo "--- bringing up the fixture (compose.test-$1.yaml) ---"
  docker compose -f "$REPO_ROOT/compose.test-$1.yaml" up -d --build --wait
}

fixture_down() {
  docker compose -f "$REPO_ROOT/compose.test-$1.yaml" down -v >/dev/null 2>&1 || true
}

# run_step [--tee] <engine> <prefix> [VAR=value...]: runs dist/main.cjs as one
# step against the fixture origins, in the workspace <prefix> sits in, with a
# fresh <prefix>.state and <prefix>.md and its output in <prefix>.log, also
# printed as it comes with --tee. The VARs come last, so they override any of
# these. Returns the step's exit code.
run_step() {
  local tee=false
  if [ "$1" = --tee ]; then
    tee=true
    shift
  fi
  local engine="$1" prefix="$2"
  shift 2
  if [ "$engine" = inspect ]; then
    set -- BUILDCAGE_TEST_CERT_PATH="$REPO_ROOT/test/test-server-inspect/cert.pem" "$@"
  fi
  : > "$prefix.state"
  : > "$prefix.md"
  local cmd=(
    env
    GITHUB_WORKSPACE="$(dirname "$prefix")"
    GITHUB_STATE="$prefix.state"
    GITHUB_STEP_SUMMARY="$prefix.md"
    BUILDCAGE_LOCAL_IMAGE_REF="$BUILDCAGE_LOCAL_IMAGE_REF"
    BUILDCAGE_TEST_COMPOSE_FILE="$REPO_ROOT/docker/compose.action.test-$engine.yaml"
    INPUT_PROXY_ENGINE="$engine"
    "$@"
    node "$REPO_ROOT/dist/main.cjs"
  )
  if [ "$tee" = true ]; then
    "${cmd[@]}" 2>&1 | tee "$prefix.log"
    return "${PIPESTATUS[0]}"
  fi
  "${cmd[@]}" > "$prefix.log" 2>&1
}

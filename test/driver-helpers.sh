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
# compose.test-<engine>.yaml. Both leave alone a fixture with-fixture.sh
# started for every driver it runs.
fixture_up() {
  [ "${BUILDCAGE_SHARED_FIXTURE:-}" = "$1" ] && return
  echo "--- bringing up the fixture (compose.test-$1.yaml) ---"
  docker compose -f "$REPO_ROOT/compose.test-$1.yaml" up -d --build --wait
}

fixture_down() {
  [ "${BUILDCAGE_SHARED_FIXTURE:-}" = "$1" ] && return
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
    BUILDCAGE_TEST_COMPOSE_OVERLAY="$REPO_ROOT/docker/compose.action.test-$engine.yaml"
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

# state_container_name <state file>: the proxy container name a step wrote to
# its GITHUB_STATE, empty if it wrote none.
state_container_name() {
  awk '/^container_name<</{getline; print; exit}' "$1" 2>/dev/null
}

# proxy_project <container name>: the Compose project the step started that
# container under, as deriveProjectName (src/core/lib/docker/compose-project-name.ts)
# derives it. Once the container is gone its labels can't be read.
proxy_project() {
  printf 'buildcage-%s' "$(printf '%s' "$1" | sha256sum | cut -c1-12)"
}

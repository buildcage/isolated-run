#!/bin/bash
# Verifies that a write_through: entry the inspect engine's CA directory mount
# would shadow is refused when the CA directory is a symlink, whether the entry
# names the link or where it leads. Drives dist/main.cjs directly, without the
# real action wrapper.
set -uo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/helpers.sh"

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

: "${BUILDCAGE_LOCAL_IMAGE_REF:?BUILDCAGE_LOCAL_IMAGE_REF must be set to a locally built inspect-engine image (BUILDCAGE_TEST_HOOKS=1 PROXY_ENGINE=inspect docker compose build proxy)}"

WORKDIR=$(mktemp -d)
TARGET_PARENT=$(mktemp -d)
TARGET="$TARGET_PARENT/anchors"
mkdir "$TARGET"
# A CA directory candidate this runner lacks, made a symlink to $TARGET.
CA_DIR_LINK=""
for candidate in /etc/pki/ca-trust/source/anchors /etc/pki/trust/anchors /var/lib/ca-certificates/pem; do
  if [ ! -e "$candidate" ] && [ ! -L "$candidate" ]; then
    CA_DIR_LINK="$candidate"
    break
  fi
done
# The shallowest directory made for the link, removed with it.
MADE_DIR=""
cleanup() {
  docker compose -f "$REPO_ROOT/compose.test-inspect.yaml" down -v >/dev/null 2>&1 || true
  if [ -n "$MADE_DIR" ]; then sudo -n rm -rf "$MADE_DIR"; fi
  rm -rf "$WORKDIR" "$TARGET_PARENT"
}
trap cleanup EXIT
touch "$WORKDIR/state.env" "$WORKDIR/summary.md"

run_instance() {
  local write_through="$1" run_script="$2"
  GITHUB_WORKSPACE="$WORKDIR" \
  GITHUB_STATE="$WORKDIR/state.env" \
  GITHUB_STEP_SUMMARY="$WORKDIR/summary.md" \
  BUILDCAGE_BUILD_TEST_HOOKS=1 \
  BUILDCAGE_LOCAL_IMAGE_REF="$BUILDCAGE_LOCAL_IMAGE_REF" \
  BUILDCAGE_TEST_COMPOSE_FILE="$REPO_ROOT/docker/compose.action.test-inspect.yaml" \
  BUILDCAGE_TEST_CERT_PATH="$REPO_ROOT/test/test-server-inspect/cert.pem" \
  INPUT_PROXY_ENGINE="inspect" \
  INPUT_WRITE_THROUGH="$write_through" \
  INPUT_RUN="$run_script" \
    node "$REPO_ROOT/dist/main.cjs" > "$WORKDIR/out.log" 2>&1
  echo $? > "$WORKDIR/exit_code"
  cat "$WORKDIR/out.log"
}

echo ""
echo "=== Inspect Engine reserved-mount Assertions ==="
echo ""

if [ -z "$CA_DIR_LINK" ]; then
  echo "  SKIP  every CA directory candidate already exists"
  assert_results
  exit
fi

MADE_DIR="$CA_DIR_LINK"
while [ ! -e "$(dirname "$MADE_DIR")" ]; do MADE_DIR=$(dirname "$MADE_DIR"); done
if ! sudo -n mkdir -p "$(dirname "$CA_DIR_LINK")" || ! sudo -n ln -s "$TARGET" "$CA_DIR_LINK"; then
  fail "could not link $CA_DIR_LINK to $TARGET"
  assert_results
fi

echo "--- bringing up fixture origins (compose.test-inspect.yaml) ---"
docker compose -f "$REPO_ROOT/compose.test-inspect.yaml" up -d --build --wait

for entry in "$CA_DIR_LINK" "$TARGET"; do
  run_instance "$entry" "true"
  CODE=$(cat "$WORKDIR/exit_code")
  if [ "$CODE" != "0" ] && grep -qF "is in the CA directory \"$CA_DIR_LINK\" (a symlink to \"$TARGET\")" "$WORKDIR/out.log"; then
    pass "write_through: $entry is refused when $CA_DIR_LINK links to $TARGET"
  else
    fail "write_through: $entry was accepted (exit $CODE)"
  fi
done

# The parent stays allowed, and the CA copy still lands where the link leads.
run_instance "$TARGET_PARENT" "test -f '$TARGET/buildcage-proxy-ca.pem'"
CODE=$(cat "$WORKDIR/exit_code")
if [ "$CODE" = "0" ]; then
  pass "write_through: the directory holding $TARGET is allowed, and the CA lands in $TARGET"
else
  fail "write_through: the directory holding $TARGET failed the step (exit $CODE)"
fi

assert_results

#!/bin/bash
# Verifies that a write-through: entry the inspect engine's CA directory mount
# would shadow is refused when the CA directory is a symlink, whether the entry
# names the link or where it leads. Drives dist/main.cjs directly, without the
# real action wrapper.
set -uo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/driver-helpers.sh"

require_local_image inspect

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
  fixture_down inspect
  if [ -n "$MADE_DIR" ]; then sudo -n rm -rf "$MADE_DIR"; fi
  rm -rf "$WORKDIR" "$TARGET_PARENT"
}
trap cleanup EXIT

run_instance() {
  local write_through="$1" run_script="$2"
  run_step inspect "$WORKDIR/step" \
    INPUT_WRITE_THROUGH="$write_through" \
    INPUT_RUN="$run_script"
  echo $? > "$WORKDIR/exit_code"
  cat "$WORKDIR/step.log"
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

fixture_up inspect

# The link itself fails as a symlink, before the CA directory check.
run_instance "$CA_DIR_LINK" "true"
CODE=$(cat "$WORKDIR/exit_code")
if [ "$CODE" != "0" ] && grep -qF "symlinks are not followed. Name the path it leads to instead: \"$TARGET\"" "$WORKDIR/step.log"; then
  pass "write-through: $CA_DIR_LINK is refused as a symlink to $TARGET"
else
  fail "write-through: $CA_DIR_LINK was accepted (exit $CODE)"
fi

run_instance "$TARGET" "true"
CODE=$(cat "$WORKDIR/exit_code")
if [ "$CODE" != "0" ] && grep -qF "is in the CA directory \"$CA_DIR_LINK\" (a symlink to \"$TARGET\")" "$WORKDIR/step.log"; then
  pass "write-through: $TARGET is refused when $CA_DIR_LINK links to it"
else
  fail "write-through: $TARGET was accepted (exit $CODE)"
fi

# The parent stays allowed, and the CA copy still lands where the link leads.
run_instance "$TARGET_PARENT" "test -f '$TARGET/buildcage-proxy-ca.pem'"
CODE=$(cat "$WORKDIR/exit_code")
if [ "$CODE" = "0" ]; then
  pass "write-through: the directory holding $TARGET is allowed, and the CA lands in $TARGET"
else
  fail "write-through: the directory holding $TARGET failed the step (exit $CODE)"
fi

assert_results

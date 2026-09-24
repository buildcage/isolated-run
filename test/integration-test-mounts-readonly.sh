#!/bin/bash
# Verifies how the sandbox treats real host mounts, by driving dist/main.cjs
# directly, without the real action wrapper; see test-e2e.yml's
# test_sandbox_enforcement for the one case that does. Two mounts, one sandbox,
# since a start is not cheap.
#
# The first is a bind mount nested under $GITHUB_WORKSPACE: a separate mount
# under a writable path is writable too.
#
# The second is a pseudo-filesystem that is not among runc's own default
# base-spec mounts (see freshMountDestinationsFrom in sandbox/oci-mounts.ts),
# so it must not be tolerated merely for looking like one. securityfs is the
# realistic case: the Actions Ubuntu images mount it at /sys/kernel/security
# for AppArmor, and runc's default spec never declares it. Remounting the real
# one from a test is not safe, so this mounts an equivalent at a throwaway
# location outside every writable exception.
set -uo pipefail

: "${BUILDCAGE_LOCAL_IMAGE_REF:?BUILDCAGE_LOCAL_IMAGE_REF must be set to the locally built proxy image}"

WORKDIR=$(mktemp -d)
NESTED_SRC=$(mktemp -d)
NESTED_MOUNT="$WORKDIR/nested-mount"
mkdir -p "$NESTED_MOUNT"

# Deliberately under /var/tmp, not /tmp: /tmp is always a writable exception,
# which would defeat the point.
SECURITYFS_MOUNT="/var/tmp/buildcage-securityfs-test-$$"
mkdir -p "$SECURITYFS_MOUNT"

cleanup() {
  sudo -n umount "$NESTED_MOUNT" >/dev/null 2>&1
  sudo -n umount "$SECURITYFS_MOUNT" >/dev/null 2>&1
  rmdir "$SECURITYFS_MOUNT" 2>/dev/null
  rm -rf "$WORKDIR" "$NESTED_SRC"
}
trap cleanup EXIT

sudo -n mount --bind "$NESTED_SRC" "$NESTED_MOUNT"
sudo -n mount -t securityfs securityfs "$SECURITYFS_MOUNT"
touch "$WORKDIR/state.env" "$WORKDIR/summary.md"

# Both checks run whatever the other one did, so one failure does not hide the
# other's result.
GITHUB_WORKSPACE="$WORKDIR" \
GITHUB_STATE="$WORKDIR/state.env" \
GITHUB_STEP_SUMMARY="$WORKDIR/summary.md" \
BUILDCAGE_BUILD_TEST_HOOKS=1 \
BUILDCAGE_LOCAL_IMAGE_REF="$BUILDCAGE_LOCAL_IMAGE_REF" \
INPUT_RUN="rc=0

mp=\"\$GITHUB_WORKSPACE/nested-mount\"
if [ ! -d \"\$mp\" ]; then
  echo 'UNEXPECTED: nested mount point not visible in sandbox'
  rc=1
elif echo x > \"\$mp/.buildcage-nested-mount-test\" 2>/dev/null; then
  echo 'OK: nested mount under workdir is visible and writable'
else
  echo 'UNEXPECTED: nested mount under workdir was not writable'
  rc=1
fi

mp='$SECURITYFS_MOUNT'
# securityfs's own directory entries are populated by kernel LSM subsystems,
# not user-creatable, so creating a file there fails with EACCES whether the
# mount is ro or rw, which would not tell a fixed sandbox from a broken one.
# Read the mount options in this mount namespace instead.
if [ ! -d \"\$mp\" ]; then
  echo 'UNEXPECTED: securityfs mount point not visible in sandbox'
  rc=1
else
  opts=\$(awk -v mp=\"\$mp\" '\$5 == mp { last = \$6 } END { print last }' /proc/self/mountinfo)
  case \",\$opts,\" in
    *,ro,*) echo 'OK: securityfs mount is read-only' ;;
    *)
      echo \"UNEXPECTED: securityfs mount options were '\$opts' (expected ro)\"
      rc=1
      ;;
  esac
fi

exit \$rc
" \
  node dist/main.cjs
CODE=$?

echo ""
echo "=== Sandbox Read-Only Mount Assertions ==="
echo ""
# The step's exit status is the two checks and-ed together, so it is the
# verdict; the UNEXPECTED line above says which one gave way.
if [ "$CODE" = "0" ]; then
  echo "  PASS  a real mount nested under workdir is visible and writable"
  echo "  PASS  a real securityfs mount not among runc's own default mounts is forced read-only"
else
  echo "  FAIL  a nested mount was not writable, or a mount outside every writable path was not read-only (exit $CODE)"
  exit 1
fi
echo ""

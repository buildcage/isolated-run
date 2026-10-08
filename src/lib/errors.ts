import { ActionError } from "#core/lib/errors.ts";

/**
 * Intentional error in the run action's own logic. Image provenance failures throw
 * ProvenanceError instead (see core/lib/provenance/errors.ts); invalid ACL rule syntax
 * throws InvalidRulesError instead (see core/lib/acl/rules.ts); a malformed boolean,
 * retention, proxy_engine or proxy_mode input throws InvalidInputError (see
 * core/lib/actions/inputs.ts).
 *
 * Codes that carry more than their name says:
 *   PROXY_NOT_RUNNING                 the proxy container isn't running after `docker compose up`
 *   PROXY_NOT_READY                   the proxy container started but never became usable
 *   RUNC_EXTRACT_FAILED               failed to `docker cp` runc/gen-seccomp-profile out of the proxy image
 *   CA_EXTRACT_FAILED                 inspect engine only: failed to `docker cp` the proxy's CA out of the image
 *   OCI_CONFIG_BUILD_FAILED           failed to run gen-seccomp-profile/runc spec or assemble config.json
 *   DOCKER_UNAVAILABLE                docker CLI missing from PATH or a docker command failed
 *   UNSAFE_PRIMARY_GID                the runner's primary GID is privileged and no safe substitute GID exists
 *   ROOT_RUNNER                       the runner is uid 0, where DAC alone would guard root-owned host sockets
 *   FILESYSTEM_INPUT_CONFLICT         filesystem_mode/write_through inputs combined in a disallowed way, or a
 *                                     writable path that collides with a mount the sandbox needs itself
 *   INVALID_WRITE_THROUGH_PATH        a write_through entry failed path-resolution rules (unknown $VAR, etc.)
 *   WRITE_THROUGH_TARGET_MISSING      a write_through entry resolves to a well-known GITHUB_* file that doesn't exist
 *   WRITE_THROUGH_TARGET_UNCREATABLE  a write_through entry doesn't exist and the runner couldn't create it
 *   ALLOW_WRITE_REMOVED               the removed allow_write input was supplied (renamed to write_through)
 *   OVERLAYFS_UNSUPPORTED             filesystem_mode: ephemeral's overlayfs preflight probe failed
 *   OVERLAY_PROBE_CLEANUP_FAILED      that probe mounted fine, but its root-owned leftovers could not be removed,
 *                                     which is what ephemeral's own cleanup needs too
 *   FILESYSTEM_PLAN_FAILED            computing filesystem_mode: ephemeral's overlay roots failed for a reason
 *                                     unrelated to write_through's own syntax (e.g. a permissions error reading
 *                                     one of the fixed $HOME/$RUNNER_TEMP/etc. candidate paths)
 *   SCRATCH_BASE_UNSAFE               the sandbox scratch base exists but isn't a private directory the action owns
 *   CONTAINER_NAME_INVALID            a value read back from GITHUB_STATE isn't a name this action generates
 *   SCRATCH_DIR_UNSAFE                the sudo rm -rf fallback's target isn't owned by the runner uid
 *   HOST_COMMAND_UNPINNABLE           `docker` or `sudo` is only on PATH somewhere the sandboxed command can write
 *   HOST_DIR_UNPROTECTABLE            a directory kept read-only (the docker config, an action checkout, the
 *                                     runner's install directory) or the runner's
 *                                     GITHUB_ENV/GITHUB_PATH/GITHUB_STATE file goes through a symlink the
 *                                     sandboxed command can replace, or through too many symlinks to resolve
 *   NSS_DATABASE_CA_COPIED            inspect engine only: what the command wrote to the runner's NSS database
 *                                     carries a copy of the proxy CA, under fail_on_ca_residue: true
 *   NSS_DATABASE_WRITE_BACK_FAILED    inspect engine only: what the command wrote to the runner's NSS database
 *                                     could not be written back
 *   SANDBOX_TERMINATED                a signal ended run-isolated.sh, so the command's exit status is unknown
 *   SANDBOX_LAUNCH_FAILED             `sudo run-isolated.sh` could not be started at all
 *   SCRATCH_BASE_SYMLINKED            /var/tmp, the sandbox scratch base's parent, resolves through a symlink
 *   INVALID_AWS_ACCOUNTS              an allowed_aws_role_accounts entry is not a 12-digit account ID
 *   AWS_ACCESS_KEY_MISSING            aws_key_check is on but the step has no AWS_ACCESS_KEY_ID to start from
 *   AWS_ACCOUNTS_REMOVED              the replaced allowed_aws_accounts input was supplied
 *   AWS_KEY_CHECK_CONFLICT            allowed_aws_role_accounts names accounts while aws_key_check is false
 */
export type SandboxErrorCode =
  | "MISSING_RUN"
  | "PROXY_NOT_RUNNING"
  | "PROXY_NOT_READY"
  | "RUNC_EXTRACT_FAILED"
  | "CA_EXTRACT_FAILED"
  | "OCI_CONFIG_BUILD_FAILED"
  | "DOCKER_UNAVAILABLE"
  | "PASSWORDLESS_SUDO_REQUIRED"
  | "UNSAFE_PRIMARY_GID"
  | "ROOT_RUNNER"
  | "FILESYSTEM_INPUT_CONFLICT"
  | "INVALID_FILESYSTEM_MODE"
  | "INVALID_WRITE_THROUGH_PATH"
  | "WRITE_THROUGH_TARGET_MISSING"
  | "WRITE_THROUGH_TARGET_UNCREATABLE"
  | "ALLOW_WRITE_REMOVED"
  | "OVERLAYFS_UNSUPPORTED"
  | "OVERLAY_PROBE_CLEANUP_FAILED"
  | "FILESYSTEM_PLAN_FAILED"
  | "SCRATCH_BASE_UNSAFE"
  | "CONTAINER_NAME_INVALID"
  | "SCRATCH_DIR_OUT_OF_BASE"
  | "SCRATCH_DIR_UNSAFE"
  | "HOST_COMMAND_UNPINNABLE"
  | "HOST_DIR_UNPROTECTABLE"
  | "NSS_DATABASE_CA_COPIED"
  | "NSS_DATABASE_WRITE_BACK_FAILED"
  | "SANDBOX_TERMINATED"
  | "SANDBOX_LAUNCH_FAILED"
  | "SCRATCH_BASE_SYMLINKED"
  | "INVALID_AWS_ACCOUNTS"
  | "AWS_ACCESS_KEY_MISSING"
  | "AWS_ACCOUNTS_REMOVED"
  | "AWS_KEY_CHECK_CONFLICT";

export class SandboxError extends ActionError<SandboxErrorCode> {}

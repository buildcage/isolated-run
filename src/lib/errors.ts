import { ActionError } from "#core/lib/errors.ts";

/**
 * SandboxError — intentional error in the run action's own logic. Image
 * provenance failures throw ProvenanceError instead (see
 * core/lib/provenance/errors.ts); invalid ACL rule syntax throws
 * InvalidRulesError instead (see core/lib/acl/rules.ts).
 *
 * Codes:
 *   MISSING_RUN                – required `run` input was empty
 *   INVALID_PROXY_ENGINE       – proxy_engine input isn't a recognized engine
 *   PROXY_NOT_RUNNING          – sandbox proxy container isn't running after `docker compose up`
 *   RUNC_EXTRACT_FAILED        – failed to `docker cp` runc/gen-seccomp-profile out of the proxy image
 *   CA_EXTRACT_FAILED          – inspect engine only: failed to `docker cp` the proxy's CA out of the image
 *   OCI_CONFIG_BUILD_FAILED    – failed to run gen-seccomp-profile/runc spec or assemble config.json
 *   DOCKER_UNAVAILABLE         – docker CLI missing from PATH or a docker command failed
 *   PASSWORDLESS_SUDO_REQUIRED    – sudo -n check failed; passwordless sudo isn't configured
 *   UNSAFE_PRIMARY_GID            – the runner's primary GID is privileged and no safe substitute GID exists
 *   FILESYSTEM_INPUT_CONFLICT      – filesystem/writable/allow_write inputs combined in a disallowed way
 *   INVALID_FILESYSTEM_MODE       – filesystem input isn't "persistent" or "ephemeral"
 *   INVALID_ALLOW_WRITE_PATH      – an allow_write entry failed path-resolution rules (unknown $VAR, etc.)
 *   ALLOW_WRITE_TARGET_MISSING    – an allow_write entry resolves to a well-known GITHUB_* file that doesn't exist
 *   ALLOW_WRITE_TARGET_UNCREATABLE – an allow_write entry doesn't exist and couldn't be created (sudo mkdir/chown failed)
 *   OVERLAYFS_UNSUPPORTED         – filesystem: ephemeral's overlayfs preflight probe failed
 *   FILESYSTEM_PLAN_FAILED        – computing filesystem: ephemeral's overlay roots failed for a reason
 *                                    unrelated to allow_write's own syntax (e.g. a permissions error reading
 *                                    one of the fixed $HOME/$RUNNER_TEMP/etc. candidate paths)
 *   SCRATCH_BASE_UNSAFE           – the sandbox scratch base exists but isn't a private directory we own
 */
export type SandboxErrorCode =
  | "MISSING_RUN"
  | "INVALID_PROXY_ENGINE"
  | "PROXY_NOT_RUNNING"
  | "RUNC_EXTRACT_FAILED"
  | "CA_EXTRACT_FAILED"
  | "OCI_CONFIG_BUILD_FAILED"
  | "DOCKER_UNAVAILABLE"
  | "PASSWORDLESS_SUDO_REQUIRED"
  | "UNSAFE_PRIMARY_GID"
  | "FILESYSTEM_INPUT_CONFLICT"
  | "INVALID_FILESYSTEM_MODE"
  | "INVALID_ALLOW_WRITE_PATH"
  | "ALLOW_WRITE_TARGET_MISSING"
  | "ALLOW_WRITE_TARGET_UNCREATABLE"
  | "OVERLAYFS_UNSUPPORTED"
  | "FILESYSTEM_PLAN_FAILED"
  | "SCRATCH_BASE_UNSAFE";

export class SandboxError extends ActionError<SandboxErrorCode> {}

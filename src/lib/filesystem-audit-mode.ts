import { SandboxError } from "./errors.ts";

/**
 * Lives here rather than in inputs.ts for the same reason filesystem-mode.ts
 * does: sandbox/ needs only the type.
 */
const FILESYSTEM_AUDIT = ["off", "record"] as const;
export type FilesystemAudit = (typeof FILESYSTEM_AUDIT)[number];

export function resolveFilesystemAudit(input: string | undefined): FilesystemAudit {
  const trimmed = input?.trim() || "off";
  if (!(FILESYSTEM_AUDIT as readonly string[]).includes(trimmed)) {
    throw new SandboxError(
      `Invalid filesystem_audit: ${JSON.stringify(input)}. Must be one of ${FILESYSTEM_AUDIT.join(", ")}.`,
      "INVALID_FILESYSTEM_AUDIT",
    );
  }
  return trimmed as FilesystemAudit;
}

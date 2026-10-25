import { SandboxError } from "./errors.ts";

/**
 * Lives here rather than in inputs.ts so that sandbox/, which needs only the
 * type, does not import inputs.ts.
 */
const FILESYSTEM_MODES = ["persistent", "ephemeral"] as const;
export type FilesystemMode = (typeof FILESYSTEM_MODES)[number];

export function resolveFilesystemMode(input: string | undefined): FilesystemMode {
  const trimmed = input?.trim() || "persistent";
  if (!(FILESYSTEM_MODES as readonly string[]).includes(trimmed)) {
    throw new SandboxError(
      `Invalid filesystem_mode: ${JSON.stringify(input)}. Must be one of ${FILESYSTEM_MODES.join(", ")}.`,
      "INVALID_FILESYSTEM_MODE",
    );
  }
  return trimmed as FilesystemMode;
}

import { dirname } from "node:path";

import * as core from "@actions/core";

import type { Annotation } from "#core/lib/actions/annotation.ts";
import { errorMessage } from "#core/lib/errors.ts";

/** Collision-free across concurrent invocations in one job: containerName's
 *  own random suffix already is (see generateContainerName). */
export function filesystemAuditArtifactName(containerName: string): string {
  return `buildcage-filesystem-audit-${containerName.split("-").at(-1)}`;
}

export type UploadArtifact = (
  name: string,
  files: string[],
  rootDirectory: string,
  options: { retentionDays?: number },
) => Promise<unknown>;

/* v8 ignore start -- the default behind the upload seam, loaded lazily so a
 *  run that records nothing never imports @actions/artifact. */
const uploadViaActionsArtifact: UploadArtifact = async (name, files, rootDirectory, options) => {
  const { DefaultArtifactClient } = await import("@actions/artifact");
  return new DefaultArtifactClient().uploadArtifact(name, files, rootDirectory, options);
};
/* v8 ignore stop */

/**
 * Upload the recording the tracer already wrote, and return the artifact's
 * name, or undefined on failure. The JSON lines carry absolute paths, so
 * treat the artifact as sensitive. Best-effort: a failed upload only warns.
 */
export async function uploadFilesystemAuditArtifact(
  outPath: string,
  containerName: string,
  retentionDays: number | undefined,
  annotation: Annotation,
  { upload = uploadViaActionsArtifact }: { upload?: UploadArtifact } = {},
): Promise<string | undefined> {
  try {
    const name = filesystemAuditArtifactName(containerName);
    await upload(name, [outPath], dirname(outPath), { retentionDays });
    console.log(`Uploaded the filesystem audit as ${name}`);
    return name;
  } catch (e) {
    annotation.warning(`Could not upload the filesystem audit artifact: ${errorMessage(e)}`);
    return undefined;
  }
}

/** Set the filesystem_audit_artifact_name output, empty when none was
 *  uploaded. Written after the command, which is last-write-wins over
 *  anything the command itself wrote to the same key. */
export function setFilesystemAuditOutput(name: string): void {
  core.setOutput("filesystem_audit_artifact_name", name);
}

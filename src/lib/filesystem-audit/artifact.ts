import { dirname } from "node:path";

import * as core from "@actions/core";

import type { Annotation } from "#core/lib/actions/annotation.ts";
import { errorMessage } from "#core/lib/errors.ts";

import { artifactName, uploadViaActionsArtifact, type UploadArtifact } from "../artifact-upload.ts";

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
    const name = artifactName("buildcage-filesystem-audit", containerName);
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

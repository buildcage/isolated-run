import { dirname } from "node:path";

import * as core from "@actions/core";

import type { Annotation } from "#core/lib/actions/annotation.ts";
import { errorMessage } from "#core/lib/errors.ts";

import { artifactName, uploadViaActionsArtifact, type UploadArtifact } from "../artifact-upload.ts";

/** The name uploadFilesystemAuditArtifact uploads under. */
export function filesystemAuditArtifactName(containerName: string): string {
  return artifactName("buildcage-filesystem-audit", containerName);
}

/** An uploaded artifact: its name, and its page where the run is known. */
export interface UploadedArtifact {
  name: string;
  url?: string;
}

// The page upload-artifact links to as its artifact-url output.
function artifactUrl(uploaded: unknown, env: NodeJS.ProcessEnv): string | undefined {
  const id = (uploaded as { id?: unknown } | undefined)?.id;
  const { GITHUB_SERVER_URL: server, GITHUB_REPOSITORY: repo, GITHUB_RUN_ID: run } = env;
  if (typeof id !== "number" || !server || !repo || !run) return undefined;
  return `${server}/${repo}/actions/runs/${run}/artifacts/${id}`;
}

/**
 * Upload the files, all in one directory, as the step's filesystem audit
 * artifact, and return it, or undefined on failure. The JSON lines carry
 * absolute paths, so treat the artifact as sensitive. Best-effort: a failed
 * upload only warns.
 */
export async function uploadFilesystemAuditArtifact(
  files: string[],
  containerName: string,
  retentionDays: number | undefined,
  annotation: Annotation,
  {
    upload = uploadViaActionsArtifact,
    env = process.env,
  }: { upload?: UploadArtifact; env?: NodeJS.ProcessEnv } = {},
): Promise<UploadedArtifact | undefined> {
  try {
    const name = filesystemAuditArtifactName(containerName);
    const uploaded = await upload(name, files, dirname(files[0]), { retentionDays });
    console.log(`Uploaded the filesystem audit as ${name}`);
    const url = artifactUrl(uploaded, env);
    return url ? { name, url } : { name };
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

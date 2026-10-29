import { mkdtempSync, rmSync } from "node:fs";
import { join } from "node:path";

import * as core from "@actions/core";

import type { Annotation } from "#core/lib/actions/annotation.ts";
import { errorMessage } from "#core/lib/errors.ts";
import { buildTrafficRecords, writeTrafficFile } from "#core/lib/report/outcome/traffic-output.ts";

import type { AwsTrafficFields } from "../proxy/aws-log.ts";
import { artifactName, uploadViaActionsArtifact, type UploadArtifact } from "./artifact-upload.ts";
import { withAwsKeyNames } from "./aws-keys.ts";
import type { Report } from "./report.ts";
import { SANDBOX_SCRATCH_BASE, ensureOwnScratchBase } from "./sandbox/scratch-dir.ts";

/** `upload` is injectable so tests can assert on the arguments instead of
 *  mocking @actions/artifact directly. */
export interface UploadTrafficArtifactDeps {
  upload?: UploadArtifact;
  scratchBase?: string;
}

/**
 * Upload the traffic JSON and return the artifact's name, or undefined if the
 * upload failed. Best-effort: the step's own outcome is already decided by
 * this point, so a failed upload only warns.
 */
export async function uploadTrafficArtifact(
  report: Report,
  containerName: string,
  retentionDays: number | undefined,
  annotation: Annotation,
  {
    upload = uploadViaActionsArtifact,
    scratchBase = SANDBOX_SCRATCH_BASE,
  }: UploadTrafficArtifactDeps = {},
): Promise<string | undefined> {
  // The JSON carries URLs verbatim. /tmp is shared with every sandbox; the
  // scratch base is hidden from them.
  ensureOwnScratchBase(scratchBase);
  const scratchDir = mkdtempSync(join(scratchBase, "traffic-"));
  try {
    const file = join(scratchDir, "traffic.json");
    writeTrafficFile(
      file,
      buildTrafficRecords<AwsTrafficFields>(withAwsKeyNames(report.timeline), report.startedAt),
    );
    const name = artifactName("buildcage-traffic", containerName);
    await upload(name, [file], scratchDir, { retentionDays });
    console.log(`Uploaded the traffic JSON as ${name}`);
    return name;
  } catch (e) {
    annotation.warning(`Could not upload the traffic artifact: ${errorMessage(e)}`);
    return undefined;
  } finally {
    rmSync(scratchDir, { recursive: true, force: true });
  }
}

/**
 * Set the traffic-artifact-name output, under both its spellings, empty when
 * no artifact was uploaded.
 * Written on every path, after the isolated command has exited:
 * GITHUB_OUTPUT is last-write-wins, so this is what overrides anything the
 * command itself wrote to the same key.
 */
export function setTrafficArtifactOutput(name: string): void {
  core.setOutput("traffic-artifact-name", name);
  core.setOutput("traffic_artifact_name", name);
}

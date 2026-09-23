import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import * as core from "@actions/core";

import type { Annotation } from "#core/lib/actions/annotation.ts";
import { errorMessage } from "#core/lib/errors.ts";
import { buildTrafficRecords, writeTrafficFile } from "#core/lib/report/outcome/traffic-output.ts";
import type { Report } from "./report.ts";

export function wantsTrafficArtifact(): boolean {
  try {
    return core.getBooleanInput("upload_traffic_artifact");
  } catch {
    // Unset, as in the integration/unit invocations that run this from
    // source rather than through action.yml's own defaults.
    return false;
  }
}

/** Guaranteed collision-free across concurrent invocations of this action in
 *  the same job, since containerName's own random suffix already is (see
 *  generateContainerName). Unlike buildcage/docker, there is no stable
 *  builder_name-equivalent identity to name it from instead. */
export function trafficArtifactName(containerName: string): string {
  return `buildcage-traffic-${containerName.split("-").at(-1)}`;
}

export type UploadArtifact = (
  name: string,
  files: string[],
  rootDirectory: string,
  options: { retentionDays?: number },
) => Promise<unknown>;

/**
 * Imported lazily so a run that asks for no artifact does not load it.
 *
 * Untested by design: the default behind `upload`'s seam below, which only
 * hands @actions/artifact what the tested caller decided.
 */
/* v8 ignore start */
const uploadViaActionsArtifact: UploadArtifact = async (name, files, rootDirectory, options) => {
  const { DefaultArtifactClient } = await import("@actions/artifact");
  return new DefaultArtifactClient().uploadArtifact(name, files, rootDirectory, options);
};
/* v8 ignore stop */

/** `upload` is injectable so tests can assert on the arguments instead of
 *  mocking @actions/artifact directly. */
export interface UploadTrafficArtifactDeps {
  upload?: UploadArtifact;
}

/**
 * Upload the traffic JSON and return the artifact's name, or undefined if the
 * upload failed. Best-effort: the step's own outcome is already decided by
 * this point, so a failed upload only warns.
 */
export async function uploadTrafficArtifact(
  report: Report,
  containerName: string,
  annotation: Annotation,
  { upload = uploadViaActionsArtifact }: UploadTrafficArtifactDeps = {},
): Promise<string | undefined> {
  const scratchDir = mkdtempSync(join(tmpdir(), "buildcage-traffic-"));
  try {
    const file = join(scratchDir, "traffic.json");
    writeTrafficFile(file, buildTrafficRecords(report.timeline, report.startedAt));
    const days = Number(core.getInput("traffic_artifact_retention_days") || "");
    const name = trafficArtifactName(containerName);
    await upload(name, [file], scratchDir, {
      retentionDays: Number.isFinite(days) && days > 0 ? days : undefined,
    });
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
 * Set the traffic_artifact_name output, empty when no artifact was uploaded.
 * Written on every path, after the isolated command has exited:
 * GITHUB_OUTPUT is last-write-wins, so this is what overrides anything the
 * command itself wrote to the same key.
 */
export function setTrafficArtifactOutput(name: string): void {
  core.setOutput("traffic_artifact_name", name);
}

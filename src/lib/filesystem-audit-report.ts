import { appendFileSync, readFileSync, realpathSync, writeFileSync } from "node:fs";
import { dirname } from "node:path";

import type { Annotation } from "#core/lib/actions/annotation.ts";
import { writeStepSummary } from "#core/lib/actions/write-step-summary.ts";
import { errorMessage } from "#core/lib/errors.ts";

import {
  setFilesystemAuditOutput,
  uploadFilesystemAuditArtifact,
} from "./filesystem-audit-artifact.ts";
import { stripSandboxMachinery } from "./filesystem-audit-strip.ts";
import { renderFilesystemAuditSummary } from "./filesystem-audit-summary.ts";
import type { FilesystemAuditPaths } from "./sandbox/filesystem-audit.ts";

export interface FilesystemAuditReportOptions {
  /** Set only under filesystem_audit: record; undefined leaves no report. */
  audit: FilesystemAuditPaths | undefined;
  /** The proxy's start, in epoch seconds; undefined shows absolute times. */
  startedAt: number | undefined;
  retentionDays: number | undefined;
  containerName: string;
  annotation: Annotation;
  env: NodeJS.ProcessEnv;
}

export interface FilesystemAuditReportDeps {
  readFile: (path: string) => string;
  writeFile: (path: string, content: string) => void;
  realpath: (path: string) => string;
  writeStepSummary: typeof writeStepSummary;
  uploadArtifact: typeof uploadFilesystemAuditArtifact;
  setOutput: typeof setFilesystemAuditOutput;
  appendFile: (path: string, content: string) => void;
}

// Untested by design: the defaults behind the seams, which only hand node:fs
// and @actions what the tested caller decided.
/* v8 ignore start */
const realDeps: FilesystemAuditReportDeps = {
  readFile: (path) => readFileSync(path, "utf8"),
  writeFile: (path, content) => writeFileSync(path, content),
  realpath: (path) => realpathSync(path),
  writeStepSummary,
  uploadArtifact: uploadFilesystemAuditArtifact,
  setOutput: setFilesystemAuditOutput,
  appendFile: (path, content) => appendFileSync(path, content),
};
/* v8 ignore stop */

// The recorded paths are canonical (symlink-resolved); $GITHUB_WORKSPACE and
// $HOME may not be, so match against both forms.
function prefixes(value: string | undefined, realpath: (p: string) => string): string[] {
  if (!value) return [];
  const out = [value];
  try {
    const real = realpath(value);
    if (real !== value) out.push(real);
  } catch {
    // The path does not exist; the raw value is the only prefix to try.
  }
  return out;
}

/**
 * Render the recording into the Job Summary, upload it as an artifact, and set
 * the output. Runs after reportStepTraffic so its section follows the traffic
 * report. Never throws: a failure here only warns, and the output is still
 * set so a later step can read it. Does nothing when nothing was recorded.
 */
export async function reportStepFilesystemAudit(
  { audit, startedAt, retentionDays, containerName, annotation, env }: FilesystemAuditReportOptions,
  overrides: Partial<FilesystemAuditReportDeps> = {},
): Promise<void> {
  const deps = { ...realDeps, ...overrides };
  let artifactName = "";
  const raw = audit && readOptional(audit.outPath, deps.readFile);
  if (audit && raw) {
    // The recording sits under the scratch base (see sandbox/filesystem-audit.ts),
    // next to the exec wrapper's own files, so its directory is the one holding
    // buildcage's own machinery. Strip that out once and feed the result to both
    // the summary and the uploaded artifact.
    const clean = stripSandboxMachinery(raw, dirname(audit.outPath));
    // The summary and the upload are independent: a render failure (e.g. a
    // line the tracer left truncated) must not also drop the artifact, which is
    // most wanted when the recording is incomplete.
    try {
      const markdown = renderFilesystemAuditSummary(clean, {
        workspace: prefixes(env.GITHUB_WORKSPACE, deps.realpath),
        home: prefixes(env.HOME, deps.realpath),
        startedAt,
      });
      await deps.writeStepSummary(markdown, env.GITHUB_STEP_SUMMARY);
      mirrorForDebug(env, deps.appendFile, raw, markdown);
    } catch (e) {
      annotation.warning(`Failed to write the filesystem audit summary: ${errorMessage(e)}`);
    }
    // Upload the stripped copy, written beside the recording under the scratch
    // base. That directory is ours (not $RUNNER_TEMP or /tmp), so the sandbox
    // cannot reach the copy, and writing a new file leaves the root-owned
    // recording in place: a failed write loses nothing and never uploads the
    // raw. The suffix keeps it off the recording's own name.
    const cleanPath = audit.outPath.replace(/\.jsonl$/, ".step.jsonl");
    let wrote = false;
    try {
      deps.writeFile(cleanPath, clean);
      wrote = true;
    } catch (e) {
      annotation.warning(`Failed to prepare the filesystem audit artifact: ${errorMessage(e)}`);
    }
    if (wrote)
      artifactName =
        (await deps.uploadArtifact(cleanPath, containerName, retentionDays, annotation)) ?? "";
  }
  deps.setOutput(artifactName);
}

function readOptional(path: string, readFile: (p: string) => string): string | undefined {
  try {
    return readFile(path) || undefined;
  } catch {
    return undefined; // nothing was recorded, or the file is already gone
  }
}

// Debug-only mirror, matching writeReportSummary's: GITHUB_STEP_SUMMARY is
// per-step and cannot be read back, so this repo's own e2e reads a copy, and
// the raw recording (before stripping) feeds the test fixtures. The env reads
// stay inside the build-time test-hooks guard so a normal build tree-shakes
// the whole body out and dist carries neither variable (see rolldown.config.js).
function mirrorForDebug(
  env: NodeJS.ProcessEnv,
  appendFile: (path: string, content: string) => void,
  raw: string,
  summary: string,
): void {
  if (process.env.BUILDCAGE_BUILD_TEST_HOOKS !== "1") return;
  if (env.BUILDCAGE_RUN_DEBUG_RAW_FILE) appendFile(env.BUILDCAGE_RUN_DEBUG_RAW_FILE, raw);
  if (env.BUILDCAGE_RUN_DEBUG_SUMMARY_FILE)
    appendFile(env.BUILDCAGE_RUN_DEBUG_SUMMARY_FILE, summary);
}

import { appendFileSync, readFileSync, realpathSync, writeFileSync } from "node:fs";
import { dirname } from "node:path";

import type { Annotation } from "#core/lib/actions/annotation.ts";
import { errorMessage } from "#core/lib/errors.ts";
import {
  joinSummaryBlocks,
  withNotices,
  type SummaryBlock,
} from "#core/lib/report/render/fit-step-summary.ts";

import {
  filesystemAuditArtifactName,
  setFilesystemAuditOutput,
  uploadFilesystemAuditArtifact,
} from "./filesystem-audit-artifact.ts";
import { stripSandboxMachinery } from "./filesystem-audit-strip.ts";
import {
  filesystemTruncationNote,
  renderFilesystemAuditBlocks,
} from "./filesystem-audit-summary.ts";
import type { FilesystemAuditPaths } from "./sandbox/filesystem-audit.ts";
import { FILESYSTEM_PRIORITIES } from "./summary-priorities.ts";

export interface FilesystemAuditReportOptions {
  /** Set only under filesystem_audit: record; undefined leaves no report. */
  audit: FilesystemAuditPaths | undefined;
  retentionDays: number | undefined;
  containerName: string;
  annotation: Annotation;
  env: NodeJS.ProcessEnv;
}

export interface FilesystemAuditReportDeps {
  readFile: (path: string) => string;
  writeFile: (path: string, content: string) => void;
  realpath: (path: string) => string;
  renderBlocks: typeof renderFilesystemAuditBlocks;
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
  renderBlocks: renderFilesystemAuditBlocks,
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

export interface StepFilesystemAudit {
  /**
   * The audit's Job Summary blocks, timed from the proxy's start (undefined
   * counts from the first access shown), each with its notice, or none when
   * nothing was recorded or the recording could not be rendered.
   */
  blocks: (startedAt: number | undefined) => SummaryBlock[];
  /** Uploads the recording and sets the output. Never throws. */
  finish: () => Promise<void>;
}

/**
 * Read and strip the recording once, for the Job Summary blocks and the
 * artifact. Never throws: a failure here only warns, and finish still sets the
 * output so a later step can read it.
 */
export function prepareStepFilesystemAudit(
  { audit, retentionDays, containerName, annotation, env }: FilesystemAuditReportOptions,
  overrides: Partial<FilesystemAuditReportDeps> = {},
): StepFilesystemAudit {
  const deps = { ...realDeps, ...overrides };
  const raw = audit && readOptional(audit.outPath, deps.readFile);
  // An empty recording is still reported: a tracer that stops cleanly always
  // writes an end line, so an empty one was cut short and gets the warning.
  if (!audit || raw === undefined) {
    return { blocks: () => [], finish: async () => deps.setOutput("") };
  }
  // The recording sits under the scratch base (see sandbox/filesystem-audit.ts),
  // next to the exec wrapper's own files, so its directory is the one holding
  // buildcage's own machinery. Strip that out once and feed the result to both
  // the summary and the uploaded artifact.
  const clean = stripSandboxMachinery(raw, dirname(audit.outPath));
  const notice = filesystemTruncationNote(filesystemAuditArtifactName(containerName));

  // The summary and the upload are independent: a render failure (e.g. a
  // line the tracer left truncated) must not also drop the artifact, which is
  // most wanted when the recording is incomplete.
  const blocks = (startedAt: number | undefined): SummaryBlock[] => {
    try {
      const rendered = deps.renderBlocks(
        clean,
        {
          workspace: prefixes(env.GITHUB_WORKSPACE, deps.realpath),
          home: prefixes(env.HOME, deps.realpath),
          startedAt,
        },
        FILESYSTEM_PRIORITIES,
      );
      mirrorForDebug(env, deps.appendFile, raw, joinSummaryBlocks(rendered));
      return withNotices(rendered, () => notice);
    } catch (e) {
      annotation.warning(`Failed to render the filesystem audit summary: ${errorMessage(e)}`);
      return [];
    }
  };

  const finish = async (): Promise<void> => {
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
    let artifactName = "";
    if (wrote && clean)
      artifactName =
        (await deps.uploadArtifact(cleanPath, containerName, retentionDays, annotation)) ?? "";
    deps.setOutput(artifactName);
  };
  return { blocks, finish };
}

function readOptional(path: string, readFile: (p: string) => string): string | undefined {
  try {
    return readFile(path);
  } catch {
    return undefined; // the tracer never started, or the file is already gone
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

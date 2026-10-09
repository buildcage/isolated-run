import {
  appendFileSync,
  closeSync,
  openSync,
  readFileSync,
  readSync,
  realpathSync,
  writeSync,
} from "node:fs";
import { dirname } from "node:path";

import type { Annotation } from "#core/lib/actions/annotation.ts";
import { errorMessage } from "#core/lib/errors.ts";
import {
  joinSummaryBlocks,
  withNotices,
  type SummaryBlock,
} from "#core/lib/report/render/fit-step-summary.ts";

import {
  setFilesystemAuditOutput,
  uploadFilesystemAuditArtifact,
} from "./filesystem-audit-artifact.ts";
import { createStripper } from "./filesystem-audit-strip.ts";
import {
  createAuditSummary,
  filesystemTruncationNote,
  parseLine,
  renderAuditSummaryBlocks,
  unreadableSummaryBlocks,
  type AuditSummary,
  type SummaryOptions,
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
  readLines: typeof readLines;
  createSummary: typeof createAuditSummary;
  openWriter: typeof openWriter;
  readFile: (path: string) => string;
  realpath: (path: string) => string;
  renderBlocks: typeof renderAuditSummaryBlocks;
  uploadArtifact: typeof uploadFilesystemAuditArtifact;
  setOutput: typeof setFilesystemAuditOutput;
  appendFile: (path: string, content: string) => void;
}

const CHUNK_BYTES = 1 << 20;

/**
 * Calls onLine with each line of the file, as split("\n") would give them,
 * reading it a chunk at a time so no file is too large to read.
 */
export function readLines(
  path: string,
  onLine: (line: string) => void,
  chunkBytes = CHUNK_BYTES,
): void {
  const fd = openSync(path, "r");
  try {
    const buf = Buffer.alloc(chunkBytes);
    // The start of a line no chunk has ended yet, joined once it does.
    let carry: Buffer[] = [];
    for (let n; (n = readSync(fd, buf, 0, buf.length, null)) > 0;) {
      const chunk = buf.subarray(0, n);
      let start = 0;
      for (let nl; (nl = chunk.indexOf(10, start)) !== -1; start = nl + 1) {
        onLine(Buffer.concat([...carry, chunk.subarray(start, nl)]).toString("utf8"));
        carry = [];
      }
      if (start < n) carry.push(Buffer.from(chunk.subarray(start)));
    }
    onLine(Buffer.concat(carry).toString("utf8"));
  } finally {
    closeSync(fd);
  }
}

/** Writes lines to a new file, joined by newlines, a chunk at a time. */
export function openWriter(
  path: string,
  chunkBytes = CHUNK_BYTES,
): { write: (line: string) => void; close: () => void } {
  const fd = openSync(path, "w");
  let pending: string[] = [];
  let size = 0;
  let first = true;
  const flush = (): void => {
    // writeSync may write less than it is given.
    const data = Buffer.from(pending.join(""));
    for (let off = 0; off < data.length;) off += writeSync(fd, data, off);
    pending = [];
    size = 0;
  };
  return {
    write: (line) => {
      pending.push(first ? line : `\n${line}`);
      first = false;
      size += line.length;
      if (size >= chunkBytes) flush();
    },
    close: () => {
      try {
        flush();
      } finally {
        closeSync(fd);
      }
    },
  };
}

// Untested by design: the defaults behind the seams, which only hand node:fs
// and @actions what the tested caller decided.
/* v8 ignore start */
const realDeps: FilesystemAuditReportDeps = {
  readLines,
  createSummary: createAuditSummary,
  openWriter,
  readFile: (path) => readFileSync(path, "utf8"),
  realpath: (path) => realpathSync(path),
  renderBlocks: renderAuditSummaryBlocks,
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
}

const NONE: StepFilesystemAudit = { blocks: () => [] };

/**
 * Uploads the recording before the Job Summary is written, so a cut section's
 * notice can say whether the artifact holds the rest. Never throws, so the
 * report and the proxy's teardown that follow are always reached.
 */
export async function prepareStepFilesystemAudit(
  { audit, retentionDays, containerName, annotation, env }: FilesystemAuditReportOptions,
  overrides: Partial<FilesystemAuditReportDeps> = {},
): Promise<StepFilesystemAudit> {
  const deps = { ...realDeps, ...overrides };
  let artifactName = "";
  try {
    if (!audit) return NONE;
    const options: SummaryOptions = {
      workspace: prefixes(env.GITHUB_WORKSPACE, deps.realpath),
      home: prefixes(env.HOME, deps.realpath),
    };
    // The stripped copy goes beside the recording under the scratch base,
    // which the sandbox cannot reach (unlike $RUNNER_TEMP or /tmp). Writing a
    // new file leaves the root-owned recording in place, so a failed write
    // never uploads the raw.
    const cleanPath = audit.outPath.replace(/\.jsonl$/, ".step.jsonl");
    let reduced: Reduced | undefined;
    try {
      reduced = reduce(audit.outPath, cleanPath, options, annotation, deps);
    } catch (e) {
      annotation.warning(`Failed to read the filesystem audit recording: ${errorMessage(e)}`);
      return { blocks: () => unreadableSummaryBlocks() };
    }
    if (!reduced) return NONE;
    const { summary, summaryError } = reduced;
    if (reduced.written)
      artifactName =
        (await deps.uploadArtifact(cleanPath, containerName, retentionDays, annotation)) ?? "";
    const notice = filesystemTruncationNote(artifactName || undefined);

    // The summary and the upload are independent: a render failure must not
    // also drop the artifact, which is most wanted when the recording is
    // incomplete.
    const blocks = (startedAt: number | undefined): SummaryBlock[] => {
      let rendered: SummaryBlock[];
      try {
        if (!summary) throw summaryError;
        rendered = deps.renderBlocks(summary, startedAt, FILESYSTEM_PRIORITIES, notice);
      } catch (e) {
        annotation.warning(`Failed to render the filesystem audit summary: ${errorMessage(e)}`);
        return [];
      }
      mirrorForDebug(env, deps, audit.outPath, joinSummaryBlocks(rendered));
      return withNotices(rendered, () => notice);
    };
    return { blocks };
  } catch (e) {
    annotation.warning(`Failed to report the filesystem audit: ${errorMessage(e)}`);
    return NONE;
  } finally {
    try {
      deps.setOutput(artifactName);
    } catch (e) {
      annotation.warning(
        `Failed to set the filesystem_audit_artifact_name output: ${errorMessage(e)}`,
      );
    }
  }
}

interface Reduced {
  /** Undefined when reducing failed, for summaryError. */
  summary: AuditSummary | undefined;
  summaryError?: unknown;
  /** False when the copy holds nothing or could not be written. */
  written: boolean;
}

// Reads the recording twice, a line at a time: first to find buildcage's own
// machinery and what each process loaded, then to write the step's lines to
// the stripped copy and reduce them to the summary. Undefined when there is no
// recording; throws when it cannot be read. A summary that fails is reported
// on its own, so it never costs the artifact.
function reduce(
  outPath: string,
  cleanPath: string,
  options: SummaryOptions,
  annotation: Annotation,
  deps: FilesystemAuditReportDeps,
): Reduced | undefined {
  // The recording sits under the scratch base (see sandbox/filesystem-audit.ts),
  // next to the exec wrapper's own files, so its directory is the one holding
  // buildcage's own machinery.
  const stripper = createStripper(dirname(outPath));
  const summary = deps.createSummary(options);
  let summaryError: unknown;
  let failedSummary = false;
  const summarize = (step: () => void): void => {
    if (failedSummary) return;
    try {
      step();
    } catch (e) {
      [failedSummary, summaryError] = [true, e];
    }
  };

  let lines = 0;
  try {
    deps.readLines(outPath, (line) => {
      lines++;
      const r = parseLine(line);
      stripper.observe(r);
      summarize(() => summary.observe(r));
    });
  } catch (e) {
    // The tracer never started, or the file is already gone.
    if ((e as NodeJS.ErrnoException).code === "ENOENT") return undefined;
    throw e;
  }

  let writer: ReturnType<typeof openWriter> | undefined;
  let written = false;
  const dropCopy = (e: unknown): void => {
    annotation.warning(`Failed to prepare the filesystem audit artifact: ${errorMessage(e)}`);
    const open = writer;
    writer = undefined;
    written = false;
    try {
      open?.close();
    } catch {
      // already reported
    }
  };
  try {
    writer = deps.openWriter(cleanPath);
  } catch (e) {
    dropCopy(e);
  }
  let again = 0;
  try {
    deps.readLines(outPath, (line) => {
      again++;
      const r = parseLine(line);
      const kept = stripper.filter(line, r);
      summarize(() => summary.add(kept ? kept.record : r, kept !== undefined));
      if (!kept || !writer) return;
      try {
        writer.write(kept.line);
        written = true;
      } catch (e) {
        dropCopy(e);
      }
    });
  } finally {
    const open = writer;
    writer = undefined;
    try {
      open?.close();
    } catch (e) {
      dropCopy(e);
    }
  }
  // The tracer has stopped, so the two reads see the same lines, which the
  // line positions the first pass found depend on.
  if (again !== lines) throw new Error("the recording changed while it was being read");

  let result: AuditSummary | undefined;
  summarize(() => (result = summary.finish()));
  return { summary: result, summaryError, written };
}

// Debug-only mirror, matching writeReportSummary's: GITHUB_STEP_SUMMARY is
// per-step and cannot be read back, so this repo's own e2e reads a copy, and
// the raw recording (before stripping) feeds the test fixtures. The env reads
// stay inside the build-time test-hooks guard so a normal build tree-shakes
// the whole body out and dist carries neither variable (see rolldown.config.js).
function mirrorForDebug(
  env: NodeJS.ProcessEnv,
  deps: FilesystemAuditReportDeps,
  outPath: string,
  summary: string,
): void {
  if (process.env.BUILDCAGE_BUILD_TEST_HOOKS !== "1") return;
  // A debug copy that cannot be written must not cost the real summary.
  try {
    if (env.BUILDCAGE_RUN_DEBUG_RAW_FILE)
      deps.appendFile(env.BUILDCAGE_RUN_DEBUG_RAW_FILE, deps.readFile(outPath));
    if (env.BUILDCAGE_RUN_DEBUG_SUMMARY_FILE)
      deps.appendFile(env.BUILDCAGE_RUN_DEBUG_SUMMARY_FILE, summary);
  } catch {
    // ignored: test hooks only
  }
}

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

import { failOrWarn } from "../fail-or-warn.ts";
import type { FilesystemAuditPaths } from "../sandbox/filesystem-audit-paths.ts";
import { FILESYSTEM_PRIORITIES } from "../summary-priorities.ts";
import {
  filesystemAuditArtifactName,
  setFilesystemAuditOutput,
  uploadFilesystemAuditArtifact,
} from "./artifact.ts";
import type { CutCause } from "./fold-tree.ts";
import {
  createAuditSummary,
  reduceRecording,
  type ReducedRecording,
  type SummaryOptions,
} from "./reduce.ts";
import {
  filesystemLegendNote,
  filesystemTruncationNote,
  renderAuditSummaryBlocks,
  unreadableSummaryBlocks,
  type RecordArtifact,
} from "./render.ts";

export interface FilesystemAuditReportOptions {
  /** Set only under filesystem_audit: record; undefined leaves no report. */
  audit: FilesystemAuditPaths | undefined;
  /** Whether the tracer attached. Once it has, its recording is there until
   *  the post step, so one that is gone was removed by something else. */
  attached: boolean;
  /** upload_filesystem_audit_artifact: whether to upload the record at all. */
  upload: boolean;
  retentionDays: number | undefined;
  containerName: string;
  annotation: Annotation;
  env: NodeJS.ProcessEnv;
  /** Where the guide the summary links to is read from. */
  actionRepo: string;
  actionRef: string;
  /** Under restrict with fail_on_blocked: an output that cannot be set fails the step. */
  failClosed: boolean;
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
        if (carry.length === 0) onLine(chunk.toString("utf8", start, nl));
        else onLine(Buffer.concat([...carry, chunk.subarray(start, nl)]).toString("utf8"));
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
      size += line.length + 1; // UTF-16 units, close enough to bytes to pace the flushes
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

export interface ReadStepFilesystemAudit {
  /** What the notes are to say of the artifact when the summary is written
   *  before upload has run: the name it is to be uploaded under. */
  expected: RecordArtifact;
  /** Uploads the stripped copy and sets the output; what came of it is what
   *  the notes say when the summary is written after. Never throws. */
  upload: () => Promise<RecordArtifact>;
  /** The audit's Job Summary blocks (see StepFilesystemAudit), their notes
   *  saying `artifact` of the record. */
  blocks: (startedAt: number | undefined, artifact: RecordArtifact) => SummaryBlock[];
}

/**
 * Reads the recording. Never throws, so the traffic report that follows is
 * always reached.
 */
export function readStepFilesystemAudit(
  {
    audit,
    attached,
    upload,
    retentionDays,
    containerName,
    annotation,
    env,
    actionRepo,
    actionRef,
    failClosed,
  }: FilesystemAuditReportOptions,
  overrides: Partial<FilesystemAuditReportDeps> = {},
): ReadStepFilesystemAudit {
  const deps = { ...realDeps, ...overrides };
  const setOutput = (artifactName: string) => {
    try {
      deps.setOutput(artifactName);
    } catch (e) {
      failOrWarn(
        annotation,
        failClosed,
      )(`Failed to set the filesystem_audit_artifact_name output: ${errorMessage(e)}`);
    }
  };
  // Nothing to upload, and blocks that say nothing of an artifact.
  const settled = (result: StepFilesystemAudit): ReadStepFilesystemAudit => ({
    expected: "not-requested",
    upload: async () => {
      setOutput("");
      return "not-requested";
    },
    blocks: (startedAt) => result.blocks(startedAt),
  });
  if (!audit) return settled(NONE);
  const options: SummaryOptions = {
    workspace: prefixes(env.GITHUB_WORKSPACE, deps.realpath),
    home: prefixes(env.HOME, deps.realpath),
  };
  // The stripped copy goes beside the recording under the scratch base,
  // which the sandbox cannot reach (unlike $RUNNER_TEMP or /tmp). Writing a
  // new file leaves the root-owned recording in place, so a failed write
  // never uploads the raw. The post step removes both.
  const cleanPath = audit.stepPath;
  let reduced: Reduced | undefined;
  try {
    reduced = reduce(audit.outPath, upload ? cleanPath : undefined, options, annotation, deps);
  } catch (e) {
    annotation.warning(`Failed to read the filesystem audit recording: ${errorMessage(e)}`);
    return settled({ blocks: () => unreadableSummaryBlocks() });
  }
  if (!reduced) {
    if (!attached) return settled(NONE);
    annotation.error(
      "The filesystem audit recording is gone: something removed it after the tracer started; failing the step",
    );
    process.exitCode = 1;
    return settled({ blocks: () => unreadableSummaryBlocks() });
  }
  const { summary, summaryError, written } = reduced;
  const guide = `https://github.com/${actionRepo}/blob/${actionRef}/docs/filesystem-audit.md`;
  return {
    expected: !upload
      ? "not-requested"
      : written
        ? { name: filesystemAuditArtifactName(containerName) }
        : "upload-failed",
    upload: async () => {
      let artifactName = "";
      try {
        if (written)
          artifactName =
            (await deps.uploadArtifact(cleanPath, containerName, retentionDays, annotation)) ?? "";
      } catch (e) {
        annotation.warning(`Failed to report the filesystem audit: ${errorMessage(e)}`);
      }
      setOutput(artifactName);
      return !upload ? "not-requested" : artifactName ? { name: artifactName } : "upload-failed";
    },
    // The summary and the upload are independent: a render failure must not
    // also drop the artifact, which is most wanted when the recording is
    // incomplete.
    blocks: (startedAt, artifact) => {
      const cutNote = (cause?: CutCause): string => filesystemTruncationNote(artifact, cause);
      let rendered: SummaryBlock[];
      try {
        if (!summary) throw summaryError;
        rendered = deps.renderBlocks(summary, {
          startedAt,
          priorities: FILESYSTEM_PRIORITIES,
          cutNote,
          legendNote: filesystemLegendNote(artifact, `${guide}#reading-the-summary`),
          skippedHooksUrl: `${guide}#skipped-hooks`,
        });
      } catch (e) {
        annotation.warning(`Failed to render the filesystem audit summary: ${errorMessage(e)}`);
        return [];
      }
      mirrorForDebug(env, deps, audit.outPath, rendered);
      const notice = cutNote();
      return withNotices(rendered, () => notice);
    },
  };
}

/**
 * Uploads the recording before the Job Summary is written, so a cut section's
 * notice can say whether the artifact holds the rest. Never throws.
 */
export async function prepareStepFilesystemAudit(
  options: FilesystemAuditReportOptions,
  overrides: Partial<FilesystemAuditReportDeps> = {},
): Promise<StepFilesystemAudit> {
  const read = readStepFilesystemAudit(options, overrides);
  const artifact = await read.upload();
  return { blocks: (startedAt) => read.blocks(startedAt, artifact) };
}

interface Reduced extends ReducedRecording {
  /** False when the copy holds nothing or could not be written. */
  written: boolean;
}

// Undefined when there is no recording; throws when it cannot be read.
function reduce(
  outPath: string,
  /** Where to write the stripped copy to upload; undefined writes none. */
  cleanPath: string | undefined,
  options: SummaryOptions,
  annotation: Annotation,
  deps: FilesystemAuditReportDeps,
): Reduced | undefined {
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
  const openSink = (): ((line: string) => void) => {
    try {
      if (cleanPath !== undefined) writer = deps.openWriter(cleanPath);
    } catch (e) {
      dropCopy(e);
    }
    return (line) => {
      if (!writer) return;
      try {
        writer.write(line);
        written = true;
      } catch (e) {
        dropCopy(e);
      }
    };
  };

  let readOnce = false;
  let reduced: ReducedRecording;
  try {
    // The recording sits under the scratch base (see sandbox/filesystem-audit-paths.ts),
    // next to the exec wrapper's own files, so its directory is the one holding
    // buildcage's own machinery.
    reduced = reduceRecording(
      (onLine) => {
        deps.readLines(outPath, onLine);
        readOnce = true;
      },
      dirname(outPath),
      options,
      openSink,
      deps.createSummary,
    );
  } catch (e) {
    // The tracer never started, or something removed the file.
    if (!readOnce && (e as NodeJS.ErrnoException).code === "ENOENT") return undefined;
    throw e;
  } finally {
    const open = writer;
    writer = undefined;
    try {
      open?.close();
    } catch (e) {
      dropCopy(e);
    }
  }
  // After the close, which can still drop the copy.
  return { ...reduced, written };
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
  blocks: SummaryBlock[],
): void {
  if (process.env.BUILDCAGE_BUILD_TEST_HOOKS !== "1") return;
  // A debug copy that cannot be written must not cost the real summary.
  try {
    if (env.BUILDCAGE_RUN_DEBUG_RAW_FILE)
      deps.appendFile(env.BUILDCAGE_RUN_DEBUG_RAW_FILE, deps.readFile(outPath));
    if (env.BUILDCAGE_RUN_DEBUG_SUMMARY_FILE)
      deps.appendFile(env.BUILDCAGE_RUN_DEBUG_SUMMARY_FILE, joinSummaryBlocks(blocks));
  } catch {
    // ignored: test hooks only
  }
}

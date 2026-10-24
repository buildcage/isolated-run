import {
  appendFileSync,
  closeSync,
  openSync,
  readFileSync,
  readSync,
  realpathSync,
  writeFileSync,
  writeSync,
} from "node:fs";
import { basename, dirname } from "node:path";

import type { Annotation } from "#core/lib/actions/annotation.ts";
import { errorMessage } from "#core/lib/errors.ts";
import {
  joinSummaryBlocks,
  withNotices,
  type SummaryBlock,
} from "#core/lib/report/render/fit-step-summary.ts";
import type { VerdictItems } from "#core/lib/report/render/verdict.ts";

import { failOrWarn } from "../fail-or-warn.ts";
import { reportTitle } from "../report.ts";
import type { FilesystemAuditPaths } from "../sandbox/filesystem-audit-paths.ts";
import {
  MEDIATED_VARIABLES,
  mediatedPathOf,
  type MediatedVariable,
} from "../sandbox/runner-output-files.ts";
import { FILESYSTEM_PRIORITIES } from "../summary-priorities.ts";
import {
  filesystemAuditArtifactName,
  setFilesystemAuditOutput,
  uploadFilesystemAuditArtifact,
  type UploadedArtifact,
} from "./artifact.ts";
import type { CutCause } from "./fold-tree.ts";
import { writeProposedRules } from "./proposed-rules.ts";
import {
  createAuditSummary,
  reduceRecording,
  type AuditSummary,
  type ReducedRecording,
  type SummaryOptions,
} from "./reduce.ts";
import {
  filesystemLegendNote,
  filesystemTruncationNote,
  renderAuditSummaryBlocks,
  rulesNote,
  unreadableSummaryBlocks,
  type RecordArtifact,
} from "./render.ts";
import { EXPECTED_RULES_INPUT, RuleMatcher, type ExpectedRules } from "./rules.ts";

export const FILESYSTEM_ACTIVITY_TITLE = "Filesystem Activity Report";

export interface FilesystemAuditReportOptions {
  /** Set only under filesystem_audit: record; undefined leaves no report. */
  audit: FilesystemAuditPaths | undefined;
  /** Whether the tracer attached. Once it has, its recording is there until
   *  the post step, so one that is gone was removed by something else. */
  attached: boolean;
  /** A cancelled step cuts the tracer's stop short, so its record may lack the
   *  end line, and the step fails anyway. */
  cancelled: boolean;
  /** upload_filesystem_audit_artifact: whether to upload the record at all. */
  upload: boolean;
  retentionDays: number | undefined;
  containerName: string;
  annotation: Annotation;
  env: NodeJS.ProcessEnv;
  /** The runner files the command wrote through backing copies. */
  mediated: readonly MediatedVariable[];
  /** Where the guide the summary links to is read from. */
  actionRepo: string;
  actionRef: string;
  /** Under restrict with fail_on_blocked: an output that cannot be set fails the step. */
  failClosed: boolean;
  /** expected_filesystem_rules, undefined when none were given. */
  rules?: ExpectedRules;
  /** fail_on_unexpected_file_access: an access no rule takes fails the step. */
  failOnUnexpected?: boolean;
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
  writeFile: (path: string, content: string) => void;
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
  writeFile: (path, content) => writeFileSync(path, content, { flag: "wx" }),
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

// A mediated runner file is written at its backing copy, its real path masked
// from the command, so an access there keeps that path. One ephemeral leaves
// unmediated is written at its real path under the overlay.
function runnerFiles(
  env: NodeJS.ProcessEnv,
  mediated: readonly MediatedVariable[],
  realpath: (p: string) => string,
): Map<string, string> {
  const out = new Map<string, string>();
  for (const variable of MEDIATED_VARIABLES) {
    const paths = mediated.includes(variable)
      ? [mediatedPathOf(variable)]
      : prefixes(env[variable], realpath);
    for (const path of paths) out.set(path, variable);
  }
  return out;
}

export interface StepFilesystemAudit {
  /**
   * The audit's Job Summary blocks under `title`, timed from the proxy's start
   * (undefined counts from the first access shown), each with its notice, or
   * none when nothing was recorded or the recording could not be rendered.
   */
  blocks: (startedAt: number | undefined, title: string) => SummaryBlock[];
}

const NONE: StepFilesystemAudit = { blocks: () => [] };

export interface ReadStepFilesystemAudit {
  /** The artifact as it will be once uploaded, for a summary written before
   *  the upload. */
  expected: RecordArtifact;
  /** The traffic report's verdict items: the accesses no rule took, if any,
   *  as a caution when they fail the step. */
  verdictItems: VerdictItems;
  /** The proposed rules file's name, when the artifact is to hold it. */
  rulesFile?: string;
  /** Uploads the stripped copy, sets the output and returns the artifact as
   *  it is. Never throws. */
  upload: () => Promise<RecordArtifact>;
  /** The audit's Job Summary blocks (see StepFilesystemAudit), their notes
   *  saying `artifact` of the record, titled with the step's label. */
  blocks: (
    startedAt: number | undefined,
    artifact: RecordArtifact,
    stepLabel: string | undefined,
  ) => SummaryBlock[];
}

/**
 * Reads the recording. Never throws, so the traffic report that follows is
 * always reached.
 */
export function readStepFilesystemAudit(
  {
    audit,
    attached,
    cancelled,
    upload,
    retentionDays,
    containerName,
    annotation,
    env,
    mediated,
    actionRepo,
    actionRef,
    failClosed,
    rules,
    failOnUnexpected = false,
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
  const settled = (
    result: StepFilesystemAudit,
    verdictItems: VerdictItems = {},
  ): ReadStepFilesystemAudit => ({
    expected: "not-requested",
    verdictItems,
    upload: async () => {
      setOutput("");
      return "not-requested";
    },
    blocks: (startedAt, _artifact, stepLabel) =>
      result.blocks(startedAt, reportTitle(stepLabel, FILESYSTEM_ACTIVITY_TITLE)),
  });
  if (!audit) return settled(NONE);
  const options: SummaryOptions = {
    workspace: prefixes(env.GITHUB_WORKSPACE, deps.realpath),
    home: prefixes(env.HOME, deps.realpath),
    runnerFiles: runnerFiles(env, mediated, deps.realpath),
    ...(rules && { rules: new RuleMatcher(rules.rules) }),
    propose: upload,
  };
  // The stripped copy goes beside the recording under the scratch base,
  // which the sandbox cannot reach (unlike $RUNNER_TEMP or /tmp). Writing a
  // new file leaves the root-owned recording in place, so a failed write
  // never uploads the raw. The post step removes both.
  const cleanPath = audit.stepPath;
  // What the verdict says of accesses that could not all be checked, which
  // fail the step as unexpected ones would.
  const checkIncomplete: VerdictItems =
    rules && failOnUnexpected ? { caution: ["file access check incomplete"] } : {};
  const unchecked = (what: string): VerdictItems => {
    if (!checkIncomplete.caution) return {};
    annotation.error(`${what}; failing the step, as fail_on_unexpected_file_access is true.`);
    process.exitCode = 1;
    return checkIncomplete;
  };
  let reduced: Reduced | undefined;
  try {
    reduced = reduce(audit.outPath, upload ? cleanPath : undefined, options, annotation, deps);
  } catch (e) {
    annotation.warning(`Failed to read the filesystem audit recording: ${errorMessage(e)}`);
    const incomplete = unchecked(
      `The file accesses could not be checked against ${EXPECTED_RULES_INPUT}, as the recording could not be read`,
    );
    return settled({ blocks: (_startedAt, title) => unreadableSummaryBlocks(title) }, incomplete);
  }
  if (!reduced) {
    if (!attached) return settled(NONE);
    annotation.error(
      "The filesystem audit recording is gone: something removed it after the tracer started; failing the step",
    );
    process.exitCode = 1;
    return settled(
      { blocks: (_startedAt, title) => unreadableSummaryBlocks(title) },
      checkIncomplete,
    );
  }
  const { summary, summaryError, ended, written } = reduced;
  let incomplete: VerdictItems = {};
  if (!summary)
    incomplete = unchecked(
      `The file accesses could not be checked against ${EXPECTED_RULES_INPUT}, as summarizing the recording failed`,
    );
  else if (summary.lost)
    incomplete = unchecked(
      `Not every file access was checked against ${EXPECTED_RULES_INPUT}, as the recording misses some`,
    );
  else if (summary.hostMissed)
    incomplete = unchecked(
      `Not every file access may have been checked against ${EXPECTED_RULES_INPUT}, as the kernel skipped the tracer's hooks`,
    );
  // The tracer exited during the step, as a full disk makes it, or did not
  // finish its record when stopped. Only the banner would say so otherwise.
  if (attached && !ended && !cancelled) {
    annotation.error(
      "The filesystem audit tracer stopped before it finished its record, so the record misses part of the step; failing the step. Any reason it gave is in the step log, on a line starting with filesystem-audit: fatal:",
    );
    process.exitCode = 1;
    incomplete = checkIncomplete;
  }
  const proposed = upload
    ? writeProposedRules(summary, rules, audit.rulesPath, annotation, deps.writeFile)
    : "none";
  const given = rules !== undefined;
  const unexpected = given ? reportUnexpected(summary, failOnUnexpected, annotation) : {};
  // Both are cautions, as only fail_on_unexpected_file_access makes the check's.
  const verdictItems = incomplete.caution
    ? { caution: [...(unexpected.caution ?? []), ...incomplete.caution] }
    : unexpected;
  const artifactOf = (uploaded: UploadedArtifact | undefined): RecordArtifact =>
    !upload ? "not-requested" : uploaded ? uploaded : "upload-failed";
  const guide = `https://github.com/${actionRepo}/blob/${actionRef}/docs/filesystem-audit.md`;
  return {
    expected: artifactOf(
      written ? { name: filesystemAuditArtifactName(containerName) } : undefined,
    ),
    verdictItems,
    ...(proposed === "written" && { rulesFile: basename(audit.rulesPath) }),
    upload: async () => {
      let uploaded: UploadedArtifact | undefined;
      try {
        if (written)
          uploaded = await deps.uploadArtifact(
            proposed === "written" ? [cleanPath, audit.rulesPath] : [cleanPath],
            containerName,
            retentionDays,
            annotation,
          );
      } catch (e) {
        annotation.warning(`Could not upload the filesystem audit artifact: ${errorMessage(e)}`);
      }
      setOutput(uploaded?.name ?? "");
      return artifactOf(uploaded);
    },
    // The summary and the upload are independent: a render failure must not
    // also drop the artifact, which is most wanted when the recording is
    // incomplete.
    blocks: (startedAt, artifact, stepLabel) => {
      const cutNote = (cause?: CutCause): string => filesystemTruncationNote(artifact, cause);
      let rendered: SummaryBlock[];
      try {
        if (!summary) throw summaryError;
        rendered = deps.renderBlocks(summary, {
          title: reportTitle(stepLabel, FILESYSTEM_ACTIVITY_TITLE),
          startedAt,
          priorities: FILESYSTEM_PRIORITIES,
          cutNote,
          legendNote: filesystemLegendNote(artifact, `${guide}#reading-the-summary`),
          skippedHooksUrl: `${guide}#skipped-hooks`,
          expected: given,
          rulesNote: rulesNote(artifact, proposed, {
            fileName: basename(audit.rulesPath),
            guideUrl: `${guide}#expected-accesses`,
            given,
          }),
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
 * Annotates the accesses no rule took and returns the verdict's item for
 * them, a caution when they fail the step, counted as the Unexpected Accesses table lists them, which a table
 * given up does not.
 */
function reportUnexpected(
  summary: AuditSummary | undefined,
  failOnUnexpected: boolean,
  annotation: Annotation,
): VerdictItems {
  if (!summary?.unexpected) return {};
  const n = summary.proposed?.length;
  const es = n === 1 ? "" : "es";
  const what =
    n === undefined
      ? "unexpected file accesses (too many to list)"
      : `${n} unexpected file access${es}`;
  const message =
    n === undefined
      ? `File accesses fell outside ${EXPECTED_RULES_INPUT} on too many distinct paths to list.`
      : `${n} file access${es} fell outside ${EXPECTED_RULES_INPUT}; the Unexpected Accesses table lists ${n === 1 ? "it" : "them"}.`;
  if (failOnUnexpected) {
    annotation.error(`${message} Failing the step, as fail_on_unexpected_file_access is true.`);
    process.exitCode = 1;
    return { caution: [what] };
  }
  annotation.warning(message);
  return { warning: [what] };
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

// Debug-only mirror, as in writeReportSummary; the raw recording (before
// stripping) also feeds the test fixtures. The env reads stay inside the
// test-hooks guard so dist carries neither variable (see rolldown.config.js).
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

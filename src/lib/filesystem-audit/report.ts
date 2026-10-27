import { appendFileSync, mkdirSync, readFileSync, realpathSync, writeFileSync } from "node:fs";
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
import { openWriter, readLines } from "./line-file.ts";
import { writeProposedRules, type ProposedState } from "./proposed-rules.ts";
import {
  createAuditSummary,
  recordedNoFileAccess,
  reduceRecording,
  type AuditSummary,
  type ReducedRecording,
  type SummaryOptions,
} from "./reduce.ts";
import {
  filesystemLegendNote,
  filesystemTruncationNote,
  renderAuditSummaryBlocks,
  proposalOf,
  rulesNote,
  unreadableSummaryBlocks,
  type RecordArtifact,
} from "./render.ts";
import { EXPECTED_RULES_INPUT, RuleMatcher, type ExpectedRules } from "./rules.ts";

export const FILESYSTEM_ACTIVITY_TITLE = "Filesystem Activity Report";

export interface FilesystemAuditReportOptions {
  /** Set only under filesystem_audit: record; undefined leaves no report. */
  audit: FilesystemAuditPaths | undefined;
  /** Whether the tracer attached. Without it nothing is reported, as a
   *  recording found then is not trusted. Once it has, its recording is there
   *  until the post step, so one that is gone was removed by something else. */
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
  makeDir: (path: string) => void;
  readFile: (path: string) => string;
  realpath: (path: string) => string;
  renderBlocks: typeof renderAuditSummaryBlocks;
  uploadArtifact: typeof uploadFilesystemAuditArtifact;
  setOutput: typeof setFilesystemAuditOutput;
  appendFile: (path: string, content: string) => void;
  writeFile: (path: string, content: string) => void;
}

// Untested by design: the defaults behind the seams, which only hand node:fs
// and @actions what the tested caller decided.
/* v8 ignore start */
const realDeps: FilesystemAuditReportDeps = {
  readLines,
  createSummary: createAuditSummary,
  openWriter,
  // Never recursive: anything already at the path, a symlink included, fails it.
  makeDir: (path) => mkdirSync(path, { mode: 0o700 }),
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

const NO_RULES: ExpectedRules = { rules: [] };

/** The filesystem audit guide at the ref the step runs. */
export const filesystemAuditGuide = (actionRepo: string, actionRef: string): string =>
  `https://github.com/${actionRepo}/blob/${actionRef}/docs/filesystem-audit.md`;

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
    rules: givenRules,
    failOnUnexpected = false,
  }: FilesystemAuditReportOptions,
  overrides: Partial<FilesystemAuditReportDeps> = {},
): ReadStepFilesystemAudit {
  const deps = { ...realDeps, ...overrides };
  // Under fail_on_unexpected_file_access, a step without rules has every
  // access unexpected.
  const rules = givenRules ?? (failOnUnexpected ? NO_RULES : undefined);
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
  if (!audit || !attached) return settled(NONE);
  // The stripped copy and the proposed rules go in the step's own directory
  // under the scratch base, which the sandbox cannot reach (unlike
  // $RUNNER_TEMP or /tmp). Writing a new file leaves the root-owned recording
  // in place, so a failed write never uploads the raw. The post step removes
  // both.
  const cleanPath = audit.stepPath;
  let prepared = upload;
  if (upload)
    try {
      deps.makeDir(audit.uploadDir);
    } catch (e) {
      annotation.warning(`Failed to prepare the filesystem audit artifact: ${errorMessage(e)}`);
      prepared = false;
    }
  const options: SummaryOptions = {
    workspace: prefixes(env.GITHUB_WORKSPACE, deps.realpath),
    home: prefixes(env.HOME, deps.realpath),
    toolCache: prefixes(env.RUNNER_TOOL_CACHE, deps.realpath),
    runnerFiles: runnerFiles(env, mediated, deps.realpath),
    ...(rules && { rules: new RuleMatcher(rules.rules) }),
    // Only a prepared directory takes the proposed rules.
    propose: prepared,
  };
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
    reduced = reduce(audit.outPath, prepared ? cleanPath : undefined, options, annotation, deps);
  } catch (e) {
    annotation.warning(`Failed to read the filesystem audit recording: ${errorMessage(e)}`);
    const incomplete = unchecked(
      `The file accesses could not be checked against ${EXPECTED_RULES_INPUT}, as the recording could not be read`,
    );
    return settled({ blocks: (_startedAt, title) => unreadableSummaryBlocks(title) }, incomplete);
  }
  if (!reduced) {
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
  // The tracer exited during the step, as a full disk makes it, or did not
  // finish its record when stopped. Only the banner would say so otherwise.
  if (!ended && !cancelled) {
    annotation.error(
      "The filesystem audit tracer did not finish its record, so the record may miss part of the step; failing the step. Any reason it gave is in the step log, on a line starting with filesystem-audit: fatal:, or in the buildcage: filesystem audit totals group, on a line starting with filesystem-audit: read loss counters:",
    );
    process.exitCode = 1;
    incomplete = checkIncomplete;
  }
  const given = rules !== undefined;
  // Nothing to add where no file access was recorded, or none fell outside
  // the rules, even where the recording misses some: what it lacks cannot be
  // proposed.
  const nothingToAdd =
    summary !== undefined && (recordedNoFileAccess(summary) || (given && summary.unexpected === 0));
  const proposed: ProposedState = nothingToAdd
    ? "nothing-to-add"
    : !upload
      ? "not-requested"
      : !prepared
        ? "not-prepared"
        : writeProposedRules(summary, audit.rulesPath, annotation, deps.writeFile);
  const unexpected = given
    ? reportUnexpected(summary, failOnUnexpected, annotation, givenRules === undefined)
    : {};
  // An incomplete check exists only under fail_on_unexpected_file_access, so
  // the unexpected accesses are a caution then too.
  const verdictItems = incomplete.caution
    ? { caution: [...(unexpected.caution ?? []), ...incomplete.caution] }
    : unexpected;
  const artifactOf = (uploaded: UploadedArtifact | undefined): RecordArtifact =>
    !upload ? "not-requested" : uploaded ? uploaded : "upload-failed";
  const guide = filesystemAuditGuide(actionRepo, actionRef);
  return {
    expected: artifactOf(
      written ? { name: filesystemAuditArtifactName(containerName) } : undefined,
    ),
    verdictItems,
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
          ...(given && { expected: givenRules ? "given" : "empty" }),
          rulesNote: rulesNote(proposalOf(proposed, artifact), {
            fileName: basename(audit.rulesPath),
            guideUrl: `${guide}#expected-accesses`,
            given: givenRules !== undefined,
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
 * them, a caution when they fail the step. The count is the Unexpected
 * Accesses table's rows, and absent when the table was given up.
 */
function reportUnexpected(
  summary: AuditSummary | undefined,
  failOnUnexpected: boolean,
  annotation: Annotation,
  empty: boolean,
): VerdictItems {
  if (!summary?.unexpected) return {};
  const n = summary.proposed?.length;
  const es = n === 1 ? "" : "es";
  const what =
    n === undefined
      ? "unexpected file accesses (too many to list)"
      : `${n} unexpected file access${es}`;
  const outside = empty ? `${EXPECTED_RULES_INPUT}, which is empty` : EXPECTED_RULES_INPUT;
  const message =
    n === undefined
      ? `File accesses fell outside ${outside}${empty ? "," : ""} on too many distinct paths to list.`
      : `${n} file access${es} fell outside ${outside}; the Unexpected Accesses table lists ${n === 1 ? "it" : "them"}.`;
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

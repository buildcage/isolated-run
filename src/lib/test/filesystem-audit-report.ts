import { vi, type Mock } from "vitest";

import type { Annotation } from "#core/lib/actions/annotation.ts";
import { joinSummaryBlocks, type SummaryBlock } from "#core/lib/report/render/fit-step-summary.ts";

import {
  readStepFilesystemAudit,
  resolveAuditPrefixes,
  type FilesystemAuditReportDeps,
  type FilesystemAuditReportOptions,
  type ReadStepFilesystemAudit,
} from "../filesystem-audit/report.ts";
import { isWorkspace } from "../sandbox/working-directory.ts";

// The step's own directory, uploaded as is.
export const UPLOAD_DIR = "/var/tmp/buildcage-0/filesystem-audit-deadbeef";

// The stripped copy, uploaded in place of the recording.
export const CLEAN = `${UPLOAD_DIR}/filesystem-audit.jsonl`;

// The proposed rules, uploaded beside it.
export const RULES = `${UPLOAD_DIR}/expected-filesystem-rules-to-add.txt`;

export const AUDIT = {
  outPath: "/var/tmp/buildcage-0/filesystem-audit-deadbeef.jsonl",
  pidFilePath: "/var/tmp/buildcage-0/filesystem-audit-deadbeef.pid",
  uploadDir: UPLOAD_DIR,
  stepPath: CLEAN,
  rulesPath: RULES,
};

export function annotation(): Annotation & { warning: Mock; error: Mock } {
  return { notice: vi.fn(), warning: vi.fn(), error: vi.fn() };
}

// A recording held as a string, read a line at a time as readLines would.
const recording =
  (text: string): FilesystemAuditReportDeps["readLines"] =>
  (_path, onLine) => {
    for (const line of text.split("\n")) onLine(line);
  };

export function deps(overrides: Partial<FilesystemAuditReportDeps> & { raw?: string } = {}): {
  deps: Partial<FilesystemAuditReportDeps>;
  summaries: string[];
  uploads: string[][];
  outputs: string[];
  appended: string[];
  writes: { path: string; content: string }[];
  ruleFiles: { path: string; content: string }[];
} {
  const summaries: string[] = [];
  const uploads: string[][] = [];
  const ruleFiles: { path: string; content: string }[] = [];
  const outputs: string[] = [];
  const appended: string[] = [];
  const writes: { path: string; content: string }[] = [];
  const { raw = JSON.stringify({ kind: "write", comm: "node", path: "/work/a.txt" }), ...rest } =
    overrides;
  return {
    summaries,
    uploads,
    outputs,
    appended,
    writes,
    ruleFiles,
    deps: {
      readLines: recording(raw),
      readFile: () => raw,
      makeDir: () => {},
      openWriter: (path) => {
        const lines: string[] = [];
        return {
          write: (line) => void lines.push(line),
          close: () => void writes.push({ path, content: lines.join("\n") }),
        };
      },
      uploadArtifact: async (files) => {
        uploads.push(files);
        return { name: "buildcage-filesystem-audit-deadbeef" };
      },
      writeFile: (path, content) => void ruleFiles.push({ path, content }),
      setOutput: (name) => void outputs.push(name),
      appendFile: (_path, content) => void appended.push(content),
      ...rest,
    },
  };
}

export type TestReportOptions = Omit<FilesystemAuditReportOptions, "prefixes"> & {
  /** The working-directory input's real path; the workspace when unset. */
  workingDirectory?: string;
  /** How the step resolved symlinks before the command ran. */
  realpath?: (path: string) => string;
};

/** The options with the prefixes the step would have resolved from them. */
export function withPrefixes({
  workingDirectory,
  realpath = (p) => p,
  ...options
}: TestReportOptions): FilesystemAuditReportOptions {
  const { env } = options;
  const baseDir =
    workingDirectory ?? (env.GITHUB_WORKSPACE ? realpath(env.GITHUB_WORKSPACE) : undefined);
  const given = workingDirectory !== undefined && {
    input: workingDirectory,
    path: workingDirectory,
    isWorkspace: isWorkspace(workingDirectory, env, realpath),
  };
  return {
    ...options,
    prefixes: resolveAuditPrefixes(env, baseDir, given || undefined, realpath),
  };
}

export const readAudit = (
  options: TestReportOptions,
  overrides: Partial<FilesystemAuditReportDeps>,
): ReadStepFilesystemAudit => readStepFilesystemAudit(withPrefixes(options), overrides);

// Prepares the audit and renders its blocks as the report step would,
// collecting their text.
export async function reportStepFilesystemAudit(
  options: TestReportOptions & { startedAt?: number },
  d: Partial<FilesystemAuditReportDeps> & { summaries?: string[] },
): Promise<void> {
  const { summaries = [], ...overrides } = d;
  const blocks = await uploadedBlocks(options, overrides);
  if (blocks.length > 0) summaries.push(joinSummaryBlocks(blocks));
}

// Uploads first, as a step that ran to the end does, then renders.
export async function uploadedBlocks(
  options: TestReportOptions & { startedAt?: number },
  overrides: Partial<FilesystemAuditReportDeps>,
): Promise<SummaryBlock[]> {
  const read = readAudit(options, overrides);
  return read.blocks(options.startedAt, await read.upload(), undefined);
}

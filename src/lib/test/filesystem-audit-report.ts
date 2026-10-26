import { vi, type Mock } from "vitest";

import type { Annotation } from "#core/lib/actions/annotation.ts";
import { joinSummaryBlocks, type SummaryBlock } from "#core/lib/report/render/fit-step-summary.ts";

import {
  readStepFilesystemAudit,
  type FilesystemAuditReportDeps,
  type FilesystemAuditReportOptions,
} from "../filesystem-audit/report.ts";

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
      realpath: (p) => p,
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

// Prepares the audit and renders its blocks as the report step would,
// collecting their text.
export async function reportStepFilesystemAudit(
  options: FilesystemAuditReportOptions & { startedAt?: number },
  d: Partial<FilesystemAuditReportDeps> & { summaries?: string[] },
): Promise<void> {
  const { summaries = [], ...overrides } = d;
  const blocks = await uploadedBlocks(options, overrides);
  if (blocks.length > 0) summaries.push(joinSummaryBlocks(blocks));
}

// Uploads first, as a step that ran to the end does, then renders.
export async function uploadedBlocks(
  options: FilesystemAuditReportOptions & { startedAt?: number },
  overrides: Partial<FilesystemAuditReportDeps>,
): Promise<SummaryBlock[]> {
  const read = readStepFilesystemAudit(options, overrides);
  return read.blocks(options.startedAt, await read.upload(), undefined);
}

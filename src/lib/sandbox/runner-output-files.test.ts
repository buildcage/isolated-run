import { execFileSync } from "node:child_process";
import { mkdirSync, mkdtempSync, readFileSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { afterEach, describe, expect, it } from "vitest";

import {
  mediateRunnerOutputFiles,
  readBackingFile,
  RUNNER_FILES_DIR,
} from "./runner-output-files.ts";

const ENV = {
  GITHUB_OUTPUT: "/home/runner/work/_temp/_runner_file_commands/set_output_abc",
  GITHUB_STEP_SUMMARY: "/home/runner/work/_temp/_runner_file_commands/step_summary_abc",
};

describe("mediateRunnerOutputFiles", () => {
  const captured = () => {
    const made: string[] = [];
    const wrote: string[] = [];
    const deps = {
      mkdir: (path: string) => made.push(path),
      writeFile: (path: string) => wrote.push(path),
    };
    return { made, wrote, deps };
  };

  it("mediates both variables: a directory bind, the real paths masked, the env repointed", () => {
    const { made, wrote, deps } = captured();
    const result = mediateRunnerOutputFiles(ENV, "/scratch/backing", deps);

    expect(made).toStrictEqual(["/scratch/backing"]);
    expect(wrote).toStrictEqual(["/scratch/backing/output", "/scratch/backing/step-summary"]);
    expect(result).toStrictEqual({
      envOverrides: {
        GITHUB_OUTPUT: `${RUNNER_FILES_DIR}/output`,
        GITHUB_STEP_SUMMARY: `${RUNNER_FILES_DIR}/step-summary`,
      },
      mounts: [
        {
          destination: RUNNER_FILES_DIR,
          type: "none",
          source: "/scratch/backing",
          options: ["rbind", "rw"],
        },
      ],
      maskedPaths: [ENV.GITHUB_OUTPUT, ENV.GITHUB_STEP_SUMMARY],
      files: [
        {
          variable: "GITHUB_OUTPUT",
          realPath: ENV.GITHUB_OUTPUT,
          backingPath: "/scratch/backing/output",
        },
        {
          variable: "GITHUB_STEP_SUMMARY",
          realPath: ENV.GITHUB_STEP_SUMMARY,
          backingPath: "/scratch/backing/step-summary",
        },
      ],
    });
  });

  it("mediates only the variable the step has", () => {
    const { wrote, deps } = captured();
    const result = mediateRunnerOutputFiles({ GITHUB_OUTPUT: ENV.GITHUB_OUTPUT }, "/scratch", deps);

    expect(wrote).toStrictEqual(["/scratch/output"]);
    expect(result?.files.map((f) => f.variable)).toStrictEqual(["GITHUB_OUTPUT"]);
    expect(result?.maskedPaths).toStrictEqual([ENV.GITHUB_OUTPUT]);
  });

  it("does nothing, touching no directory, when neither variable is set", () => {
    const { made, deps } = captured();
    expect(mediateRunnerOutputFiles({}, "/scratch", deps)).toBeUndefined();
    expect(made).toStrictEqual([]);
  });

  it("creates the backing directory and empty files on disk by default", () => {
    const base = mkdtempSync(join(tmpdir(), "mediate-"));
    const backingDir = join(base, "backing");
    try {
      mediateRunnerOutputFiles(ENV, backingDir);
      expect(readFileSync(join(backingDir, "output"), "utf8")).toBe("");
      expect(readFileSync(join(backingDir, "step-summary"), "utf8")).toBe("");
    } finally {
      rmSync(base, { recursive: true, force: true });
    }
  });
});

describe("readBackingFile", () => {
  let dir: string;
  afterEach(() => rmSync(dir, { recursive: true, force: true }));

  it("reads a regular file the command wrote", () => {
    dir = mkdtempSync(join(tmpdir(), "backing-"));
    const path = join(dir, "output");
    writeFileSync(path, "a=1\n");
    expect(readBackingFile(path)).toStrictEqual({ bytes: Buffer.from("a=1\n") });
  });

  it("takes a removed backing file as empty", () => {
    dir = mkdtempSync(join(tmpdir(), "backing-"));
    expect(readBackingFile(join(dir, "gone"))).toStrictEqual({ empty: true });
  });

  it("refuses a symlink without following it", () => {
    dir = mkdtempSync(join(tmpdir(), "backing-"));
    const secret = join(dir, "secret");
    const path = join(dir, "output");
    writeFileSync(secret, "secret=1\n");
    symlinkSync(secret, path);
    expect(readBackingFile(path)).toStrictEqual({ reason: "it was not a regular file" });
  });

  // lstat, not open: opening a FIFO would block.
  it("refuses a FIFO without opening it", () => {
    dir = mkdtempSync(join(tmpdir(), "backing-"));
    const path = join(dir, "output");
    execFileSync("mkfifo", [path]);
    expect(readBackingFile(path)).toStrictEqual({ reason: "it was not a regular file" });
  });

  it("refuses a directory", () => {
    dir = mkdtempSync(join(tmpdir(), "backing-"));
    const path = join(dir, "output");
    mkdirSync(path);
    expect(readBackingFile(path)).toStrictEqual({ reason: "it was not a regular file" });
  });

  it("refuses a file over 64 MiB without reading it", () => {
    const read = readBackingFile("/backing/output", {
      lstat: () => ({ isFile: () => true, size: 64 * 1024 * 1024 + 1 }),
      readFile: () => {
        throw new Error("should not read");
      },
    });
    expect(read).toStrictEqual({ reason: "it was over 64 MiB" });
  });

  it("rethrows a read error that is not a missing file", () => {
    expect(() =>
      readBackingFile("/backing/output", {
        lstat: () => {
          throw Object.assign(new Error("EACCES"), { code: "EACCES" });
        },
        readFile: () => Buffer.alloc(0),
      }),
    ).toThrow("EACCES");
  });
});

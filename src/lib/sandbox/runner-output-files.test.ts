import { execFileSync } from "node:child_process";
import {
  chmodSync,
  existsSync,
  linkSync,
  lstatSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  symlinkSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { afterEach, beforeEach, describe, expect, it } from "vitest";

import {
  mediateRunnerOutputFiles,
  readBackingFile,
  removeBackingDir,
  rewriteRunnerFile,
  RUNNER_FILES_DIR,
  runnerFilesDirFor,
  writeRunnerFile,
} from "./runner-output-files.ts";
import { SANDBOX_SCRATCH_BASE } from "./scratch-dir.ts";

const ENV = {
  GITHUB_OUTPUT: "/home/runner/work/_temp/_runner_file_commands/set_output_abc",
  GITHUB_STEP_SUMMARY: "/home/runner/work/_temp/_runner_file_commands/step_summary_abc",
};
const BOTH = ["GITHUB_OUTPUT", "GITHUB_STEP_SUMMARY"] as const;

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
    const result = mediateRunnerOutputFiles(ENV, BOTH, "/scratch/backing", deps);

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

  it("mediates only the variables it is given", () => {
    const { wrote, deps } = captured();
    const result = mediateRunnerOutputFiles(ENV, ["GITHUB_OUTPUT"], "/scratch", deps);

    expect(wrote).toStrictEqual(["/scratch/output"]);
    expect(result?.files.map((f) => f.variable)).toStrictEqual(["GITHUB_OUTPUT"]);
    expect(result?.maskedPaths).toStrictEqual([ENV.GITHUB_OUTPUT]);
  });

  it("does nothing, touching no directory, when given no variable", () => {
    const { made, deps } = captured();
    expect(mediateRunnerOutputFiles(ENV, [], "/scratch", deps)).toBeUndefined();
    expect(made).toStrictEqual([]);
  });

  it("creates the backing directory and empty files on disk by default", () => {
    const base = mkdtempSync(join(tmpdir(), "mediate-"));
    const backingDir = join(base, "backing");
    try {
      mediateRunnerOutputFiles(ENV, BOTH, backingDir);
      expect(readFileSync(join(backingDir, "output"), "utf8")).toBe("");
      expect(readFileSync(join(backingDir, "step-summary"), "utf8")).toBe("");
    } finally {
      rmSync(base, { recursive: true, force: true });
    }
  });

  it("refuses a backing directory already there", () => {
    const base = mkdtempSync(join(tmpdir(), "mediate-"));
    const backingDir = join(base, "backing");
    mkdirSync(backingDir);
    try {
      expect(() => mediateRunnerOutputFiles(ENV, BOTH, backingDir)).toThrow(/EEXIST/);
    } finally {
      rmSync(base, { recursive: true, force: true });
    }
  });

  it("refuses a parent others can write to", () => {
    const base = mkdtempSync(join(tmpdir(), "mediate-"));
    chmodSync(base, 0o777);
    try {
      expect(() => mediateRunnerOutputFiles(ENV, BOTH, join(base, "backing"))).toThrow(
        /not a private directory/,
      );
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
    expect(readBackingFile(path, 1024)).toStrictEqual({ bytes: Buffer.from("a=1\n") });
  });

  it("takes a removed backing file as empty", () => {
    dir = mkdtempSync(join(tmpdir(), "backing-"));
    expect(readBackingFile(join(dir, "gone"), 1024)).toStrictEqual({ empty: true });
  });

  it("refuses a symlink without following it", () => {
    dir = mkdtempSync(join(tmpdir(), "backing-"));
    const secret = join(dir, "secret");
    const path = join(dir, "output");
    writeFileSync(secret, "secret=1\n");
    symlinkSync(secret, path);
    expect(readBackingFile(path, 1024)).toStrictEqual({ reason: "it was not a regular file" });
  });

  // lstat, not open: opening a FIFO would block.
  it("refuses a FIFO without opening it", () => {
    dir = mkdtempSync(join(tmpdir(), "backing-"));
    const path = join(dir, "output");
    execFileSync("mkfifo", [path]);
    expect(readBackingFile(path, 1024)).toStrictEqual({ reason: "it was not a regular file" });
  });

  it("refuses a directory", () => {
    dir = mkdtempSync(join(tmpdir(), "backing-"));
    const path = join(dir, "output");
    mkdirSync(path);
    expect(readBackingFile(path, 1024)).toStrictEqual({ reason: "it was not a regular file" });
  });

  it("measures a file over the limit without reading it", () => {
    const read = readBackingFile("/backing/output", 1024, {
      lstat: () => ({ isFile: () => true, size: 1025 }),
      readFile: () => {
        throw new Error("should not read");
      },
    });
    expect(read).toStrictEqual({ oversize: 1025 });
  });

  it("reads a file exactly at the limit", () => {
    const read = readBackingFile("/backing/output", 1024, {
      lstat: () => ({ isFile: () => true, size: 1024 }),
      readFile: () => Buffer.from("x"),
    });
    expect(read).toStrictEqual({ bytes: Buffer.from("x") });
  });

  // The command can take the directory's permissions away. Only the code goes
  // into the annotation: the message names the host-side path.
  it("refuses a file it cannot lstat, without throwing or naming the path", () => {
    const read = readBackingFile("/backing/output", 1024, {
      lstat: () => {
        throw Object.assign(new Error("EACCES: permission denied, lstat '/backing/output'"), {
          code: "EACCES",
        });
      },
      readFile: () => Buffer.alloc(0),
    });
    expect(read).toStrictEqual({ reason: "it could not be read (EACCES)" });
  });

  // Or the file's own.
  it("refuses a regular file it cannot read, without throwing", () => {
    const read = readBackingFile("/backing/output", 1024, {
      lstat: () => ({ isFile: () => true, size: 1 }),
      readFile: () => {
        throw Object.assign(new Error("EACCES: permission denied"), { code: "EACCES" });
      },
    });
    expect(read).toStrictEqual({ reason: "it could not be read (EACCES)" });
  });

  // Only lstat's ENOENT means the command removed the file.
  it("refuses a regular file that is gone by the read", () => {
    const read = readBackingFile("/backing/output", 1024, {
      lstat: () => ({ isFile: () => true, size: 1 }),
      readFile: () => {
        throw Object.assign(new Error("ENOENT: no such file"), { code: "ENOENT" });
      },
    });
    expect(read).toStrictEqual({ reason: "it could not be read (ENOENT)" });
  });

  it("falls back to the message for an error with no code", () => {
    const read = readBackingFile("/backing/output", 1024, {
      lstat: () => {
        throw new Error("odd");
      },
      readFile: () => Buffer.alloc(0),
    });
    expect(read).toStrictEqual({ reason: "it could not be read (odd)" });
  });
});

describe("writeRunnerFile", () => {
  let dir: string;
  afterEach(() => rmSync(dir, { recursive: true, force: true }));

  it("replaces a regular file's content", () => {
    dir = mkdtempSync(join(tmpdir(), "runner-"));
    const path = join(dir, "set_output_abc");
    writeFileSync(path, "old=longer value\n");
    writeRunnerFile(path, Buffer.from("a=1\n"));
    expect(readFileSync(path, "utf8")).toBe("a=1\n");
  });

  it("does not create a missing file", () => {
    dir = mkdtempSync(join(tmpdir(), "runner-"));
    const path = join(dir, "set_output_abc");
    expect(() => writeRunnerFile(path, Buffer.from("a=1\n"))).toThrow(/ENOENT/);
    expect(existsSync(path)).toBe(false);
  });

  it("does not follow a symlink", () => {
    dir = mkdtempSync(join(tmpdir(), "runner-"));
    const target = join(dir, "bashrc");
    const path = join(dir, "set_output_abc");
    writeFileSync(target, "kept\n");
    symlinkSync(target, path);
    expect(() => writeRunnerFile(path, Buffer.from("a=1\n"))).toThrow(/ELOOP|EMLINK/);
    expect(readFileSync(target, "utf8")).toBe("kept\n");
  });

  it("does not block on a FIFO", () => {
    dir = mkdtempSync(join(tmpdir(), "runner-"));
    const path = join(dir, "set_output_abc");
    execFileSync("mkfifo", [path]);
    expect(() => writeRunnerFile(path, Buffer.from("a=1\n"))).toThrow("not a regular file");
  });

  it("refuses a directory", () => {
    dir = mkdtempSync(join(tmpdir(), "runner-"));
    const path = join(dir, "set_output_abc");
    mkdirSync(path);
    expect(() => writeRunnerFile(path, Buffer.from("a=1\n"))).toThrow(/EISDIR/);
  });

  it("refuses a device it can open", () => {
    expect(() => writeRunnerFile("/dev/null", Buffer.from("a=1\n"))).toThrow("not a regular file");
  });

  it("does not write through a hard link", () => {
    dir = mkdtempSync(join(tmpdir(), "runner-"));
    const target = join(dir, "bashrc");
    const path = join(dir, "set_output_abc");
    writeFileSync(target, "kept\n");
    linkSync(target, path);
    expect(() => writeRunnerFile(path, Buffer.from("a=1\n"))).toThrow(
      "a hard link to another file",
    );
    expect(readFileSync(target, "utf8")).toBe("kept\n");
  });
});

describe("rewriteRunnerFile", () => {
  let dir: string;
  let path: string;
  beforeEach(() => {
    dir = mkdtempSync(join(tmpdir(), "runner-"));
    path = join(dir, "step_summary_abc");
  });
  afterEach(() => rmSync(dir, { recursive: true, force: true }));

  it("rewrites the file from its start with what it is given of the content", () => {
    writeFileSync(path, "command\nreport\n");
    rewriteRunnerFile(path, (content) => Buffer.from(content.toString("utf8").slice(8)));
    expect(readFileSync(path, "utf8")).toBe("report\n");
  });

  it("leaves the file alone when given nothing", () => {
    writeFileSync(path, "kept\n");
    rewriteRunnerFile(path, () => undefined);
    expect(readFileSync(path, "utf8")).toBe("kept\n");
  });

  it("does not follow a symlink", () => {
    const target = join(dir, "add_path_abc");
    writeFileSync(target, "kept\n");
    symlinkSync(target, path);
    expect(() => rewriteRunnerFile(path, () => Buffer.from("x\n"))).toThrow(/ELOOP|EMLINK/);
    expect(readFileSync(target, "utf8")).toBe("kept\n");
  });

  it("does not write through a hard link", () => {
    const target = join(dir, "add_path_abc");
    writeFileSync(target, "kept\n");
    linkSync(target, path);
    expect(() => rewriteRunnerFile(path, () => Buffer.from("x\n"))).toThrow(
      "a hard link to another file",
    );
    expect(readFileSync(target, "utf8")).toBe("kept\n");
  });
});

describe("removeBackingDir", () => {
  let base: string;
  afterEach(() => {
    chmodSync(base, 0o700);
    rmSync(base, { recursive: true, force: true });
  });

  it("removes the directory and what the command left in it", () => {
    base = mkdtempSync(join(tmpdir(), "backing-"));
    const dir = join(base, "runner-files");
    mkdirSync(join(dir, "nested"), { recursive: true });
    writeFileSync(join(dir, "nested", "file"), "");
    removeBackingDir(dir);
    expect(existsSync(dir)).toBe(false);
  });

  it("gives back the permissions the command took away, down the tree", () => {
    base = mkdtempSync(join(tmpdir(), "backing-"));
    const dir = join(base, "runner-files");
    mkdirSync(join(dir, "a", "b"), { recursive: true });
    writeFileSync(join(dir, "a", "b", "file"), "");
    chmodSync(join(dir, "a", "b"), 0);
    chmodSync(join(dir, "a"), 0);
    chmodSync(dir, 0);
    removeBackingDir(dir);
    expect(existsSync(dir)).toBe(false);
  });

  it("does not follow a symlink to a directory elsewhere", () => {
    base = mkdtempSync(join(tmpdir(), "backing-"));
    const dir = join(base, "runner-files");
    const outside = join(base, "outside");
    mkdirSync(dir);
    mkdirSync(outside);
    chmodSync(outside, 0o500);
    symlinkSync(outside, join(dir, "link"));
    removeBackingDir(dir);
    expect(existsSync(dir)).toBe(false);
    expect(lstatSync(outside).mode & 0o777).toBe(0o500);
  });

  it("does nothing when the directory is already gone", () => {
    base = mkdtempSync(join(tmpdir(), "backing-"));
    expect(() => removeBackingDir(join(base, "runner-files"))).not.toThrow();
  });

  it("throws on a path it cannot look at", () => {
    base = mkdtempSync(join(tmpdir(), "backing-"));
    writeFileSync(join(base, "file"), "");
    expect(() => removeBackingDir(join(base, "file", "runner-files"))).toThrow(/ENOTDIR/);
  });
});

describe("runnerFilesDirFor", () => {
  it("names the directory beside the container's scratch dir", () => {
    expect(runnerFilesDirFor("buildcage-proxy-deadbeef")).toBe(
      `${SANDBOX_SCRATCH_BASE}/runner-files-deadbeef`,
    );
  });

  it("refuses a container name that is not one of this action's", () => {
    expect(() => runnerFilesDirFor("../etc")).toThrow(/Refusing to derive/);
  });
});

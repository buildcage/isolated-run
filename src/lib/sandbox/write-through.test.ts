import { describe, it, expect, vi } from "vitest";

import {
  resolveWriteThroughEntry,
  resolveWriteThroughPaths,
  ensureWriteThroughTargetsExist,
  removeCreatedDirsIfEmpty,
  WriteThroughTargetMissingError,
  WriteThroughTargetUncreatableError,
} from "./write-through.ts";

const ENV = {
  HOME: "/home/runner",
  GITHUB_WORKSPACE: "/home/runner/work/repo/repo",
  RUNNER_TEMP: "/home/runner/work/_temp",
  GITHUB_OUTPUT: "/home/runner/work/_temp/_runner_file_commands/set_output_abc",
  GITHUB_ENV: "/home/runner/work/_temp/_runner_file_commands/set_env_abc",
  GITHUB_PATH: "/home/runner/work/_temp/_runner_file_commands/add_path_abc",
  GITHUB_STEP_SUMMARY: "/home/runner/work/_temp/_runner_file_commands/step_summary_abc",
};

describe("resolveWriteThroughEntry", () => {
  it("expands $NAME and ${NAME} forms for allowed variables", () => {
    expect(resolveWriteThroughEntry("$GITHUB_OUTPUT", ENV)).toBe(ENV.GITHUB_OUTPUT);
    expect(resolveWriteThroughEntry("${GITHUB_OUTPUT}", ENV)).toBe(ENV.GITHUB_OUTPUT);
  });

  it("expands a leading ~/ to $HOME", () => {
    expect(resolveWriteThroughEntry("~/.local/bin", ENV)).toBe("/home/runner/.local/bin");
  });

  it("does not expand a bare ~ or ~user/ -- treated as an ordinary relative path instead", () => {
    expect(resolveWriteThroughEntry("~", ENV)).toBe(`${ENV.GITHUB_WORKSPACE}/~`);
    expect(resolveWriteThroughEntry("~other/x", ENV)).toBe(`${ENV.GITHUB_WORKSPACE}/~other/x`);
  });

  it("resolves a relative path against $GITHUB_WORKSPACE", () => {
    expect(resolveWriteThroughEntry("./dist", ENV)).toBe("/home/runner/work/repo/repo/dist");
    expect(resolveWriteThroughEntry("dist", ENV)).toBe("/home/runner/work/repo/repo/dist");
  });

  it("leaves an absolute path untouched (after normalization)", () => {
    expect(resolveWriteThroughEntry("/usr/local/bin", ENV)).toBe("/usr/local/bin");
  });

  it("normalizes .. segments", () => {
    expect(resolveWriteThroughEntry("/usr/local/bin/../lib", ENV)).toBe("/usr/local/lib");
  });

  it("rejects an unlisted variable name", () => {
    expect(() => resolveWriteThroughEntry("$SECRET_TOKEN/x", ENV)).toThrow(
      /unsupported variable \$SECRET_TOKEN/,
    );
  });

  it("rejects an allowed variable that isn't set, rather than resolving somewhere else", () => {
    // "" would leave "$RUNNER_TEMP/cache" resolving to "<workspace>/cache" --
    // a different path than the one named, made write-through silently.
    const { RUNNER_TEMP: _omitted, ...noRunnerTemp } = ENV;
    expect(() => resolveWriteThroughEntry("$RUNNER_TEMP/cache", noRunnerTemp)).toThrow(
      /\$RUNNER_TEMP, which is not set/,
    );
  });

  it("rejects a relative entry when $GITHUB_WORKSPACE is unset, rather than returning a relative path", () => {
    expect(() => resolveWriteThroughEntry("./dist", { HOME: ENV.HOME })).toThrow(/is relative/);
  });

  it("strips a trailing slash so the result string-equals the bare candidate path", () => {
    expect(resolveWriteThroughEntry("$HOME/", ENV)).toBe(ENV.HOME);
    expect(resolveWriteThroughEntry("/usr/local/bin/", ENV)).toBe("/usr/local/bin");
  });

  it("leaves a bare '/' alone rather than stripping it down to an empty string", () => {
    expect(resolveWriteThroughEntry("/", ENV)).toBe("/");
  });

  it("does not swallow a stray closing brace from a malformed reference", () => {
    // "$GITHUB_WORKSPACE}suffix" is missing its opening brace -- the "}"
    // must be treated as literal text, not consumed into the match.
    expect(resolveWriteThroughEntry("$GITHUB_WORKSPACE}suffix", ENV)).toBe(
      `${ENV.GITHUB_WORKSPACE}}suffix`,
    );
  });

  it("accepts every allowed variable name", () => {
    expect(resolveWriteThroughEntry("$HOME", ENV)).toBe(ENV.HOME);
    expect(resolveWriteThroughEntry("$GITHUB_WORKSPACE", ENV)).toBe(ENV.GITHUB_WORKSPACE);
    expect(resolveWriteThroughEntry("$RUNNER_TEMP", ENV)).toBe(ENV.RUNNER_TEMP);
    expect(resolveWriteThroughEntry("$GITHUB_ENV", ENV)).toBe(ENV.GITHUB_ENV);
    expect(resolveWriteThroughEntry("$GITHUB_PATH", ENV)).toBe(ENV.GITHUB_PATH);
    expect(resolveWriteThroughEntry("$GITHUB_STEP_SUMMARY", ENV)).toBe(ENV.GITHUB_STEP_SUMMARY);
  });
});

describe("resolveWriteThroughPaths", () => {
  it("splits on newlines, trims, and drops blank lines", () => {
    expect(resolveWriteThroughPaths("$GITHUB_WORKSPACE\n\n  ./dist  \n", ENV)).toStrictEqual([
      ENV.GITHUB_WORKSPACE,
      `${ENV.GITHUB_WORKSPACE}/dist`,
    ]);
  });

  it("returns [] for undefined/empty input", () => {
    expect(resolveWriteThroughPaths(undefined, ENV)).toStrictEqual([]);
    expect(resolveWriteThroughPaths("", ENV)).toStrictEqual([]);
    expect(resolveWriteThroughPaths("   \n  \n", ENV)).toStrictEqual([]);
  });

  it("does not split on internal spaces (paths may contain them)", () => {
    expect(resolveWriteThroughPaths("/path with spaces\n/other", ENV)).toStrictEqual([
      "/path with spaces",
      "/other",
    ]);
  });

  it("folds duplicates, including ones only different spellings made look distinct", () => {
    expect(resolveWriteThroughPaths("/opt/cache\n/opt/cache/\n/opt/./cache", ENV)).toStrictEqual([
      "/opt/cache",
    ]);
  });

  it("keeps the lone / sentinel intact", () => {
    expect(resolveWriteThroughPaths("/", ENV)).toStrictEqual(["/"]);
  });
});

describe("ensureWriteThroughTargetsExist", () => {
  it("does nothing for an already-existing path", () => {
    const execFile = vi.fn();
    ensureWriteThroughTargetsExist(["/usr/local/bin"], ENV, { exists: () => true, execFile });
    expect(execFile).not.toHaveBeenCalled();
  });

  it("throws WriteThroughTargetMissingError when a missing entry equals a KNOWN_FILE_VARS value", () => {
    const execFile = vi.fn();
    expect(() =>
      ensureWriteThroughTargetsExist([ENV.GITHUB_OUTPUT], ENV, { exists: () => false, execFile }),
    ).toThrow(WriteThroughTargetMissingError);
    expect(execFile).not.toHaveBeenCalled();
  });

  it("creates a missing directory via sudo mkdir -p and mirrors the nearest existing ancestor's owner/mode onto every new segment", () => {
    const calls: string[][] = [];
    const execFile = (cmd: string, args: string[]) => calls.push([cmd, ...args]);
    // /a exists; /a/b and /a/b/c do not.
    const exists = (p: string) => p === "/a";
    const stat = (p: string) => {
      expect(p).toBe("/a");
      return { uid: 1000, gid: 1000, mode: 0o40755 }; // dir bits + 0755
    };

    ensureWriteThroughTargetsExist(["/a/b/c"], ENV, { exists, stat, execFile });

    expect(calls[0]).toStrictEqual(["sudo", "mkdir", "-p", "/a/b/c"]);
    // Both newly-created segments (/a/b and /a/b/c), shallowest first, each chown+chmod'd.
    expect(calls.slice(1)).toStrictEqual([
      ["sudo", "chown", "1000:1000", "/a/b"],
      ["sudo", "chmod", "755", "/a/b"],
      ["sudo", "chown", "1000:1000", "/a/b/c"],
      ["sudo", "chmod", "755", "/a/b/c"],
    ]);
  });

  it("mirrors a restrictive ancestor's ownership too, ending up unwritable by a non-root uid (e.g. /etc/test)", () => {
    const calls: string[][] = [];
    const execFile = (cmd: string, args: string[]) => calls.push([cmd, ...args]);
    const exists = (p: string) => p === "/etc";
    const stat = () => ({ uid: 0, gid: 0, mode: 0o40755 }); // root:root 755

    ensureWriteThroughTargetsExist(["/etc/test"], ENV, { exists, stat, execFile });

    expect(calls).toStrictEqual([
      ["sudo", "mkdir", "-p", "/etc/test"],
      ["sudo", "chown", "0:0", "/etc/test"],
      ["sudo", "chmod", "755", "/etc/test"],
    ]);
  });

  it("throws WriteThroughTargetUncreatableError when the sudo sequence itself fails", () => {
    const execFile = vi.fn(() => {
      throw new Error("sudo: a password is required");
    });
    expect(() =>
      ensureWriteThroughTargetsExist(["/a/b"], ENV, {
        exists: (p) => p === "/a",
        stat: () => ({ uid: 1000, gid: 1000, mode: 0o40755 }),
        execFile,
      }),
    ).toThrow(WriteThroughTargetUncreatableError);
  });

  it("rolls back everything it created so far when a later entry fails", () => {
    const calls: string[][] = [];
    const created = new Set(["/a"]); // pre-existing ancestor only
    const exists = (p: string) => created.has(p);
    const stat = () => ({ uid: 1000, gid: 1000, mode: 0o40755 });
    const execFile = (cmd: string, args: string[]) => {
      calls.push([cmd, ...args]);
      if (cmd === "sudo" && args[0] === "mkdir") {
        if (args[2] === "/a/fail") throw new Error("sudo: permission denied");
        created.add(args[2]!);
      }
    };

    expect(() =>
      ensureWriteThroughTargetsExist(["/a/ok/x", "/a/fail"], ENV, { exists, stat, execFile }),
    ).toThrow(WriteThroughTargetUncreatableError);

    // The first entry succeeded (created /a/ok and /a/ok/x) before the
    // second entry failed -- both must be rolled back, deepest first.
    expect(calls).toStrictEqual([
      ["sudo", "mkdir", "-p", "/a/ok/x"],
      ["sudo", "chown", "1000:1000", "/a/ok"],
      ["sudo", "chmod", "755", "/a/ok"],
      ["sudo", "chown", "1000:1000", "/a/ok/x"],
      ["sudo", "chmod", "755", "/a/ok/x"],
      ["sudo", "mkdir", "-p", "/a/fail"],
      ["sudo", "rm", "-rf", "/a/ok/x"],
      ["sudo", "rm", "-rf", "/a/ok"],
    ]);
  });

  it("does not let a rollback failure mask the original error", () => {
    const execFile = (cmd: string, args: string[]) => {
      if (cmd === "sudo" && args[0] === "mkdir" && args[2] === "/a") return; // first entry succeeds
      if (cmd === "sudo" && args[0] === "rm") throw new Error("sudo: rm also failed"); // rollback itself fails
      if (cmd === "sudo" && args[0] === "mkdir" && args[2] === "/a/b/fail") {
        throw new Error("sudo: mkdir failed");
      }
    };
    expect(() =>
      ensureWriteThroughTargetsExist(["/a", "/a/b/fail"], ENV, {
        exists: (p) => p === "/",
        stat: () => ({ uid: 1000, gid: 1000, mode: 0o40755 }),
        execFile,
      }),
    ).toThrow(/mkdir failed/);
  });

  it("returns every segment it created, shallowest first, and nothing for pre-existing paths", () => {
    const created = ensureWriteThroughTargetsExist(["/a/b/c", "/usr/local/bin"], ENV, {
      exists: (p) => p === "/a" || p === "/usr/local/bin",
      stat: () => ({ uid: 1000, gid: 1000, mode: 0o40755 }),
      execFile: () => {},
    });
    expect(created).toStrictEqual(["/a/b", "/a/b/c"]);
  });
});

describe("removeCreatedDirsIfEmpty", () => {
  it("rmdirs deepest first, so a nested set unwinds in the order it was created", () => {
    const calls: string[][] = [];
    removeCreatedDirsIfEmpty(["/a/b", "/a/b/c"], {
      execFile: (cmd, args) => calls.push([cmd, ...args]),
    });
    expect(calls).toStrictEqual([
      ["sudo", "rmdir", "/a/b/c"],
      ["sudo", "rmdir", "/a/b"],
    ]);
  });

  it("keeps going when a directory isn't empty (the command wrote there, so it stays)", () => {
    const calls: string[][] = [];
    const execFile = (cmd: string, args: string[]) => {
      calls.push([cmd, ...args]);
      if (args[1] === "/a/b/c") throw new Error("rmdir: failed to remove: Directory not empty");
    };
    expect(() => removeCreatedDirsIfEmpty(["/a/b", "/a/b/c"], { execFile })).not.toThrow();
    expect(calls).toStrictEqual([
      ["sudo", "rmdir", "/a/b/c"],
      ["sudo", "rmdir", "/a/b"],
    ]);
  });

  it("does nothing when nothing was created", () => {
    const execFile = vi.fn();
    removeCreatedDirsIfEmpty([], { execFile });
    expect(execFile).not.toHaveBeenCalled();
  });
});

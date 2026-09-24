import { describe, it, expect, vi } from "vitest";

import {
  resolveWriteThroughEntry,
  resolveWriteThroughPaths,
  resolveWriteThroughOnHost,
  ensureWriteThroughTargetsExist,
  removeCreatedDirsIfEmpty,
  splitWriteThroughInput,
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

  it("rejects an entry that only resolves to '/', so the full opt-out has to be spelled out", () => {
    for (const spelling of [
      "/.",
      "//",
      "/opt/..",
      "../../../../..",
      "$GITHUB_WORKSPACE/../../../../..",
    ]) {
      expect(() => resolveWriteThroughEntry(spelling, ENV)).toThrow(/resolves to "\/"/);
    }
  });

  it("still allows '..' that lands anywhere other than '/'", () => {
    expect(resolveWriteThroughEntry("/opt/x/..", ENV)).toBe("/opt");
    expect(resolveWriteThroughEntry("$GITHUB_WORKSPACE/../..", ENV)).toBe("/home/runner/work");
  });

  it("does not swallow a stray closing brace from a malformed reference", () => {
    // "$GITHUB_WORKSPACE}suffix" is missing its opening brace: the "}"
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

  it("drops a whole-line comment, keeping the / sentinel on its own line", () => {
    expect(resolveWriteThroughPaths("# drop the restriction\n/", ENV)).toStrictEqual(["/"]);
  });
});

describe("ensureWriteThroughTargetsExist", () => {
  const DIR = { uid: 1000, gid: 1000, mode: 0o40755 };
  const asOwner = ["-u", "#1000", "-g", "#1000"];

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

  it("creates a missing directory with one mkdir -p, run as the nearest existing ancestor's owner", () => {
    const calls: string[][] = [];
    // /a exists; /a/b and /a/b/c do not.
    const statted: string[] = [];
    const stat = (p: string) => {
      statted.push(p);
      return DIR;
    };

    ensureWriteThroughTargetsExist(["/a/b/c"], ENV, {
      exists: (p) => p === "/a",
      stat,
      execFile: (cmd, args) => calls.push([cmd, ...args]),
    });

    expect(calls).toStrictEqual([["sudo", ...asOwner, "mkdir", "-p", "-m", "755", "--", "/a/b/c"]]);
    expect(statted).toStrictEqual(["/a", "/a/b", "/a/b/c"]);
  });

  it("carries an ancestor that is writable through its group or world bits, not its owner", () => {
    const calls: string[][] = [];
    // /tmp and /var/tmp are root-owned and 1777: the runner can write a target
    // under one only if those bits come down with it.
    ensureWriteThroughTargetsExist(["/sticky/cache"], ENV, {
      exists: (p) => p === "/sticky",
      stat: () => ({ uid: 0, gid: 0, mode: 0o41777 }),
      execFile: (cmd, args) => calls.push([cmd, ...args]),
    });
    expect(calls).toStrictEqual([
      ["sudo", "-u", "#0", "-g", "#0", "mkdir", "-p", "-m", "1777", "--", "/sticky/cache"],
    ]);
  });

  it("mirrors a restrictive ancestor's ownership, ending up unwritable by a non-root uid (e.g. /etc/test)", () => {
    const calls: string[][] = [];

    ensureWriteThroughTargetsExist(["/etc/test"], ENV, {
      exists: (p) => p === "/etc",
      stat: () => ({ uid: 0, gid: 0, mode: 0o40755 }), // root:root
      execFile: (cmd, args) => calls.push([cmd, ...args]),
    });

    expect(calls).toStrictEqual([
      ["sudo", "-u", "#0", "-g", "#0", "mkdir", "-p", "-m", "755", "--", "/etc/test"],
    ]);
  });

  it("throws WriteThroughTargetUncreatableError when the sudo sequence itself fails", () => {
    const execFile = vi.fn(() => {
      throw new Error("sudo: a password is required");
    });
    const run = () =>
      ensureWriteThroughTargetsExist(["/a/b"], ENV, {
        exists: (p) => p === "/a",
        stat: () => DIR,
        execFile,
      });
    // The class is what resolveFilesystemPlan branches on to pick an error
    // code, so it matters as much as the message reaching the user does.
    expect(run).toThrow(WriteThroughTargetUncreatableError);
    expect(run).toThrow(/a password is required/);
  });

  it("rolls back everything it created so far when a later entry fails", () => {
    const calls: string[][] = [];
    const made = new Set(["/a"]); // pre-existing ancestor only
    const execFile = (cmd: string, args: string[]) => {
      calls.push([cmd, ...args]);
      if (args.at(-1) === "/a/fail") throw new Error("sudo: permission denied");
    };

    expect(() =>
      ensureWriteThroughTargetsExist(["/a/ok/x", "/a/fail"], ENV, {
        exists: (p) => made.has(p),
        stat: () => DIR,
        execFile,
      }),
    ).toThrow(WriteThroughTargetUncreatableError);

    // The first entry succeeded (created /a/ok and /a/ok/x) before the
    // second entry failed: both must be rolled back, deepest first, and as
    // the same identity that created them.
    expect(calls).toStrictEqual([
      ["sudo", ...asOwner, "mkdir", "-p", "-m", "755", "--", "/a/ok/x"],
      ["sudo", ...asOwner, "mkdir", "-p", "-m", "755", "--", "/a/fail"],
      ["sudo", ...asOwner, "rmdir", "--", "/a/ok/x"],
      ["sudo", ...asOwner, "rmdir", "--", "/a/ok"],
    ]);
  });

  it("does not let a rollback failure mask the original error", () => {
    const execFile = (_cmd: string, args: string[]) => {
      if (args.includes("rmdir")) throw new Error("sudo: rmdir also failed");
      if (args.at(-1) === "/a/b/fail") throw new Error("sudo: mkdir failed");
    };
    expect(() =>
      ensureWriteThroughTargetsExist(["/a", "/a/b/fail"], ENV, {
        exists: (p) => p === "/",
        stat: () => DIR,
        execFile,
      }),
    ).toThrow(/mkdir failed/);
  });

  it("returns every segment it created with its owner, shallowest first, and nothing for pre-existing paths", () => {
    const created = ensureWriteThroughTargetsExist(["/a/b/c", "/usr/local/bin"], ENV, {
      exists: (p) => p === "/a" || p === "/usr/local/bin",
      stat: () => DIR,
      execFile: () => {},
    });
    expect(created).toStrictEqual([
      { path: "/a/b", uid: 1000, gid: 1000 },
      { path: "/a/b/c", uid: 1000, gid: 1000 },
    ]);
  });
});

describe("removeCreatedDirsIfEmpty", () => {
  const dirs = [
    { path: "/a/b", uid: 1000, gid: 1000 },
    { path: "/a/b/c", uid: 1000, gid: 1000 },
  ];
  const asOwner = ["-u", "#1000", "-g", "#1000"];

  it("rmdirs deepest first as the owner, so a nested set unwinds in the order it was created", () => {
    const calls: string[][] = [];
    removeCreatedDirsIfEmpty(dirs, { execFile: (cmd, args) => calls.push([cmd, ...args]) });
    expect(calls).toStrictEqual([
      ["sudo", ...asOwner, "rmdir", "--", "/a/b/c"],
      ["sudo", ...asOwner, "rmdir", "--", "/a/b"],
    ]);
  });

  it("keeps going when a directory isn't empty (the command wrote there, so it stays)", () => {
    const calls: string[][] = [];
    const execFile = (cmd: string, args: string[]) => {
      calls.push([cmd, ...args]);
      if (args[6] === "/a/b/c") throw new Error("rmdir: failed to remove: Directory not empty");
    };
    expect(() => removeCreatedDirsIfEmpty(dirs, { execFile })).not.toThrow();
    expect(calls).toStrictEqual([
      ["sudo", ...asOwner, "rmdir", "--", "/a/b/c"],
      ["sudo", ...asOwner, "rmdir", "--", "/a/b"],
    ]);
  });

  it("does nothing when nothing was created", () => {
    const execFile = vi.fn();
    removeCreatedDirsIfEmpty([], { execFile });
    expect(execFile).not.toHaveBeenCalled();
  });
});

describe("ensureWriteThroughTargetsExist: nothing to create it under", () => {
  const OWNED_DIR = { uid: 1000, gid: 1000, mode: 0o40755 };

  it("rolls back and refuses when no ancestor exists at all", () => {
    const execFile = vi.fn();
    expect(() =>
      ensureWriteThroughTargetsExist(["/a/b/c"], ENV, { exists: () => false, execFile }),
    ).toThrow(WriteThroughTargetUncreatableError);
  });

  // The message carries whatever mkdir failed with, and sudo can fail with
  // something that is not an Error.
  it("wraps a non-Error failure from mkdir", () => {
    const execFile = vi.fn(() => {
      throw "sudo: a password is required";
    });
    expect(() =>
      ensureWriteThroughTargetsExist(["/a/b"], ENV, {
        exists: (path) => path === "/a",
        stat: () => OWNED_DIR,
        execFile,
      }),
    ).toThrow(/a password is required/);
  });
});

describe("resolveWriteThroughEntry: a tilde with no HOME to expand to", () => {
  // The empty fallback leaves a relative path, which then resolves against the
  // workspace like any other. What matters is that "undefined" never lands in it.
  it("resolves the remainder rather than putting undefined in the path", () => {
    const resolved = resolveWriteThroughEntry("~/cache", { ...ENV, HOME: undefined });
    expect(resolved).not.toContain("undefined");
    expect(resolved.endsWith("/cache")).toBe(true);
  });
});

describe("splitWriteThroughInput", () => {
  it("splits on newlines, trims, and drops blank lines", () => {
    expect(splitWriteThroughInput(" /opt/cache \n\n./dist\n")).toStrictEqual([
      "/opt/cache",
      "./dist",
    ]);
    expect(splitWriteThroughInput("")).toStrictEqual([]);
    expect(splitWriteThroughInput(undefined)).toStrictEqual([]);
  });

  it("drops a whole-line comment (first non-space character is #) and a blank line", () => {
    expect(splitWriteThroughInput("# caches\n/opt/cache\n\n   # more\n./dist")).toStrictEqual([
      "/opt/cache",
      "./dist",
    ]);
  });

  it("keeps a # anywhere else in the path, so a path with a # or a space+# is not truncated", () => {
    expect(splitWriteThroughInput("/opt/cache#1\n/tmp/a#b\n/data/my logs #2/cache")).toStrictEqual([
      "/opt/cache#1",
      "/tmp/a#b",
      "/data/my logs #2/cache",
    ]);
  });
});

describe("resolveWriteThroughOnHost", () => {
  const DIR = { uid: 1000, gid: 1000, mode: 0o40755 };
  const host = (dirs: string[], links: Record<string, { target: string; uid: number }> = {}) => ({
    exists: (p: string) => p === "/" || dirs.includes(p) || p in links,
    stat: (p: string) => (p in links ? { uid: links[p]!.uid, gid: 0, mode: 0o120777 } : DIR),
    readlink: (p: string) => links[p]!.target,
  });

  it("returns a path with no symlinks on it unchanged", () => {
    expect(resolveWriteThroughOnHost("/a/b", host(["/a", "/a/b"]))).toBe("/a/b");
  });

  it("keeps the components that don't exist yet as written", () => {
    expect(resolveWriteThroughOnHost("/a/b/c", host(["/a"]))).toBe("/a/b/c");
  });

  it("refuses a symlink the runner's uid owns, which an earlier step could have planted", () => {
    const fake = host(["/ws", "/tmp/_temp"], { "/ws/cache": { target: "/tmp/_temp", uid: 1000 } });
    expect(() => resolveWriteThroughOnHost("/ws/cache", fake)).toThrow(
      /"\/ws\/cache", a symlink to "\/tmp\/_temp" owned by uid 1000/,
    );
    // Also when it sits partway along the path.
    expect(() => resolveWriteThroughOnHost("/ws/cache/sub", fake)).toThrow(/owned by uid 1000/);
  });

  it("follows a root-owned symlink, absolute or relative, to the directory really there", () => {
    const fake = host(["/data", "/data/home", "/data/home/runner", "/opt", "/opt/real"], {
      "/home": { target: "/data/home", uid: 0 },
      "/opt/link": { target: "../opt/./real", uid: 0 },
    });
    expect(resolveWriteThroughOnHost("/home/runner/x", fake)).toBe("/data/home/runner/x");
    expect(resolveWriteThroughOnHost("/opt/link", fake)).toBe("/opt/real");
  });

  it("walks a link target's .. back up through a component that doesn't exist yet", () => {
    const fake = host(["/a"], { "/a/l": { target: "missing/../real", uid: 0 } });
    expect(resolveWriteThroughOnHost("/a/l", fake)).toBe("/a/real");
  });

  it("refuses a root-owned symlink that lands on /", () => {
    const fake = host([], { "/root-link": { target: "/", uid: 0 } });
    expect(() => resolveWriteThroughOnHost("/root-link", fake)).toThrow(/resolves to "\/"/);
  });

  it("gives up on a symlink loop", () => {
    const fake = host([], { "/loop": { target: "/loop", uid: 0 } });
    expect(() => resolveWriteThroughOnHost("/loop", fake)).toThrow(/too many symlinks/);
  });
});

describe("ensureWriteThroughTargetsExist: the path changing under it", () => {
  const DIR = { uid: 1000, gid: 1000, mode: 0o40755 };

  it("refuses an ancestor that is no longer a directory", () => {
    const execFile = vi.fn();
    expect(() =>
      ensureWriteThroughTargetsExist(["/a/b"], ENV, {
        exists: (p) => p === "/a",
        stat: () => ({ uid: 0, gid: 0, mode: 0o120777 }),
        execFile,
      }),
    ).toThrow(/"\/a" is not a directory/);
    expect(execFile).not.toHaveBeenCalled();
  });

  it("does not record a segment that isn't the owner's directory, and rolls back the rest", () => {
    const calls: string[][] = [];
    const stat = (p: string) => (p === "/a/x/y" ? { ...DIR, mode: 0o120777 } : DIR);
    expect(() =>
      ensureWriteThroughTargetsExist(["/a/ok", "/a/x/y"], ENV, {
        exists: (p) => p === "/a",
        stat,
        execFile: (cmd, args) => calls.push([cmd, ...args]),
      }),
    ).toThrow(/"\/a\/x\/y" is not a directory owned by uid 1000/);
    expect(calls.filter((c) => c.includes("rmdir"))).toStrictEqual([
      ["sudo", "-u", "#1000", "-g", "#1000", "rmdir", "--", "/a/ok"],
    ]);
  });

  it("does not record a segment someone else owns", () => {
    const stat = (p: string) => (p === "/a/b" ? { ...DIR, uid: 0 } : DIR);
    expect(() =>
      ensureWriteThroughTargetsExist(["/a/b"], ENV, {
        exists: (p) => p === "/a",
        stat,
        execFile: () => {},
      }),
    ).toThrow(WriteThroughTargetUncreatableError);
  });
});

import { describe, it, expect } from "vitest";

import {
  resolveWriteThroughEntry,
  resolveWriteThroughPaths,
  resolveWriteThroughOnHost,
  ensureWriteThroughTargetsExist,
  splitWriteThroughInput,
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

describe("ensureWriteThroughTargetsExist", () => {
  /** Records every mkdir; `dirs` exist, and the runner can write `writable`. */
  function host(dirs: string[], writable: string[] = dirs) {
    const made: string[] = [];
    return {
      made,
      deps: {
        exists: (p: string) => p === "/" || dirs.includes(p),
        canWrite: (p: string) => writable.includes(p),
        mkdir: (p: string) => {
          made.push(p);
        },
      },
    };
  }

  it("does nothing for an already-existing path", () => {
    const { made, deps } = host(["/usr/local/bin"], []);
    ensureWriteThroughTargetsExist(["/usr/local/bin"], deps);
    expect(made).toStrictEqual([]);
  });

  it("makes the whole path as the runner under the nearest ancestor it can write", () => {
    const { made, deps } = host(["/tmp"]);
    ensureWriteThroughTargetsExist(["/tmp/build/out"], deps);
    expect(made).toStrictEqual(["/tmp/build/out"]);
  });

  it("refuses a path under an ancestor the runner can't write, naming both", () => {
    const { deps } = host(["/etc"], []);
    const run = () => ensureWriteThroughTargetsExist(["/etc/test/sub"], deps);
    expect(run).toThrow(WriteThroughTargetUncreatableError);
    expect(run).toThrow(
      /"\/etc\/test\/sub" doesn't exist, and the runner can't create it under "\/etc"/,
    );
  });

  it("refuses a path with nothing but / above it", () => {
    const { deps } = host([]);
    expect(() => ensureWriteThroughTargetsExist(["/a/b"], deps)).toThrow(/under "\/"/);
  });

  it("makes nothing when any path is refused, even one listed earlier", () => {
    const { made, deps } = host(["/tmp", "/etc"], ["/tmp"]);
    expect(() => ensureWriteThroughTargetsExist(["/tmp/ok", "/etc/test"], deps)).toThrow(
      WriteThroughTargetUncreatableError,
    );
    expect(made).toStrictEqual([]);
  });

  it.each([new Error("EROFS: read-only file system"), "EROFS: read-only file system"])(
    "wraps a mkdir failure (%s)",
    (thrown) => {
      const { deps } = host(["/tmp"]);
      const run = () =>
        ensureWriteThroughTargetsExist(["/tmp/out"], {
          ...deps,
          mkdir: () => {
            throw thrown;
          },
        });
      expect(run).toThrow(WriteThroughTargetUncreatableError);
      expect(run).toThrow(/"\/tmp\/out" doesn't exist and couldn't be created: EROFS/);
    },
  );
});

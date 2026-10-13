import { describe, it, expect } from "vitest";

import {
  resolveWriteThroughEntry,
  resolveWriteThroughPaths,
  assertNoSymlinkInWriteThrough,
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

describe("assertNoSymlinkInWriteThrough", () => {
  /** Every path exists; `links` are the symlinks, each to its stored target. */
  const host = (links: Record<string, string> = {}) => ({
    lstat: (p: string) => ({ isSymbolicLink: () => p in links }),
    readlink: (p: string) => links[p]!,
  });

  it("accepts a path with no symlinks on it, including one still to be created", () => {
    const missing = { lstat: () => undefined, readlink: () => "" };
    expect(() => assertNoSymlinkInWriteThrough("/a/b", host())).not.toThrow();
    expect(() => assertNoSymlinkInWriteThrough("/a/b", missing)).not.toThrow();
  });

  it("refuses a path that is itself a symlink, naming where it leads", () => {
    expect(() =>
      assertNoSymlinkInWriteThrough("/ws/cache", host({ "/ws/cache": "/tmp/_temp" })),
    ).toThrow(
      '"/ws/cache", a symlink to "/tmp/_temp", and symlinks are not followed. ' +
        'Name the path it leads to instead: "/tmp/_temp".',
    );
  });

  it("refuses a symlink partway along the path, as an OS's own /home link", () => {
    expect(() =>
      assertNoSymlinkInWriteThrough("/home/runner/x", host({ "/home": "var/home" })),
    ).toThrow(/goes through "\/home".*instead: "\/var\/home\/runner\/x"/);
  });

  it("names no path to use instead when the symlink leads to / or loops", () => {
    for (const links of [{ "/root-link": "/" }, { "/root-link": "/root-link" }]) {
      expect(() => assertNoSymlinkInWriteThrough("/root-link", host(links))).toThrow(
        /symlinks are not followed\.$/,
      );
    }
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

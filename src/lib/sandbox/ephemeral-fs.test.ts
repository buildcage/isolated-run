import { describe, it, expect, vi } from "vitest";

import {
  resolveAllowWriteEntry,
  resolveAllowWritePaths,
  ensureAllowWriteTargetsExist,
  AllowWriteTargetMissingError,
  AllowWriteTargetUncreatableError,
  determineOverlayRoots,
  createOverlayScratchDirs,
  formatFilesystemPlanLog,
} from "./ephemeral-fs.ts";

const ENV = {
  HOME: "/home/runner",
  GITHUB_WORKSPACE: "/home/runner/work/repo/repo",
  RUNNER_TEMP: "/home/runner/work/_temp",
  GITHUB_OUTPUT: "/home/runner/work/_temp/_runner_file_commands/set_output_abc",
  GITHUB_ENV: "/home/runner/work/_temp/_runner_file_commands/set_env_abc",
  GITHUB_PATH: "/home/runner/work/_temp/_runner_file_commands/add_path_abc",
  GITHUB_STEP_SUMMARY: "/home/runner/work/_temp/_runner_file_commands/step_summary_abc",
};

describe("resolveAllowWriteEntry", () => {
  it("expands $NAME and ${NAME} forms for allowed variables", () => {
    expect(resolveAllowWriteEntry("$GITHUB_OUTPUT", ENV)).toBe(ENV.GITHUB_OUTPUT);
    expect(resolveAllowWriteEntry("${GITHUB_OUTPUT}", ENV)).toBe(ENV.GITHUB_OUTPUT);
  });

  it("expands a leading ~/ to $HOME", () => {
    expect(resolveAllowWriteEntry("~/.local/bin", ENV)).toBe("/home/runner/.local/bin");
  });

  it("does not expand a bare ~ or ~user/ -- treated as an ordinary relative path instead", () => {
    expect(resolveAllowWriteEntry("~", ENV)).toBe(`${ENV.GITHUB_WORKSPACE}/~`);
    expect(resolveAllowWriteEntry("~other/x", ENV)).toBe(`${ENV.GITHUB_WORKSPACE}/~other/x`);
  });

  it("resolves a relative path against $GITHUB_WORKSPACE", () => {
    expect(resolveAllowWriteEntry("./dist", ENV)).toBe("/home/runner/work/repo/repo/dist");
    expect(resolveAllowWriteEntry("dist", ENV)).toBe("/home/runner/work/repo/repo/dist");
  });

  it("leaves an absolute path untouched (after normalization)", () => {
    expect(resolveAllowWriteEntry("/usr/local/bin", ENV)).toBe("/usr/local/bin");
  });

  it("normalizes .. segments", () => {
    expect(resolveAllowWriteEntry("/usr/local/bin/../lib", ENV)).toBe("/usr/local/lib");
  });

  it("rejects an unlisted variable name", () => {
    expect(() => resolveAllowWriteEntry("$SECRET_TOKEN/x", ENV)).toThrow(
      /unsupported variable \$SECRET_TOKEN/,
    );
  });

  it("strips a trailing slash so the result string-equals the bare candidate path", () => {
    expect(resolveAllowWriteEntry("$HOME/", ENV)).toBe(ENV.HOME);
    expect(resolveAllowWriteEntry("/usr/local/bin/", ENV)).toBe("/usr/local/bin");
  });

  it("leaves a bare '/' alone rather than stripping it down to an empty string", () => {
    expect(resolveAllowWriteEntry("/", ENV)).toBe("/");
  });

  it("does not swallow a stray closing brace from a malformed reference", () => {
    // "$GITHUB_WORKSPACE}suffix" is missing its opening brace -- the "}"
    // must be treated as literal text, not consumed into the match.
    expect(resolveAllowWriteEntry("$GITHUB_WORKSPACE}suffix", ENV)).toBe(
      `${ENV.GITHUB_WORKSPACE}}suffix`,
    );
  });

  it("accepts every allowed variable name", () => {
    expect(resolveAllowWriteEntry("$HOME", ENV)).toBe(ENV.HOME);
    expect(resolveAllowWriteEntry("$GITHUB_WORKSPACE", ENV)).toBe(ENV.GITHUB_WORKSPACE);
    expect(resolveAllowWriteEntry("$RUNNER_TEMP", ENV)).toBe(ENV.RUNNER_TEMP);
    expect(resolveAllowWriteEntry("$GITHUB_ENV", ENV)).toBe(ENV.GITHUB_ENV);
    expect(resolveAllowWriteEntry("$GITHUB_PATH", ENV)).toBe(ENV.GITHUB_PATH);
    expect(resolveAllowWriteEntry("$GITHUB_STEP_SUMMARY", ENV)).toBe(ENV.GITHUB_STEP_SUMMARY);
  });
});

describe("resolveAllowWritePaths", () => {
  it("splits on newlines, trims, and drops blank lines", () => {
    expect(resolveAllowWritePaths("$GITHUB_WORKSPACE\n\n  ./dist  \n", ENV)).toStrictEqual([
      ENV.GITHUB_WORKSPACE,
      `${ENV.GITHUB_WORKSPACE}/dist`,
    ]);
  });

  it("returns [] for undefined/empty input", () => {
    expect(resolveAllowWritePaths(undefined, ENV)).toStrictEqual([]);
    expect(resolveAllowWritePaths("", ENV)).toStrictEqual([]);
  });
});

describe("ensureAllowWriteTargetsExist", () => {
  it("does nothing for an already-existing path", () => {
    const execFile = vi.fn();
    ensureAllowWriteTargetsExist(["/usr/local/bin"], ENV, { exists: () => true, execFile });
    expect(execFile).not.toHaveBeenCalled();
  });

  it("throws AllowWriteTargetMissingError when a missing entry equals a KNOWN_FILE_VARS value", () => {
    const execFile = vi.fn();
    expect(() =>
      ensureAllowWriteTargetsExist([ENV.GITHUB_OUTPUT], ENV, { exists: () => false, execFile }),
    ).toThrow(AllowWriteTargetMissingError);
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

    ensureAllowWriteTargetsExist(["/a/b/c"], ENV, { exists, stat, execFile });

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

    ensureAllowWriteTargetsExist(["/etc/test"], ENV, { exists, stat, execFile });

    expect(calls).toStrictEqual([
      ["sudo", "mkdir", "-p", "/etc/test"],
      ["sudo", "chown", "0:0", "/etc/test"],
      ["sudo", "chmod", "755", "/etc/test"],
    ]);
  });

  it("throws AllowWriteTargetUncreatableError when the sudo sequence itself fails", () => {
    const execFile = vi.fn(() => {
      throw new Error("sudo: a password is required");
    });
    expect(() =>
      ensureAllowWriteTargetsExist(["/a/b"], ENV, {
        exists: (p) => p === "/a",
        stat: () => ({ uid: 1000, gid: 1000, mode: 0o40755 }),
        execFile,
      }),
    ).toThrow(AllowWriteTargetUncreatableError);
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
      ensureAllowWriteTargetsExist(["/a/ok/x", "/a/fail"], ENV, { exists, stat, execFile }),
    ).toThrow(AllowWriteTargetUncreatableError);

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
      ensureAllowWriteTargetsExist(["/a", "/a/b/fail"], ENV, {
        exists: (p) => p === "/",
        stat: () => ({ uid: 1000, gid: 1000, mode: 0o40755 }),
        execFile,
      }),
    ).toThrow(/mkdir failed/);
  });
});

describe("determineOverlayRoots", () => {
  const exists = () => true;
  // Every test path here is fictional, so the real fs.statSync-backed
  // default deviceOf would throw for all of them -- inject a fake that
  // reports "same device" unconditionally, matching the common case these
  // tests are about (a plain subdirectory, not a distinct mount).
  const sameDevice = () => 1;

  it("folds RUNNER_TEMP and GITHUB_WORKSPACE into HOME when both are nested under it", () => {
    const candidates = [ENV.HOME, ENV.RUNNER_TEMP, "/tmp", ENV.GITHUB_WORKSPACE];
    expect(determineOverlayRoots(candidates, [], { exists, deviceOf: sameDevice })).toStrictEqual([
      { path: ENV.HOME },
      { path: "/tmp" },
    ]);
  });

  it("excludes a candidate that is itself named in allow_write", () => {
    const candidates = [ENV.HOME, "/tmp"];
    expect(
      determineOverlayRoots(candidates, [ENV.HOME], { exists, deviceOf: sameDevice }),
    ).toStrictEqual([{ path: "/tmp" }]);
  });

  it("keeps a candidate that is only an ancestor of a narrower allow_write entry (the entry's own rw bind persists just that subtree on top -- see buildOciConfig's mount ordering)", () => {
    const candidates = [ENV.HOME, "/tmp"];
    expect(
      determineOverlayRoots(candidates, [`${ENV.HOME}/.npmrc`], { exists, deviceOf: sameDevice }),
    ).toStrictEqual([{ path: ENV.HOME }, { path: "/tmp" }]);
  });

  it("excludes a candidate that is a descendant of a broader allow_write entry", () => {
    const candidates = [`${ENV.HOME}/.cache`, "/tmp"];
    expect(
      determineOverlayRoots(candidates, [ENV.HOME], { exists, deviceOf: sameDevice }),
    ).toStrictEqual([{ path: "/tmp" }]);
  });

  it("drops a candidate that doesn't exist on disk", () => {
    const candidates = [ENV.HOME, "/tmp"];
    expect(
      determineOverlayRoots(candidates, [], {
        exists: (p) => p !== "/tmp",
        deviceOf: sameDevice,
      }),
    ).toStrictEqual([{ path: ENV.HOME }]);
  });

  it("dedupes identical candidates (e.g. RUNNER_TEMP === HOME on some self-hosted setups)", () => {
    expect(
      determineOverlayRoots([ENV.HOME, ENV.HOME], [], { exists, deviceOf: sameDevice }),
    ).toStrictEqual([{ path: ENV.HOME }]);
  });

  it("does not let a non-existent outer candidate drop an existing inner one's coverage", () => {
    // HOME doesn't exist; RUNNER_TEMP (nested under it) does. Previously the
    // nesting fold ran before the exists() filter, so RUNNER_TEMP was
    // dropped as "covered by" HOME regardless, and HOME was then also
    // dropped for not existing -- leaving RUNNER_TEMP with no overlay at all.
    const candidates = [ENV.HOME, ENV.RUNNER_TEMP];
    expect(
      determineOverlayRoots(candidates, [], {
        exists: (p) => p === ENV.RUNNER_TEMP,
        deviceOf: sameDevice,
      }),
    ).toStrictEqual([{ path: ENV.RUNNER_TEMP }]);
  });

  it("keeps a nested candidate that is actually a distinct mount instead of folding it into the outer one", () => {
    // RUNNER_TEMP is nested under HOME by path, but reports a different
    // device -- a real (if unusual) self-hosted layout where RUNNER_TEMP is
    // its own separate filesystem mounted inside $HOME. Folding it away
    // would leave it uncovered by any overlay (see buildOciConfig's
    // protectedPaths, matched by exact mount point).
    const candidates = [ENV.HOME, ENV.RUNNER_TEMP];
    const deviceOf = (p: string) => (p === ENV.RUNNER_TEMP ? 2 : 1);
    expect(determineOverlayRoots(candidates, [], { exists, deviceOf })).toStrictEqual([
      { path: ENV.HOME },
      { path: ENV.RUNNER_TEMP },
    ]);
  });

  it("still folds a same-device nested candidate away even when deviceOf is given", () => {
    const candidates = [ENV.HOME, ENV.RUNNER_TEMP];
    expect(determineOverlayRoots(candidates, [], { exists, deviceOf: sameDevice })).toStrictEqual([
      { path: ENV.HOME },
    ]);
  });

  it("keeps a nested candidate when deviceOf can't be determined for it (fails closed toward extra coverage)", () => {
    const candidates = [ENV.HOME, ENV.RUNNER_TEMP];
    const deviceOf = (p: string) => {
      if (p === ENV.RUNNER_TEMP) throw new Error("EACCES");
      return 1;
    };
    expect(determineOverlayRoots(candidates, [], { exists, deviceOf })).toStrictEqual([
      { path: ENV.HOME },
      { path: ENV.RUNNER_TEMP },
    ]);
  });
});

describe("createOverlayScratchDirs", () => {
  it("creates upper/work as siblings of rootfs under <scratchDir>/ephemeral/<slug>", () => {
    const created: string[] = [];
    const mkdir = ((p: string) => {
      created.push(p);
    }) as unknown as typeof import("node:fs").mkdirSync;

    const result = createOverlayScratchDirs(
      "/var/tmp/buildcage/sandbox-xyz",
      [{ path: "/home/runner" }],
      {
        mkdir,
      },
    );

    expect(result).toStrictEqual([
      {
        path: "/home/runner",
        upper: "/var/tmp/buildcage/sandbox-xyz/ephemeral/_home_runner/upper",
        work: "/var/tmp/buildcage/sandbox-xyz/ephemeral/_home_runner/work",
      },
    ]);
    expect(created).toStrictEqual([
      "/var/tmp/buildcage/sandbox-xyz/ephemeral/_home_runner/upper",
      "/var/tmp/buildcage/sandbox-xyz/ephemeral/_home_runner/work",
    ]);
    // Never nested under the rootfs bind dir itself (a sibling, not a child).
    for (const p of [result[0]!.upper, result[0]!.work]) {
      expect(p.startsWith("/var/tmp/buildcage/sandbox-xyz/rootfs/")).toBe(false);
    }
  });
});

describe("formatFilesystemPlanLog", () => {
  it("returns [] for persistent mode", () => {
    expect(formatFilesystemPlanLog("persistent", ["/home/runner"], ["/tmp/x"])).toStrictEqual([]);
  });

  it("lists the mode, folded overlay roots, then allow_write entries for ephemeral mode", () => {
    expect(
      formatFilesystemPlanLog("ephemeral", ["/home/runner", "/tmp"], [ENV.GITHUB_WORKSPACE]),
    ).toStrictEqual([
      "Filesystem mode: ephemeral",
      "Ephemeral (writes discarded at step end): /home/runner",
      "Ephemeral (writes discarded at step end): /tmp",
      `Writable (persisted):                    ${ENV.GITHUB_WORKSPACE}`,
    ]);
  });

  it("emits only the mode line when there is nothing to fold either way", () => {
    expect(formatFilesystemPlanLog("ephemeral", [], [])).toStrictEqual([
      "Filesystem mode: ephemeral",
    ]);
  });
});

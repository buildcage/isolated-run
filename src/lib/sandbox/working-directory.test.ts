import type { Stats } from "node:fs";

import { describe, expect, it } from "vitest";

import { SandboxError } from "../errors.ts";
import {
  assertSandboxCanEnter,
  hiddenWorkingDirectory,
  isWorkspace,
  readWorkingDirectory,
  unsearchableAncestor,
  workingDirectoryOf,
} from "./working-directory.ts";

const WS = "/home/runner/work/repo/repo";
// null leaves $GITHUB_WORKSPACE unset.
const envWith = (input?: string, workspace: string | null = WS): NodeJS.ProcessEnv => ({
  ...(workspace !== null && { GITHUB_WORKSPACE: workspace }),
  ...(input !== undefined && { "INPUT_WORKING-DIRECTORY": input }),
});

const stats = (over: Partial<Stats> = {}): Stats =>
  ({ isDirectory: () => true, uid: 0, gid: 0, mode: 0o40755, ...over }) as Stats;

describe("workingDirectoryOf", () => {
  it("is the workspace without the input", () => {
    expect(workingDirectoryOf(envWith())).toBe(WS);
    expect(workingDirectoryOf(envWith("  "))).toBe(WS);
  });

  it("joins a relative input to the workspace, normalized", () => {
    expect(workingDirectoryOf(envWith("app/"))).toBe(`${WS}/app`);
    expect(workingDirectoryOf(envWith("./a//b/../c"))).toBe(`${WS}/a/c`);
    expect(workingDirectoryOf(envWith(".."))).toBe("/home/runner/work/repo");
  });

  it("takes an absolute input as it is, normalized", () => {
    expect(workingDirectoryOf(envWith("/opt/app/"))).toBe("/opt/app");
    expect(workingDirectoryOf(envWith("/opt/app", null))).toBe("/opt/app");
    expect(workingDirectoryOf(envWith("/"))).toBe("/");
  });

  it("is undefined when nothing makes it absolute", () => {
    expect(workingDirectoryOf(envWith(undefined, null))).toBeUndefined();
    expect(workingDirectoryOf(envWith("app", null))).toBeUndefined();
  });

  it("expands nothing, as the workflow's own working-directory does not", () => {
    expect(workingDirectoryOf(envWith("~/x"))).toBe(`${WS}/~/x`);
    expect(workingDirectoryOf(envWith("$RUNNER_TEMP"))).toBe(`${WS}/$RUNNER_TEMP`);
  });
});

describe("isWorkspace", () => {
  it("compares as normalized paths", () => {
    expect(isWorkspace(WS, envWith(undefined, `${WS}/`))).toBe(true);
    expect(isWorkspace(`${WS}/app/..`, envWith())).toBe(true);
    expect(isWorkspace(`${WS}/app`, envWith())).toBe(false);
    expect(isWorkspace(WS, envWith(undefined, null))).toBe(false);
  });
});

describe("readWorkingDirectory", () => {
  const realpath = (path: string) => path.replace("/link", "/real");

  it("is undefined without the input", () => {
    expect(readWorkingDirectory(envWith(), { realpath, stat: () => stats() })).toBeUndefined();
  });

  it("keeps the spelling relative paths join to, and the real path the command starts in", () => {
    expect(
      readWorkingDirectory(envWith(" link/app "), { realpath, stat: () => stats() }),
    ).toStrictEqual({
      input: "link/app",
      dir: `${WS}/link/app`,
      real: `${WS}/real/app`,
      isWorkspace: false,
    });
  });

  it("says when it names the workspace anyway", () => {
    expect(readWorkingDirectory(envWith("."), { realpath, stat: () => stats() })).toMatchObject({
      dir: WS,
      isWorkspace: true,
    });
  });

  const refused = (env: NodeJS.ProcessEnv, deps: Parameters<typeof readWorkingDirectory>[1]) => {
    try {
      readWorkingDirectory(env, deps);
    } catch (e) {
      expect(e).toBeInstanceOf(SandboxError);
      expect((e as SandboxError).code).toBe("INVALID_WORKING_DIRECTORY");
      return (e as Error).message;
    }
    throw new Error("not refused");
  };
  const missing = () => {
    throw new Error("ENOENT");
  };

  it("refuses a relative input without the workspace", () => {
    expect(refused(envWith("app", null), {})).toBe(
      'working-directory "app" is relative and $GITHUB_WORKSPACE is not set.',
    );
  });

  it("refuses a directory that does not exist, which runc would create as root", () => {
    expect(refused(envWith("app"), { realpath: missing })).toBe(
      `working-directory "app" (${WS}/app) does not exist.`,
    );
  });

  it("says a variable or ~ is not expanded", () => {
    for (const input of ["~/build", "$RUNNER_TEMP/build"])
      expect(refused(envWith(input), { realpath: missing })).toMatch(
        /does not exist\. Variables and ~ are not expanded; use an expression such as \$\{\{ runner\.temp \}\}\.$/,
      );
  });

  it("refuses a file", () => {
    expect(
      refused(envWith("a.txt"), { realpath, stat: () => stats({ isDirectory: () => false }) }),
    ).toBe(`working-directory "a.txt" (${WS}/a.txt) is not a directory.`);
  });
});

describe("hiddenWorkingDirectory", () => {
  const bind = (path: string, source = path) => ({
    destination: path,
    type: "none",
    source,
    options: ["rbind", "rw"],
  });

  it("leaves a path no mount covers to the rootfs, the host's own", () => {
    expect(hiddenWorkingDirectory("/opt/app", [bind("/home/runner")], [])).toBeUndefined();
  });

  it("takes a bind of the host's own path, or an overlay over it", () => {
    expect(hiddenWorkingDirectory(`${WS}/app`, [bind("/home/runner")], [])).toBeUndefined();
    const overlay = {
      destination: "/home/runner",
      type: "overlay",
      source: "overlay",
      options: ["lowerdir=/home/runner", "upperdir=/s/u", "workdir=/s/w"],
    };
    expect(hiddenWorkingDirectory(`${WS}/app`, [overlay], [])).toBeUndefined();
  });

  it("goes by the last mount covering it", () => {
    const shm = { destination: "/dev/shm", type: "tmpfs", source: "shm", options: [] };
    expect(hiddenWorkingDirectory("/dev/shm/build", [shm], [])).toBe(
      "the sandbox mounts its own /dev/shm",
    );
    expect(
      hiddenWorkingDirectory("/run/x", [{ ...shm, destination: "/run" }, bind("/run/x")], []),
    ).toBeUndefined();
  });

  it("refuses a bind of something else, and a masked path", () => {
    expect(hiddenWorkingDirectory("/etc/ssl/x", [bind("/etc/ssl", "/var/tmp/ca")], [])).toBe(
      "the sandbox mounts its own /etc/ssl",
    );
    expect(hiddenWorkingDirectory("/proc/acpi/x", [], ["/proc/acpi"])).toBe(
      "/proc/acpi is hidden from the sandbox",
    );
  });
});

describe("unsearchableAncestor", () => {
  const user = { uid: 1001, gid: 1001 };
  const tree = (modes: Record<string, Partial<Stats>>) => (path: string) =>
    stats(modes[path] ?? {});

  it("goes by the owner's, group's or others' bits, whichever applies", () => {
    expect(unsearchableAncestor("/a/b", user, tree({}))).toBeUndefined();
    expect(
      unsearchableAncestor("/a/b", user, tree({ "/a": { uid: 1001, mode: 0o700 } })),
    ).toBeUndefined();
    expect(
      unsearchableAncestor("/a/b", user, tree({ "/a": { gid: 1001, mode: 0o750 } })),
    ).toBeUndefined();
    expect(unsearchableAncestor("/a/b", user, tree({ "/a/b": { mode: 0o750 } }))).toBe("/a/b");
    expect(unsearchableAncestor("/a/b", user, tree({ "/a": { uid: 1001, mode: 0o077 } }))).toBe(
      "/a",
    );
    expect(unsearchableAncestor("/", user, tree({ "/": { mode: 0o700 } }))).toBe("/");
  });

  it("ignores the runner's supplementary groups, which the sandbox drops", () => {
    expect(unsearchableAncestor("/a", user, tree({ "/a": { gid: 999, mode: 0o750 } }))).toBe("/a");
  });
});

describe("assertSandboxCanEnter", () => {
  const wd = { input: "app", dir: `${WS}/app`, real: `${WS}/app`, isWorkspace: false };
  const spec = { mounts: [], maskedPaths: [], uid: 1001, gid: 1001 };

  it("passes a visible, searchable directory", () => {
    expect(() => assertSandboxCanEnter(wd, spec, () => stats())).not.toThrow();
  });

  it("refuses one the sandbox would not see", () => {
    expect(() =>
      assertSandboxCanEnter(wd, { ...spec, maskedPaths: ["/home/runner"] }, () => stats()),
    ).toThrow(
      `working-directory "app" (${WS}/app) is unusable: /home/runner is hidden from the sandbox.`,
    );
  });

  it("refuses one the sandbox's user cannot search", () => {
    expect(() =>
      assertSandboxCanEnter(wd, spec, (path) => stats(path === WS ? { mode: 0o700 } : {})),
    ).toThrow(
      `working-directory "app" (${WS}/app) is unusable: the sandbox's user ` +
        `(uid 1001, gid 1001, no supplementary groups) cannot search ${WS}.`,
    );
  });
});

import { describe, it, expect } from "vitest";

import {
  determineOverlayRoots,
  createOverlayScratchDirs,
  formatFilesystemPlanLog,
  nestedMountRoots,
} from "./ephemeral-fs.ts";
import type { HostMount } from "./types.ts";

const ENV = {
  HOME: "/home/runner",
  GITHUB_WORKSPACE: "/home/runner/work/repo/repo",
  RUNNER_TEMP: "/home/runner/work/_temp",
};

describe("determineOverlayRoots", () => {
  const exists = () => true;

  it("folds RUNNER_TEMP and GITHUB_WORKSPACE into HOME when both are nested under it", () => {
    const candidates = [ENV.HOME, ENV.RUNNER_TEMP, "/tmp", ENV.GITHUB_WORKSPACE];
    expect(determineOverlayRoots(candidates, [], { exists }).roots).toStrictEqual([
      ENV.HOME,
      "/tmp",
    ]);
  });

  it("excludes a candidate that is itself named in write_through", () => {
    const candidates = [ENV.HOME, "/tmp"];
    expect(determineOverlayRoots(candidates, [ENV.HOME], { exists }).roots).toStrictEqual(["/tmp"]);
  });

  it("keeps a candidate that is only an ancestor of a narrower write_through entry", () => {
    const candidates = [ENV.HOME, "/tmp"];
    expect(
      determineOverlayRoots(candidates, [`${ENV.HOME}/.npmrc`], { exists }).roots,
    ).toStrictEqual([ENV.HOME, "/tmp"]);
  });

  it("excludes a candidate that is a descendant of a broader write_through entry", () => {
    const candidates = [`${ENV.HOME}/.cache`, "/tmp"];
    expect(determineOverlayRoots(candidates, [ENV.HOME], { exists }).roots).toStrictEqual(["/tmp"]);
  });

  it("drops a candidate that doesn't exist on disk", () => {
    const candidates = [ENV.HOME, "/tmp"];
    expect(
      determineOverlayRoots(candidates, [], {
        exists: (p) => p !== "/tmp",
      }).roots,
    ).toStrictEqual([ENV.HOME]);
  });

  it("dedupes identical candidates (e.g. RUNNER_TEMP === HOME on some self-hosted setups)", () => {
    expect(determineOverlayRoots([ENV.HOME, ENV.HOME], [], { exists }).roots).toStrictEqual([
      ENV.HOME,
    ]);
  });

  it("does not let a non-existent outer candidate drop an existing inner one's coverage", () => {
    // HOME doesn't exist; RUNNER_TEMP (nested under it) does. Pins the order of
    // the exists() filter and the nesting fold: the other order leaves
    // RUNNER_TEMP with no overlay at all.
    const candidates = [ENV.HOME, ENV.RUNNER_TEMP];
    expect(
      determineOverlayRoots(candidates, [], {
        exists: (p) => p === ENV.RUNNER_TEMP,
      }).roots,
    ).toStrictEqual([ENV.RUNNER_TEMP]);
  });

  it("folds a nested candidate on a filesystem of its own too, leaving its mount to nestedMountRoots", () => {
    const candidates = [ENV.HOME, ENV.RUNNER_TEMP];
    expect(determineOverlayRoots(candidates, [], { exists })).toStrictEqual({
      candidates,
      roots: [ENV.HOME],
    });
  });
});

const RUNNER = { uid: 1001, gid: 1001 };

/** Records what createOverlayScratchDirs does, with `stat` as the lower root's owner and mode. */
function scratchDeps(
  stat: { uid: number; gid: number; mode: number } = { ...RUNNER, mode: 0o40755 },
) {
  const calls: string[][] = [];
  return {
    calls,
    deps: {
      mkdir: ((p: string) => {
        calls.push(["mkdir", p]);
      }) as unknown as typeof import("node:fs").mkdirSync,
      chmod: (p: string, mode: number) => calls.push(["chmod", p, mode.toString(8)]),
      stat: () => stat,
      execFile: (command: string, args: string[]) => calls.push([command, ...args]),
      self: RUNNER,
    },
  };
}

describe("createOverlayScratchDirs", () => {
  const SCRATCH = "/var/tmp/buildcage/sandbox-xyz";
  const SLUG_DIR = `${SCRATCH}/ephemeral/b1cbc5f347543a03`;

  it("creates upper/work as siblings of rootfs under <scratchDir>/ephemeral/<slug>", () => {
    const { deps } = scratchDeps();

    const result = createOverlayScratchDirs(SCRATCH, ["/home/runner"], deps);

    expect(result).toStrictEqual([
      { path: "/home/runner", upper: `${SLUG_DIR}/upper`, work: `${SLUG_DIR}/work` },
    ]);
    // Never nested under the rootfs bind dir itself (a sibling, not a child).
    for (const p of [result[0]!.upper, result[0]!.work]) {
      expect(p.startsWith(`${SCRATCH}/rootfs/`)).toBe(false);
    }
  });

  it("gives upper the mode of a root the runner owns, without sudo", () => {
    const { calls, deps } = scratchDeps({ ...RUNNER, mode: 0o40750 });

    createOverlayScratchDirs(SCRATCH, ["/home/runner"], deps);

    expect(calls).toStrictEqual([
      ["mkdir", `${SLUG_DIR}/work`],
      ["mkdir", `${SLUG_DIR}/upper`],
      ["chmod", `${SLUG_DIR}/upper`, "750"],
    ]);
  });

  it("keeps an upper that already exists, as prepareNssDb makes $HOME's", () => {
    const { deps } = scratchDeps();
    const mkdir = ((p: string, options?: { recursive?: boolean }) => {
      if (p === `${SLUG_DIR}/upper` && !options?.recursive) throw new Error("EEXIST");
    }) as unknown as typeof import("node:fs").mkdirSync;

    expect(() =>
      createOverlayScratchDirs(SCRATCH, ["/home/runner"], { ...deps, mkdir }),
    ).not.toThrow();
  });

  it.each([
    { mode: 0o41777, octal: "1777" },
    { mode: 0o42775, octal: "2775" },
  ])(
    "makes upper through sudo with the owner and mode $octal of a root owned by another",
    ({ mode, octal }) => {
      const { calls, deps } = scratchDeps({ uid: 0, gid: 0, mode });

      createOverlayScratchDirs(SCRATCH, ["/home/runner"], deps);

      expect(calls).toStrictEqual([
        ["mkdir", `${SLUG_DIR}/work`],
        ["sudo", "install", "-d", "-o", "0", "-g", "0", "-m", octal, "--", `${SLUG_DIR}/upper`],
      ]);
    },
  );

  it("uses sudo when only the group differs", () => {
    const { calls, deps } = scratchDeps({ uid: RUNNER.uid, gid: 0, mode: 0o40775 });

    createOverlayScratchDirs(SCRATCH, ["/home/runner"], deps);

    expect(calls.at(-1)).toStrictEqual([
      "sudo",
      "install",
      "-d",
      "-o",
      "1001",
      "-g",
      "0",
      "-m",
      "775",
      "--",
      `${SLUG_DIR}/upper`,
    ]);
  });
});

describe("nestedMountRoots", () => {
  const ext4 = (...mountPoints: string[]) =>
    mountPoints.map((mountPoint) => ({ mountPoint, fsType: "ext4" }));
  /** Roots that are also the only candidates, none nested in another. */
  const only = (...roots: string[]) => ({ candidates: roots, roots });

  function warned(hostMounts: HostMount[], isDirectory: (path: string) => boolean = () => true) {
    const warnings: string[] = [];
    const roots = nestedMountRoots(only("/home/runner"), hostMounts, [], {
      isDirectory,
      warn: (message) => warnings.push(message),
    });
    return { roots, warnings };
  }

  it("returns every mount under a root, nested ones included, but not the roots themselves", () => {
    expect(
      nestedMountRoots(
        only("/home/runner", "/tmp"),
        ext4(
          "/",
          "/home/runner",
          "/home/runner/_tool",
          "/home/runner/_tool/node",
          "/tmp/x",
          "/opt",
        ),
        [],
        { isDirectory: () => true },
      ),
    ).toStrictEqual(["/home/runner/_tool", "/home/runner/_tool/node", "/tmp/x"]);
  });

  it("leaves a mount under write_through to that path's own rbind", () => {
    expect(
      nestedMountRoots(only("/home/runner"), ext4("/home/runner/out", "/home/runner/out/cache"), [
        "/home/runner/out",
      ]),
    ).toStrictEqual([]);
  });

  it("lists a mount point stacked more than once only once", () => {
    expect(
      nestedMountRoots(only("/home/runner"), ext4("/home/runner/_tool", "/home/runner/_tool"), [], {
        isDirectory: () => true,
      }),
    ).toStrictEqual(["/home/runner/_tool"]);
  });

  it("leaves a file mount hidden without a warning, since overlayfs cannot overlay one", () => {
    expect(
      warned(
        ext4("/home/runner/.gitconfig", "/home/runner/_tool"),
        (p) => p !== "/home/runner/.gitconfig",
      ),
    ).toStrictEqual({ roots: ["/home/runner/_tool"], warnings: [] });
  });

  it("warns and leaves hidden a FUSE mount without allow_other, which root cannot read", () => {
    const user = ["rw", "user_id=1001", "group_id=1001"];
    const { roots, warnings } = warned([
      { mountPoint: "/home/runner/remote", fsType: "fuse.sshfs", superOptions: user },
      { mountPoint: "/home/runner/ntfs", fsType: "fuseblk", superOptions: user },
      { mountPoint: "/home/runner/plain", fsType: "fuse" },
      { mountPoint: "/home/runner/_tool", fsType: "fusectl" },
    ]);

    expect(roots).toStrictEqual(["/home/runner/_tool"]);
    expect(warnings).toStrictEqual([
      'filesystem_mode: ephemeral cannot overlay the host mount "/home/runner/remote", so the ' +
        "command sees the empty directory beneath it: it is a FUSE mount (fuse.sshfs) without " +
        "allow_other, which root cannot read. Use filesystem_mode: persistent if the command " +
        "needs its contents.",
      expect.stringContaining('"/home/runner/ntfs"'),
      expect.stringContaining('"/home/runner/plain"'),
    ]);
  });

  it("overlays a FUSE mount made with allow_other", () => {
    expect(
      warned([
        {
          mountPoint: "/home/runner/remote",
          fsType: "fuse.sshfs",
          superOptions: ["rw", "user_id=1001", "group_id=1001", "allow_other"],
        },
      ]),
    ).toStrictEqual({ roots: ["/home/runner/remote"], warnings: [] });
  });

  it("judges a stacked mount point by the mount on top", () => {
    expect(
      warned([
        { mountPoint: "/home/runner/remote", fsType: "ext4" },
        { mountPoint: "/home/runner/remote", fsType: "fuse.rclone" },
      ]).roots,
    ).toStrictEqual([]);
  });

  it("warns and leaves hidden a mount whose path an overlay option cannot carry", () => {
    const { roots, warnings } = warned(ext4("/home/runner/a,b", "/home/runner/c:d"));

    expect(roots).toStrictEqual([]);
    expect(warnings).toStrictEqual([
      expect.stringContaining(
        '"/home/runner/a,b", so the command sees the empty directory ' +
          'beneath it: an overlay mount option cannot contain "," or ":".',
      ),
      expect.stringContaining('"/home/runner/c:d"'),
    ]);
  });

  // A mount point covered by a later mount, or one mountinfo marks //deleted.
  it("warns and leaves hidden a mount point it cannot stat", () => {
    const { roots, warnings } = warned(ext4("/home/runner/gone//deleted"), () => {
      throw new Error("ENOENT: no such file or directory");
    });

    expect(roots).toStrictEqual([]);
    expect(warnings).toStrictEqual([
      expect.stringContaining(
        "empty directory beneath it: the runner cannot stat it (ENOENT: no such file or directory).",
      ),
    ]);
  });

  describe("a mount it cannot overlay that is a candidate or holds one", () => {
    const sshfs = (mountPoint: string) => [{ mountPoint, fsType: "fuse.sshfs" }];
    const temp = ENV.RUNNER_TEMP;

    it("fails rather than hide a nested candidate", () => {
      const roots = { candidates: [ENV.HOME, temp], roots: [ENV.HOME] };
      expect(() => nestedMountRoots(roots, sshfs(temp), [])).toThrow(
        `cannot overlay the host mount "${temp}": it is a FUSE mount (fuse.sshfs) without ` +
          `allow_other, which root cannot read. Use filesystem_mode: persistent, or list ` +
          `"${temp}" in write_through.`,
      );
    });

    it("fails rather than hide a candidate that is an overlay root itself", () => {
      expect(() => nestedMountRoots(only("/tmp"), sshfs("/tmp"), [])).toThrow(
        'cannot overlay the host mount "/tmp": it is a FUSE mount',
      );
    });

    it("fails rather than hide a mount holding a candidate", () => {
      const roots = { candidates: [ENV.HOME, temp], roots: [ENV.HOME] };
      expect(() => nestedMountRoots(roots, sshfs("/home/runner/work"), [])).toThrow(
        `cannot overlay the host mount "/home/runner/work", which holds "${temp}": it is a FUSE`,
      );
    });
  });
});

describe("formatFilesystemPlanLog", () => {
  it("returns [] for persistent mode", () => {
    expect(formatFilesystemPlanLog("persistent", ["/home/runner"], ["/tmp/x"])).toStrictEqual([]);
  });

  it("lists the mode, folded overlay roots, then write_through entries for ephemeral mode", () => {
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

describe("createOverlayScratchDirs: directory names", () => {
  const name = (upper: string) => upper.split("/").at(-2)!;

  it("gives roots that differ only in / and _ their own directories", () => {
    const dirs = createOverlayScratchDirs(
      "/scratch",
      ["/a/b_c", "/a/b/c", "/a/b%5Fc"],
      scratchDeps().deps,
    );
    expect(new Set(dirs.map((d) => d.upper)).size).toBe(3);
  });

  it("keeps the name short for a root past the 255-byte name limit", () => {
    const roots = [`/mnt/${"d".repeat(300)}`, `/mnt/${"_".repeat(200)}`];
    const dirs = createOverlayScratchDirs("/scratch", roots, scratchDeps().deps);
    expect(dirs.map((d) => name(d.upper).length)).toStrictEqual([16, 16]);
  });
});

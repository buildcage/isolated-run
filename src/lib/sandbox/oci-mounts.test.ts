import { describe, it, expect } from "vitest";

import {
  ephemeralLayers,
  freshMountDestinationsFrom,
  hostRunCoverageLayers,
  persistentLayers,
  scratchBaseLayers,
  withHostShmSize,
  writableDirsOf,
  HOST_RUN_DIR,
  HOST_RUN_LOCK_DIR,
} from "./oci-mounts.ts";
import { SANDBOX_SCRATCH_BASE } from "./scratch-dir.ts";

describe("freshMountDestinationsFrom", () => {
  it("collects every mounts[].destination from the base spec", () => {
    const baseSpec = {
      mounts: [{ destination: "/proc" }, { destination: "/sys" }, { destination: "/dev/pts" }],
    };
    expect(freshMountDestinationsFrom(baseSpec)).toStrictEqual(
      new Set(["/proc", "/sys", "/dev/pts"]),
    );
  });
});

describe("withHostShmSize", () => {
  const shm = {
    destination: "/dev/shm",
    type: "tmpfs",
    source: "shm",
    options: ["nosuid", "noexec", "nodev", "mode=1777", "size=65536k"],
  };
  const other = { destination: "/dev", type: "tmpfs", source: "tmpfs", options: ["size=65536k"] };

  it("replaces runc's 64MB cap with the host's own /dev/shm size", () => {
    const [rewritten] = withHostShmSize([shm], 4 * 1024 * 1024 * 1024);
    expect(rewritten.options).toStrictEqual([
      "nosuid",
      "noexec",
      "nodev",
      "mode=1777",
      "size=4294967296",
    ]);
  });

  it("drops the cap entirely when the host's size is unknown, leaving the kernel default", () => {
    const [rewritten] = withHostShmSize([shm], undefined);
    expect(rewritten.options).toStrictEqual(["nosuid", "noexec", "nodev", "mode=1777"]);
  });

  it("adds the size to a /dev/shm entry that carries no options at all", () => {
    const [rewritten] = withHostShmSize(
      [{ destination: "/dev/shm", type: "tmpfs", source: "shm" }],
      1024,
    );
    expect(rewritten.options).toStrictEqual(["size=1024"]);
  });

  it("leaves every other mount alone, size= included", () => {
    // /dev is a separate tmpfs holding device nodes only; 64MB is ample there.
    expect(withHostShmSize([other], 1024)).toStrictEqual([other]);
  });
});

describe("writableDirsOf", () => {
  it("keeps workdir, home, /tmp and RUNNER_TEMP, plus whatever write_through named", () => {
    expect(
      writableDirsOf({
        workdir: "/home/runner/work/repo/repo",
        home: "/home/runner",
        runnerTemp: "/opt/actions-runner/_work/_temp",
        writablePaths: ["/var/cache/app"],
      }),
    ).toStrictEqual([
      "/home/runner/work/repo/repo",
      "/home/runner",
      "/tmp",
      "/opt/actions-runner/_work/_temp",
      "/var/cache/app",
    ]);
  });

  it("drops the ones the environment never set, rather than binding undefined", () => {
    expect(writableDirsOf({})).toStrictEqual(["/tmp"]);
  });

  it("dedupes, so a RUNNER_TEMP that is already a writable path is bound once", () => {
    // Nested under $HOME on a GitHub-hosted runner, and a write_through entry
    // may name it too. Either way it must not be bind-mounted twice.
    expect(
      writableDirsOf({ home: "/home/runner", runnerTemp: "/tmp", writablePaths: ["/home/runner"] }),
    ).toStrictEqual(["/home/runner", "/tmp"]);
  });
});

describe("persistentLayers", () => {
  const fresh = new Set(["/proc"]);

  it("binds each writable dir read-write and reports it as writable", () => {
    const { mounts, writablePaths } = persistentLayers(["/home/runner", "/tmp"], fresh, {
      disableReadonly: false,
    });
    expect(mounts).toStrictEqual([
      {
        destination: "/home/runner",
        type: "none",
        source: "/home/runner",
        options: ["rbind", "rw"],
      },
      { destination: "/tmp", type: "none", source: "/tmp", options: ["rbind", "rw"] },
    ]);
    expect(writablePaths).toStrictEqual(new Set(["/home/runner", "/tmp"]));
  });

  it("mounts nothing under `writable: /`, the whole root being writable already", () => {
    // Still reports the paths, since oci-protected-paths.ts reads them to
    // decide what not to force read-only.
    const { mounts, writablePaths } = persistentLayers(["/home/runner"], fresh, {
      disableReadonly: true,
    });
    expect(mounts).toStrictEqual([]);
    expect(writablePaths).toStrictEqual(new Set(["/home/runner"]));
  });

  it("refuses a writable dir inside a destination runc mounts fresh content at", () => {
    expect(() => persistentLayers(["/proc/sys"], fresh, { disableReadonly: false })).toThrow(
      /which the sandbox mounts itself/,
    );
  });
});

describe("ephemeralLayers", () => {
  const fresh = new Set(["/proc"]);
  const root = (path: string) => ({
    path,
    upper: `/scratch${path}/upper`,
    work: `/scratch${path}/work`,
  });

  it("stacks an overlay per root, lowerdir being the untouched host path", () => {
    const { mounts } = ephemeralLayers({ overlayRoots: [root("/home")], allowWrite: [] }, fresh);
    expect(mounts).toStrictEqual([
      {
        destination: "/home",
        type: "overlay",
        source: "overlay",
        options: ["lowerdir=/home", "upperdir=/scratch/home/upper", "workdir=/scratch/home/work"],
      },
    ]);
  });

  it("punches each write_through entry back through as a plain rw rbind", () => {
    const { mounts } = ephemeralLayers({ overlayRoots: [], allowWrite: ["/var/cache"] }, fresh);
    expect(mounts).toStrictEqual([
      { destination: "/var/cache", type: "none", source: "/var/cache", options: ["rbind", "rw"] },
    ]);
  });

  it("orders overlays shallow-first, then the write_through entries shallow-first", () => {
    // A deeper mount applied before the shallower one containing it would be
    // buried by it.
    const { mounts } = ephemeralLayers(
      {
        overlayRoots: [root("/home/runner/deep"), root("/home")],
        allowWrite: ["/home/runner/deep/allow", "/allow"],
      },
      fresh,
    );
    expect(mounts.map((m) => m.destination)).toStrictEqual([
      "/home",
      "/home/runner/deep",
      "/allow",
      "/home/runner/deep/allow",
    ]);
  });

  it("reports both the overlay roots and the write_through paths as writable", () => {
    const { writablePaths } = ephemeralLayers(
      { overlayRoots: [root("/home")], allowWrite: ["/var/cache"] },
      fresh,
    );
    expect(writablePaths).toStrictEqual(new Set(["/home", "/var/cache"]));
  });

  it("refuses a write_through entry inside a destination runc mounts fresh content at", () => {
    expect(() => ephemeralLayers({ overlayRoots: [], allowWrite: ["/proc/sys"] }, fresh)).toThrow(
      /which the sandbox mounts itself/,
    );
  });

  it("refuses a root whose host path carries an overlay option delimiter", () => {
    for (const bad of ["/home/a,b", "/home/a:b"]) {
      expect(() => ephemeralLayers({ overlayRoots: [root(bad)], allowWrite: [] }, fresh)).toThrow(
        /an overlay mount option cannot contain/,
      );
    }
  });

  it("refuses a root whose upper/work path carries a delimiter", () => {
    expect(() =>
      ephemeralLayers(
        {
          overlayRoots: [{ path: "/home", upper: "/scratch/a:b/upper", work: "/scratch/work" }],
          allowWrite: [],
        },
        fresh,
      ),
    ).toThrow(/"\/scratch\/a:b\/upper"/);
  });
});

describe("scratchBaseLayers", () => {
  const execDir = `${SANDBOX_SCRATCH_BASE}/sandbox-xyz/exec`;

  it("covers the scratch base with an empty tmpfs the sandbox can only traverse", () => {
    const [mask] = scratchBaseLayers(execDir);
    expect(mask).toStrictEqual({
      destination: SANDBOX_SCRATCH_BASE,
      type: "tmpfs",
      source: "tmpfs",
      options: ["nosuid", "nodev", "mode=0555"],
    });
  });

  it("reveals this run's own execDir again, after the mask", () => {
    const layers = scratchBaseLayers(execDir);
    expect(layers.map((m) => m.destination)).toStrictEqual([SANDBOX_SCRATCH_BASE, execDir]);
  });

  it("reveals it with `bind`, never `rbind`, which would pull in the whole host /", () => {
    const [, reveal] = scratchBaseLayers(execDir);
    expect(reveal.options).toStrictEqual(["bind", "ro"]);
  });
});

describe("hostRunCoverageLayers", () => {
  it("covers /run with an empty tmpfs, then recreates a writable /run/lock", () => {
    const { mounts } = hostRunCoverageLayers();
    expect(mounts).toStrictEqual([
      {
        destination: HOST_RUN_DIR,
        type: "tmpfs",
        source: "tmpfs",
        options: ["nosuid", "nodev", "mode=0755"],
      },
      {
        destination: HOST_RUN_LOCK_DIR,
        type: "tmpfs",
        source: "tmpfs",
        options: ["nosuid", "nodev", "noexec", "mode=1777", "size=5242880"],
      },
    ]);
  });

  it("mounts /run before /run/lock, so the lock has its parent to mount onto", () => {
    const { mounts } = hostRunCoverageLayers();
    expect(mounts.map((m) => m.destination)).toStrictEqual([HOST_RUN_DIR, HOST_RUN_LOCK_DIR]);
  });

  it("reports /run/lock as writable so it isn't forced read-only again", () => {
    const { writablePaths } = hostRunCoverageLayers();
    expect(writablePaths).toStrictEqual(new Set([HOST_RUN_LOCK_DIR]));
  });
});

import { describe, it, expect } from "vitest";

import {
  determineOverlayRoots,
  createOverlayScratchDirs,
  formatFilesystemPlanLog,
} from "./ephemeral-fs.ts";

const ENV = {
  HOME: "/home/runner",
  GITHUB_WORKSPACE: "/home/runner/work/repo/repo",
  RUNNER_TEMP: "/home/runner/work/_temp",
};

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

  it("excludes a candidate that is itself named in write_through", () => {
    const candidates = [ENV.HOME, "/tmp"];
    expect(
      determineOverlayRoots(candidates, [ENV.HOME], { exists, deviceOf: sameDevice }),
    ).toStrictEqual([{ path: "/tmp" }]);
  });

  it("keeps a candidate that is only an ancestor of a narrower write_through entry (the entry's own rw bind persists just that subtree on top -- see buildOciConfig's mount ordering)", () => {
    const candidates = [ENV.HOME, "/tmp"];
    expect(
      determineOverlayRoots(candidates, [`${ENV.HOME}/.npmrc`], { exists, deviceOf: sameDevice }),
    ).toStrictEqual([{ path: ENV.HOME }, { path: "/tmp" }]);
  });

  it("excludes a candidate that is a descendant of a broader write_through entry", () => {
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

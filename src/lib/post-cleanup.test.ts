import { describe, it, expect, vi, type Mock } from "vitest";

import type { Annotation } from "#core/lib/actions/annotation.ts";

import { planPostCleanup, reclaimCaPlaceholder, type PostCleanupDeps } from "./post-cleanup.ts";
import { OWN_CA_DESTINATION } from "./sandbox/ca-trust.ts";
import { scratchDirFor } from "./sandbox/scratch-dir.ts";

/** A minimal fs.Stats standing in for lstat's return. */
function statLike(isFile: boolean, size: number): import("node:fs").Stats {
  return { isFile: () => isFile, size } as import("node:fs").Stats;
}

const CONTAINER = "buildcage-proxy-deadbeef";
const STATE = { containerName: CONTAINER, ephemeralRoots: "" };

/** A real Actions step's environment, which ownerToken joins into a token. */
const ENV = {
  GITHUB_RUN_ID: "1",
  GITHUB_RUN_ATTEMPT: "1",
  GITHUB_JOB: "build",
  GITHUB_ACTION: "buildcage",
};
const OWNER = "1/1/build/buildcage";

/** The emitter the entry point supplies; asserted on directly rather than
 *  through a console.log spy. */
function annotation(): Annotation & { error: Mock; warning: Mock } {
  return { notice: vi.fn(), warning: vi.fn(), error: vi.fn() };
}

function deps(overrides: PostCleanupDeps = {}): {
  deps: PostCleanupDeps;
  removed: { dir: string; ephemeralRoots?: string[] }[];
} {
  const removed: { dir: string; ephemeralRoots?: string[] }[] = [];
  return {
    removed,
    deps: {
      readOwner: () => OWNER,
      fileExists: () => true,
      removeScratchDir: (dir, { ephemeralRoots }) => removed.push({ dir, ephemeralRoots }),
      reclaimCaPlaceholder: () => {},
      ...overrides,
    },
  };
}

describe("planPostCleanup", () => {
  it("reclaims the scratch dir and hands back the container to stop", () => {
    const { deps: d, removed } = deps();
    const note = annotation();

    const targets = planPostCleanup(STATE, ENV, note, d);

    expect(targets).toStrictEqual({
      containerName: CONTAINER,
      projectName: expect.any(String) as string,
    });
    expect(removed).toStrictEqual([{ dir: scratchDirFor(CONTAINER), ephemeralRoots: undefined }]);
  });

  it("passes the ephemeral roots on, so the discarded writes can be logged", () => {
    const { deps: d, removed } = deps();
    const note = annotation();

    planPostCleanup({ ...STATE, ephemeralRoots: '["/usr","/etc"]' }, ENV, note, d);

    expect(removed[0].ephemeralRoots).toStrictEqual(["/usr", "/etc"]);
  });

  it("does nothing at all when the step was never reached", () => {
    const { deps: d, removed } = deps();
    const note = annotation();

    expect(planPostCleanup({ containerName: "", ephemeralRoots: "" }, ENV, note, d)).toBeNull();
    expect(removed).toStrictEqual([]);
    expect(note.error).not.toHaveBeenCalled();
    expect(note.warning).not.toHaveBeenCalled();
  });

  it("reports a state value this action could not have written, and stops", () => {
    const { deps: d, removed } = deps();
    const note = annotation();

    const targets = planPostCleanup({ containerName: "/etc", ephemeralRoots: "" }, ENV, note, d);

    expect(targets).toBeNull();
    expect(removed).toStrictEqual([]);
    expect(note.error.mock.calls[0][0]).toContain("run post-cleanup:");
  });

  it("tears down nothing when the container belongs to a different step", () => {
    const { deps: d, removed } = deps({ readOwner: () => "9/1/other/buildcage" });
    const note = annotation();

    expect(planPostCleanup(STATE, ENV, note, d)).toBeNull();
    expect(removed).toStrictEqual([]);
    expect(note.error.mock.calls[0][0]).toContain("was started by a different step");
  });

  it("treats a name with no container left behind as this step's leftovers", () => {
    const { deps: d, removed } = deps({ readOwner: () => null });
    const note = annotation();

    expect(planPostCleanup(STATE, ENV, note, d)).not.toBeNull();
    expect(removed).toHaveLength(1);
  });

  it("leaves nothing to remove when the scratch dir is already gone", () => {
    const { deps: d, removed } = deps({ fileExists: () => false });
    const note = annotation();

    expect(planPostCleanup(STATE, ENV, note, d)).not.toBeNull();
    expect(removed).toStrictEqual([]);
  });

  it("still stops the container when the scratch dir cannot be removed", () => {
    const note = annotation();
    const { deps: d } = deps({
      removeScratchDir: () => {
        throw new Error("device or resource busy");
      },
    });

    expect(planPostCleanup(STATE, ENV, note, d)).not.toBeNull();
    expect(note.warning).toHaveBeenCalledWith(
      "run post-cleanup: failed to remove sandbox scratch dir: device or resource busy",
    );
  });

  it("lets a docker failure through, since ownership cannot be established", () => {
    const note = annotation();
    const { deps: d } = deps({
      readOwner: () => {
        throw new Error("docker daemon is not running");
      },
    });

    expect(() => planPostCleanup(STATE, ENV, note, d)).toThrow("docker daemon is not running");
  });

  // cleanupScratchDir has its own warning to report (a mount it could not
  // detach), and must not pick its own emitter either.
  it("hands the scratch dir cleanup the same emitter", () => {
    const calls: { warn?: (message: string) => void }[] = [];
    const note = annotation();
    const { deps: d } = deps({
      removeScratchDir: (_dir, options) => calls.push(options),
    });

    planPostCleanup(STATE, ENV, note, d);

    expect(calls[0].warn).toBe(note.warning);
  });

  it("reclaims the CA placeholder with the same emitter", () => {
    const note = annotation();
    const warns: ((message: string) => void)[] = [];
    const { deps: d } = deps({ reclaimCaPlaceholder: (warn) => warns.push(warn) });

    planPostCleanup(STATE, ENV, note, d);

    expect(warns).toStrictEqual([note.warning]);
  });
});

describe("reclaimCaPlaceholder", () => {
  const warn = vi.fn();

  it("removes the placeholder while it is still the empty file this run created", () => {
    const exec = vi.fn();
    reclaimCaPlaceholder(warn, { lstat: () => statLike(true, 0), exec });

    expect(exec).toHaveBeenCalledWith("sudo", ["-n", "rm", "-f", OWN_CA_DESTINATION]);
    expect(warn).not.toHaveBeenCalled();
  });

  it("runs no privileged command when nothing is there (universal, or a clean exit)", () => {
    const exec = vi.fn();
    reclaimCaPlaceholder(warn, {
      lstat: () => {
        throw Object.assign(new Error("ENOENT"), { code: "ENOENT" });
      },
      exec,
    });

    expect(exec).not.toHaveBeenCalled();
  });

  it("leaves a non-empty file at the reserved path untouched", () => {
    const exec = vi.fn();
    reclaimCaPlaceholder(warn, { lstat: () => statLike(true, 12), exec });

    expect(exec).not.toHaveBeenCalled();
  });

  it("does not follow a symlink sitting at the reserved path", () => {
    const exec = vi.fn();
    reclaimCaPlaceholder(warn, { lstat: () => statLike(false, 0), exec });

    expect(exec).not.toHaveBeenCalled();
  });

  it("warns rather than throws when the privileged removal fails", () => {
    const localWarn = vi.fn();
    reclaimCaPlaceholder(localWarn, {
      lstat: () => statLike(true, 0),
      exec: () => {
        throw new Error("sudo: a password is required");
      },
    });

    expect(localWarn).toHaveBeenCalledWith(
      `run post-cleanup: failed to remove the CA placeholder ${OWN_CA_DESTINATION}: sudo: a password is required`,
    );
  });
});

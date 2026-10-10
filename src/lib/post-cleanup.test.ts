import { describe, it, expect, vi, type Mock } from "vitest";

import type { Annotation } from "#core/lib/actions/annotation.ts";

import { planPostCleanup, type PostCleanupDeps } from "./post-cleanup.ts";
import { filesystemAuditPaths } from "./sandbox/filesystem-audit.ts";
import { SANDBOX_SCRATCH_BASE, scratchDirFor } from "./sandbox/scratch-dir.ts";

const CONTAINER = "buildcage-proxy-deadbeef";
const STATE = { containerName: CONTAINER, ephemeralRoots: "" };
const AUDIT = filesystemAuditPaths(CONTAINER, SANDBOX_SCRATCH_BASE);

/** A real Actions step's environment, which ownerToken joins into a token. */
const ENV = {
  GITHUB_RUN_ID: "1",
  GITHUB_RUN_ATTEMPT: "1",
  GITHUB_JOB: "build",
  GITHUB_ACTION: "buildcage",
  RUNNER_TEMP: "/runner-1/_work/_temp",
};
const OWNER = "1/1/build/buildcage//runner-1/_work/_temp";

/** The emitter the entry point supplies; asserted on directly rather than
 *  through a console.log spy. */
function annotation(): Annotation & { error: Mock; warning: Mock } {
  return { notice: vi.fn(), warning: vi.fn(), error: vi.fn() };
}

function deps(overrides: PostCleanupDeps = {}): {
  deps: PostCleanupDeps;
  removed: { dir: string; ephemeralRoots?: string[] }[];
  released: string[];
  killed: number[];
  removedFiles: string[];
} {
  const removed: { dir: string; ephemeralRoots?: string[] }[] = [];
  const released: string[] = [];
  const killed: number[] = [];
  const removedFiles: string[] = [];
  return {
    removed,
    released,
    killed,
    removedFiles,
    deps: {
      readOwner: () => OWNER,
      // The tracer pidfile is absent unless a test sets it.
      fileExists: (p) => p !== AUDIT.pidFilePath && !removed.some((r) => r.dir === p),
      removeScratchDir: (dir, { ephemeralRoots }) => {
        removed.push({ dir, ephemeralRoots });
        released.push("after the scratch dir");
      },
      releaseNssDb: (name) => released.push(`nssdb:${name}`),
      // The pidfile holds the pid; /proc/<pid>/comm identifies it as the tracer.
      readFile: (p) => (p === AUDIT.pidFilePath ? "4321\n" : "filesystem-audi\n"),
      killTracer: (pid) => killed.push(pid),
      removeFile: (p) => removedFiles.push(p),
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

  it("ends the step's uses of the directories Buildcage made, after the scratch dir", () => {
    const { deps: d, released } = deps();

    planPostCleanup(STATE, ENV, annotation(), d);

    expect(released).toStrictEqual(["after the scratch dir", "nssdb:sandbox-deadbeef"]);
  });

  it("leaves the uses registered when the scratch dir cannot be removed", () => {
    const { deps: d, released } = deps({
      removeScratchDir: () => {
        throw new Error("device or resource busy");
      },
    });

    planPostCleanup(STATE, ENV, annotation(), d);

    expect(released).toStrictEqual([]);
  });

  it("leaves the uses registered when the scratch dir is still there after its removal", () => {
    const { deps: d, released } = deps({ fileExists: () => true });

    planPostCleanup(STATE, ENV, annotation(), d);

    expect(released).toStrictEqual(["after the scratch dir"]);
  });

  it("ends the uses when the scratch dir was already gone", () => {
    const { deps: d, released } = deps({ fileExists: () => false });

    planPostCleanup(STATE, ENV, annotation(), d);

    expect(released).toStrictEqual(["nssdb:sandbox-deadbeef"]);
  });

  it("releases nothing when the container belongs to a different step", () => {
    const { deps: d, released } = deps({ readOwner: () => "9/1/other/buildcage" });

    planPostCleanup(STATE, ENV, annotation(), d);

    expect(released).toStrictEqual([]);
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

  it("stops a tracer a cancel orphaned and removes its files", () => {
    const { deps: d, killed, removedFiles } = deps({ fileExists: () => true });

    planPostCleanup(STATE, ENV, annotation(), d);

    expect(killed).toStrictEqual([4321]);
    expect(removedFiles).toStrictEqual(expect.arrayContaining([AUDIT.pidFilePath, AUDIT.outPath]));
  });

  it("does not signal a pid that is no longer the tracer", () => {
    const {
      deps: d,
      killed,
      removedFiles,
    } = deps({
      fileExists: () => true,
      // The pid is gone (or reused), so /proc/<pid>/comm no longer reads ours.
      readFile: (p) => {
        if (p === AUDIT.pidFilePath) return "4321\n";
        throw new Error("ESRCH");
      },
    });

    planPostCleanup(STATE, ENV, annotation(), d);

    expect(killed).toStrictEqual([]);
    expect(removedFiles).toContain(AUDIT.pidFilePath);
  });

  it("keeps reclaiming the scratch dir when the audit cleanup throws", () => {
    const note = annotation();
    const { deps: d, released } = deps({
      fileExists: () => true,
      removeFile: () => {
        throw new Error("EBUSY");
      },
    });

    planPostCleanup(STATE, ENV, note, d);

    expect(note.warning).toHaveBeenCalledWith(
      "run post-cleanup: filesystem_audit cleanup failed: EBUSY",
    );
    expect(released).toContain("after the scratch dir");
  });

  it("only clears the audit output when the tracer was already stopped", () => {
    const { deps: d, killed, removedFiles } = deps();

    planPostCleanup(STATE, ENV, annotation(), d);

    expect(killed).toStrictEqual([]);
    expect(removedFiles).toStrictEqual([AUDIT.outPath, AUDIT.stepPath]);
  });

  it("warns but carries on when a pidfile holds no usable pid", () => {
    const note = annotation();
    const { deps: d, killed } = deps({ fileExists: () => true, readFile: () => "not-a-pid" });

    planPostCleanup(STATE, ENV, note, d);

    expect(killed).toStrictEqual([]);
    expect(note.warning).not.toHaveBeenCalled(); // a non-numeric pid is skipped, not an error
  });

  it("warns and still removes the files when stopping the tracer fails", () => {
    const note = annotation();
    const { deps: d, removedFiles } = deps({
      fileExists: () => true,
      killTracer: () => {
        throw new Error("no such process");
      },
    });

    planPostCleanup(STATE, ENV, note, d);

    expect(note.warning).toHaveBeenCalledWith(
      "run post-cleanup: failed to stop the file-audit tracer: no such process",
    );
    expect(removedFiles).toStrictEqual(expect.arrayContaining([AUDIT.pidFilePath, AUDIT.outPath]));
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
});

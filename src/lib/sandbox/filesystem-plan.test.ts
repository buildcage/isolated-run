import { describe, it, expect, vi } from "vitest";

import { resolveFilesystemPlan, validateFilesystemInputs } from "./filesystem-plan.ts";
import { SandboxError } from "../errors.ts";
import { RESERVED_INTERNAL_DESTINATIONS } from "./oci-mounts.ts";
import { SANDBOX_SCRATCH_BASE } from "./scratch-dir.ts";

describe("resolveFilesystemPlan", () => {
  const ENV = {
    HOME: "/home/runner",
    GITHUB_WORKSPACE: "/home/runner/work/repo/repo",
    RUNNER_TEMP: "/home/runner/work/_temp",
  };
  // Everything "exists" by default (candidates + write_through targets) unless
  // a test narrows it, which keeps each test focused on the one thing it checks.
  const alwaysExists = () => true;

  it("returns an empty plan for persistent mode with no write_through:, without touching the filesystem", () => {
    const exists = vi.fn(alwaysExists);
    const plan = resolveFilesystemPlan("persistent", "", ENV, { exists });
    expect(plan).toStrictEqual({ overlayRoots: [], writeThroughPaths: [], createdDirs: [] });
    expect(exists).not.toHaveBeenCalled();
  });

  it("resolves write_through: in persistent mode too, normalizing each entry", () => {
    const plan = resolveFilesystemPlan("persistent", "./dist\n/opt/./cache/\n", ENV, {
      exists: alwaysExists,
    });
    expect(plan.writeThroughPaths).toStrictEqual([`${ENV.GITHUB_WORKSPACE}/dist`, "/opt/cache"]);
    expect(plan.overlayRoots).toStrictEqual([]);
  });

  it("pre-creates a missing write_through target in persistent mode and reports what it created", () => {
    const execFileCalls: string[][] = [];
    const plan = resolveFilesystemPlan("persistent", "/opt/build-output", ENV, {
      exists: (p) => p !== "/opt/build-output",
      stat: () => ({ uid: 1000, gid: 1000, mode: 0o40755 }),
      execFile: (cmd, args) => execFileCalls.push([cmd, ...args]),
    });
    expect(execFileCalls[0]).toStrictEqual([
      "sudo",
      "-u",
      "#1000",
      "-g",
      "#1000",
      "mkdir",
      "-p",
      "-m",
      "755",
      "/opt/build-output",
    ]);
    expect(plan.createdDirs).toStrictEqual([{ path: "/opt/build-output", uid: 1000, gid: 1000 }]);
  });

  it("skips the guard and creates nothing for the / sentinel", () => {
    const exists = vi.fn(alwaysExists);
    const plan = resolveFilesystemPlan("persistent", "/", ENV, { exists });
    expect(plan).toStrictEqual({ overlayRoots: [], writeThroughPaths: ["/"], createdDirs: [] });
    expect(exists).not.toHaveBeenCalled();
  });

  it("throws FILESYSTEM_INPUT_CONFLICT for write_through: / in ephemeral mode", () => {
    expect.assertions(2);
    try {
      resolveFilesystemPlan("ephemeral", "/", ENV);
    } catch (err) {
      expect(err).toBeInstanceOf(SandboxError);
      expect((err as SandboxError).code).toBe("FILESYSTEM_INPUT_CONFLICT");
    }
  });

  it("rejects a spelling that only resolves to the / sentinel, in either mode", () => {
    // Unchecked, these would drop the read-only restriction wholesale under
    // persistent and leave ephemeral with no overlay roots at all.
    for (const mode of ["persistent", "ephemeral"] as const) {
      for (const spelling of ["/.", "//", `${ENV.GITHUB_WORKSPACE}/../../../../..`]) {
        let caught: unknown;
        try {
          resolveFilesystemPlan(mode, spelling, ENV);
        } catch (err) {
          caught = err;
        }
        expect(caught).toBeInstanceOf(SandboxError);
        expect((caught as SandboxError).code).toBe("INVALID_WRITE_THROUGH_PATH");
      }
    }
  });

  it("rejects a path overlapping the sandbox's own scratch base before creating anything", () => {
    const execFile = vi.fn();
    expect.assertions(3);
    try {
      resolveFilesystemPlan("persistent", `${SANDBOX_SCRATCH_BASE}/x`, ENV, {
        exists: () => false,
        stat: () => ({ uid: 1000, gid: 1000, mode: 0o40755 }),
        execFile,
      });
    } catch (err) {
      expect(err).toBeInstanceOf(SandboxError);
      expect((err as SandboxError).code).toBe("FILESYSTEM_INPUT_CONFLICT");
    }
    expect(execFile).not.toHaveBeenCalled();
  });

  it("catches an overlap that only normalization reveals", () => {
    expect(() =>
      resolveFilesystemPlan("persistent", `${SANDBOX_SCRATCH_BASE}/./x`, ENV, {
        exists: alwaysExists,
      }),
    ).toThrow(/overlaps/);
  });

  it("accepts an empty write_through: in ephemeral mode silently (maximum isolation is a valid choice)", () => {
    const plan = resolveFilesystemPlan("ephemeral", "", ENV, {
      exists: alwaysExists,
      deviceOf: () => 1,
    });
    expect(plan.writeThroughPaths).toStrictEqual([]);
    // RUNNER_TEMP is nested under HOME in this fixture's ENV (as on a real
    // GitHub-hosted runner), so it folds away; GITHUB_WORKSPACE is also
    // nested under HOME here, so it folds away too: only HOME and /tmp
    // are left.
    expect(plan.overlayRoots.sort()).toStrictEqual([ENV.HOME, "/tmp"].sort());
  });

  it("resolves and pre-creates write_through targets, then excludes only what's actually covered by them", () => {
    // Self-hosted-style ENV: GITHUB_WORKSPACE isn't nested under HOME here, so
    // its own overlay survives folding. That is what lets this exercise, end to
    // end, a candidate that merely contains a narrower write_through entry.
    const selfHostedEnv = { ...ENV, GITHUB_WORKSPACE: "/workspace" };
    const execFileCalls: string[][] = [];
    const plan = resolveFilesystemPlan("ephemeral", "./dist", selfHostedEnv, {
      exists: (p) => p !== "/workspace/dist",
      stat: () => ({ uid: 1000, gid: 1000, mode: 0o40755 }),
      execFile: (cmd, args) => execFileCalls.push([cmd, ...args]),
      deviceOf: () => 1,
    });
    expect(plan.writeThroughPaths).toStrictEqual(["/workspace/dist"]);
    expect(execFileCalls[0]).toStrictEqual([
      "sudo",
      "-u",
      "#1000",
      "-g",
      "#1000",
      "mkdir",
      "-p",
      "-m",
      "755",
      "/workspace/dist",
    ]);
    // RUNNER_TEMP still folds away under HOME as usual; GITHUB_WORKSPACE
    // keeps its own overlay since it isn't nested under HOME here.
    expect(plan.overlayRoots.sort()).toStrictEqual([ENV.HOME, "/tmp", "/workspace"].sort());
  });

  it("wraps a missing well-known runner file as WRITE_THROUGH_TARGET_MISSING", () => {
    const envWithOutput = { ...ENV, GITHUB_OUTPUT: "/home/runner/_temp/set_output" };
    expect.assertions(2);
    try {
      resolveFilesystemPlan("ephemeral", "$GITHUB_OUTPUT", envWithOutput, {
        exists: () => false,
      });
    } catch (err) {
      expect(err).toBeInstanceOf(SandboxError);
      expect((err as SandboxError).code).toBe("WRITE_THROUGH_TARGET_MISSING");
    }
  });

  it("wraps a sudo mkdir/chown/chmod failure as WRITE_THROUGH_TARGET_UNCREATABLE", () => {
    expect.assertions(2);
    try {
      resolveFilesystemPlan("ephemeral", "./dist", ENV, {
        exists: (p) => p !== `${ENV.GITHUB_WORKSPACE}/dist`,
        stat: () => ({ uid: 1000, gid: 1000, mode: 0o40755 }),
        execFile: () => {
          throw new Error("sudo: a password is required");
        },
      });
    } catch (err) {
      expect(err).toBeInstanceOf(SandboxError);
      expect((err as SandboxError).code).toBe("WRITE_THROUGH_TARGET_UNCREATABLE");
    }
  });

  it("wraps any other pre-creation failure as INVALID_WRITE_THROUGH_PATH", () => {
    expect.assertions(2);
    try {
      resolveFilesystemPlan("ephemeral", "./dist", ENV, {
        exists: () => {
          throw new Error("EACCES: permission denied");
        },
      });
    } catch (err) {
      expect(err).toBeInstanceOf(SandboxError);
      expect((err as SandboxError).code).toBe("INVALID_WRITE_THROUGH_PATH");
    }
  });

  it("wraps an unsupported $VAR in write_through: as INVALID_WRITE_THROUGH_PATH", () => {
    expect.assertions(2);
    try {
      resolveFilesystemPlan("ephemeral", "$SECRET_TOKEN/x", ENV);
    } catch (err) {
      expect(err).toBeInstanceOf(SandboxError);
      expect((err as SandboxError).code).toBe("INVALID_WRITE_THROUGH_PATH");
    }
  });

  it("wraps a determineOverlayRoots failure as FILESYSTEM_PLAN_FAILED, not a write_through problem", () => {
    // exists() throwing here isn't about write_through's own input at all:
    // it's determineOverlayRoots reading one of the fixed candidate paths
    // (e.g. a permissions error on $HOME), so it must not come back
    // labeled as a write_through syntax issue.
    expect.assertions(2);
    try {
      resolveFilesystemPlan("ephemeral", "", ENV, {
        exists: () => {
          throw new Error("EACCES: permission denied");
        },
      });
    } catch (err) {
      expect(err).toBeInstanceOf(SandboxError);
      expect((err as SandboxError).code).toBe("FILESYSTEM_PLAN_FAILED");
    }
  });
});

describe("validateFilesystemInputs", () => {
  it("throws FILESYSTEM_INPUT_CONFLICT for write_through: / in ephemeral mode", () => {
    expect.assertions(2);
    try {
      validateFilesystemInputs("ephemeral", ["/"]);
    } catch (err) {
      expect(err).toBeInstanceOf(SandboxError);
      expect((err as SandboxError).code).toBe("FILESYSTEM_INPUT_CONFLICT");
    }
  });

  it("finds the / sentinel among other entries, not just on its own", () => {
    expect(() => validateFilesystemInputs("ephemeral", ["./dist", "/"])).toThrow(SandboxError);
  });

  it("allows the / sentinel in persistent mode, and ordinary paths in either", () => {
    expect(() => validateFilesystemInputs("persistent", ["/"])).not.toThrow();
    expect(() => validateFilesystemInputs("persistent", ["/opt/cache"])).not.toThrow();
    expect(() => validateFilesystemInputs("ephemeral", ["./dist"])).not.toThrow();
    expect(() => validateFilesystemInputs("persistent", [])).not.toThrow();
    expect(() => validateFilesystemInputs("ephemeral", [])).not.toThrow();
  });

  it.each(RESERVED_INTERNAL_DESTINATIONS)("rejects the reserved path %s in either mode", (path) => {
    expect(() => validateFilesystemInputs("persistent", [path])).toThrow(/reserved/);
    expect(() => validateFilesystemInputs("ephemeral", [path])).toThrow(/reserved/);
  });

  // The CA paths are only really mounted by the inspect engine, but this
  // function never sees the engine: an input accepted under one engine and
  // refused under another would be worse than refusing it everywhere.
  it("rejects a path under a reserved one", () => {
    expect(() => validateFilesystemInputs("persistent", ["/etc/resolv.conf/x"])).toThrow(
      /reserved/,
    );
  });

  it("allows a directory containing a reserved path, which the reserved mount is layered over", () => {
    expect(() => validateFilesystemInputs("persistent", ["/etc"])).not.toThrow();
    expect(() => validateFilesystemInputs("ephemeral", ["/etc/ssl/certs"])).not.toThrow();
  });

  it("names the offending entry and the reserved path it collides with", () => {
    expect(() => validateFilesystemInputs("persistent", ["/etc/resolv.conf"])).toThrow(
      /"\/etc\/resolv\.conf"/,
    );
  });

  it("rejects /run and paths under it, which the empty-tmpfs coverage would shadow", () => {
    for (const path of ["/run", "/run/lock", "/run/myapp/sock"]) {
      expect(() => validateFilesystemInputs("persistent", [path])).toThrow(/\/run/);
      expect(() => validateFilesystemInputs("ephemeral", [path])).toThrow(/\/run/);
    }
  });

  it("still allows /, the read-only opt-out, which only contains /run rather than being under it", () => {
    expect(() => validateFilesystemInputs("persistent", ["/"])).not.toThrow();
  });
});

import { describe, it, expect, vi } from "vitest";

import { SandboxError } from "../errors.ts";
import { resolveFilesystemPlan, validateFilesystemInputs } from "./filesystem-plan.ts";
import { reservedInternalDestinations } from "./oci-mounts.ts";
import { SANDBOX_SCRATCH_BASE } from "./scratch-dir.ts";

// /proc/self/mountinfo is Linux-only, so the default listHostMounts is mocked.
vi.mock("./mountinfo.ts", () => ({
  listHostMounts: () => [{ mountPoint: "/home/runner/remote", fsType: "fuse.sshfs" }],
}));

describe("resolveFilesystemPlan", () => {
  const ENV = {
    HOME: "/home/runner",
    GITHUB_WORKSPACE: "/home/runner/work/repo/repo",
    RUNNER_TEMP: "/home/runner/work/_temp",
  };
  // Everything "exists" by default (candidates + write_through targets) unless
  // a test narrows it, which keeps each test focused on the one thing it checks.
  const alwaysExists = () => true;
  const notLink = () => ({ isSymbolicLink: () => false });

  it("returns an empty plan for persistent mode with no write_through:, without touching the filesystem", () => {
    const exists = vi.fn(alwaysExists);
    const plan = resolveFilesystemPlan("persistent", "", ENV, { exists });
    expect(plan).toStrictEqual({ overlayRoots: [], writeThroughPaths: [] });
    expect(exists).not.toHaveBeenCalled();
  });

  it("resolves write_through: in persistent mode too, normalizing each entry", () => {
    const plan = resolveFilesystemPlan("persistent", "./dist\n/opt/./cache/\n", ENV, {
      exists: alwaysExists,
      realpath: (p) => p,
      lstat: notLink,
    });
    expect(plan.writeThroughPaths).toStrictEqual([`${ENV.GITHUB_WORKSPACE}/dist`, "/opt/cache"]);
    expect(plan.overlayRoots).toStrictEqual([]);
  });

  it("pre-creates a missing write_through target in persistent mode", () => {
    const mkdir = vi.fn();
    resolveFilesystemPlan("persistent", "/opt/build-output", ENV, {
      exists: (p) => p !== "/opt/build-output",
      lstat: notLink,
      canWrite: () => true,
      mkdir,
    });
    expect(mkdir.mock.calls).toStrictEqual([["/opt/build-output"]]);
  });

  it("skips the guard and creates nothing for the / sentinel", () => {
    const exists = vi.fn(alwaysExists);
    const plan = resolveFilesystemPlan("persistent", "/", ENV, { exists });
    expect(plan).toStrictEqual({ overlayRoots: [], writeThroughPaths: ["/"] });
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
    const mkdir = vi.fn();
    expect.assertions(3);
    try {
      resolveFilesystemPlan("persistent", `${SANDBOX_SCRATCH_BASE}/x`, ENV, {
        exists: () => false,
        lstat: notLink,
        mkdir,
      });
    } catch (err) {
      expect(err).toBeInstanceOf(SandboxError);
      expect((err as SandboxError).code).toBe("FILESYSTEM_INPUT_CONFLICT");
    }
    expect(mkdir).not.toHaveBeenCalled();
  });

  describe("the file a CA store candidate really is", () => {
    const REAL_STORE = "/etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem";
    // As on Fedora, where the candidates are symlinks into ca-trust.
    const realpath = (p: string) => (p === "/etc/ssl/cert.pem" ? REAL_STORE : p);

    it("is reserved like the candidate itself", () => {
      expect(() =>
        resolveFilesystemPlan("persistent", REAL_STORE, ENV, {
          exists: alwaysExists,
          lstat: notLink,
          realpath,
        }),
      ).toThrow(expect.objectContaining({ code: "FILESYSTEM_INPUT_CONFLICT" }));
    });

    it("leaves a directory containing it allowed", () => {
      const plan = resolveFilesystemPlan("persistent", "/etc/pki/ca-trust", ENV, {
        exists: alwaysExists,
        lstat: notLink,
        realpath,
      });
      expect(plan.writeThroughPaths).toStrictEqual(["/etc/pki/ca-trust"]);
    });
  });

  it("refuses an entry through a symlink as INVALID_WRITE_THROUGH_PATH, before creating anything", () => {
    const mkdir = vi.fn();
    expect.assertions(3);
    try {
      resolveFilesystemPlan("ephemeral", "./cache", ENV, {
        exists: alwaysExists,
        realpath: (p) => p,
        lstat: (p) => ({ isSymbolicLink: () => p === `${ENV.GITHUB_WORKSPACE}/cache` }),
        readlink: () => ENV.RUNNER_TEMP,
        mkdir,
      });
    } catch (err) {
      expect(err).toBeInstanceOf(SandboxError);
      expect((err as SandboxError).code).toBe("INVALID_WRITE_THROUGH_PATH");
    }
    expect(mkdir).not.toHaveBeenCalled();
  });

  describe("an entry under a runner directory that goes through a symlink", () => {
    // As on Fedora Atomic, where /home links to /var/home.
    const fedora = (extraLinks: string[] = []) => ({
      exists: alwaysExists,
      lstat: (p: string) => ({ isSymbolicLink: () => p === "/home" || extraLinks.includes(p) }),
      readlink: () => "var/home",
      realpath: (p: string) => p.replace(/^\/home\//, "/var/home/"),
      mkdir: () => {},
    });

    it("takes the runner directory at its real path, however the entry spells it", () => {
      const plan = resolveFilesystemPlan(
        "persistent",
        "./dist\n~/.cache/pip\n/home/runner/out\n$RUNNER_TEMP/x",
        ENV,
        fedora(),
      );
      expect(plan.writeThroughPaths).toStrictEqual([
        "/var/home/runner/work/repo/repo/dist",
        "/var/home/runner/.cache/pip",
        "/var/home/runner/out",
        "/var/home/runner/work/_temp/x",
      ]);
    });

    it("does not take an entry that only resolves to / as the full opt-out", () => {
      expect(() =>
        resolveFilesystemPlan("persistent", "$HOME", ENV, {
          ...fedora(),
          realpath: (p) => (p === ENV.HOME ? "/" : p),
        }),
      ).toThrow(expect.objectContaining({ code: "FILESYSTEM_INPUT_CONFLICT" }));
    });

    it("leaves an entry under no runner directory as written", () => {
      const env = { HOME: ENV.HOME, GITHUB_WORKSPACE: ENV.GITHUB_WORKSPACE };
      expect(
        resolveFilesystemPlan("persistent", "/opt/out", env, fedora()).writeThroughPaths,
      ).toStrictEqual(["/opt/out"]);
    });

    it("still refuses a symlink in what the entry adds below it", () => {
      expect(() =>
        resolveFilesystemPlan(
          "persistent",
          "~/.cache/pip",
          ENV,
          fedora(["/var/home/runner/.cache"]),
        ),
      ).toThrow(expect.objectContaining({ code: "INVALID_WRITE_THROUGH_PATH" }));
    });
  });

  it("catches an overlap that only normalization reveals", () => {
    expect(() =>
      resolveFilesystemPlan("persistent", `${SANDBOX_SCRATCH_BASE}/./x`, ENV, {
        exists: alwaysExists,
        lstat: notLink,
      }),
    ).toThrow(/overlaps/);
  });

  it("accepts an empty write_through: in ephemeral mode silently (maximum isolation is a valid choice)", () => {
    const plan = resolveFilesystemPlan("ephemeral", "", ENV, {
      exists: alwaysExists,
      deviceOf: () => 1,
      listHostMounts: () => [],
      realpath: (p) => p,
    });
    expect(plan.writeThroughPaths).toStrictEqual([]);
    // RUNNER_TEMP is nested under HOME in this fixture's ENV (as on a real
    // GitHub-hosted runner), so it folds away; GITHUB_WORKSPACE is also
    // nested under HOME here, so it folds away too: only HOME and /tmp
    // are left.
    expect(plan.overlayRoots.sort()).toStrictEqual([ENV.HOME, "/tmp"].sort());
  });

  it("takes the overlay candidates by their real paths, as write_through's are", () => {
    const plan = resolveFilesystemPlan("ephemeral", "", ENV, {
      exists: alwaysExists,
      deviceOf: () => 1,
      listHostMounts: () => [],
      realpath: (p) => p.replace(/^\/home\//, "/var/home/"),
    });
    expect(plan.overlayRoots.sort()).toStrictEqual(["/tmp", "/var/home/runner"]);
  });

  it("adds an overlay for each host mount under an overlay root, but not under write_through", () => {
    const plan = resolveFilesystemPlan("ephemeral", "/home/runner/out", ENV, {
      exists: alwaysExists,
      lstat: notLink,
      deviceOf: () => 1,
      realpath: (p) => p,
      listHostMounts: () =>
        ["/", "/home/runner", "/home/runner/_tool", "/home/runner/out/cache", "/opt/data"].map(
          (mountPoint) => ({ mountPoint, fsType: "ext4" }),
        ),
      isDirectory: () => true,
    });
    expect(plan.overlayRoots.sort()).toStrictEqual(["/home/runner", "/home/runner/_tool", "/tmp"]);
  });

  it("warns about a host mount it leaves out rather than failing", () => {
    const warn = vi.fn();
    const plan = resolveFilesystemPlan("ephemeral", "", ENV, {
      exists: alwaysExists,
      deviceOf: () => 1,
      realpath: (p) => p,
      listHostMounts: () => [{ mountPoint: "/home/runner/remote", fsType: "fuse.sshfs" }],
      warn,
    });
    expect(plan.overlayRoots.sort()).toStrictEqual(["/home/runner", "/tmp"]);
    expect(warn).toHaveBeenCalledWith(expect.stringContaining('"/home/runner/remote"'));
  });

  it("reads the host mount table by default", () => {
    const warn = vi.fn();
    resolveFilesystemPlan("ephemeral", "", ENV, {
      exists: alwaysExists,
      deviceOf: () => 1,
      realpath: (p) => p,
      warn,
    });
    expect(warn).toHaveBeenCalledWith(expect.stringContaining('"/home/runner/remote"'));
  });

  it("resolves and pre-creates write_through targets, then excludes only what's actually covered by them", () => {
    // Self-hosted-style ENV: GITHUB_WORKSPACE isn't nested under HOME here, so
    // its own overlay survives folding. That is what lets this exercise, end to
    // end, a candidate that merely contains a narrower write_through entry.
    const selfHostedEnv = { ...ENV, GITHUB_WORKSPACE: "/workspace" };
    const mkdir = vi.fn();
    const plan = resolveFilesystemPlan("ephemeral", "./dist", selfHostedEnv, {
      exists: (p) => p !== "/workspace/dist",
      lstat: notLink,
      canWrite: () => true,
      mkdir,
      deviceOf: () => 1,
      listHostMounts: () => [],
      realpath: (p) => p,
    });
    expect(plan.writeThroughPaths).toStrictEqual(["/workspace/dist"]);
    expect(mkdir.mock.calls).toStrictEqual([["/workspace/dist"]]);
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

  it("still reports a missing runner file as missing when its directory sits behind a symlink", () => {
    const envBehindLink = { ...ENV, GITHUB_OUTPUT: "/work/_temp/set_output" };
    const mkdir = vi.fn();
    expect.assertions(3);
    try {
      resolveFilesystemPlan("persistent", "$GITHUB_OUTPUT", envBehindLink, {
        exists: (p) =>
          p === "/work" || p === "/mnt" || p === "/mnt/work" || p === "/mnt/work/_temp",
        lstat: (p) => ({ isSymbolicLink: () => p === "/work" }),
        readlink: () => "/mnt/work",
        mkdir,
      });
    } catch (err) {
      expect(err).toBeInstanceOf(SandboxError);
      expect((err as SandboxError).code).toBe("WRITE_THROUGH_TARGET_MISSING");
    }
    expect(mkdir).not.toHaveBeenCalled();
  });

  it("wraps a target the runner can't create as WRITE_THROUGH_TARGET_UNCREATABLE", () => {
    expect.assertions(2);
    try {
      resolveFilesystemPlan("ephemeral", "./dist", ENV, {
        exists: (p) => p !== `${ENV.GITHUB_WORKSPACE}/dist`,
        realpath: (p) => p,
        lstat: notLink,
        canWrite: () => false,
      });
    } catch (err) {
      expect(err).toBeInstanceOf(SandboxError);
      expect((err as SandboxError).code).toBe("WRITE_THROUGH_TARGET_UNCREATABLE");
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

  it.each(reservedInternalDestinations())("rejects the reserved path %s in either mode", (path) => {
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

  it("allows /run, and any path under it, to be re-exposed on top of the coverage tmpfs", () => {
    // write_through opens exactly what it names: the whole host /run, or a single
    // path under it, re-exposed over the empty /run tmpfs (see oci-config.ts).
    for (const path of ["/run", "/var/run", "/run/snapd.socket", "/run/myapp"]) {
      expect(() => validateFilesystemInputs("persistent", [path])).not.toThrow();
      expect(() => validateFilesystemInputs("ephemeral", [path])).not.toThrow();
    }
  });
});

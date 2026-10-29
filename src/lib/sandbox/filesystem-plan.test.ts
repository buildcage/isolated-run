import { beforeEach, describe, it, expect, vi } from "vitest";

import { SandboxError } from "../errors.ts";
import { RUNNER_DIRS_ENV } from "../test/runner-host.ts";
import { resolveFilesystemPlan, validateFilesystemInputs } from "./filesystem-plan.ts";
import { listHostMounts } from "./mountinfo.ts";
import { reservedInternalDestinations } from "./oci-mounts.ts";
import { SANDBOX_SCRATCH_BASE } from "./scratch-dir.ts";

// /proc/self/mountinfo is Linux-only, so the default listHostMounts is mocked.
vi.mock("./mountinfo.ts", () => ({ listHostMounts: vi.fn(() => []) }));

// Back to the empty table, in case a test's own value went unread.
beforeEach(() => vi.mocked(listHostMounts).mockReset());

describe("resolveFilesystemPlan", () => {
  const ENV = RUNNER_DIRS_ENV;
  // Everything "exists" by default (candidates and write-through targets)
  // unless a test narrows it.
  const alwaysExists = () => true;
  const notLink = () => ({ isSymbolicLink: () => false });

  it("returns an empty plan for persistent mode with no write-through:, without touching the filesystem", () => {
    const exists = vi.fn(alwaysExists);
    const plan = resolveFilesystemPlan("persistent", "", ENV, { exists });
    expect(plan).toStrictEqual({ overlayRoots: [], writeThroughPaths: [], mediatedVariables: [] });
    expect(exists).not.toHaveBeenCalled();
  });

  it("resolves write-through: in persistent mode too, normalizing each entry", () => {
    const plan = resolveFilesystemPlan("persistent", "./dist\n/opt/./cache/\n", ENV, {
      exists: alwaysExists,
      realpath: (p) => p,
      lstat: notLink,
    });
    expect(plan.writeThroughPaths).toStrictEqual([`${ENV.GITHUB_WORKSPACE}/dist`, "/opt/cache"]);
    expect(plan.overlayRoots).toStrictEqual([]);
  });

  it("pre-creates a missing write-through target in persistent mode", () => {
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
    expect(plan).toStrictEqual({
      overlayRoots: [],
      writeThroughPaths: ["/"],
      mediatedVariables: [],
    });
    expect(exists).not.toHaveBeenCalled();
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

  it("accepts an empty write-through: in ephemeral mode silently (maximum isolation is a valid choice)", () => {
    const plan = resolveFilesystemPlan("ephemeral", "", ENV, {
      exists: alwaysExists,
      deviceOf: () => 1,
      listHostMounts: () => [],
      realpath: (p) => p,
    });
    expect(plan.writeThroughPaths).toStrictEqual([]);
    // RUNNER_TEMP and GITHUB_WORKSPACE sit under HOME here, as on a
    // GitHub-hosted runner, so they fold away.
    expect(plan.overlayRoots.sort()).toStrictEqual([ENV.HOME, "/tmp"].sort());
  });

  describe("which runner files are mediated back", () => {
    const FILES_ENV = {
      ...ENV,
      GITHUB_OUTPUT: `${ENV.RUNNER_TEMP}/_runner_file_commands/set_output_abc`,
      GITHUB_STEP_SUMMARY: `${ENV.RUNNER_TEMP}/_runner_file_commands/step_summary_abc`,
    };
    const plan = (mode: "persistent" | "ephemeral", writeThrough: string) =>
      resolveFilesystemPlan(mode, writeThrough, FILES_ENV, {
        exists: alwaysExists,
        lstat: notLink,
        deviceOf: () => 1,
        listHostMounts: () => [],
        realpath: (p) => p,
      });

    it("mediates every runner file the step has in persistent mode", () => {
      expect(plan("persistent", "").mediatedVariables).toStrictEqual([
        "GITHUB_OUTPUT",
        "GITHUB_STEP_SUMMARY",
      ]);
    });

    it("leaves both under the overlay in ephemeral mode unless write-through covers them", () => {
      expect(plan("ephemeral", "./dist").mediatedVariables).toStrictEqual([]);
    });

    // The mediation writes the file back, so the entry needs no bind of its own.
    it("mediates a file write-through names, and drops it from the binds", () => {
      const named = plan("ephemeral", "./dist\n$GITHUB_OUTPUT");
      expect(named.mediatedVariables).toStrictEqual(["GITHUB_OUTPUT"]);
      expect(named.writeThroughPaths).toStrictEqual([`${ENV.GITHUB_WORKSPACE}/dist`]);
    });

    it("mediates the files under a directory write-through names", () => {
      const covered = plan("ephemeral", "$RUNNER_TEMP");
      expect(covered.mediatedVariables).toStrictEqual(["GITHUB_OUTPUT", "GITHUB_STEP_SUMMARY"]);
      expect(covered.writeThroughPaths).toStrictEqual([ENV.RUNNER_TEMP]);
    });

    it("compares a runner file by its real path, as write-through's are", () => {
      const covered = resolveFilesystemPlan("ephemeral", "$RUNNER_TEMP", FILES_ENV, {
        exists: alwaysExists,
        lstat: notLink,
        deviceOf: () => 1,
        listHostMounts: () => [],
        realpath: (p) => p.replace(/^\/home\//, "/var/home/"),
      });
      expect(covered.mediatedVariables).toStrictEqual(["GITHUB_OUTPUT", "GITHUB_STEP_SUMMARY"]);
    });

    describe("through another mount of the runner's work directory", () => {
      const aliased = (writeThrough: string) =>
        resolveFilesystemPlan("ephemeral", writeThrough, FILES_ENV, {
          exists: alwaysExists,
          lstat: notLink,
          deviceOf: () => 1,
          realpath: (p) => p,
          listHostMounts: () => [
            { mountPoint: "/", fsType: "ext4", device: "8:1", root: "/" },
            { mountPoint: "/mnt/alias", fsType: "ext4", device: "8:1", root: "/home/runner/work" },
          ],
        });

      it("mediates the files under a directory write-through names there", () => {
        const covered = aliased("/mnt/alias/_temp");
        expect(covered.mediatedVariables).toStrictEqual(["GITHUB_OUTPUT", "GITHUB_STEP_SUMMARY"]);
        expect(covered.writeThroughPaths).toStrictEqual(["/mnt/alias/_temp"]);
      });

      it("finds the mounts of a runner file reached through a symlink", () => {
        const covered = resolveFilesystemPlan("ephemeral", "/mnt/commands", FILES_ENV, {
          exists: alwaysExists,
          lstat: (p) => ({ isSymbolicLink: () => p.endsWith("/_runner_file_commands") }),
          readlink: () => "/srv/commands",
          deviceOf: () => 1,
          realpath: (p) => p,
          listHostMounts: () => [
            { mountPoint: "/", fsType: "ext4", device: "8:1", root: "/" },
            { mountPoint: "/mnt/commands", fsType: "ext4", device: "8:1", root: "/srv/commands" },
          ],
        });
        expect(covered.mediatedVariables).toStrictEqual(["GITHUB_OUTPUT", "GITHUB_STEP_SUMMARY"]);
      });

      it("mediates a file write-through names there, and drops it from the binds", () => {
        const named = aliased("/mnt/alias/_temp/_runner_file_commands/set_output_abc");
        expect(named.mediatedVariables).toStrictEqual(["GITHUB_OUTPUT"]);
        expect(named.writeThroughPaths).toStrictEqual([]);
      });
    });

    it("fails as FILESYSTEM_PLAN_FAILED when the host mount table cannot be read", () => {
      const run = () =>
        resolveFilesystemPlan("ephemeral", "", FILES_ENV, {
          listHostMounts: () => {
            throw new Error("EACCES");
          },
        });
      expect(run).toThrow(SandboxError);
      expect(run).toThrow(expect.objectContaining({ code: "FILESYSTEM_PLAN_FAILED" }));
    });
  });

  it("takes the overlay candidates by their real paths, as write-through's are", () => {
    const plan = resolveFilesystemPlan("ephemeral", "", ENV, {
      exists: alwaysExists,
      deviceOf: () => 1,
      listHostMounts: () => [],
      realpath: (p) => p.replace(/^\/home\//, "/var/home/"),
    });
    expect(plan.overlayRoots.sort()).toStrictEqual(["/tmp", "/var/home/runner"]);
  });

  it("adds an overlay for each host mount under an overlay root, but not under write-through", () => {
    const plan = resolveFilesystemPlan("ephemeral", "/home/runner/out", ENV, {
      exists: alwaysExists,
      lstat: notLink,
      deviceOf: () => 1,
      realpath: (p) => p,
      listHostMounts: () =>
        ["/", "/home/runner", "/home/runner/_tool", "/home/runner/out/cache", "/opt/data"].map(
          (mountPoint, i) => ({ mountPoint, fsType: "ext4", device: `8:${i}`, root: "/" }),
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
      listHostMounts: () => [
        { mountPoint: "/home/runner/remote", fsType: "fuse.sshfs", device: "0:50", root: "/" },
      ],
      warn,
    });
    expect(plan.overlayRoots.sort()).toStrictEqual(["/home/runner", "/tmp"]);
    expect(warn).toHaveBeenCalledWith(expect.stringContaining('"/home/runner/remote"'));
  });

  it("reads the host mount table by default", () => {
    vi.mocked(listHostMounts).mockReturnValueOnce([
      { mountPoint: "/home/runner/remote", fsType: "fuse.sshfs", device: "0:50", root: "/" },
    ]);
    const warn = vi.fn();
    resolveFilesystemPlan("ephemeral", "", ENV, {
      exists: alwaysExists,
      deviceOf: () => 1,
      realpath: (p) => p,
      warn,
    });
    expect(warn).toHaveBeenCalledWith(expect.stringContaining('"/home/runner/remote"'));
  });

  it("resolves and pre-creates write-through targets, then excludes only what's actually covered by them", () => {
    // Self-hosted layout: GITHUB_WORKSPACE is not under HOME, so it keeps its
    // own overlay, one that contains a narrower write-through entry.
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
    expect(plan.overlayRoots.sort()).toStrictEqual([ENV.HOME, "/tmp", "/workspace"].sort());
  });

  it("wraps a missing well-known runner file as WRITE_THROUGH_TARGET_MISSING", () => {
    const envWithEnvFile = { ...ENV, GITHUB_ENV: "/home/runner/_temp/set_env" };
    expect.assertions(2);
    try {
      resolveFilesystemPlan("ephemeral", "$GITHUB_ENV", envWithEnvFile, {
        exists: () => false,
      });
    } catch (err) {
      expect(err).toBeInstanceOf(SandboxError);
      expect((err as SandboxError).code).toBe("WRITE_THROUGH_TARGET_MISSING");
    }
  });

  it("still reports a missing runner file as missing when its directory sits behind a symlink", () => {
    const envBehindLink = { ...ENV, GITHUB_ENV: "/work/_temp/set_env" };
    const mkdir = vi.fn();
    expect.assertions(3);
    try {
      resolveFilesystemPlan("persistent", "$GITHUB_ENV", envBehindLink, {
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

  it("wraps an unsupported $VAR in write-through: as INVALID_WRITE_THROUGH_PATH", () => {
    expect.assertions(2);
    try {
      resolveFilesystemPlan("ephemeral", "$SECRET_TOKEN/x", ENV);
    } catch (err) {
      expect(err).toBeInstanceOf(SandboxError);
      expect((err as SandboxError).code).toBe("INVALID_WRITE_THROUGH_PATH");
    }
  });

  it("wraps a determineOverlayRoots failure as FILESYSTEM_PLAN_FAILED, not a write-through problem", () => {
    // exists() fails on a fixed candidate path, not on write-through's input.
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
  it("throws FILESYSTEM_INPUT_CONFLICT for write-through: / in ephemeral mode", () => {
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
    // write-through opens exactly what it names: the whole host /run, or a single
    // path under it, re-exposed over the empty /run tmpfs (see oci-config.ts).
    for (const path of ["/run", "/var/run", "/run/snapd.socket", "/run/myapp"]) {
      expect(() => validateFilesystemInputs("persistent", [path])).not.toThrow();
      expect(() => validateFilesystemInputs("ephemeral", [path])).not.toThrow();
    }
  });
});

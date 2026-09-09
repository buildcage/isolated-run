/**
 * Unit tests for main.ts
 *
 * Run with: vp test run src/main.test.ts
 */
import { describe, it, expect, vi } from "vitest";

import {
  buildACLRules,
  readKnownBlockedRules,
  resolveProxyEngine,
  resolveFilesystemMode,
  resolveFilesystemPlan,
  resolveWriteThroughInput,
  splitWriteThroughInput,
  validateFilesystemInputs,
} from "./main.ts";
import { InvalidRulesError } from "#core/lib/acl/rules.ts";
import { SandboxError } from "./lib/errors.ts";
import { SANDBOX_SCRATCH_BASE } from "./lib/sandbox/scratch-dir.ts";

describe("resolveProxyEngine", () => {
  it("defaults to universal for undefined", () => {
    expect(resolveProxyEngine(undefined)).toBe("universal");
  });

  it("defaults to universal for empty string", () => {
    expect(resolveProxyEngine("")).toBe("universal");
  });

  it("accepts universal explicitly", () => {
    expect(resolveProxyEngine("universal")).toBe("universal");
  });

  it("accepts inspect", () => {
    expect(resolveProxyEngine("inspect")).toBe("inspect");
  });

  it("throws SandboxError for an invalid value", () => {
    expect(() => resolveProxyEngine("restrict")).toThrow();
  });

  it("throws SandboxError for a value with different casing (case-sensitive)", () => {
    expect(() => resolveProxyEngine("Inspect")).toThrow();
  });

  // `transparent` is universal's old name, kept working permanently as an
  // alias — see ENGINE_ALIASES.
  describe("the transparent alias", () => {
    it("resolves transparent to universal", () => {
      const log = vi.spyOn(console, "log").mockImplementation(() => {});
      try {
        expect(resolveProxyEngine("transparent")).toBe("universal");
      } finally {
        log.mockRestore();
      }
    });

    it("prints a ::notice:: pointing at the new name", () => {
      const log = vi.spyOn(console, "log").mockImplementation(() => {});
      try {
        resolveProxyEngine("transparent");
        expect(log).toHaveBeenCalledWith(expect.stringContaining("::notice::"));
        expect(log).toHaveBeenCalledWith(expect.stringContaining("proxy_engine: transparent"));
        expect(log).toHaveBeenCalledWith(expect.stringContaining("proxy_engine: universal"));
      } finally {
        log.mockRestore();
      }
    });

    it("does not print a notice for any other value", () => {
      const log = vi.spyOn(console, "log").mockImplementation(() => {});
      try {
        resolveProxyEngine("universal");
        resolveProxyEngine("inspect");
        expect(log).not.toHaveBeenCalled();
      } finally {
        log.mockRestore();
      }
    });

    it("no longer appears in the invalid-value error's accepted list", () => {
      expect(() => resolveProxyEngine("restrict")).toThrowError(/universal, inspect/);
    });
  });
});

describe("resolveFilesystemMode", () => {
  it("defaults to persistent for undefined", () => {
    expect(resolveFilesystemMode(undefined)).toBe("persistent");
  });

  it("defaults to persistent for empty string", () => {
    expect(resolveFilesystemMode("")).toBe("persistent");
  });

  it("accepts persistent explicitly", () => {
    expect(resolveFilesystemMode("persistent")).toBe("persistent");
  });

  it("accepts ephemeral", () => {
    expect(resolveFilesystemMode("ephemeral")).toBe("ephemeral");
  });

  it("throws SandboxError with code INVALID_FILESYSTEM_MODE for an invalid value", () => {
    expect.assertions(2);
    try {
      resolveFilesystemMode("readonly");
    } catch (err) {
      expect(err).toBeInstanceOf(SandboxError);
      expect((err as SandboxError).code).toBe("INVALID_FILESYSTEM_MODE");
    }
  });
});

describe("resolveWriteThroughInput", () => {
  const inputs = (over: Partial<Parameters<typeof resolveWriteThroughInput>[0]> = {}) => ({
    writeThrough: "",
    writable: "",
    allowWrite: "",
    ...over,
  });

  it("returns write_through: as given", () => {
    expect(resolveWriteThroughInput(inputs({ writeThrough: "/opt/cache" }))).toBe("/opt/cache");
  });

  it("accepts writable: as the pre-rename spelling", () => {
    expect(resolveWriteThroughInput(inputs({ writable: "/opt/cache" }))).toBe("/opt/cache");
  });

  it("throws FILESYSTEM_INPUT_CONFLICT when both spellings are set", () => {
    expect.assertions(2);
    try {
      resolveWriteThroughInput(inputs({ writeThrough: "/opt/a", writable: "/opt/b" }));
    } catch (err) {
      expect(err).toBeInstanceOf(SandboxError);
      expect((err as SandboxError).code).toBe("FILESYSTEM_INPUT_CONFLICT");
    }
  });

  it("rejects the removed allow_write: input rather than ignoring it", () => {
    expect.assertions(2);
    try {
      resolveWriteThroughInput(inputs({ allowWrite: "./dist" }));
    } catch (err) {
      expect(err).toBeInstanceOf(SandboxError);
      expect((err as SandboxError).code).toBe("ALLOW_WRITE_REMOVED");
    }
  });

  it("returns an empty string when nothing is set", () => {
    expect(resolveWriteThroughInput(inputs())).toBe("");
  });
});

describe("splitWriteThroughInput", () => {
  it("splits on newlines, trims, and drops blank lines", () => {
    expect(splitWriteThroughInput(" /opt/cache \n\n./dist\n")).toStrictEqual([
      "/opt/cache",
      "./dist",
    ]);
    expect(splitWriteThroughInput("")).toStrictEqual([]);
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
});

describe("resolveFilesystemPlan", () => {
  const ENV = {
    HOME: "/home/runner",
    GITHUB_WORKSPACE: "/home/runner/work/repo/repo",
    RUNNER_TEMP: "/home/runner/work/_temp",
  };
  // Everything "exists" by default (candidates + write_through targets) unless
  // a test narrows it -- keeps each test focused on the one thing it checks.
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
    expect(execFileCalls[0]).toStrictEqual(["sudo", "mkdir", "-p", "/opt/build-output"]);
    expect(plan.createdDirs).toStrictEqual(["/opt/build-output"]);
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
    // nested under HOME here, so it folds away too -- only HOME and /tmp
    // are left.
    expect(plan.overlayRoots.map((r) => r.path).sort()).toStrictEqual([ENV.HOME, "/tmp"].sort());
  });

  it("resolves and pre-creates write_through targets, then excludes only what's actually covered by them", () => {
    // Self-hosted-style ENV: GITHUB_WORKSPACE isn't nested under HOME here,
    // so its own overlay survives folding -- letting this test show, through
    // resolveFilesystemPlan end-to-end, that a candidate merely containing a
    // narrower write_through entry (./dist under the workspace) keeps its own
    // overlay rather than being dropped (see determineOverlayRoots' "covered
    // by" rule and buildOciConfig's mount ordering, which layers ./dist's
    // own rw bind on top of that overlay).
    const selfHostedEnv = { ...ENV, GITHUB_WORKSPACE: "/workspace" };
    const execFileCalls: string[][] = [];
    const plan = resolveFilesystemPlan("ephemeral", "./dist", selfHostedEnv, {
      exists: (p) => p !== "/workspace/dist",
      stat: () => ({ uid: 1000, gid: 1000, mode: 0o40755 }),
      execFile: (cmd, args) => execFileCalls.push([cmd, ...args]),
      deviceOf: () => 1,
    });
    expect(plan.writeThroughPaths).toStrictEqual(["/workspace/dist"]);
    expect(execFileCalls[0]).toStrictEqual(["sudo", "mkdir", "-p", "/workspace/dist"]);
    // RUNNER_TEMP still folds away under HOME as usual; GITHUB_WORKSPACE
    // keeps its own overlay since it isn't nested under HOME here.
    expect(plan.overlayRoots.map((r) => r.path).sort()).toStrictEqual(
      [ENV.HOME, "/tmp", "/workspace"].sort(),
    );
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
    // exists() throwing here isn't about write_through's own input at all --
    // it's determineOverlayRoots reading one of the fixed candidate paths
    // (e.g. a permissions error on $HOME) -- so it must not come back
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

describe("buildACLRules", () => {
  it("parses whitespace-separated HTTPS rules", () => {
    const { httpsRules } = buildACLRules({
      httpsRulesInput: "example.com:443 *.cdn.example.com:443",
      httpRulesInput: "",
      ipRulesInput: "",
    });
    expect(httpsRules).toStrictEqual(["example.com:443", "*.cdn.example.com:443"]);
  });

  it("handles newline-separated rules", () => {
    const { httpsRules } = buildACLRules({
      httpsRulesInput: "a.com:443\nb.com:443",
      httpRulesInput: "",
      ipRulesInput: "",
    });
    expect(httpsRules).toStrictEqual(["a.com:443", "b.com:443"]);
  });

  it("returns empty arrays for empty/undefined inputs", () => {
    const result = buildACLRules({
      httpsRulesInput: "",
      httpRulesInput: undefined,
      ipRulesInput: "   ",
    });
    expect(result.httpsRules).toStrictEqual([]);
    expect(result.httpRules).toStrictEqual([]);
    expect(result.ipRules).toStrictEqual([]);
  });

  it("throws InvalidRulesError with code INVALID_RULES for invalid rule syntax", () => {
    expect.assertions(2);
    try {
      buildACLRules({
        httpsRulesInput: "no-port-specified",
        httpRulesInput: "",
        ipRulesInput: "",
      });
    } catch (err) {
      expect(err).toBeInstanceOf(InvalidRulesError);
      expect((err as InvalidRulesError).code).toBe("INVALID_RULES");
    }
  });
});

describe("readKnownBlockedRules", () => {
  it("parses whitespace-separated rules", () => {
    expect(readKnownBlockedRules("known-bad.example.com:443 *.noisy.example.com:80")).toStrictEqual(
      ["known-bad.example.com:443", "*.noisy.example.com:80"],
    );
  });

  it("returns an empty array for empty/undefined input", () => {
    expect(readKnownBlockedRules(undefined)).toStrictEqual([]);
    expect(readKnownBlockedRules("")).toStrictEqual([]);
  });

  it("throws InvalidRulesError with code INVALID_RULES for invalid rule syntax", () => {
    expect.assertions(2);
    try {
      readKnownBlockedRules("no-port-specified");
    } catch (err) {
      expect(err).toBeInstanceOf(InvalidRulesError);
      expect((err as InvalidRulesError).code).toBe("INVALID_RULES");
    }
  });
});

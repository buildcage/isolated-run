/**
 * Unit tests for main.ts
 *
 * Run with: vp test run src/main.test.ts
 */
import { describe, it, expect, vi } from "vitest";

import {
  buildACLRules,
  parseWritablePaths,
  readKnownBlockedRules,
  resolveProxyEngine,
  resolveFilesystemMode,
  resolveFilesystemPlan,
  validateFilesystemInputs,
} from "./main.ts";
import { InvalidRulesError } from "#core/lib/acl/rules.ts";
import { SandboxError } from "./lib/errors.ts";

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

describe("validateFilesystemInputs", () => {
  it("throws FILESYSTEM_INPUT_CONFLICT for ephemeral + writable:, with no filesystem access", () => {
    expect.assertions(2);
    try {
      validateFilesystemInputs("ephemeral", "/opt/cache", "");
    } catch (err) {
      expect(err).toBeInstanceOf(SandboxError);
      expect((err as SandboxError).code).toBe("FILESYSTEM_INPUT_CONFLICT");
    }
  });

  it("throws FILESYSTEM_INPUT_CONFLICT for persistent + allow_write:", () => {
    expect.assertions(2);
    try {
      validateFilesystemInputs("persistent", "", "$GITHUB_WORKSPACE");
    } catch (err) {
      expect(err).toBeInstanceOf(SandboxError);
      expect((err as SandboxError).code).toBe("FILESYSTEM_INPUT_CONFLICT");
    }
  });

  it("does not throw for either mode used with its own matching input", () => {
    expect(() => validateFilesystemInputs("persistent", "/opt/cache", "")).not.toThrow();
    expect(() => validateFilesystemInputs("ephemeral", "", "$GITHUB_WORKSPACE")).not.toThrow();
    expect(() => validateFilesystemInputs("persistent", "", "")).not.toThrow();
    expect(() => validateFilesystemInputs("ephemeral", "", "")).not.toThrow();
  });
});

describe("resolveFilesystemPlan", () => {
  const ENV = {
    HOME: "/home/runner",
    GITHUB_WORKSPACE: "/home/runner/work/repo/repo",
    RUNNER_TEMP: "/home/runner/work/_temp",
  };
  // Everything "exists" by default (candidates + allow_write targets) unless
  // a test narrows it -- keeps each test focused on the one thing it checks.
  const alwaysExists = () => true;

  it("returns empty plans for persistent mode, without touching the filesystem", () => {
    const exists = vi.fn(alwaysExists);
    const plan = resolveFilesystemPlan("persistent", "", "", ENV, { exists });
    expect(plan).toStrictEqual({ overlayRoots: [], allowWritePaths: [] });
    expect(exists).not.toHaveBeenCalled();
  });

  it("persistent mode tolerates a non-empty writable: input (that's its normal use)", () => {
    expect(() =>
      resolveFilesystemPlan("persistent", "/opt/cache", "", ENV, { exists: alwaysExists }),
    ).not.toThrow();
  });

  it("throws FILESYSTEM_INPUT_CONFLICT when persistent mode is combined with allow_write:", () => {
    expect.assertions(2);
    try {
      resolveFilesystemPlan("persistent", "", "$GITHUB_WORKSPACE", ENV);
    } catch (err) {
      expect(err).toBeInstanceOf(SandboxError);
      expect((err as SandboxError).code).toBe("FILESYSTEM_INPUT_CONFLICT");
    }
  });

  it("throws FILESYSTEM_INPUT_CONFLICT when ephemeral mode is combined with writable:", () => {
    expect.assertions(2);
    try {
      resolveFilesystemPlan("ephemeral", "/opt/cache", "", ENV);
    } catch (err) {
      expect(err).toBeInstanceOf(SandboxError);
      expect((err as SandboxError).code).toBe("FILESYSTEM_INPUT_CONFLICT");
    }
  });

  it("treats writable: / as non-empty too -- the disable-readonly sentinel has no meaning in ephemeral mode", () => {
    expect(() => resolveFilesystemPlan("ephemeral", "/", "", ENV)).toThrow(
      /FILESYSTEM_INPUT_CONFLICT|mutually exclusive/,
    );
  });

  it("accepts an empty allow_write: in ephemeral mode silently (maximum isolation is a valid choice)", () => {
    const plan = resolveFilesystemPlan("ephemeral", "", "", ENV, {
      exists: alwaysExists,
      deviceOf: () => 1,
    });
    expect(plan.allowWritePaths).toStrictEqual([]);
    // RUNNER_TEMP is nested under HOME in this fixture's ENV (as on a real
    // GitHub-hosted runner), so it folds away; GITHUB_WORKSPACE is also
    // nested under HOME here, so it folds away too -- only HOME and /tmp
    // are left.
    expect(plan.overlayRoots.map((r) => r.path).sort()).toStrictEqual([ENV.HOME, "/tmp"].sort());
  });

  it("resolves and pre-creates allow_write targets, then excludes only what's actually covered by them", () => {
    // Self-hosted-style ENV: GITHUB_WORKSPACE isn't nested under HOME here,
    // so its own overlay survives folding -- letting this test show, through
    // resolveFilesystemPlan end-to-end, that a candidate merely containing a
    // narrower allow_write entry (./dist under the workspace) keeps its own
    // overlay rather than being dropped (see determineOverlayRoots' "covered
    // by" rule and buildOciConfig's mount ordering, which layers ./dist's
    // own rw bind on top of that overlay).
    const selfHostedEnv = { ...ENV, GITHUB_WORKSPACE: "/workspace" };
    const execFileCalls: string[][] = [];
    const plan = resolveFilesystemPlan("ephemeral", "", "./dist", selfHostedEnv, {
      exists: (p) => p !== "/workspace/dist",
      stat: () => ({ uid: 1000, gid: 1000, mode: 0o40755 }),
      execFile: (cmd, args) => execFileCalls.push([cmd, ...args]),
      deviceOf: () => 1,
    });
    expect(plan.allowWritePaths).toStrictEqual(["/workspace/dist"]);
    expect(execFileCalls[0]).toStrictEqual(["sudo", "mkdir", "-p", "/workspace/dist"]);
    // RUNNER_TEMP still folds away under HOME as usual; GITHUB_WORKSPACE
    // keeps its own overlay since it isn't nested under HOME here.
    expect(plan.overlayRoots.map((r) => r.path).sort()).toStrictEqual(
      [ENV.HOME, "/tmp", "/workspace"].sort(),
    );
  });

  it("wraps a missing well-known runner file as ALLOW_WRITE_TARGET_MISSING", () => {
    const envWithOutput = { ...ENV, GITHUB_OUTPUT: "/home/runner/_temp/set_output" };
    expect.assertions(2);
    try {
      resolveFilesystemPlan("ephemeral", "", "$GITHUB_OUTPUT", envWithOutput, {
        exists: () => false,
      });
    } catch (err) {
      expect(err).toBeInstanceOf(SandboxError);
      expect((err as SandboxError).code).toBe("ALLOW_WRITE_TARGET_MISSING");
    }
  });

  it("wraps a sudo mkdir/chown/chmod failure as ALLOW_WRITE_TARGET_UNCREATABLE", () => {
    expect.assertions(2);
    try {
      resolveFilesystemPlan("ephemeral", "", "./dist", ENV, {
        exists: (p) => p !== `${ENV.GITHUB_WORKSPACE}/dist`,
        stat: () => ({ uid: 1000, gid: 1000, mode: 0o40755 }),
        execFile: () => {
          throw new Error("sudo: a password is required");
        },
      });
    } catch (err) {
      expect(err).toBeInstanceOf(SandboxError);
      expect((err as SandboxError).code).toBe("ALLOW_WRITE_TARGET_UNCREATABLE");
    }
  });

  it("wraps an unsupported $VAR in allow_write: as INVALID_ALLOW_WRITE_PATH", () => {
    expect.assertions(2);
    try {
      resolveFilesystemPlan("ephemeral", "", "$SECRET_TOKEN/x", ENV);
    } catch (err) {
      expect(err).toBeInstanceOf(SandboxError);
      expect((err as SandboxError).code).toBe("INVALID_ALLOW_WRITE_PATH");
    }
  });

  it("wraps a determineOverlayRoots failure as FILESYSTEM_PLAN_FAILED, not an allow_write problem", () => {
    // exists() throwing here isn't about allow_write's own input at all --
    // it's determineOverlayRoots reading one of the fixed candidate paths
    // (e.g. a permissions error on $HOME) -- so it must not come back
    // labeled as an allow_write syntax issue.
    expect.assertions(2);
    try {
      resolveFilesystemPlan("ephemeral", "", "", ENV, {
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

describe("parseWritablePaths", () => {
  it("splits on newlines, trimming each entry", () => {
    expect(parseWritablePaths("/opt/extra\n /var/cache \n")).toStrictEqual([
      "/opt/extra",
      "/var/cache",
    ]);
  });

  it("does not split on internal spaces (paths may contain them)", () => {
    expect(parseWritablePaths("/path with spaces\n/other")).toStrictEqual([
      "/path with spaces",
      "/other",
    ]);
  });

  it("returns an empty array for empty/undefined input", () => {
    expect(parseWritablePaths("")).toStrictEqual([]);
    expect(parseWritablePaths(undefined)).toStrictEqual([]);
    expect(parseWritablePaths("   \n  \n")).toStrictEqual([]);
  });

  it("preserves a lone '/' entry (the disable-readonly sentinel)", () => {
    expect(parseWritablePaths("/")).toStrictEqual(["/"]);
  });
});

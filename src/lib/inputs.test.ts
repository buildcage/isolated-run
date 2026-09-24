import { describe, it, expect, vi } from "vitest";

import {
  readEngineInputs,
  readFailOnBlocked,
  readFilesystemInputs,
  readRuleInputs,
  readRunCommand,
  readStepLabel,
  resolveProxyMode,
  resolveWriteThroughInput,
} from "./inputs.ts";
import { SandboxError } from "./errors.ts";

const silent = () => {};

describe("resolveWriteThroughInput", () => {
  const inputs = (over: Partial<Parameters<typeof resolveWriteThroughInput>[0]> = {}) => ({
    writeThrough: "",
    writable: "",
    allowWrite: "",
    ...over,
  });

  it("returns write_through: as given", () => {
    expect(resolveWriteThroughInput(inputs({ writeThrough: "/opt/cache" }), silent)).toBe(
      "/opt/cache",
    );
  });

  it("accepts writable: as the pre-rename spelling, pointing at the new name", () => {
    const notice = vi.fn();

    expect(resolveWriteThroughInput(inputs({ writable: "/opt/cache" }), notice)).toBe("/opt/cache");
    expect(notice).toHaveBeenCalledWith(
      expect.stringContaining("writable: is now called write_through:"),
    );
  });

  it("throws FILESYSTEM_INPUT_CONFLICT when both spellings are set", () => {
    expect.assertions(2);
    try {
      resolveWriteThroughInput(inputs({ writeThrough: "/opt/a", writable: "/opt/b" }), silent);
    } catch (err) {
      expect(err).toBeInstanceOf(SandboxError);
      expect((err as SandboxError).code).toBe("FILESYSTEM_INPUT_CONFLICT");
    }
  });

  it("rejects the removed allow_write: input rather than ignoring it", () => {
    expect.assertions(2);
    try {
      resolveWriteThroughInput(inputs({ allowWrite: "./dist" }), silent);
    } catch (err) {
      expect(err).toBeInstanceOf(SandboxError);
      expect((err as SandboxError).code).toBe("ALLOW_WRITE_REMOVED");
    }
  });

  it("returns an empty string when nothing is set", () => {
    expect(resolveWriteThroughInput(inputs(), silent)).toBe("");
  });
});

// ---------------------------------------------------------------------------
// The input reads themselves
// ---------------------------------------------------------------------------

/** Stands in for core.getInput, which returns "" for anything unset. */
function inputs(values: Record<string, string> = {}): (name: string) => string {
  return (name) => values[name] ?? "";
}

describe("readRunCommand", () => {
  it("returns the run script as given", () => {
    expect(readRunCommand(inputs({ run: "npm ci" }))).toBe("npm ci");
  });

  // Read untrimmed, so a heredoc or an indented block survives intact.
  it("keeps leading and trailing whitespace", () => {
    expect(readRunCommand(inputs({ run: "  npm ci\n" }))).toBe("  npm ci\n");
  });

  it("rejects an absent run input", () => {
    expect(() => readRunCommand(inputs())).toThrow(/'run' is required/);
  });

  it("rejects a run input that is only whitespace", () => {
    expect(() => readRunCommand(inputs({ run: "  \n\t" }))).toThrow(/'run' is required/);
  });
});

describe("readEngineInputs", () => {
  it("defaults to inspect when unset", () => {
    expect(readEngineInputs(inputs())).toStrictEqual({ proxyEngine: "inspect" });
  });

  it("passes the input through resolveProxyEngine", () => {
    expect(readEngineInputs(inputs({ proxy_engine: "inspect" }))).toStrictEqual({
      proxyEngine: "inspect",
    });
  });

  it("rejects an unknown engine", () => {
    expect(() => readEngineInputs(inputs({ proxy_engine: "nope" }))).toThrow(
      /Invalid proxy_engine/,
    );
  });

  it("rejects the removed transparent alias", () => {
    expect(() => readEngineInputs(inputs({ proxy_engine: "transparent" }))).toThrow(
      /transparent has been renamed/,
    );
  });
});

describe("readFilesystemInputs", () => {
  it("defaults to persistent with no write_through entries", () => {
    expect(readFilesystemInputs(silent, inputs())).toStrictEqual({
      filesystemMode: "persistent",
      writeThroughInput: "",
    });
  });

  it("reads both inputs together", () => {
    expect(
      readFilesystemInputs(
        silent,
        inputs({ filesystem_mode: "ephemeral", write_through: "/tmp/out" }),
      ),
    ).toStrictEqual({ filesystemMode: "ephemeral", writeThroughInput: "/tmp/out" });
  });

  // resolveWriteThroughInput decides what these mean; what is left here is
  // that each of the three reaches it under the name action.yml declares.
  it("reads write_through:, writable: and allow_write: under those names", () => {
    const notice = vi.fn();

    expect(readFilesystemInputs(notice, inputs({ writable: "/tmp/out" })).writeThroughInput).toBe(
      "/tmp/out",
    );
    expect(notice).toHaveBeenCalledOnce();
    expect(() => readFilesystemInputs(silent, inputs({ allow_write: "/tmp/out" }))).toThrow(
      /allow_write: has been replaced/,
    );
  });
});

describe("readRuleInputs", () => {
  it("returns empty rule lists when nothing is set", () => {
    expect(readRuleInputs(inputs())).toStrictEqual({
      proxyMode: "restrict",
      httpsRules: [],
      httpRules: [],
      ipRules: [],
      urlRules: [],
      tlsRules: [],
      knownBlockedRules: [],
    });
  });

  it("parses every rule kind", () => {
    const parsed = readRuleInputs(
      inputs({
        proxy_mode: "audit",
        allowed_https_rules: "a.example.com:443",
        allowed_http_rules: "b.example.com:80",
        allowed_ip_rules: "10.0.0.5:5432",
        allowed_tls_rules: "db.example.com:443",
        allowed_url_rules: "GET https://a.example.com/pkg.json",
        known_blocked_rules: "*.sury.org:*",
      }),
    );
    expect(parsed).toStrictEqual({
      proxyMode: "audit",
      httpsRules: ["a.example.com:443"],
      httpRules: ["b.example.com:80"],
      ipRules: ["10.0.0.5:5432"],
      urlRules: ["GET https://a.example.com/pkg.json"],
      tlsRules: ["db.example.com:443"],
      knownBlockedRules: ["*.sury.org:*"],
    });
  });

  it("rejects a malformed rule rather than passing it to the proxy", () => {
    expect(() => readRuleInputs(inputs({ allowed_https_rules: "no-port" }))).toThrow();
  });

  it("rejects a malformed URL rule even though only inspect enforces one", () => {
    expect(() => readRuleInputs(inputs({ allowed_url_rules: "GET not-a-url" }))).toThrow(
      expect.objectContaining({ code: "INVALID_RULES" }),
    );
  });

  it("rejects a rule the parser accepts but the proxy would refuse", () => {
    expect(() => readRuleInputs(inputs({ allowed_https_rules: "10.0.0.0/8:443" }))).toThrow(
      expect.objectContaining({ code: "INVALID_RULES" }),
    );
  });

  it("keeps an explicit proxy_mode", () => {
    expect(readRuleInputs(inputs({ proxy_mode: "audit" })).proxyMode).toBe("audit");
  });

  it("rejects an unknown proxy_mode before any rule", () => {
    expect(() =>
      readRuleInputs(inputs({ proxy_mode: "Audit", allowed_https_rules: "no-port" })),
    ).toThrow(/Invalid proxy_mode/);
  });
});

describe("resolveProxyMode", () => {
  it("defaults to restrict when unset or blank", () => {
    expect(resolveProxyMode(undefined)).toBe("restrict");
    expect(resolveProxyMode("  ")).toBe("restrict");
  });

  it("accepts both modes", () => {
    expect(resolveProxyMode("audit")).toBe("audit");
    expect(resolveProxyMode("restrict")).toBe("restrict");
  });

  // Anything else would enforce a run meant only to record.
  it("rejects anything else, a differently cased mode included", () => {
    for (const mode of ["Audit", "RESTRICT", "enforce"]) {
      expect(() => resolveProxyMode(mode)).toThrow(
        expect.objectContaining({ code: "INVALID_PROXY_MODE" }),
      );
    }
  });
});

describe("readStepLabel", () => {
  it("returns the label when set", () => {
    expect(readStepLabel(inputs({ label: "install" }))).toBe("install");
  });

  it("returns undefined rather than an empty string when unset", () => {
    expect(readStepLabel(inputs())).toBeUndefined();
  });
});

describe("readFailOnBlocked", () => {
  it("returns what the input says", () => {
    expect(readFailOnBlocked(() => false)).toBe(false);
    expect(readFailOnBlocked(() => true)).toBe(true);
  });

  // The integration scripts run this action without action.yml's defaults, so
  // getBooleanInput throws on the unset input rather than returning one.
  it("falls back to action.yml's own default when the input is absent", () => {
    expect(
      readFailOnBlocked(() => {
        throw new Error("Input required and not supplied: fail_on_blocked");
      }),
    ).toBe(true);
  });
});

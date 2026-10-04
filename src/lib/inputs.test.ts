import { readFileSync } from "node:fs";

import { describe, it, expect, vi } from "vitest";
import { parse } from "yaml";

import { SandboxError } from "./errors.ts";
import {
  CONFIG_FILE_INPUTS,
  readProxyInputs,
  readFailOnBlocked,
  readFailOnCaResidue,
  readFilesystemInputs,
  readRunCommand,
  readStepLabel,
  resolveWriteThroughInput,
} from "./inputs.ts";

const silent = () => {};

describe("CONFIG_FILE_INPUTS", () => {
  it("names every action.yml input but run, writable and config_file itself", () => {
    const actionYml = parse(readFileSync("action.yml", "utf8")) as { inputs: object };
    const inputs = Object.keys(actionYml.inputs).filter(
      (n) => !["run", "writable", "config_file"].includes(n),
    );
    expect([...CONFIG_FILE_INPUTS.known].sort()).toEqual(inputs.sort());
  });

  it("merges only inputs it knows", () => {
    expect(CONFIG_FILE_INPUTS.known).toEqual(expect.arrayContaining([...CONFIG_FILE_INPUTS.lists]));
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

  // write_through may hold config_file's lines, which the workflow cannot see.
  it("joins writable:'s lines to write_through:'s when both are set", () => {
    const notice = vi.fn();

    expect(
      resolveWriteThroughInput(inputs({ writeThrough: "/opt/a", writable: "/opt/b" }), notice),
    ).toBe("/opt/a\n/opt/b");
    expect(notice).toHaveBeenCalledOnce();
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

describe("readProxyInputs", () => {
  it("defaults to inspect and restrict when unset", () => {
    expect(readProxyInputs(inputs())).toStrictEqual({
      proxyEngine: "inspect",
      proxyMode: "restrict",
    });
  });

  it("reads both inputs", () => {
    expect(
      readProxyInputs(inputs({ proxy_engine: "universal", proxy_mode: "audit" })),
    ).toStrictEqual({ proxyEngine: "universal", proxyMode: "audit" });
  });

  it("rejects an unknown engine before an unknown mode", () => {
    expect(() => readProxyInputs(inputs({ proxy_engine: "nope", proxy_mode: "Audit" }))).toThrow(
      /Invalid proxy_engine/,
    );
  });

  it("rejects an unknown mode", () => {
    expect(() => readProxyInputs(inputs({ proxy_mode: "Audit" }))).toThrow(/Invalid proxy_mode/);
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

describe("readStepLabel", () => {
  it("returns the label when set", () => {
    expect(readStepLabel(inputs({ label: "install" }))).toBe("install");
  });

  it("returns undefined rather than an empty string when unset", () => {
    expect(readStepLabel(inputs())).toBeUndefined();
  });
});

describe.each([
  { name: "fail_on_ca_residue", read: readFailOnCaResidue, unset: true },
  { name: "fail_on_blocked", read: readFailOnBlocked, unset: true },
])("$name", ({ name, read, unset }) => {
  it("reads its own input", () => {
    expect(read(inputs({ [name]: String(!unset) }))).toBe(!unset);
  });

  it("takes the default when unset", () => {
    expect(read(inputs())).toBe(unset);
  });

  it("names the input when it refuses a value", () => {
    expect(() => read(inputs({ [name]: "yes" }))).toThrow(
      `Invalid ${name}: "yes". Must be true or false.`,
    );
  });
});

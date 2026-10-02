import { describe, it, expect, vi } from "vitest";

import { SandboxError } from "./errors.ts";
import {
  readEngineInputs,
  readFailOnBlocked,
  readFailOnCaResidue,
  readFilesystemInputs,
  readRunCommand,
  readStepLabel,
  readTrafficArtifactInputs,
  resolveWriteThroughInput,
} from "./inputs.ts";

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
  {
    name: "upload_traffic_artifact",
    read: (getInput: (name: string) => string) => readTrafficArtifactInputs(getInput).upload,
    unset: false,
  },
])("$name", ({ name, read, unset }) => {
  it("reads its own input", () => {
    expect(read(inputs({ [name]: String(!unset) }))).toBe(!unset);
  });

  it("takes action.yml's own default when unset", () => {
    expect(read(inputs())).toBe(unset);
  });

  it("names the input when it refuses a value", () => {
    expect(() => read(inputs({ [name]: "yes" }))).toThrow(
      `Invalid ${name}: "yes". Must be true or false.`,
    );
  });
});

describe("readTrafficArtifactInputs", () => {
  it("leaves the retention to the repository's default when unset", () => {
    expect(readTrafficArtifactInputs(inputs({ upload_traffic_artifact: "true" }))).toStrictEqual({
      upload: true,
      retentionDays: undefined,
    });
  });

  it("reads a whole number of days", () => {
    expect(
      readTrafficArtifactInputs(inputs({ traffic_artifact_retention_days: "7" })),
    ).toStrictEqual({ upload: false, retentionDays: 7 });
  });

  it("refuses a bad retention even when nothing is uploaded", () => {
    expect(() =>
      readTrafficArtifactInputs(
        inputs({ upload_traffic_artifact: "false", traffic_artifact_retention_days: "0" }),
      ),
    ).toThrow(/Invalid traffic_artifact_retention_days/);
  });
});

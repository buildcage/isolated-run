import { describe, it, expect } from "vitest";
import { readFileSync, statSync } from "node:fs";

import { resolveSandboxEnv, buildEnvBlob, writeEnvLoader } from "./env-loader.ts";
import { withScratchDir } from "./scratch-dir.ts";
import { OWN_CA_DESTINATION, SYSTEM_CA_DESTINATION } from "./ca-trust.ts";

const caTrust = {
  ownCaPath: "/scratch/buildcage-ca.pem",
  systemCaPath: "/scratch/system-ca-bundle.pem",
};

/** The KEY=VALUE records of a blob, terminator excluded. */
function records(blob: Buffer): string[] {
  const parts = blob.toString("utf8").split("\0");
  expect(parts.at(-1)).toBe(""); // every record is NUL-*terminated*, not separated
  return parts.slice(0, -1);
}

describe("resolveSandboxEnv", () => {
  it("keeps the step's own environment and drops undefined values", () => {
    expect(resolveSandboxEnv({ FOO: "bar", UNSET: undefined })).toStrictEqual({ FOO: "bar" });
  });

  it("adds the CA trust variables that are unset, without overriding the step's own", () => {
    const resolved = resolveSandboxEnv({ NODE_EXTRA_CA_CERTS: "/my/own/bundle.pem" }, caTrust);
    expect(resolved.NODE_EXTRA_CA_CERTS).toBe("/my/own/bundle.pem");
    expect(resolved.REQUESTS_CA_BUNDLE).toBe(SYSTEM_CA_DESTINATION);
    expect(resolved.DENO_CERT).toBe(OWN_CA_DESTINATION);
  });

  it("drops keys a shell cannot export", () => {
    const resolved = resolveSandboxEnv({ "BASH_FUNC_x%%": "() { :; }", "1BAD": "x", OK: "y" });
    expect(resolved).toStrictEqual({ OK: "y" });
  });
});

describe("buildEnvBlob", () => {
  it("NUL-terminates every record and ends with the terminator", () => {
    expect(records(buildEnvBlob({ A: "1", B: "2" }))).toStrictEqual([
      "A=1",
      "B=2",
      "__BUILDCAGE_ENV_END__",
    ]);
  });

  it("carries values a line-based format would corrupt", () => {
    const key = "-----BEGIN KEY-----\nline two\r\nend\n";
    expect(
      records(buildEnvBlob({ KEY: key, EMPTY: "", EQUALS: "a=b=c", SPACED: " x y " })),
    ).toEqual([`KEY=${key}`, "EMPTY=", "EQUALS=a=b=c", "SPACED= x y ", "__BUILDCAGE_ENV_END__"]);
  });

  it("emits only the terminator for an empty environment", () => {
    expect(records(buildEnvBlob({}))).toStrictEqual(["__BUILDCAGE_ENV_END__"]);
  });
});

describe("writeEnvLoader", () => {
  it("writes an executable bash script that never evals and matches the blob's terminator", () => {
    withScratchDir((dir) => {
      const path = writeEnvLoader(dir);
      const content = readFileSync(path, "utf8");
      expect(content.startsWith("#!/bin/bash\n")).toBe(true);
      const code = content
        .split("\n")
        .filter((line) => !line.trimStart().startsWith("#"))
        .join("\n");
      expect(code).not.toMatch(/\beval\b/);
      expect(content).toContain('export "${record%%=*}=${record#*=}"');
      expect(content).toContain(records(buildEnvBlob({})).at(-1));
      expect(statSync(path).mode & 0o777).toBe(0o700);
    });
  });
});

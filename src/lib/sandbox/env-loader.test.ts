import { describe, it, expect, vi } from "vitest";
import { readFileSync, statSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import {
  resolveSandboxEnv,
  buildEnvBlob,
  writeEnvLoader,
  ACTION_INPUT_ENV_KEYS,
} from "./env-loader.ts";
import { withScratchDir } from "./scratch-dir.ts";
import { OWN_CA_DESTINATION } from "./ca-trust.ts";

/** Not the first candidate: the mount lands where the runner keeps its store. */
const SYSTEM_STORE = "/etc/pki/tls/certs/ca-bundle.crt";

const caTrust = {
  ownCaPath: "/scratch/buildcage-ca.pem",
  systemCa: { path: "/scratch/system-ca-bundle.pem", destination: SYSTEM_STORE },
  jvmKeystores: [],
};

/** The KEY=VALUE records of a blob, terminator excluded. */
function records(blob: Buffer): string[] {
  const parts = blob.toString("utf8").split("\0");
  expect(parts.at(-1)).toBe(""); // every record is NUL-terminated, not NUL-separated
  return parts.slice(0, -1);
}

describe("resolveSandboxEnv", () => {
  it("keeps the step's own environment, empty values included, and drops undefined ones", () => {
    // An empty value has to survive: emptying SSH_AUTH_SOCK in a step's own
    // `env:` is what keeps an agent out of the sandbox. See docs/security.md.
    expect(resolveSandboxEnv({ FOO: "bar", EMPTY: "", UNSET: undefined })).toStrictEqual({
      FOO: "bar",
      EMPTY: "",
    });
  });

  it("adds the CA trust variables that are unset, without overriding the step's own", () => {
    const resolved = resolveSandboxEnv({ NODE_EXTRA_CA_CERTS: "/my/own/bundle.pem" }, caTrust);
    expect(resolved.NODE_EXTRA_CA_CERTS).toBe("/my/own/bundle.pem");
    expect(resolved.REQUESTS_CA_BUNDLE).toBe(SYSTEM_STORE);
    expect(resolved.DENO_CERT).toBe(OWN_CA_DESTINATION);
  });

  it("withholds the credentials the runner sets for this action and not for a `run:` step", () => {
    const resolved = resolveSandboxEnv({
      ACTIONS_RUNTIME_URL: "https://pipelines.example",
      ACTIONS_RUNTIME_TOKEN: "a-real-token",
      ACTIONS_CACHE_URL: "https://cache.example",
      ACTIONS_RESULTS_URL: "https://results.example",
      ACTIONS_CACHE_SERVICE_V2: "True",
      ACTIONS_CACHE_MODE: "gzip",
      PATH: "/usr/bin",
    });
    expect(resolved).toStrictEqual({ PATH: "/usr/bin" });
  });

  it("keeps every ACTIONS_ variable it doesn't name, a `run:` step's own included", () => {
    // The last stands for anything a sweep over ACTIONS_* would take with it.
    const resolved = resolveSandboxEnv({
      ACTIONS_ID_TOKEN_REQUEST_URL: "https://idtoken.example",
      ACTIONS_ID_TOKEN_REQUEST_TOKEN: "an-oidc-token",
      ACTIONS_ORCHESTRATION_ID: "abc123",
      ACTIONS_ADDED_BY_SOMETHING_ELSE: "kept",
    });
    expect(Object.keys(resolved).sort()).toStrictEqual([
      "ACTIONS_ADDED_BY_SOMETHING_ELSE",
      "ACTIONS_ID_TOKEN_REQUEST_TOKEN",
      "ACTIONS_ID_TOKEN_REQUEST_URL",
      "ACTIONS_ORCHESTRATION_ID",
    ]);
  });

  it("withholds this action's own inputs, INPUT_RUN included", () => {
    const resolved = resolveSandboxEnv({
      INPUT_RUN: "echo $SECRET_INLINED_BY_THE_WORKFLOW",
      INPUT_PROXY_MODE: "restrict",
    });
    expect(resolved).toStrictEqual({});
  });

  it("keeps an INPUT_-shaped variable the workflow set itself", () => {
    const resolved = resolveSandboxEnv({ INPUT_DIR: "build", INPUT_FILE: "out.tar" });
    expect(resolved).toStrictEqual({ INPUT_DIR: "build", INPUT_FILE: "out.tar" });
  });

  it("drops keys a shell cannot export", () => {
    const resolved = resolveSandboxEnv({ "BASH_FUNC_x%%": "() { :; }", "1BAD": "x", OK: "y" });
    expect(resolved).toStrictEqual({ OK: "y" });
  });

  // Dropping a variable the step set is worth saying out loud, but where it is
  // said is the caller's call, not this module's.
  it("names the dropped keys to the sink it was given", () => {
    const warn = vi.fn();

    resolveSandboxEnv({ "BASH_FUNC_x%%": "() { :; }", "1BAD": "x", OK: "y" }, undefined, warn);

    expect(warn.mock.calls[0][0]).toBe(
      "Not passing environment variables whose names a shell cannot export: BASH_FUNC_x%%, 1BAD",
    );
  });

  // The runner sets these for this action alone, so they are withheld before
  // the check above ever sees them: nothing for the user to act on.
  it("says nothing about the inputs it withholds by design", () => {
    const warn = vi.fn();

    resolveSandboxEnv({ INPUT_RUN: "echo hi", OK: "y" }, undefined, warn);

    expect(warn).not.toHaveBeenCalled();
  });
});

describe("ACTION_INPUT_ENV_KEYS", () => {
  // Withholding by name only works while the name list is the whole of
  // action.yml: an input added there and forgotten here would reach the
  // sandbox as an environment variable.
  it("covers every input action.yml declares", () => {
    const actionYml = readFileSync(
      join(dirname(fileURLToPath(import.meta.url)), "../../../action.yml"),
      "utf8",
    );
    const inputs = actionYml.slice(actionYml.indexOf("\ninputs:"), actionYml.indexOf("\noutputs:"));
    const declared = [...inputs.matchAll(/^ {2}([A-Za-z0-9_]+):$/gm)].map(
      (m) => `INPUT_${m[1].toUpperCase()}`,
    );
    expect(declared.length).toBeGreaterThan(0);
    expect([...ACTION_INPUT_ENV_KEYS].sort()).toStrictEqual(declared.sort());
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

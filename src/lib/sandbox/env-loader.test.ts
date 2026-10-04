import { execFileSync, spawn, type ChildProcess } from "node:child_process";
import {
  closeSync,
  existsSync,
  mkdtempSync,
  openSync,
  readFileSync,
  rmSync,
  statSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import { describe, it, expect, vi } from "vitest";

import { OWN_CA_DESTINATION } from "./ca-trust.ts";
import {
  resolveSandboxEnv,
  buildEnvBlob,
  writeEnvLoader,
  ACTION_INPUT_ENV_KEYS,
} from "./env-loader.ts";
import { withScratchDir } from "./scratch-dir.ts";

/** Not the first candidate: the mount lands where the runner keeps its store. */
const SYSTEM_STORE = "/etc/pki/tls/certs/ca-bundle.crt";

const caTrust = {
  ownCaPath: "/scratch/buildcage-ca.pem",
  stores: [
    {
      kind: "systemStore" as const,
      path: "/scratch/system-ca-bundle.pem",
      destination: SYSTEM_STORE,
    },
  ],
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
  it("writes an executable bash script that never evals and matches the blob's terminator", async () => {
    await withScratchDir((dir) => {
      const path = writeEnvLoader(dir);
      const content = readFileSync(path, "utf8");
      expect(content.startsWith("#!/bin/bash\n")).toBe(true);
      const code = content
        .split("\n")
        .filter((line) => !line.trimStart().startsWith("#"))
        .join("\n");
      expect(code).not.toMatch(/\beval\b/);
      expect(content).toContain(records(buildEnvBlob({})).at(-1));
      expect(statSync(path).mode & 0o777).toBe(0o700);
    });
  });
});

/**
 * Runs the written loader with `script` as the run script, the way the sandbox
 * starts it, fd 3 included. `onReady` fires once the script prints "ready".
 * `started` is what the loader wrote to fd 3.
 */
async function runLoader(
  script: string,
  {
    blob = buildEnvBlob({}),
    feed = (loader) => loader.stdin?.end(blob),
    onReady,
    onExit,
  }: {
    blob?: Buffer;
    feed?: (loader: ChildProcess) => void;
    onReady?: (loader: ChildProcess) => void;
    onExit?: () => void;
  } = {},
): Promise<{ code: number | null; stdout: string; stderr: string; started: string }> {
  const dir = mkdtempSync(join(tmpdir(), "env-loader-test-"));
  try {
    const loaderPath = writeEnvLoader(dir);
    const scriptPath = join(dir, "run-script.sh");
    writeFileSync(scriptPath, `#!/bin/bash\n${script}\n`, { mode: 0o700 });
    const startedPath = join(dir, "started");
    const startedFd = openSync(startedPath, "w");
    const loader = spawn("bash", [loaderPath, scriptPath], {
      stdio: ["pipe", "pipe", "pipe", startedFd],
    });
    closeSync(startedFd);
    let stdout = "";
    let stderr = "";
    let ready = false;
    loader.stderr!.on("data", (chunk: Buffer) => {
      stderr += chunk.toString("utf8");
    });
    loader.stdout!.on("data", (chunk: Buffer) => {
      stdout += chunk.toString("utf8");
      if (!ready && stdout.includes("ready\n")) {
        ready = true;
        onReady?.(loader);
      }
    });
    loader.on("exit", () => onExit?.());
    feed(loader);
    const code = await new Promise<number | null>((resolve) => loader.on("close", resolve));
    return { code, stdout, stderr, started: readFileSync(startedPath, "utf8") };
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}

// Short sleeps: bash runs a trap only after the foreground command returns.
const WAIT_FOR_A_SIGNAL = "echo ready; while :; do sleep 0.1; done";

const [bashMajor, bashMinor] = execFileSync("bash", [
  "-c",
  'echo "${BASH_VERSINFO[0]} ${BASH_VERSINFO[1]}"',
])
  .toString()
  .trim()
  .split(" ")
  .map(Number);
// The loader relies on job control leaving SIGINT alone in a background child,
// and on $BASHPID. Runners ship 4.4+; macOS's /bin/bash is 3.2.
const BASH_4_4_OR_LATER = bashMajor > 4 || (bashMajor === 4 && bashMinor >= 4);

describe("the written loader", () => {
  it("runs the script with the step environment, literally, and an empty stdin", async () => {
    const { code, stdout } = await runLoader('echo "$A|$B"; cat', {
      blob: buildEnvBlob({ A: "one", B: "$(echo two)" }),
    });
    expect(stdout).toBe("one|$(echo two)\n");
    expect(code).toBe(0);
  });

  // Exported by the loader instead, these came out as its own values: the loop
  // variable's last record, bash's real uid, its own clock.
  it("hands the script exactly the step environment, names bash or the loader uses included", async () => {
    const env = { record: "mine", UID: "12345", SECONDS: "100", sig: "USR2" };
    const { code, stdout } = await runLoader("exec /usr/bin/env", { blob: buildEnvBlob(env) });
    const received = Object.fromEntries(
      stdout
        .trimEnd()
        .split("\n")
        .map((line) => [line.slice(0, line.indexOf("=")), line.slice(line.indexOf("=") + 1)]),
    );
    // bash adds these to the environment of any script it runs.
    for (const own of ["PWD", "SHLVL", "_", "OLDPWD"]) delete received[own];
    expect(received).toStrictEqual(env);
    expect(code).toBe(0);
  });

  it("runs the script with an empty step environment", async () => {
    const { code, stdout } = await runLoader('echo "${HOME-unset}"');
    expect(stdout).toBe("unset\n");
    expect(code).toBe(0);
  });

  it("refuses to run the script when the environment ends before its terminator", async () => {
    const blob = buildEnvBlob({ A: "one" });
    const truncated = blob.subarray(0, blob.indexOf("__BUILDCAGE_ENV_END__"));
    const { code, stdout, stderr, started } = await runLoader("echo ran", { blob: truncated });
    expect(stdout).toBe("");
    expect(stderr).toContain("ended before its terminator");
    expect(started).toBe("");
    expect(code).toBe(1);
  });

  it("writes to fd 3 before running the script, and keeps fd 3 from it", async () => {
    const { code, stdout, started } = await runLoader(
      "{ : >&3; } 2>/dev/null && echo open || echo closed",
    );
    expect(started).toBe("1");
    expect(stdout).toBe("closed\n");
    expect(code).toBe(0);
  });

  it("exits with the script's own status", async () => {
    expect((await runLoader("exit 42")).code).toBe(42);
  });

  it("gives the script a $$ of its own, so kill -TERM $$ ends it with 143", async () => {
    const { code, stdout } = await runLoader("kill -TERM $$; echo survived");
    expect(stdout).toBe("");
    expect(code).toBe(143);
  });

  it("forwards SIGTERM to the script and exits with the status its trap chose", async () => {
    const { code, stdout } = await runLoader(
      `trap 'echo got TERM; exit 0' TERM; ${WAIT_FOR_A_SIGNAL}`,
      { onReady: (loader) => loader.kill("SIGTERM") },
    );
    expect(stdout).toBe("ready\ngot TERM\n");
    expect(code).toBe(0);
  });

  it.skipIf(!BASH_4_4_OR_LATER)("forwards SIGINT to the script too", async () => {
    const { code, stdout } = await runLoader(
      `trap 'echo got INT; exit 7' INT; ${WAIT_FOR_A_SIGNAL}`,
      { onReady: (loader) => loader.kill("SIGINT") },
    );
    expect(stdout).toBe("ready\ngot INT\n");
    expect(code).toBe(7);
  });

  it.skipIf(!BASH_4_4_OR_LATER)(
    "forwards SIGTERM to the command the script runs, and waits for it to finish",
    async () => {
      const marker = join(mkdtempSync(join(tmpdir(), "env-loader-marker-")), "cleaned-up");
      const command = `trap 'sleep 0.3; echo > ${marker}; exit 0' TERM; ${WAIT_FOR_A_SIGNAL}`;
      let cleanedUpFirst: boolean | undefined;
      const { code } = await runLoader(`bash -c "${command}"`, {
        onReady: (loader) => loader.kill("SIGTERM"),
        onExit: () => {
          cleanedUpFirst = existsSync(marker);
        },
      });
      rmSync(dirname(marker), { recursive: true, force: true });
      expect(cleanedUpFirst).toBe(true);
      // The script itself does not trap it.
      expect(code).toBe(143);
    },
  );

  it.skipIf(!BASH_4_4_OR_LATER)(
    "does not wait for what the script left running after a signal that does not stop it",
    async () => {
      const started = Date.now();
      const { code } = await runLoader(
        `trap 'exit 0' USR1; (trap '' USR1; sleep 3) >/dev/null 2>&1 & ${WAIT_FOR_A_SIGNAL}`,
        { onReady: (loader) => loader.kill("SIGUSR1") },
      );
      expect(code).toBe(0);
      expect(Date.now() - started).toBeLessThan(2_000);
    },
  );

  it("does not wait for what the script left running when it exits on its own", async () => {
    const started = Date.now();
    const { code } = await runLoader("sleep 3 >/dev/null 2>&1 & exit 0");
    expect(code).toBe(0);
    expect(Date.now() - started).toBeLessThan(2_000);
  });

  it("exits 128+n when a forwarded signal kills the script", async () => {
    const { code } = await runLoader(WAIT_FOR_A_SIGNAL, {
      onReady: (loader) => loader.kill("SIGTERM"),
    });
    expect(code).toBe(143);
  });

  it("adds nothing to stderr when a signal it doesn't trap kills the script", async () => {
    const { code, stderr } = await runLoader("kill -KILL $$");
    expect(stderr).toBe("");
    expect(code).toBe(137);
  });

  // Signals the loader mid-read. The pause lets it install its traps first.
  async function signalBeforeTheScriptStarts(signal: NodeJS.Signals) {
    const blob = buildEnvBlob({ A: "one" });
    return runLoader("sleep 5; echo ran", {
      feed: (loader) => {
        loader.stdin?.write(blob.subarray(0, 3));
        setTimeout(() => {
          loader.kill(signal);
          setTimeout(() => loader.stdin?.end(blob.subarray(3)), 100);
        }, 300);
      },
    });
  }

  it.skipIf(!BASH_4_4_OR_LATER)(
    "holds a SIGTERM that arrives before the script starts and sends it on",
    async () => {
      const { code, stdout } = await signalBeforeTheScriptStarts("SIGTERM");
      expect(stdout).toBe("");
      expect(code).toBe(143);
    },
  );

  it.skipIf(!BASH_4_4_OR_LATER)(
    "holds a SIGINT that arrives before the script starts and sends it on",
    async () => {
      const { code, stdout } = await signalBeforeTheScriptStarts("SIGINT");
      expect(stdout).toBe("");
      expect(code).toBe(130);
    },
  );
});

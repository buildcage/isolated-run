import { readFileSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import { ACTION_INPUTS } from "../inputs.ts";
import { caTrustAdditions, type CaTrustFiles } from "./ca-trust.ts";
import type { Warn } from "./scratch-dir.ts";

// The step environment reaches the sandbox over stdin instead of through
// config.json, so `env:` secrets never land on the runner's disk. Records
// are NUL-delimited because NUL is the one byte an environment value cannot
// hold, and values legitimately contain newlines (multi-line keys, JSON).

// Ending the blob explicitly rather than at EOF turns a truncated transfer
// into a failed step instead of one running with variables silently
// missing. Holds no "=", so it cannot collide with a real record.
export const ENV_BLOB_TERMINATOR = "__BUILDCAGE_ENV_END__";

// execve accepts any key without "=", but a shell can only export
// identifier-shaped ones. Also keeps bash's `BASH_FUNC_x%%` function
// exports, an injection vector, out of the sandbox.
const ENV_KEY = /^[A-Za-z_][A-Za-z0-9_]*$/;

// The difference between NodeScriptActionHandler and ScriptHandler in
// actions/runner: what a JavaScript action's handler is handed and a `run:`
// step is not. Forwarding these would give the command a credential it could
// not have had unwrapped. ACTIONS_ID_TOKEN_REQUEST_* and
// ACTIONS_ORCHESTRATION_ID are left out because a `run:` step gets those too.
// Naming each one rather than sweeping ACTIONS_* keeps that distinction exact,
// at the price of having to follow a token the runner adds later.
const RUNNER_ONLY_ENV_KEYS = new Set([
  "ACTIONS_RUNTIME_URL",
  "ACTIONS_RUNTIME_TOKEN",
  "ACTIONS_CACHE_URL",
  "ACTIONS_RESULTS_URL",
  "ACTIONS_CACHE_SERVICE_V2",
  "ACTIONS_CACHE_MODE",
]);

// This action's own `with:` inputs, which a `run:` step has none of. INPUT_RUN
// holds the command verbatim, secrets included where the workflow inlined one,
// and the script carrying that same text is 0700 while an environment variable
// is readable from every process in the sandbox. Listed rather than swept by
// the INPUT_ prefix: a workflow is free to set an `env: INPUT_DIR` of its own,
// and this action is a JavaScript one, so no other action's inputs reach this
// process to be missed. env-loader.test.ts holds the list to action.yml.
export const ACTION_INPUT_ENV_KEYS = new Set(
  ACTION_INPUTS.map((input) => `INPUT_${input.toUpperCase()}`),
);

function isRunnerOnly(key: string): boolean {
  return RUNNER_ONLY_ENV_KEYS.has(key) || ACTION_INPUT_ENV_KEYS.has(key);
}

/** The step's own environment, minus what the runner added for this action
 *  alone, plus (inspect engine only) the CA-trust variables it left unset (see
 *  ca-trust.ts) and `overrides`, which repoint the command at its mediated
 *  runner files (see runner-output-files.ts). `overrides` win over the step's
 *  own values and are identifier-shaped by construction, so they skip the
 *  name check. */
export function resolveSandboxEnv(
  env: NodeJS.ProcessEnv,
  caTrust?: CaTrustFiles,
  warn?: Warn,
  overrides: Record<string, string> = {},
): Record<string, string> {
  const merged = { ...env, ...(caTrust ? caTrustAdditions(caTrust, env).env : undefined) };
  const resolved: Record<string, string> = {};
  const skipped: string[] = [];
  for (const [key, value] of Object.entries(merged)) {
    if (value === undefined) continue;
    // Ahead of ENV_KEY so these never reach the warning below, which is for
    // input the user can act on.
    if (isRunnerOnly(key)) continue;
    if (!ENV_KEY.test(key)) skipped.push(key);
    else resolved[key] = value;
  }
  if (skipped.length > 0) {
    warn?.(
      `Not passing environment variables whose names a shell cannot export: ${skipped.join(", ")}`,
    );
  }
  return { ...resolved, ...overrides };
}

export function buildEnvBlob(resolved: Record<string, string>): Buffer {
  const records = [...Object.entries(resolved).map(([k, v]) => `${k}=${v}`), ENV_BLOB_TERMINATOR];
  return Buffer.from(records.map((record) => `${record}\0`).join(""), "utf8");
}

// Resolved from the bundle's own location: dist/main.cjs sits beside scripts/.
const __dirname = dirname(fileURLToPath(import.meta.url));

/** The sandbox's PID 1, shipped in scripts/ as run-isolated.sh is. */
export const ENV_LOADER_SOURCE = join(__dirname, "..", "scripts", "buildcage-init.sh");

/** Copies the loader into `execDir`. bash reads a script as it runs, and the
 *  checkout may be writable from the sandbox, so the sandbox runs the copy. */
export function writeEnvLoader(execDir: string, source = ENV_LOADER_SOURCE): string {
  // The name the step sees as its PID 1, in ps and /proc/1/cmdline.
  const loaderPath = join(execDir, "buildcage-init");
  writeFileSync(loaderPath, readFileSync(source), { mode: 0o700 });
  return loaderPath;
}

/** How the loader is started: the record that ends the environment, then the
 *  script to run. */
export function envLoaderArgs(loaderPath: string, scriptPath: string): string[] {
  return [loaderPath, ENV_BLOB_TERMINATOR, scriptPath];
}

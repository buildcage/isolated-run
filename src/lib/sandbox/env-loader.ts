import { writeFileSync } from "node:fs";
import { join } from "node:path";

import { caTrustAdditions, type CaTrustFiles } from "./ca-trust.ts";
import type { Warn } from "./scratch-dir.ts";

// The step environment reaches the sandbox over stdin instead of through
// config.json, so `env:` secrets never land on the runner's disk. Records
// are NUL-delimited because NUL is the one byte an environment value cannot
// hold, and values legitimately contain newlines (multi-line keys, JSON).

// Ending the blob explicitly rather than at EOF turns a truncated transfer
// into a failed step instead of one running with variables silently
// missing. Holds no "=", so it cannot collide with a real record.
const ENV_BLOB_TERMINATOR = "__BUILDCAGE_ENV_END__";

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
  [
    "run",
    "proxy_mode",
    "proxy_engine",
    "allowed_https_rules",
    "allowed_http_rules",
    "allowed_ip_rules",
    "allowed_url_rules",
    "allowed_tls_rules",
    "upload_traffic_artifact",
    "traffic_artifact_retention_days",
    "fail_on_blocked",
    "fail_on_ca_residue",
    "known_blocked_rules",
    "write_through",
    "writable",
    "filesystem_mode",
    "label",
  ].map((input) => `INPUT_${input.toUpperCase()}`),
);

function isRunnerOnly(key: string): boolean {
  return RUNNER_ONLY_ENV_KEYS.has(key) || ACTION_INPUT_ENV_KEYS.has(key);
}

/** The step's own environment, minus what the runner added for this action
 *  alone, plus (inspect engine only) the CA-trust variables it left unset.
 *  See ca-trust.ts. */
export function resolveSandboxEnv(
  env: NodeJS.ProcessEnv,
  caTrust?: CaTrustFiles,
  warn?: Warn,
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
  return resolved;
}

export function buildEnvBlob(resolved: Record<string, string>): Buffer {
  const records = [...Object.entries(resolved).map(([k, v]) => `${k}=${v}`), ENV_BLOB_TERMINATOR];
  return Buffer.from(records.map((record) => `${record}\0`).join(""), "utf8");
}

// Not #!/bin/sh: runners' /bin/sh is dash, which has no `read -d`. bash is
// guaranteed present, since the sandbox rootfs is the runner's own `/` and
// run-isolated.sh already runs there under it. Builtins only, so the empty
// environment runc starts this with is enough.
//
// Stays PID 1 so the command doesn't have to be: the kernel drops any signal
// PID 1 has no handler for and hands it every orphan, which a user's command
// (or python, node) neither handles nor reaps.
const ENV_LOADER_SCRIPT = `#!/bin/bash
# Applies the step environment from stdin, then runs $1 as a child: forwards
# signals to it, reaps orphans, and exits with its status. See
# sandbox/env-loader.ts for the wire format.
#
# No eval: \`export "K=V"\` expands the value once and never re-interprets
# it, so a value containing $(...) or a backtick stays literal.
set -u

# Trapped before reading, as PID 1 drops untrapped signals. Any that arrive
# before the child exists are held for it.
child=
pending=
forward() {
  if [ -n "$child" ]; then
    kill -s "$1" "$child" 2>/dev/null
  else
    pending="$pending $1"
  fi
}
for sig in TERM INT HUP QUIT USR1 USR2; do trap "forward $sig" "$sig"; done

complete=
while IFS= read -r -d '' record; do
  if [ "$record" = "${ENV_BLOB_TERMINATOR}" ]; then
    complete=1
    break
  fi
  [[ $record =~ ^[A-Za-z_][A-Za-z0-9_]*= ]] || continue
  export "\${record%%=*}=\${record#*=}"
done

if [ -z "$complete" ]; then
  echo "buildcage: the sandbox environment ended before its terminator; refusing to run" >&2
  exit 1
fi

# Never hand the run script the tail of this blob.
exec 0</dev/null

# Without job control bash starts a background child with SIGINT and SIGQUIT
# ignored; \`trap -\` restores them (bash 4.4+). Held signals are raised only
# after that, from inside the child. A held SIGQUIT is still dropped, since bash
# ignores it in itself.
held=$pending
{
  trap - INT QUIT
  for sig in $held; do kill -s "$sig" "$BASHPID"; done
  exec "$1"
} &
child=$!
# Signals that arrived during the fork. An INT or QUIT among them can still hit
# the ignore.
for sig in \${pending#"$held"}; do kill -s "$sig" "$child" 2>/dev/null; done
# Keeps bash's "Killed" job notice out of the step's output. The child has its
# own stderr.
exec 2>/dev/null
# A trapped signal interrupts \`wait\` with 128+n; the final \`wait\` returns the
# child's own status, 128+n if a signal killed it, as runc reports for an init.
while kill -0 "$child" 2>/dev/null; do wait "$child"; done
wait "$child"
exit $?
`;

export function writeEnvLoader(execDir: string): string {
  const loaderPath = join(execDir, "env-loader.sh");
  writeFileSync(loaderPath, ENV_LOADER_SCRIPT, { mode: 0o700 });
  return loaderPath;
}

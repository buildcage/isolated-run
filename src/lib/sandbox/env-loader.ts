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
    "config_file",
    "proxy_mode",
    "proxy_engine",
    "allowed_https_rules",
    "allowed_http_rules",
    "allowed_ip_rules",
    "allowed_url_rules",
    "allowed_tls_rules",
    "aws_key_check",
    "allowed_aws_role_accounts",
    "upload_traffic_artifact",
    "traffic_artifact_retention_days",
    "fail_on_blocked",
    "fail_on_ca_residue",
    "known_blocked_rules",
    "write_through",
    "writable",
    "filesystem_mode",
    "filesystem_audit",
    "filesystem_audit_retention_days",
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
// run-isolated.sh already runs there under it. Only builtins, and env (and
// sleep, in the fallback below) by their absolute paths, so the empty
// environment runc starts this with is enough. Short of that fallback, it
// starts no process once the step runs, so the filesystem audit sees nothing
// of it but its own accesses.
//
// Stays PID 1 so the command doesn't have to be: the kernel drops any signal
// PID 1 has no handler for and hands it every orphan, which a user's command
// (or python, node) neither handles nor reaps.
const ENV_LOADER_SCRIPT = `#!/bin/bash
# Applies the step environment from stdin, then runs $1 as a child: forwards
# signals to it, reaps orphans, and exits with its status. See
# sandbox/env-loader.ts for the wire format.
#
# The records go to env(1) rather than being exported, so a step variable
# named like one of this script's, or like a bash readonly or dynamic variable
# (UID, SECONDS), arrives as set. No eval: each record is one argument, never
# re-interpreted, so a value containing $(...) or a backtick stays literal.
set -u

# Trapped before reading, as PID 1 drops untrapped signals. Any that arrive
# before the child exists are held for it. TERM and INT stop the step, so
# they go to everything the step started, a process it moved out of the
# child's group with setsid included; the rest go to that group, which holds
# the command the script runs.
child=
# As the sandbox's PID 1, -1 reaches every process in its pid namespace but
# itself; anywhere else, as in this script's own tests, it would reach every
# process the user owns, so it stops at the child's group.
stop_target=
[ "$$" = 1 ] && stop_target=-1
pending=
stopping=
forward() {
  if [ -n "$child" ]; then
    case "$1" in
      TERM | INT)
        stopping=1
        kill -s "$1" -- "\${stop_target:--$child}" 2>/dev/null
        ;;
      *) kill -s "$1" -- "-$child" 2>/dev/null ;;
    esac
  else
    pending="$pending $1"
  fi
}
for sig in TERM INT HUP QUIT USR1 USR2; do trap "forward $sig" "$sig"; done

complete=
records=()
while IFS= read -r -d '' record; do
  if [ "$record" = "${ENV_BLOB_TERMINATOR}" ]; then
    complete=1
    break
  fi
  [[ $record =~ ^[A-Za-z_][A-Za-z0-9_]*= ]] || continue
  records+=("$record")
done

if [ -z "$complete" ]; then
  echo "buildcage: the sandbox environment ended before its terminator; refusing to run" >&2
  exit 1
fi

# Never hand the run script the tail of this blob.
exec 0</dev/null

# A pipe this process holds both ends of, so \`read -t\` on it waits out its
# timeout: a pause that starts no process, unlike sleep(1). Opened before the
# step starts, so its one fork happens before then. Linux reopens the
# pipe through /dev/fd; where that fails, the wait falls back to sleep(1).
nap=
if ! { exec 9<> <(:); } 2>/dev/null; then
  nap=/usr/bin/sleep
  [ -x "$nap" ] || nap=/bin/sleep
fi

# Tells run-isolated.sh that the command is starting. The command never gets
# fd 3.
{ printf 1 >&3; } 2>/dev/null
exec 3>&-

# Job control puts the child in a process group of its own, and leaves SIGINT
# and SIGQUIT as they are rather than ignoring them in it. Held signals are
# raised from inside the child.
held=$pending
set -m
{
  for sig in $held; do kill -s "$sig" "$BASHPID"; done
  exec 9>&-
  # $1 is this run's script, whose path holds no "=" for env to read as a record.
  exec /usr/bin/env -i -- \${records[@]+"\${records[@]}"} "$1"
} &
child=$!
set +m
# Signals that arrived during the fork.
for sig in \${pending#"$held"}; do forward "$sig"; done
# Keeps bash's "Killed" job notice out of the step's output. The child has its
# own stderr.
exec 2>/dev/null
# A trapped signal interrupts \`wait\` with 128+n; the final \`wait\` returns the
# child's own status, 128+n if a signal killed it, as runc reports for an init.
while kill -0 "$child" 2>/dev/null; do wait "$child"; done
wait "$child"
status=$?
# The script can exit on a SIGTERM or SIGINT while the command it ran is still
# winding down, and this process exiting would kill it. Anything that ignores
# the signal holds the step until it is killed from outside.
if [ -n "$stopping" ]; then
  while kill -0 -- "\${stop_target:--$child}" 2>/dev/null; do
    if [ -n "$nap" ]; then "$nap" 0.1; else read -r -t 0.1 -u 9 _ || :; fi
  done
fi
exit $status
`;

export function writeEnvLoader(execDir: string): string {
  // The name the step sees as its PID 1, in ps and /proc/1/cmdline.
  const loaderPath = join(execDir, "buildcage-init");
  writeFileSync(loaderPath, ENV_LOADER_SCRIPT, { mode: 0o700 });
  return loaderPath;
}

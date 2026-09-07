import { writeFileSync } from "node:fs";
import { join } from "node:path";
import { caTrustAdditions, type CaTrustFiles } from "./ca-trust.ts";

/**
 * The step's environment is handed to the sandbox over stdin rather than
 * embedded in config.json, so no part of it (`env:` secrets included) is
 * ever written to the runner's disk. `run.ts` pipes the blob into
 * `sudo run-isolated.sh`, which passes stdin through untouched to
 * `runc run` and from there to the loader below.
 *
 * Records are NUL-delimited: NUL is the one byte an environment value
 * cannot contain (execve's own envp is a NUL-terminated array), so it is
 * the only delimiter that survives values holding newlines -- a multi-line
 * private key or an inline JSON document, both ordinary `env:` contents.
 *
 * The blob ends with an explicit terminator record instead of relying on
 * EOF, so a truncated transfer fails the step rather than running it with
 * silently missing variables. It holds no "=", so it can never collide
 * with a real KEY=VALUE record.
 */
const ENV_BLOB_TERMINATOR = "__BUILDCAGE_ENV_END__";

// execve accepts any key without "=", but a shell can only export the
// identifier-shaped ones. The rest (e.g. bash's own `BASH_FUNC_x%%`
// function exports, a known injection vector, and absent from a runner's
// normal environment) are dropped rather than smuggled through.
const ENV_KEY = /^[A-Za-z_][A-Za-z0-9_]*$/;

/**
 * The environment the sandboxed process should see: the step's own, plus
 * (inspect engine only) the CA-trust variables that were left unset -- see
 * ca-trust.ts. Undefined values are dropped, as they were when this went
 * into config.json's `process.env`.
 */
export function resolveSandboxEnv(
  env: NodeJS.ProcessEnv,
  caTrust?: CaTrustFiles,
): Record<string, string> {
  const merged = { ...env, ...(caTrust ? caTrustAdditions(caTrust, env).env : undefined) };
  const resolved: Record<string, string> = {};
  const skipped: string[] = [];
  for (const [key, value] of Object.entries(merged)) {
    if (value === undefined) continue;
    if (!ENV_KEY.test(key)) skipped.push(key);
    else resolved[key] = value;
  }
  if (skipped.length > 0) {
    console.log(
      `::warning::Not passing environment variables whose names a shell cannot export: ${skipped.join(", ")}`,
    );
  }
  return resolved;
}

/** Serialize the resolved environment for the loader below. */
export function buildEnvBlob(resolved: Record<string, string>): Buffer {
  const records = [...Object.entries(resolved).map(([k, v]) => `${k}=${v}`), ENV_BLOB_TERMINATOR];
  return Buffer.from(records.map((record) => `${record}\0`).join(""), "utf8");
}

// #!/bin/bash, not #!/bin/sh: GitHub-hosted runners' /bin/sh is dash, which
// has no `read -d`. The sandbox rootfs is the runner's own `/` and
// run-isolated.sh already runs there under bash, so bash is guaranteed
// present. Uses only builtins, so it works with the empty environment runc
// starts it with.
const ENV_LOADER_SCRIPT = `#!/bin/bash
# Applies the step environment from stdin, then execs the run script given
# as $1. See sandbox/env-loader.ts for the wire format.
#
# No eval: \`export "K=V"\` expands the value once, within double quotes, and
# never re-interprets it, so a value containing $(...) or a backtick stays
# literal -- the same reasoning as writeRunScript routing the run: input
# through a file instead of inlining it into a shell.
set -u

while IFS= read -r -d '' record; do
  if [ "$record" = "${ENV_BLOB_TERMINATOR}" ]; then
    # The run script gets a clean stdin, never the tail of this blob.
    exec 0</dev/null
    exec "$1"
  fi
  [[ $record =~ ^[A-Za-z_][A-Za-z0-9_]*= ]] || continue
  export "\${record%%=*}=\${record#*=}"
done

echo "buildcage: the sandbox environment ended before its terminator; refusing to run" >&2
exit 1
`;

/** Write the loader that `process.args` execs ahead of the run script. */
export function writeEnvLoader(execDir: string): string {
  const loaderPath = join(execDir, "env-loader.sh");
  writeFileSync(loaderPath, ENV_LOADER_SCRIPT, { mode: 0o700 });
  return loaderPath;
}

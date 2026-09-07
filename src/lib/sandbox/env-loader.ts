import { writeFileSync } from "node:fs";
import { join } from "node:path";

/**
 * NUL-delimited "KEY=VALUE\0KEY=VALUE\0..." encoding, read back by the
 * loader script from writeEnvLoader. NUL, not newline, is the delimiter:
 * a value may legitimately contain newlines, but never a NUL byte --
 * execve's own envp is a NUL-terminated array.
 */
export function encodeEnvBlob(entries: [string, string][]): Buffer {
  return Buffer.concat(entries.map(([k, v]) => Buffer.from(`${k}=${v}\0`, "utf8")));
}

/**
 * Write the loader script that sits between runc's process.args and the
 * user's run-script.sh: reads encodeEnvBlob's output, base64-decoded,
 * from its own stdin, exports each KEY=VALUE pair, then execs into $1
 * (the real scriptPath) with that env in place. Keeps the step's
 * environment -- including any `env:` secrets -- out of config.json
 * entirely; see oci-config.ts's buildEnvBlob.
 *
 * base64, not raw bytes: `sudo` allocates a pseudo-tty for the child on
 * any host where sudoers sets `Defaults use_pty` (the GitHub-hosted-
 * runner default), and a pty in canonical mode intercepts specific
 * control bytes (ISIG/IXON) as signals or flow control instead of
 * delivering them as data, corrupting any secret containing one. base64's
 * output alphabet contains none of those bytes.
 *
 * #!/bin/bash, not #!/bin/sh: needs `read -d ''` for NUL-delimited reads,
 * which dash (the default /bin/sh on GitHub-hosted ubuntu-* runners)
 * lacks.
 *
 * `export "$key=$value"`, never eval: the value is expanded exactly once
 * and not re-parsed as shell syntax, so metacharacters inside it stay
 * inert.
 */
export function writeEnvLoader(dir: string): string {
  const loaderPath = join(dir, "env-loader.sh");
  const content = `#!/bin/bash
set -e
while IFS= read -r -d '' kv; do
  key="\${kv%%=*}"
  value="\${kv#*=}"
  if [[ "$key" =~ ^[A-Za-z_][A-Za-z0-9_]*$ ]]; then
    export "$key=$value"
  fi
done < <(base64 -d)
exec "$1"
`;
  writeFileSync(loaderPath, content, { mode: 0o700 });
  return loaderPath;
}

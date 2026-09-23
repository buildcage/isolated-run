/**
 * What this action runs on the host once the sandboxed command has started,
 * kept out of the command's reach.
 *
 * The command can write to some host paths, and those writes outlive it:
 * everything persistent mode binds back read-write, or whatever write_through
 * names in ephemeral mode. This step goes on running `docker` and `sudo` after
 * the command exits, to read the report and tear the sandbox down. Looked up
 * through the inherited `$PATH` at that point, a `docker` the command dropped
 * into `~/.local/bin` would run in their place, outside every namespace and
 * with the runner's own access. So both are resolved once, before the command
 * starts, to a binary none of those paths contain.
 *
 * The same applies to what the docker CLI loads (plugins such as `compose`,
 * contexts, config) and to this action's own files (the post step's script),
 * which sandboxReadonlyHostDirs covers by making them read-only inside the sandbox.
 */

import { accessSync, constants, realpathSync } from "node:fs";
import { delimiter, dirname, isAbsolute, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { SandboxError } from "../errors.ts";
import type { FilesystemMode } from "../filesystem-mode.ts";
import { writableDirsOf } from "./oci-mounts.ts";
import { isAtOrUnder } from "./paths.ts";
import { pinCommand } from "./pinned-commands.ts";

// rollup's cjs output doesn't convert import.meta.dirname (it silently
// becomes undefined), so use this form instead.
const __dirname = dirname(fileURLToPath(import.meta.url));

/** The action's own checkout: `dist/` is where the bundle this runs from lives. */
const ACTION_ROOT = resolve(__dirname, "..");

const PINNED_COMMANDS = ["docker", "sudo"] as const;

/**
 * Host paths the sandboxed command can write to whose contents survive it.
 * Ephemeral mode's overlay roots are left out: their writes are discarded
 * before anything here runs again.
 */
export function persistingWritablePaths(
  filesystemMode: FilesystemMode,
  writeThroughPaths: string[],
  env: NodeJS.ProcessEnv,
): string[] {
  if (filesystemMode === "ephemeral") return writeThroughPaths;
  return writableDirsOf({
    workdir: env.GITHUB_WORKSPACE,
    home: env.HOME,
    runnerTemp: env.RUNNER_TEMP,
    writablePaths: writeThroughPaths,
  });
}

export interface FindCommandDeps {
  isExecutable: (path: string) => boolean;
  realpath: (path: string) => string;
}

// Untested by design: the defaults behind this module's seams, which only hand
// node:fs what the tested caller decided.
/* v8 ignore start */
const realFindCommandDeps: FindCommandDeps = {
  isExecutable: (path) => {
    try {
      accessSync(path, constants.X_OK);
      return true;
    } catch {
      return false;
    }
  },
  realpath: (path) => realpathSync(path),
};
/* v8 ignore stop */

/**
 * The first `command` on `pathEnv` whose real location is outside every one
 * of `persisting`, as that real path. A relative `$PATH` entry is skipped: it
 * resolves against the working directory, which is the workspace.
 * `write_through: /` leaves nothing outside, and is the documented full
 * opt-out, so the first match is taken as is.
 */
export function findPinnableCommand(
  command: string,
  pathEnv: string | undefined,
  persisting: string[],
  { isExecutable, realpath }: FindCommandDeps = realFindCommandDeps,
): string | undefined {
  const optedOut = persisting.includes("/");
  for (const dir of (pathEnv ?? "").split(delimiter)) {
    if (!isAbsolute(dir)) continue;
    const candidate = join(dir, command);
    if (!isExecutable(candidate)) continue;
    const real = realpath(candidate);
    if (optedOut || !persisting.some((p) => isAtOrUnder(real, p))) return real;
  }
  return undefined;
}

/**
 * Resolves `docker` and `sudo` for the rest of this process. Must run before
 * the sandboxed command starts: after that, `$PATH` may lead somewhere it wrote.
 */
export function pinHostCommands(
  persisting: string[],
  env: NodeJS.ProcessEnv,
  deps: FindCommandDeps = realFindCommandDeps,
): void {
  for (const command of PINNED_COMMANDS) {
    const path = findPinnableCommand(command, env.PATH, persisting, deps);
    if (!path) {
      throw new SandboxError(
        `No '${command}' found on PATH outside the paths the sandboxed command can write to ` +
          `(${persisting.join(", ")}). This step runs it after the command exits, so it has to ` +
          "live somewhere the command cannot replace it.",
        "HOST_COMMAND_UNPINNABLE",
      );
    }
    pinCommand(command, path);
  }
}

/** The directory the docker CLI reads its config, contexts and plugins from. */
export function dockerConfigDir(env: NodeJS.ProcessEnv): string | undefined {
  if (env.DOCKER_CONFIG) return resolve(env.DOCKER_CONFIG);
  return env.HOME ? join(env.HOME, ".docker") : undefined;
}

/**
 * Of this action's own directory and the docker CLI's config directory, the
 * ones the sandbox has to see read-only: those inside a persisting writable
 * path. One that itself contains such a path is left alone, since making it
 * read-only would take that path with it: `uses: ./` puts the action in the
 * workspace, and a write_through entry may name the config directory outright.
 */
export function sandboxReadonlyHostDirs(
  persisting: string[],
  env: NodeJS.ProcessEnv,
  actionRoot: string = ACTION_ROOT,
): string[] {
  const candidates = [actionRoot, dockerConfigDir(env)].filter((p): p is string => Boolean(p));
  return candidates.filter(
    (dir) =>
      persisting.some((p) => isAtOrUnder(dir, p)) && !persisting.some((p) => isAtOrUnder(p, dir)),
  );
}

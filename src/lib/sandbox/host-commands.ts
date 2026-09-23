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

import { accessSync, constants, readlinkSync } from "node:fs";
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
  /** The immediate target of `path` if it is a symlink (resolved to absolute
   *  against `path`'s own directory), or null if it is not one. */
  readlink: (path: string) => string | null;
}

// Symlink hops followed before giving up, matching the kernel's own
// MAXSYMLINKS. A loop hits this too, so it doubles as the cycle guard.
const MAX_SYMLINK_HOPS = 40;

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
  readlink: (path) => {
    try {
      const target = readlinkSync(path);
      return isAbsolute(target) ? target : resolve(dirname(path), target);
    } catch {
      // ENOENT (dangling) or EINVAL (not a symlink): either way there is no
      // further hop to follow from here.
      return null;
    }
  },
};
/* v8 ignore stop */

/**
 * Every path a `command` lookup would touch: the `$PATH` entry itself, then
 * each symlink target down to the real file. What matters is that none of
 * them sits where the sandboxed command can write, since it could repoint any
 * hop that does. Component symlinks (a symlink in a parent directory) are not
 * walked: the directories `$PATH` names are outside the writable set to begin
 * with, so only the final-component chain can lead back into it.
 */
function commandChain(candidate: string, readlink: FindCommandDeps["readlink"]): string[] {
  const chain = [candidate];
  let current = candidate;
  for (let i = 0; i < MAX_SYMLINK_HOPS; i++) {
    const target = readlink(current);
    if (target === null) break;
    chain.push(target);
    current = target;
  }
  return chain;
}

/**
 * The first `command` on `pathEnv` whose every symlink hop, its own `$PATH`
 * entry included, lies outside all of `persisting`, returned as that `$PATH`
 * entry rather than the resolved target: a tool such as snap's `docker`
 * (`/snap/bin/docker` -> `/usr/bin/snap`) decides its role from the name it
 * was invoked by, which the resolved path would lose. A relative `$PATH`
 * entry is skipped: it resolves against the working directory, which is the
 * workspace. `write_through: /` leaves nothing outside, and is the documented
 * full opt-out, so the first match is taken as is.
 */
export function findPinnableCommand(
  command: string,
  pathEnv: string | undefined,
  persisting: string[],
  { isExecutable, readlink }: FindCommandDeps = realFindCommandDeps,
): string | undefined {
  const optedOut = persisting.includes("/");
  for (const dir of (pathEnv ?? "").split(delimiter)) {
    if (!isAbsolute(dir)) continue;
    const candidate = join(dir, command);
    if (!isExecutable(candidate)) continue;
    const reachable = (p: string): boolean => persisting.some((w) => isAtOrUnder(p, w));
    if (optedOut || !commandChain(candidate, readlink).some(reachable)) return candidate;
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

/**
 * The directories that must be turned into mount points so a read-only dir
 * from sandboxReadonlyHostDirs cannot be freed by renaming a parent. A
 * read-only bind is itself a mount point, so it cannot be renamed; but the
 * writable directories above it are not, and `mv ~/work/_actions/buildcage
 * ~/x` would move the whole subtree and let the command recreate the action's
 * files at the original path, which its post step runs from. The kernel
 * refuses to rename a mount point (EBUSY), so every directory between the
 * writable root and the read-only dir is bound onto itself read-write here:
 * still writable, but no longer renamable.
 *
 * The writable root itself is already a mount point (persistent binds it, and
 * ephemeral overlays it), and the read-only dir is one too, so only the
 * strictly-in-between directories remain. A dir sitting directly under the
 * root (like `~/.docker`) therefore contributes none.
 */
export function renameGuardDirs(readonlyDirs: string[], persisting: string[]): string[] {
  const guards = new Set<string>();
  for (const dir of readonlyDirs) {
    // The deepest containing writable path: fewest intermediates, all of them
    // still inside the writable area.
    const root = persisting
      .filter((p) => p !== "/" && isAtOrUnder(dir, p))
      .sort((a, b) => b.length - a.length)[0];
    if (!root) continue;
    for (let p = dirname(dir); p !== root && isAtOrUnder(p, root); p = dirname(p)) {
      guards.add(p);
    }
  }
  // Shallowest first, so a parent guard is bound before the child that nests in
  // it (same ordering persistentLayers uses for its own binds).
  return [...guards].sort((a, b) => a.length - b.length || a.localeCompare(b));
}

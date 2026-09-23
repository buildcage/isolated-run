/**
 * Keeps what this action runs on the host out of reach of the sandboxed
 * command, whose writes to some host paths outlive it. `docker` and `sudo`
 * are pinned to binaries outside those paths, since a lookup through `$PATH`
 * could pick one the command planted (`~/.local/bin` precedes `/usr/bin` on
 * hosted runners). The docker CLI's config directory and this action's own
 * checkout, which hold its plugins and the post step's script, are made
 * read-only inside the sandbox.
 */

import { accessSync, constants, readlinkSync, realpathSync } from "node:fs";
import { basename, delimiter, dirname, isAbsolute, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { SandboxError } from "../errors.ts";
import type { FilesystemMode } from "../filesystem-mode.ts";
import { writableDirsOf } from "./oci-mounts.ts";
import { isAtOrUnder } from "./paths.ts";
import { pinCommand } from "./pinned-commands.ts";
import { resolveWriteThroughPaths } from "./write-through.ts";

// rollup's cjs output doesn't convert import.meta.dirname (it silently
// becomes undefined), so use this form instead.
const __dirname = dirname(fileURLToPath(import.meta.url));

/** The bundle runs from `dist/`, one level below the checkout. */
const ACTION_ROOT = resolve(__dirname, "..");

const PINNED_COMMANDS = ["docker", "sudo"] as const;

/** Host paths whose writes outlive the command. Ephemeral mode's overlays
 *  discard theirs, so only write_through counts there. */
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
  /** The absolute target of one symlink hop, or null if `path` is not a symlink. */
  readlink: (path: string) => string | null;
  realpathDir: (dir: string) => string;
}

// The kernel's MAXSYMLINKS; also stops a symlink loop.
const MAX_SYMLINK_HOPS = 40;

// Untested by design: the defaults behind this module's seams, which only hand
// node:fs what the tested caller decided.
/* v8 ignore start */
function realpathOrSelf(path: string): string {
  try {
    return realpathSync(path);
  } catch {
    return path;
  }
}

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
      // The kernel resolves a relative target against the real directory.
      return isAbsolute(target) ? target : resolve(realpathOrSelf(dirname(path)), target);
    } catch {
      return null;
    }
  },
  realpathDir: realpathOrSelf,
};
/* v8 ignore stop */

/** `paths` plus their real spellings, since `$HOME` may itself be a symlink. */
export function withRealPaths(
  paths: string[],
  realpath: (path: string) => string = realpathOrSelf,
): string[] {
  return [...new Set([...paths, ...paths.map(realpath)])];
}

/** The `$PATH` entry and each symlink hop after it. The command could repoint
 *  any hop it can write, so every one of them is checked. */
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
 * The first `command` on `pathEnv` with no hop inside `persisting`, judged by
 * both its spelling and its real directory (a self-hosted `/opt/tools` may
 * point into `$HOME`). Returns the `$PATH` entry, not the resolved target:
 * snap's `/snap/bin/docker` -> `/usr/bin/snap` picks its role from the name it
 * was invoked by. Relative entries resolve against the workspace, so they are
 * skipped. `write_through: /` is the documented full opt-out.
 */
export function findPinnableCommand(
  command: string,
  pathEnv: string | undefined,
  persisting: string[],
  { isExecutable, readlink, realpathDir }: FindCommandDeps = realFindCommandDeps,
): string | undefined {
  const optedOut = persisting.includes("/");
  const writable = withRealPaths(persisting, realpathDir);
  const inside = (p: string): boolean => writable.some((w) => isAtOrUnder(p, w));
  const reachable = (hop: string): boolean =>
    inside(hop) || inside(join(realpathDir(dirname(hop)), basename(hop)));
  for (const dir of (pathEnv ?? "").split(delimiter)) {
    if (!isAbsolute(dir)) continue;
    const candidate = join(dir, command);
    if (!isExecutable(candidate)) continue;
    if (optedOut || !commandChain(candidate, readlink).some(reachable)) return candidate;
  }
  return undefined;
}

/**
 * Pins `docker` and `sudo` for the rest of this process. A command missing
 * from PATH altogether is left unpinned, so the sudo preflight or docker's
 * ENOENT reports a runner without them in clearer terms than this would.
 */
export function pinHostCommands(
  paths: string[],
  env: NodeJS.ProcessEnv,
  deps: FindCommandDeps = realFindCommandDeps,
): void {
  for (const command of PINNED_COMMANDS) {
    const path = findPinnableCommand(command, env.PATH, paths, deps);
    if (path) {
      pinCommand(command, path);
      continue;
    }
    if (!findPinnableCommand(command, env.PATH, [], deps)) continue;
    throw new SandboxError(
      `'${command}' is on PATH only under paths a sandboxed command can write to ` +
        `(${paths.join(", ")}). This action runs it outside the sandbox, so it has to live ` +
        "somewhere no sandboxed command can replace it, such as /usr/bin.",
      "HOST_COMMAND_UNPINNABLE",
    );
  }
}

/**
 * Persistent mode's writable set plus write_through, in either mode: an earlier
 * step's sandbox may have written there even if this one's writes are
 * discarded, and the post step cannot trust GITHUB_STATE to say which mode ran.
 * An input that does not parse never became writable, so it adds nothing.
 */
export function pinningPaths(
  readWriteThroughInput: () => string,
  env: NodeJS.ProcessEnv,
): string[] {
  let writeThroughPaths: string[] = [];
  try {
    writeThroughPaths = resolveWriteThroughPaths(readWriteThroughInput(), env);
  } catch {
    // See above.
  }
  return persistingWritablePaths("persistent", writeThroughPaths, env);
}

export function dockerConfigDir(env: NodeJS.ProcessEnv): string | undefined {
  if (env.DOCKER_CONFIG) return resolve(env.DOCKER_CONFIG);
  return env.HOME ? join(env.HOME, ".docker") : undefined;
}

/**
 * The action checkout and docker config directory, where a persisting path
 * contains them. One that is itself a persisting path is skipped: `uses: ./`
 * runs the action from the workspace, and write_through may name the config
 * directory. A persisting path nested inside one stays writable, since runc
 * remounts only the top of a read-only path.
 */
export function sandboxReadonlyHostDirs(
  persisting: string[],
  env: NodeJS.ProcessEnv,
  actionRoot: string = ACTION_ROOT,
): string[] {
  const candidates = [actionRoot, dockerConfigDir(env)].filter((p): p is string => Boolean(p));
  return candidates.filter(
    (dir) => persisting.some((p) => isAtOrUnder(dir, p)) && !persisting.includes(dir),
  );
}

/**
 * The writable directories between a read-only dir and the persisting root
 * above it. Renaming one would move the read-only dir aside and free its path
 * for a replacement; binding each onto itself makes it a mount point, which
 * the kernel refuses to rename. The root and the read-only dir are mount
 * points already.
 */
export function renameGuardDirs(readonlyDirs: string[], persisting: string[]): string[] {
  const guards = new Set<string>();
  for (const dir of readonlyDirs) {
    const root = persisting
      .filter((p) => p !== "/" && isAtOrUnder(dir, p))
      .sort((a, b) => b.length - a.length)[0];
    if (!root) continue;
    for (let p = dirname(dir); p !== root && isAtOrUnder(p, root); p = dirname(p)) {
      guards.add(p);
    }
  }
  // Parents are bound before the children nested in them.
  return [...guards].sort((a, b) => a.length - b.length || a.localeCompare(b));
}

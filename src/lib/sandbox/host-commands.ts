/**
 * Keeps what this action runs on the host out of reach of the sandboxed
 * command, whose writes to some host paths outlive it. `docker`, `sudo` and
 * the inspect engine's `keytool` are pinned to binaries outside those paths,
 * since a lookup through `$PATH` could pick one the command planted
 * (`~/.local/bin` precedes `/usr/bin` on hosted runners). For the same reason
 * docker and sudo run with those paths left off PATH. The paths the sandbox
 * makes read-only for the same reason are in host-protected-paths.ts.
 */

import { accessSync, constants } from "node:fs";
import { basename, delimiter, dirname, isAbsolute, join, resolve } from "node:path";

import { SandboxError } from "../errors.ts";
import type { FilesystemMode } from "../filesystem-mode.ts";
import type { JvmTools } from "./ca-trust.ts";
import { writableDirsOf } from "./oci-mounts.ts";
import { isAtOrUnder, pathAliases } from "./paths.ts";
import { pinCommand, pinCommandPathEnv, SYSTEM_PATH } from "./pinned-commands.ts";
import {
  realPathOf,
  realSymlinkDeps,
  resolveHostPath,
  type ResolvedHostPath,
  type SymlinkDeps,
} from "./symlinks.ts";
import type { MountinfoEntry } from "./types.ts";
import { resolveWriteThroughPaths } from "./write-through.ts";

const PINNED_COMMANDS = ["docker", "sudo"] as const;

/**
 * Host paths whose writes outlive the command. Ephemeral mode's overlays
 * discard theirs, so only write_through counts there. The runner's own
 * directories are taken by real path, write_through entries as written: one
 * through a symlink is refused before it is mounted.
 */
export function persistingWritablePaths(
  filesystemMode: FilesystemMode,
  writeThroughPaths: string[],
  env: NodeJS.ProcessEnv,
  realpath: (path: string) => string = realPathOf,
): string[] {
  if (filesystemMode === "ephemeral") return writeThroughPaths;
  return writableDirsOf({
    ...resolveDefaultWritableDirs(env, realpath),
    writablePaths: writeThroughPaths,
  });
}

export interface FindCommandDeps extends SymlinkDeps {
  isExecutable: (path: string) => boolean;
}

// Untested by design: the defaults behind this module's seams, which only hand
// node:fs what the tested caller decided.
/* v8 ignore start */
const realFindCommandDeps: FindCommandDeps = {
  ...realSymlinkDeps,
  isExecutable: (path) => {
    try {
      accessSync(path, constants.X_OK);
      return true;
    } catch {
      return false;
    }
  },
};
/* v8 ignore stop */

export interface DefaultWritableDirs {
  workdir?: string;
  home?: string;
  runnerTemp?: string;
  tmp: string;
}

/**
 * The directories persistent mode keeps writable, spelled as they really
 * resolve: runc follows symlinks in a mount's destination, and the host mount
 * table they are checked against names real paths.
 */
export function resolveDefaultWritableDirs(
  env: NodeJS.ProcessEnv,
  realpath: (path: string) => string = realPathOf,
): DefaultWritableDirs {
  return {
    workdir: env.GITHUB_WORKSPACE ? realpath(env.GITHUB_WORKSPACE) : undefined,
    home: env.HOME ? realpath(env.HOME) : undefined,
    runnerTemp: env.RUNNER_TEMP ? realpath(env.RUNNER_TEMP) : undefined,
    tmp: realpath("/tmp"),
  };
}

function insideOf(persisting: string[]): (path: string) => boolean {
  return (path) => persisting.some((w) => isAtOrUnder(path, w));
}

/** Whether a path resolves inside `persisting`, passes through a symlink there, or loops. */
function reachableFrom(persisting: string[], deps: SymlinkDeps): (path: string) => boolean {
  const inside = insideOf(persisting);
  return (path) => {
    const resolved = resolveHostPath(path, deps);
    return "loop" in resolved || resolved.links.some((l) => inside(l.at)) || inside(resolved.real);
  };
}

/**
 * `pathEnv` without the entries inside `persisting`, through a symlink there, or
 * in a symlink loop. Relative and empty entries resolve against the workspace,
 * so they go too.
 */
export function pathOutside(
  pathEnv: string = "",
  persisting: string[],
  deps: SymlinkDeps = realSymlinkDeps,
): string {
  if (persisting.includes("/")) return pathEnv;
  const reachable = reachableFrom(persisting, deps);
  return pathEnv
    .split(delimiter)
    .filter((dir) => isAbsolute(dir) && !reachable(dir))
    .join(delimiter);
}

/**
 * The first `command` on `pathEnv` that does not resolve inside `persisting`.
 * Returns the `$PATH` entry, not the resolved target: snap's
 * `/snap/bin/docker` -> `/usr/bin/snap` picks its role from the name it was
 * invoked by. One that passes through a symlink there, which the command could
 * repoint (a self-hosted `/opt/tools` may point into `$HOME`), is taken by the
 * file it leads to now, provided that file bears the command's own name and
 * the `$PATH` entry is not itself in reach, as `/usr/bin/sudo` ->
 * `/etc/alternatives/sudo` -> `/usr/lib/cargo/bin/sudo` is under
 * `write_through: /etc`. Relative entries resolve against the workspace, so
 * they are skipped. `write_through: /` is the documented full opt-out.
 */
export function findPinnableCommand(
  command: string,
  pathEnv: string | undefined,
  persisting: string[],
  deps: FindCommandDeps = realFindCommandDeps,
): string | undefined {
  return searchPath(command, pathEnv, persisting, deps).pinned;
}

/** A `command` in a `$PATH` directory out of reach, refused for what it resolves to. */
interface Refusal {
  candidate: string;
  real: string;
  /** The symlink in reach it passes through, when `real` is out of reach but
   *  bears another name. */
  link?: string;
}

interface PathSearch {
  pinned?: string;
  /** Whether any `command` is on PATH at all. */
  onPath: boolean;
  /** The first refused that was not in a directory in reach. */
  refusal?: Refusal;
}

function searchPath(
  command: string,
  pathEnv: string | undefined,
  persisting: string[],
  deps: FindCommandDeps,
): PathSearch {
  const optedOut = persisting.includes("/");
  const inside = insideOf(persisting);
  const reachable = reachableFrom(persisting, deps);
  const search: PathSearch = { onPath: false };
  for (const dir of (pathEnv ?? "").split(delimiter)) {
    if (!isAbsolute(dir)) continue;
    const candidate = join(dir, command);
    if (!deps.isExecutable(candidate)) continue;
    search.onPath = true;
    if (optedOut || !reachable(candidate)) return { ...search, pinned: candidate };
    // A directory the command can write to may hold a symlink it planted.
    if (reachable(dir)) continue;
    const resolved = resolveHostPath(candidate, deps);
    if (!("real" in resolved)) continue;
    const { real } = resolved;
    if (inside(real)) {
      search.refusal ??= { candidate, real };
      continue;
    }
    if (basename(real) === command) return { ...search, pinned: real };
    // In reach without its directory or real file being so: a symlink on its way is.
    search.refusal ??= { candidate, real, link: resolved.links.find((l) => inside(l.at))!.at };
  }
  return search;
}

function unpinnableMessage(command: string, refusal: Refusal | undefined, persisting: string[]) {
  const under = (path: string) => persisting.find((p) => isAtOrUnder(path, p));
  const tail =
    "which a sandboxed command can write to. This action runs it outside the sandbox, so";
  if (refusal?.link) {
    const { candidate, real, link } = refusal;
    return (
      `'${command}' on PATH, ${candidate}, leads to ${real} through ${link}, under ` +
      `${under(link)}, ${tail} through such a symlink it pins only a file named '${command}'.`
    );
  }
  if (refusal) {
    const { candidate, real } = refusal;
    const leadsTo = real === candidate ? "is" : `leads to ${real},`;
    return (
      `'${command}' on PATH, ${candidate}, ${leadsTo} under ${under(real)}, ${tail} it has to ` +
      "be a file no sandboxed command can replace."
    );
  }
  return (
    `'${command}' is on PATH only in directories a sandboxed command can write to or reach ` +
    `through a symlink it can repoint (${persisting.join(", ")}). This action runs it outside ` +
    "the sandbox, so it has to be found in a $PATH directory outside those paths."
  );
}

/**
 * Pins `docker` and `sudo`, and the PATH each runs with, for the rest of this
 * process. A command missing from PATH altogether is
 * left unpinned, so the sudo preflight or docker's ENOENT reports a runner
 * without them in clearer terms than this would.
 */
export function pinHostCommands(
  paths: string[],
  env: NodeJS.ProcessEnv,
  deps: FindCommandDeps = realFindCommandDeps,
): void {
  for (const command of PINNED_COMMANDS) {
    const { pinned, onPath, refusal } = searchPath(command, env.PATH, paths, deps);
    if (pinned) {
      pinCommand(command, pinned);
      continue;
    }
    if (!onPath) continue;
    throw new SandboxError(unpinnableMessage(command, refusal, paths), "HOST_COMMAND_UNPINNABLE");
  }
  pinCommandPathEnv("docker", pathOutside(env.PATH, paths, deps));
  pinCommandPathEnv("sudo", pathOutside(SYSTEM_PATH, paths, deps));
}

/**
 * The first `java` on PATH, whose keystore the step's JVM reads; it is never
 * run, so it may live anywhere. `keytool` runs on the host, so it is pinned
 * like docker and sudo, JAVA_HOME's before PATH's.
 */
export function jvmTools(
  env: NodeJS.ProcessEnv,
  persisting: string[],
  deps: FindCommandDeps = realFindCommandDeps,
): JvmTools {
  const javaHomeBin = env.JAVA_HOME ? join(env.JAVA_HOME, "bin") : undefined;
  return {
    java: findPinnableCommand("java", env.PATH, [], deps),
    keytool:
      findPinnableCommand("keytool", javaHomeBin, persisting, deps) ??
      findPinnableCommand("keytool", env.PATH, persisting, deps),
  };
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
  realpath: (path: string) => string = realPathOf,
): string[] {
  let writeThroughPaths: string[] = [];
  try {
    writeThroughPaths = resolveWriteThroughPaths(readWriteThroughInput(), env);
  } catch {
    // See above.
  }
  return persistingWritablePaths("persistent", writeThroughPaths, env, realpath);
}

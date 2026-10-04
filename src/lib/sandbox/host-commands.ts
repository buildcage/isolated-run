/**
 * Keeps what this action runs on the host out of reach of the sandboxed
 * command, whose writes to some host paths outlive it. `docker`, `sudo` and
 * the inspect engine's `keytool` are pinned to binaries outside those paths,
 * since a lookup through `$PATH` could pick one the command planted
 * (`~/.local/bin` precedes `/usr/bin` on hosted runners). For the same reason
 * docker and sudo run with those paths left off PATH. The docker CLI's
 * config directory and this action's own checkout, which hold its plugins and
 * the post step's script, are made read-only inside the sandbox, as are the
 * runner's file commands that reach every later step.
 */

import { accessSync, constants, readlinkSync, realpathSync } from "node:fs";
import { basename, delimiter, dirname, isAbsolute, join, normalize, resolve } from "node:path";

import { SandboxError } from "../errors.ts";
import type { FilesystemMode } from "../filesystem-mode.ts";
import type { JvmTools } from "./ca-trust.ts";
import { writableDirsOf } from "./oci-mounts.ts";
import { isAtOrUnder } from "./paths.ts";
import { pinCommand, pinCommandPathEnv, SYSTEM_PATH } from "./pinned-commands.ts";
import { resolveWriteThroughPaths } from "./write-through.ts";

/** The checkout as the runner spelled it, which is the path it runs the post
 *  step from: the bundle runs from `dist/`, one level below it. Node resolves
 *  symlinks in __filename but not in argv. */
function runnerActionRoot(): string {
  return resolve(dirname(process.argv[1]!), "..");
}

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
export function realpathOrSelf(path: string): string {
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
  readlink: readlinkAbsolute,
  realpathDir: realpathOrSelf,
};

export function readlinkAbsolute(path: string): string | null {
  try {
    const target = readlinkSync(path);
    // The kernel resolves a relative target against the real directory.
    return isAbsolute(target) ? target : resolve(realpathOrSelf(dirname(path)), target);
  } catch {
    return null;
  }
}
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
  realpath: (path: string) => string = realpathOrSelf,
): DefaultWritableDirs {
  const real = (path: string) => {
    const normalized = normalize(path);
    // A path that doesn't exist comes back as given, so drop the slash here.
    return realpath(normalized.length > 1 ? normalized.replace(/\/$/, "") : normalized);
  };
  return {
    workdir: env.GITHUB_WORKSPACE ? real(env.GITHUB_WORKSPACE) : undefined,
    home: env.HOME ? real(env.HOME) : undefined,
    runnerTemp: env.RUNNER_TEMP ? real(env.RUNNER_TEMP) : undefined,
    tmp: real("/tmp"),
  };
}

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

function insidePersisting(
  persisting: string[],
  realpathDir: FindCommandDeps["realpathDir"],
): (path: string) => boolean {
  const writable = withRealPaths(persisting, realpathDir);
  return (path) => writable.some((w) => isAtOrUnder(path, w));
}

/**
 * `pathEnv` without the entries inside `persisting`, judged like
 * findPinnableCommand. Relative and empty entries resolve against the
 * workspace, so they go too.
 */
export function pathOutside(
  pathEnv: string = "",
  persisting: string[],
  realpathDir: FindCommandDeps["realpathDir"],
): string {
  if (persisting.includes("/")) return pathEnv;
  const inside = insidePersisting(persisting, realpathDir);
  return pathEnv
    .split(delimiter)
    .filter((dir) => isAbsolute(dir) && !inside(dir) && !inside(realpathDir(dir)))
    .join(delimiter);
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
  const inside = insidePersisting(persisting, realpathDir);
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
  pinCommandPathEnv("docker", pathOutside(env.PATH, paths, deps.realpathDir));
  pinCommandPathEnv("sudo", pathOutside(SYSTEM_PATH, paths, deps.realpathDir));
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
 * The action checkout and docker config directory, by real path, where a
 * persisting path contains them. One that is itself a persisting path is
 * skipped: `uses: ./` runs the action from the workspace, and write_through may
 * name the config directory. A persisting path nested inside one stays
 * writable, since runc remounts only the top of a read-only path.
 *
 * Throws when one goes through a symlink in a persisting path: the mount
 * protects only the symlink's target, and the sandbox could replace the
 * symlink itself with a directory of its own. Under write_through: / every
 * symlink is replaceable, so none is refused.
 */
export function sandboxReadonlyHostDirs(
  persisting: string[],
  env: NodeJS.ProcessEnv,
  actionRoot: string = runnerActionRoot(),
  deps: Pick<FindCommandDeps, "readlink" | "realpathDir"> = realFindCommandDeps,
): string[] {
  const docker = dockerConfigDir(env);
  const candidates = [
    {
      name: "This action's checkout",
      dir: actionRoot,
      fix: () =>
        "the runner runs this action's post step from there. Configure the runner's work " +
        "directory by its real path, not through the symlink.",
    },
    ...(docker
      ? [
          {
            name: "The docker CLI's config directory",
            dir: docker,
            fix: () =>
              "this action runs docker on the host after the command exits. Set DOCKER_CONFIG to " +
              `its real path, ${JSON.stringify(followAll(docker))}.`,
          },
        ]
      : []),
  ];
  // Followed link by link rather than realpath'd, so a dangling one still has a target.
  const followAll = (path: string) => {
    const resolved = resolveThroughFixedLinks(path, [], deps.readlink);
    return "real" in resolved ? resolved.real : path;
  };
  const roots = persisting.filter((p) => p !== "/");
  return candidates.flatMap(({ name, dir, fix }) => {
    if (persisting.includes(dir) || persisting.includes(deps.realpathDir(dir))) return [];
    const resolved = resolveThroughFixedLinks(dir, roots, deps.readlink);
    if ("link" in resolved) {
      throw new SandboxError(
        `${name} ${JSON.stringify(dir)} goes through ${JSON.stringify(resolved.link)}, a symlink the ` +
          `sandboxed command can replace, and ${fix()}`,
        "HOST_DIR_UNPROTECTABLE",
      );
    }
    const real = resolved.real;
    return persisting.some((p) => isAtOrUnder(real, p)) ? [real] : [];
  });
}

/**
 * `path` with its symlinks resolved, or the first symlink that sits in one of
 * `roots`. Components past the last existing one are kept as written.
 */
function resolveThroughFixedLinks(
  path: string,
  roots: string[],
  readlink: FindCommandDeps["readlink"],
): { real: string } | { link: string } {
  let rest = path.split("/").filter(Boolean);
  let current = "/";
  for (let hops = 0; rest.length > 0;) {
    const candidate = join(current, rest.shift()!);
    const target = readlink(candidate);
    if (target === null) {
      current = candidate;
      continue;
    }
    if (roots.some((p) => isAtOrUnder(current, p)) || ++hops > MAX_SYMLINK_HOPS) {
      return { link: candidate };
    }
    rest = [...target.split("/").filter(Boolean), ...rest];
    current = "/";
  }
  return { real: current };
}

/**
 * This step's GITHUB_ENV, GITHUB_PATH and GITHUB_STATE files, which the runner
 * applies to every later step and the post step: LD_PRELOAD in GITHUB_ENV or a
 * directory first in GITHUB_PATH would reach all of them. Read-only in either
 * mode, whatever is writable around them, unless write_through names
 * GITHUB_ENV or GITHUB_PATH itself. GITHUB_STATE, which only this action's
 * post step reads, is never opened. Like sandboxReadonlyHostDirs, throws when
 * one goes through a symlink in a persisting path.
 */
export function sandboxReadonlyFileCommands(
  writeThroughPaths: string[],
  persisting: string[],
  env: NodeJS.ProcessEnv,
  deps: Pick<FindCommandDeps, "readlink" | "realpathDir"> = realFindCommandDeps,
): string[] {
  const named = new Set(withRealPaths(writeThroughPaths, deps.realpathDir));
  const openable = (name: string, path: string) =>
    name !== "GITHUB_STATE" && (named.has(path) || named.has(deps.realpathDir(path)));
  const roots = persisting.filter((p) => p !== "/");
  return ["GITHUB_ENV", "GITHUB_PATH", "GITHUB_STATE"].flatMap((name) => {
    const path = env[name];
    if (!path || openable(name, path)) return [];
    const resolved = resolveThroughFixedLinks(path, roots, deps.readlink);
    if ("link" in resolved) {
      throw new SandboxError(
        `The runner's ${name} file ${JSON.stringify(path)} goes through ` +
          `${JSON.stringify(resolved.link)}, a symlink the sandboxed command can replace, and the ` +
          "runner reads it after the step. Configure the runner's work directory by its real " +
          "path, not through the symlink.",
        "HOST_DIR_UNPROTECTABLE",
      );
    }
    return [resolved.real];
  });
}

/**
 * The writable directories between a read-only dir and the outermost persisting
 * root above it. Renaming one would move the read-only dir aside and free its
 * path for a replacement; binding each onto itself makes it a mount point,
 * which the kernel refuses to rename. The outermost root, so a persisting path
 * nested in another (the workspace in $HOME) is guarded too, and the guards
 * stay inside what is writable anyway. The root and the read-only dir are
 * mount points already, or `/`.
 */
export function renameGuardDirs(readonlyDirs: string[], persisting: string[]): string[] {
  const guards = new Set<string>();
  for (const dir of readonlyDirs) {
    const root = persisting
      .filter((p) => p !== dir && isAtOrUnder(dir, p))
      .sort((a, b) => a.length - b.length)[0];
    if (!root) continue;
    for (let p = dirname(dir); p !== root && isAtOrUnder(p, root); p = dirname(p)) {
      guards.add(p);
    }
  }
  // Parents are bound before the children nested in them.
  return [...guards].sort((a, b) => a.length - b.length || a.localeCompare(b));
}

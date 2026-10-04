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

import { accessSync, constants } from "node:fs";
import { delimiter, dirname, isAbsolute, join, resolve } from "node:path";

import { SandboxError } from "../errors.ts";
import type { FilesystemMode } from "../filesystem-mode.ts";
import type { JvmTools } from "./ca-trust.ts";
import { writableDirsOf } from "./oci-mounts.ts";
import { isAtOrUnder } from "./paths.ts";
import { pinCommand, pinCommandPathEnv, SYSTEM_PATH } from "./pinned-commands.ts";
import {
  realPathOf,
  realSymlinkDeps,
  resolveHostPath,
  type ResolvedHostPath,
  type SymlinkDeps,
} from "./symlinks.ts";
import { resolveWriteThroughPaths } from "./write-through.ts";

/** The checkout as the runner spelled it, which is the path it runs the post
 *  step from: the bundle runs from `dist/`, one level below it. Node resolves
 *  symlinks in __filename but not in argv. */
function runnerActionRoot(): string {
  return resolve(dirname(process.argv[1]!), "..");
}

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

function insidePersisting(persisting: string[]): (path: string) => boolean {
  return (path) => persisting.some((w) => isAtOrUnder(path, w));
}

/**
 * `pathEnv` without the entries inside `persisting`, judged like
 * findPinnableCommand. Relative and empty entries resolve against the
 * workspace, so they go too.
 */
export function pathOutside(
  pathEnv: string = "",
  persisting: string[],
  deps: SymlinkDeps = realSymlinkDeps,
): string {
  if (persisting.includes("/")) return pathEnv;
  const inside = insidePersisting(persisting);
  return pathEnv
    .split(delimiter)
    .filter((dir) => isAbsolute(dir) && !inside(realPathOf(dir, deps)))
    .join(delimiter);
}

/**
 * The first `command` on `pathEnv` that neither resolves inside `persisting`
 * nor passes through a symlink there, which the command could repoint (a
 * self-hosted `/opt/tools` may point into `$HOME`). Returns the `$PATH` entry,
 * not the resolved target: snap's `/snap/bin/docker` -> `/usr/bin/snap` picks
 * its role from the name it was invoked by. Relative entries resolve against
 * the workspace, so they are skipped. `write_through: /` is the documented
 * full opt-out.
 */
export function findPinnableCommand(
  command: string,
  pathEnv: string | undefined,
  persisting: string[],
  deps: FindCommandDeps = realFindCommandDeps,
): string | undefined {
  const optedOut = persisting.includes("/");
  const inside = insidePersisting(persisting);
  const reachable = (candidate: string): boolean => {
    const resolved = resolveHostPath(candidate, deps);
    return "loop" in resolved || resolved.links.some((l) => inside(l.at)) || inside(resolved.real);
  };
  for (const dir of (pathEnv ?? "").split(delimiter)) {
    if (!isAbsolute(dir)) continue;
    const candidate = join(dir, command);
    if (!deps.isExecutable(candidate)) continue;
    if (optedOut || !reachable(candidate)) return candidate;
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
  deps: SymlinkDeps = realSymlinkDeps,
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
              `its real path, ${JSON.stringify(realPathOf(docker, deps))}.`,
          },
        ]
      : []),
  ];
  const roots = persisting.filter((p) => p !== "/");
  return candidates.flatMap(({ name, dir, fix }) => {
    if (persisting.includes(realPathOf(dir, deps))) return [];
    const resolved = resolveHostPath(dir, deps);
    const link = replaceableLink(resolved, roots);
    if (link !== undefined) {
      throw new SandboxError(
        `${name} ${JSON.stringify(dir)} goes through ${JSON.stringify(link)}, a symlink the ` +
          `sandboxed command can replace, and ${fix()}`,
        "HOST_DIR_UNPROTECTABLE",
      );
    }
    if ("loop" in resolved) {
      throw new SandboxError(
        `${name} ${JSON.stringify(dir)} goes through too many symlinks to resolve.`,
        "HOST_DIR_UNPROTECTABLE",
      );
    }
    const real = resolved.real;
    return persisting.some((p) => isAtOrUnder(real, p)) ? [real] : [];
  });
}

/** The first symlink `resolved` passed through that sits in one of `roots`. */
function replaceableLink(resolved: ResolvedHostPath, roots: string[]): string | undefined {
  return resolved.links.find((l) => roots.some((p) => isAtOrUnder(dirname(l.at), p)))?.at;
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
  deps: SymlinkDeps = realSymlinkDeps,
): string[] {
  const named = new Set(writeThroughPaths);
  const openable = (name: string, path: string) =>
    name !== "GITHUB_STATE" && named.has(realPathOf(path, deps));
  const roots = persisting.filter((p) => p !== "/");
  return ["GITHUB_ENV", "GITHUB_PATH", "GITHUB_STATE"].flatMap((name) => {
    const path = env[name];
    if (!path || openable(name, path)) return [];
    const resolved = resolveHostPath(path, deps);
    const link = replaceableLink(resolved, roots);
    if (link !== undefined) {
      throw new SandboxError(
        `The runner's ${name} file ${JSON.stringify(path)} goes through ` +
          `${JSON.stringify(link)}, a symlink the sandboxed command can replace, and the ` +
          "runner reads it after the step. Configure the runner's work directory by its real " +
          "path, not through the symlink.",
        "HOST_DIR_UNPROTECTABLE",
      );
    }
    if ("loop" in resolved) {
      throw new SandboxError(
        `The runner's ${name} file ${JSON.stringify(path)} goes through too many symlinks to resolve.`,
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

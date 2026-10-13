/**
 * The host paths the sandbox makes read-only, or binds onto themselves, so the
 * command cannot change what runs outside it later: the runner's install
 * directory, the action checkouts and the docker CLI's config directory, which
 * later steps, post steps and docker run code from, and the runner's file
 * commands that reach every later step.
 */

import { basename, dirname, join, resolve } from "node:path";

import { SandboxError } from "../errors.ts";
import { isAtOrUnder, pathAliases } from "./paths.ts";
import {
  realPathOf,
  realSymlinkDeps,
  resolveHostPath,
  type ResolvedHostPath,
  type SymlinkDeps,
} from "./symlinks.ts";
import type { MountinfoEntry } from "./types.ts";

/** The checkout as the runner spelled it, which is the path it runs the post
 *  step from: the bundle runs from `dist/`, one level below it. Node resolves
 *  symlinks in __filename but not in argv. */
function runnerActionRoot(): string {
  return resolve(dirname(process.argv[1]!), "..");
}

/** The runner's install directory, from the node it runs actions with
 *  (`externals/node24/bin/node`), or nothing when some other node runs this. */
export function runnerInstallRoot(execPath: string = process.execPath): string | undefined {
  const externals = resolve(execPath, "../../..");
  return basename(externals) === "externals" ? dirname(externals) : undefined;
}

export interface RunnerDirs {
  actionRoot: string;
  installRoot?: string;
}

export function dockerConfigDir(env: NodeJS.ProcessEnv): string | undefined {
  if (env.DOCKER_CONFIG) return resolve(env.DOCKER_CONFIG);
  return env.HOME ? join(env.HOME, ".docker") : undefined;
}

/**
 * What runs outside the sandbox after the command, by real path, where a
 * persisting path contains it: the runner's install directory, the action
 * checkouts, this one's included, and the docker config directory. One that
 * is itself a persisting path is skipped: `uses: ./` runs the action from the
 * workspace, and write_through may name the config directory. A persisting
 * path nested inside one stays writable, since runc remounts only the top of
 * a read-only path. One nested in another is left to the outer one, unless a
 * persisting path between them would reopen it. Each also covers the other
 * paths `mounts` shows it at (see pathAliases), unless write_through names one.
 *
 * Throws when one goes through a symlink in a persisting path: the mount
 * protects only the symlink's target, and the sandbox could replace the
 * symlink itself with a directory of its own. `/` itself is not one of the
 * paths checked: under write_through: / a symlink anywhere else is replaceable
 * too, and only one in another persisting path is refused.
 */
export function sandboxReadonlyHostDirs(
  persisting: string[],
  env: NodeJS.ProcessEnv,
  { actionRoot, installRoot }: RunnerDirs = {
    actionRoot: runnerActionRoot(),
    installRoot: runnerInstallRoot(),
  },
  deps: SymlinkDeps = realSymlinkDeps,
  mounts: MountinfoEntry[] = [],
): string[] {
  const docker = dockerConfigDir(env);
  const workDirFix =
    "Configure the runner's work directory by its real path, not through the symlink.";
  const candidates = [
    {
      name: "This action's checkout",
      dir: actionRoot,
      fix: () => `the runner runs this action's post step from there. ${workDirFix}`,
    },
    ...(env.RUNNER_WORKSPACE
      ? [
          {
            name: "The runner's action checkouts",
            dir: join(dirname(resolve(env.RUNNER_WORKSPACE)), "_actions"),
            fix: () => `the runner runs later steps' actions from there. ${workDirFix}`,
          },
        ]
      : []),
    ...(installRoot
      ? [
          {
            name: "The runner's install directory",
            dir: installRoot,
            fix: () =>
              "the runner runs later steps from there. Install the runner by its real path, " +
              "not through the symlink.",
          },
        ]
      : []),
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
  const dirs = candidates.flatMap(({ name, dir, fix }) => {
    if (persisting.includes(realPathOf(dir, deps))) return [];
    const { real, aliases } = resolveProtectable(dir, name, fix, roots, deps, mounts);
    return [real, ...aliases.filter((a) => !persisting.includes(a))].filter((p) =>
      persisting.some((root) => isAtOrUnder(p, root)),
    );
  });
  const unique = [...new Set(dirs)];
  return unique.filter((dir) => {
    const others = unique.filter((o) => o !== dir);
    return persisting.includes(innermost(dir, [...persisting, ...others])!);
  });
}

/** The longest of `paths` that `dir` is at or under. */
function innermost(dir: string, paths: string[]): string | undefined {
  return paths.filter((p) => isAtOrUnder(dir, p)).sort((a, b) => b.length - a.length)[0];
}

/** The first symlink `resolved` passed through that sits in one of `roots`. */
function replaceableLink(resolved: ResolvedHostPath, roots: string[]): string | undefined {
  return resolved.links.find((l) => roots.some((p) => isAtOrUnder(dirname(l.at), p)))?.at;
}

/**
 * `path`'s real path and the other paths `mounts` shows it at. Throws when it
 * goes through a symlink in one of `roots`, which the sandbox could replace,
 * or through a symlink loop. `label` names the path in the error, and `fix`
 * says why it matters and what to do.
 */
function resolveProtectable(
  path: string,
  label: string,
  fix: () => string,
  roots: string[],
  deps: SymlinkDeps,
  mounts: MountinfoEntry[],
): { real: string; aliases: string[] } {
  const resolved = resolveHostPath(path, deps);
  const link = replaceableLink(resolved, roots);
  if (link !== undefined) {
    throw new SandboxError(
      `${label} ${JSON.stringify(path)} goes through ${JSON.stringify(link)}, a symlink the ` +
        `sandboxed command can replace, and ${fix()}`,
      "HOST_DIR_UNPROTECTABLE",
    );
  }
  if ("loop" in resolved) {
    throw new SandboxError(
      `${label} ${JSON.stringify(path)} goes through too many symlinks to resolve.`,
      "HOST_DIR_UNPROTECTABLE",
    );
  }
  return { real: resolved.real, aliases: pathAliases(mounts, resolved.real) };
}

/**
 * This step's GITHUB_ENV and GITHUB_PATH files, which the runner applies to
 * every later step and the post step, and its GITHUB_STATE file: LD_PRELOAD in
 * GITHUB_ENV or a directory first in GITHUB_PATH would reach all of them.
 * Read-only in either mode, whatever is writable around them, unless
 * write_through names GITHUB_ENV or GITHUB_PATH itself. GITHUB_STATE, which
 * only this action's post step reads, is never opened. Like
 * sandboxReadonlyHostDirs, covers each at its other paths in a persisting
 * path too, and throws when one goes through a symlink in a persisting path.
 */
export function sandboxReadonlyFileCommands(
  writeThroughPaths: string[],
  persisting: string[],
  env: NodeJS.ProcessEnv,
  deps: SymlinkDeps = realSymlinkDeps,
  mounts: MountinfoEntry[] = [],
): string[] {
  const named = new Set(writeThroughPaths);
  const openable = (name: string, path: string) =>
    name !== "GITHUB_STATE" && named.has(realPathOf(path, deps));
  const roots = persisting.filter((p) => p !== "/");
  return ["GITHUB_ENV", "GITHUB_PATH", "GITHUB_STATE"].flatMap((name) => {
    const path = env[name];
    if (!path || openable(name, path)) return [];
    const { real, aliases } = resolveProtectable(
      path,
      `The runner's ${name} file`,
      () =>
        "the runner reads it after the step. Configure the runner's work directory by its real " +
        "path, not through the symlink.",
      roots,
      deps,
      mounts,
    );
    return [
      real,
      ...aliases.filter(
        (a) => !openable(name, a) && persisting.some((root) => isAtOrUnder(a, root)),
      ),
    ];
  });
}

/**
 * The writable directories between a read-only dir and the outermost persisting
 * root above it. Renaming one would move the read-only dir aside and free its
 * path for a replacement; binding each onto itself makes it a mount point,
 * which the kernel refuses to rename. The outermost root, so a persisting path
 * nested in another (the workspace in $HOME) is guarded too, and the guards
 * stay inside what is writable anyway. The root and the read-only dir are
 * mount points already, or `/`. A directory inside another read-only dir is
 * left alone: it cannot be renamed, and a read-write bind would reopen it.
 */
export function renameGuardDirs(readonlyDirs: string[], persisting: string[]): string[] {
  const writable = (dir: string) =>
    persisting.includes(innermost(dir, [...persisting, ...readonlyDirs])!);
  const guards = new Set<string>();
  for (const dir of readonlyDirs) {
    const root = persisting
      .filter((p) => p !== dir && isAtOrUnder(dir, p))
      .sort((a, b) => a.length - b.length)[0];
    if (!root) continue;
    for (let p = dirname(dir); p !== root && isAtOrUnder(p, root); p = dirname(p)) {
      if (writable(p)) guards.add(p);
    }
  }
  // Parents are bound before the children nested in them.
  return [...guards].sort((a, b) => a.length - b.length || a.localeCompare(b));
}

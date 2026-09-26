import { execFileSync } from "node:child_process";
import {
  cpSync,
  lstatSync,
  mkdirSync,
  readFileSync,
  readdirSync,
  realpathSync,
  rmdirSync,
} from "node:fs";
import { join } from "node:path";
import { buildDockerCpArgs } from "#core/lib/docker/args.ts";
import { errorMessage } from "#core/lib/errors.ts";
import { hostCommand } from "./pinned-commands.ts";
import type { MountEntry } from "./types.ts";

/**
 * Chromium on Linux trusts only its compiled-in root store and the NSS database
 * in $HOME, so a copy of a database holding only the proxy CA is mounted over
 * that one. The runner's own database is covered, never opened.
 */

/** Every Chromium reads this path when it exists, even empty; since M146 the
 *  XDG path is only the default for a new database.
 *  https://chromium.googlesource.com/chromium/src/+/main/docs/linux/cert_management.md */
export const NSS_DB_PATH = ".pki/nssdb";

/** Where init-inspect-cfg leaves the template in the proxy container. */
export const NSS_DB_TEMPLATE_CONTAINER_PATH = "/opt/buildcage/nssdb";

export interface NssDbFiles {
  /** The copy mounted over the database, in this run's scratch dir. */
  path: string;
  /** The template as extracted, to compare the copy against afterwards. */
  template: string;
  destination: string;
  /** Directories created for the mount point, shallowest first. */
  createdDirs: string[];
}

export interface NssDbDeps {
  exec?: (command: string, args: string[]) => void;
  lstat?: (path: string) => { isDirectory(): boolean; isSymbolicLink(): boolean } | undefined;
  realpath?: (path: string) => string;
  mkdir?: (path: string, mode: number) => void;
  copyDir?: (source: string, destination: string) => void;
  readDir?: (path: string) => string[];
  readFile?: (path: string) => Buffer;
  rmdir?: (path: string) => void;
  warn?: (message: string) => void;
}

// Untested by design: the defaults behind this module's seams, which only hand
// node:fs and node:child_process what the tested caller decided.
/* v8 ignore start */
function defaultExec(command: string, args: string[]): void {
  execFileSync(hostCommand(command), args);
}

function defaultLstat(path: string) {
  try {
    return lstatSync(path);
  } catch {
    return undefined;
  }
}

function defaultMkdir(path: string, mode: number): void {
  mkdirSync(path, { mode });
}

function defaultCopyDir(source: string, destination: string): void {
  cpSync(source, destination, { recursive: true });
}
/* v8 ignore stop */

type NssDbPlan = { destination: string; missing: string[] } | string;

/**
 * The database directory under `home` and the directories missing on the way,
 * shallowest first; or why it cannot be mounted over. A symlink is refused
 * because an earlier step could have pointed it anywhere.
 */
export function planNssDb(
  home: string,
  { lstat = defaultLstat }: Pick<NssDbDeps, "lstat"> = {},
): NssDbPlan {
  let dir = home;
  const missing: string[] = [];
  for (const component of NSS_DB_PATH.split("/")) {
    dir = join(dir, component);
    if (missing.length > 0) {
      missing.push(dir);
      continue;
    }
    const info = lstat(dir);
    if (info === undefined) {
      missing.push(dir);
    } else if (info.isSymbolicLink()) {
      return `${dir} is a symlink`;
    } else if (!info.isDirectory()) {
      return `${dir} is not a directory`;
    }
  }
  return { destination: dir, missing };
}

/**
 * Copies the template into `dir` and creates the mount point. The copy is
 * written as the runner user because Chromium ignores a database it cannot open
 * read-write. Returns undefined, having warned, when there is nowhere to mount it.
 */
export function prepareNssDb(
  containerName: string,
  dir: string,
  home: string | undefined,
  {
    exec = defaultExec,
    lstat = defaultLstat,
    realpath = realpathSync,
    mkdir = defaultMkdir,
    copyDir = defaultCopyDir,
    rmdir = rmdirSync,
    warn,
  }: NssDbDeps = {},
): NssDbFiles | undefined {
  if (!home || lstat(home)?.isDirectory() !== true) {
    warn?.(
      `could not add the proxy CA to Chromium's NSS database: HOME (${JSON.stringify(home ?? "")}) ` +
        "is not a directory. A Chromium step will not trust the proxy.",
    );
    return undefined;
  }
  const plan = planNssDb(realpath(home), { lstat });
  if (typeof plan === "string") {
    warn?.(
      `could not add the proxy CA to Chromium's NSS database: ${plan}. A Chromium step ` +
        "will not trust the proxy.",
    );
    return undefined;
  }

  const template = join(dir, "nssdb-template");
  exec(
    "docker",
    buildDockerCpArgs({
      containerName,
      containerPath: NSS_DB_TEMPLATE_CONTAINER_PATH,
      hostPath: template,
    }),
  );
  const path = join(dir, "nssdb");
  copyDir(template, path);

  // Created here because runc would create them as root in the runner's home.
  const files: NssDbFiles = { path, template, destination: plan.destination, createdDirs: [] };
  for (const missing of plan.missing) {
    try {
      mkdir(missing, 0o700);
    } catch (e) {
      removeNssDbDirs(files, { rmdir });
      warn?.(
        `could not add the proxy CA to Chromium's NSS database: cannot create ${missing} ` +
          `(${errorMessage(e)}). A Chromium step will not trust the proxy.`,
      );
      return undefined;
    }
    files.createdDirs.push(missing);
  }
  return files;
}

/** Read-write, since Chromium ignores a database it cannot open that way. */
export function nssDbMount(files: NssDbFiles): MountEntry {
  return {
    destination: files.destination,
    type: "none",
    source: files.path,
    options: ["rbind", "rw"],
  };
}

/** Why the copy no longer matches the template, or undefined. Compares names
 *  and bytes only, so a chmod or chown of $HOME does not count. Chromium
 *  reading the database leaves it byte-identical. */
export function nssDbChange(
  files: NssDbFiles,
  { readDir = readdirSync, readFile = readFileSync }: Pick<NssDbDeps, "readDir" | "readFile"> = {},
): string | undefined {
  const names = readDir(files.template).sort();
  const current = readDir(files.path).sort();
  const changed =
    names.length !== current.length ||
    names.some(
      (name, i) =>
        current[i] !== name ||
        !readFile(join(files.template, name)).equals(readFile(join(files.path, name))),
    );
  if (!changed) return undefined;
  return (
    `the command changed the NSS database at ${files.destination}, which the inspect engine ` +
    "replaces for the step with one trusting only its proxy CA; the write is discarded"
  );
}

/** Removes the directories prepareNssDb created, leaving any that are not empty. */
export function removeNssDbDirs(
  files: NssDbFiles,
  { rmdir = rmdirSync }: Pick<NssDbDeps, "rmdir"> = {},
): void {
  for (const dir of [...files.createdDirs].reverse()) {
    try {
      rmdir(dir);
    } catch {
      // Not empty, or already gone.
    }
  }
}

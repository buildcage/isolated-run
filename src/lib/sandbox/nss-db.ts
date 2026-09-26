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
 * Chromium's NSS database, for the inspect engine.
 *
 * Chromium on Linux reads neither the system CA store nor any CA-trust
 * variable. It trusts the Chrome Root Store compiled into it, plus what the
 * user added to the NSS shared database in their home directory, and nothing
 * else. chrome-headless-shell has no enterprise policies either. So the only
 * way to have it trust the proxy's CA is that database.
 *
 * The database is SQLite, which the runner's previous steps may have written,
 * so it is never opened here. Instead, the proxy image carries a database
 * holding only the proxy's CA, made by its own certutil when the CA was
 * generated (init-inspect-cfg). A copy of it is mounted read-write over
 * wherever Chromium would look, the same way ca-trust.ts mounts the CA store:
 * a mount-namespace-scoped overlay, not a host write. What the runner kept
 * there is covered, not merged into.
 *
 * A command that changes the copy wrote to a file buildcage replaced, and that
 * change has nowhere true to go back to, so the step fails (or, under
 * fail_on_ca_residue: false, warns) rather than drop it silently.
 */

/** Where Chromium looks for the database, relative to $HOME, in the order it
 *  looks: the legacy path wins whenever it exists, even empty, and the XDG
 *  one, the default since M146, is used otherwise.
 *  https://chromium.googlesource.com/chromium/src/+/main/docs/linux/cert_management.md */
export const NSS_DB_PATHS = [".pki/nssdb", ".local/share/pki/nssdb"];

/** Where init-inspect-cfg leaves the template in the proxy container. */
export const NSS_DB_TEMPLATE_CONTAINER_PATH = "/opt/buildcage/nssdb";

export interface NssDbFiles {
  /** The copy mounted over the database, in this run's scratch dir. */
  path: string;
  /** The template as extracted, which the copy is compared against once the
   *  command has exited. */
  template: string;
  /** The database directory Chromium would read, on the host. */
  destination: string;
  /** The directories created on the host to have somewhere to mount the copy,
   *  shallowest first, for removeNssDbDirs to take back. */
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

/** Walks `rel` down from `home`: the directory it names, and the ones missing
 *  on the way, shallowest first; or why it cannot be mounted over. */
function walk(home: string, rel: string, lstat: NonNullable<NssDbDeps["lstat"]>): NssDbPlan {
  let dir = home;
  const missing: string[] = [];
  for (const component of rel.split("/")) {
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
 * The database directory Chromium would read under `home`, and the
 * directories missing on the way to it, shallowest first. A string instead
 * says why there is none to mount over: a component that is a symlink (which
 * an earlier step could have pointed anywhere) or that is not a directory.
 */
export function planNssDb(
  home: string,
  { lstat = defaultLstat }: Pick<NssDbDeps, "lstat"> = {},
): NssDbPlan {
  const [legacy, xdg] = NSS_DB_PATHS as [string, string];
  const plan = walk(home, legacy, lstat);
  // The legacy path counts only when it is all there. The XDG one is where
  // Chromium would create the database, so it is the answer either way.
  if (typeof plan === "string" || plan.missing.length === 0) return plan;
  return walk(home, xdg, lstat);
}

/**
 * Extract the template into `dir` (this run's own scratch directory), make the
 * copy the sandbox mounts, and create the directories it is mounted over. The
 * copy is written by this process, which runs as the runner user the sandbox
 * does, so the command can open it read-write: Chromium ignores a database it
 * cannot. Returns undefined, having warned why, when there is nowhere to mount
 * it; the command then runs without it, as it did before.
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

  // Last, so a failure above leaves nothing on the host. runc would create a
  // missing mount point itself, but as root, and on this rootfs that is the
  // runner's own home. 0700, as Chromium makes them.
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

/** The mount caTrustAdditions adds for the database. Read-write: NSS opens it
 *  that way, and Chromium does not fall back to reading one it cannot. */
export function nssDbMount(files: NssDbFiles): MountEntry {
  return {
    destination: files.destination,
    type: "none",
    source: files.path,
    options: ["rbind", "rw"],
  };
}

/**
 * Why the command's copy of the database no longer matches the template, or
 * undefined if it still does. Reading it does not change it: NSS leaves every
 * file byte for byte as it found it, journal included.
 */
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

/** Take back the directories prepareNssDb created, deepest first, leaving any
 *  the command put something of its own into. Never throws. */
export function removeNssDbDirs(
  files: NssDbFiles,
  { rmdir = rmdirSync }: Pick<NssDbDeps, "rmdir"> = {},
): void {
  for (const dir of [...files.createdDirs].reverse()) {
    try {
      rmdir(dir);
    } catch {
      // Not empty (the command wrote something here), or already gone.
    }
  }
}

import { execFileSync } from "node:child_process";
import {
  accessSync,
  chmodSync,
  closeSync,
  constants,
  cpSync,
  fstatSync,
  lstatSync,
  mkdirSync,
  mkdtempSync,
  openSync,
  readFileSync,
  readdirSync,
  readlinkSync,
  realpathSync,
  renameSync,
  rmSync,
  rmdirSync,
  statSync,
  writeSync,
  ftruncateSync,
  readSync,
} from "node:fs";
import { join, relative } from "node:path";

import { buildDockerCpArgs } from "#core/lib/docker/args.ts";
import { errorMessage } from "#core/lib/errors.ts";

import { hostCommand, hostCommandEnv } from "./pinned-commands.ts";
import type { MountEntry } from "./types.ts";

/**
 * Chromium on Linux trusts only its compiled-in root store and the NSS database
 * in $HOME. That database is SQLite the runner's own steps control, so it is
 * never opened. Instead its directory is mirrored into this run's scratch dir,
 * the mirror's pkcs11.txt gains a second softoken slot, a read-only one on a
 * database holding only the proxy CA, and the mirror is mounted over the
 * database. NSS loads every module pkcs11.txt names, so Chromium trusts the CA
 * through that slot while the command's own certificates, keys and writes
 * stay in the runner's database. After the command, the slot is taken back
 * out of pkcs11.txt and the mirror written back, where the filesystem mode
 * would have kept a write there.
 *
 * A database the runner user cannot write is covered instead, with a copy of
 * a database holding only the proxy CA, and a command that changes that copy
 * fails the step: Chromium opens nothing it cannot open read-write, the slot
 * included.
 */

/** Every Chromium reads this path when it exists, even empty; since M146 the
 *  XDG path below is read only when this one is not there.
 *  https://chromium.googlesource.com/chromium/src/+/main/docs/linux/cert_management.md */
export const NSS_DB_PATH = ".pki/nssdb";
export const NSS_XDG_DB_PATH = ".local/share/pki/nssdb";

/** Where init-inspect-cfg leaves the template in the proxy container. */
export const NSS_DB_TEMPLATE_CONTAINER_PATH = "/opt/buildcage/nssdb";

/** Where the database holding only the proxy CA is mounted in the sandbox:
 *  under runc's own /dev tmpfs, so its mount point is never made on the host. */
export const NSS_CA_DB_DESTINATION = "/dev/buildcage-nssdb";

/** What pkcs11.txt gains. library= must name the softoken: left empty, the
 *  entry gives Chromium no second slot. The trailing blank line ends the entry,
 *  so a module the command adds after it with modutil stays an entry of its own
 *  rather than running into this one. */
export const NSS_SLOT =
  "library=libsoftokn3.so\n" +
  'name="buildcage proxy CA"\n' +
  `parameters="configdir='sql:${NSS_CA_DB_DESTINATION}' flags=readOnly"\n` +
  'NSS=""\n\n';

/** Names the directory a write-back is staged in, beside the database,
 *  followed by the staging process's pid. */
const STAGING_PREFIX = ".buildcage-";

function isStaging(name: string): boolean {
  return name.startsWith(STAGING_PREFIX);
}

/** Whether the step that made this staging dir may still be writing back into
 *  it. One named without a pid is an older version's, left over. */
function stagingOwnerAlive(name: string, pidAlive: (pid: number) => boolean): boolean {
  const pid = /^\.buildcage-(\d+)-/.exec(name)?.[1];
  return pid !== undefined && pidAlive(Number(pid));
}

/** Whether a path under dir lies in a staging dir directly inside it. */
function inStaging(dir: string, path: string): boolean {
  return isStaging(relative(dir, path).split("/")[0]!);
}

/** A real pkcs11.txt is a few hundred bytes per module. */
const MAX_PKCS11_TXT_BYTES = 1 << 20;

/** Bounds on a database the runner's steps could have made as large as they
 *  like, before it is covered rather than copied. */
const MAX_MIRROR_BYTES = 20 << 20;
const MAX_MIRROR_FILES = 512;

/** The files Chromium opens read-write in a database it uses, and the one the
 *  slot is appended to in the copy. */
const NSS_DB_FILES = ["cert9.db", "key4.db", "pkcs11.txt"];

/** A directory's files by path relative to it: a file's bytes, a symlink's
 *  target, null for a directory, or false for anything else, such as a FIFO,
 *  which is never read. */
export type DirSnapshot = Map<string, Buffer | string | null | false>;

export interface NssDbSlot {
  /** The CA-only database, mounted read-only at NSS_CA_DB_DESTINATION. */
  caDb: string;
  /** What was appended to the mirror's pkcs11.txt. */
  appended: string;
  /** Whether the database had a pkcs11.txt of its own. */
  hadPkcs11: boolean;
  /** The mirror right after the slot went in. */
  snapshot: DirSnapshot;
}

export interface NssDbFiles {
  /** The copy mounted over the database, in this run's scratch dir. */
  path: string;
  /** The template as extracted, to compare a covering copy against afterwards. */
  template: string;
  destination: string;
  /** Directories created for the mount point, shallowest first. */
  createdDirs: string[];
  /** Set when the runner's own database was given the slot; unset when it
   *  was covered. */
  slot?: NssDbSlot;
}

interface StatShape {
  isDirectory(): boolean;
  isSymbolicLink(): boolean;
  isFile?(): boolean;
}

export interface NssDbDeps {
  exec?: (command: string, args: string[]) => void;
  lstat?: (path: string) => StatShape | undefined;
  stat?: (path: string) => { isDirectory(): boolean } | undefined;
  realpath?: (path: string) => string;
  mkdir?: (path: string, mode: number) => void;
  copyDir?: (source: string, destination: string, filter?: (path: string) => boolean) => void;
  readDir?: (path: string) => string[];
  readFile?: (path: string) => Buffer;
  rmdir?: (path: string) => void;
  /** Throws when the runner user cannot write path. */
  access?: (path: string) => void;
  warn?: (message: string) => void;
  info?: (message: string) => void;
}

// Untested by design: the defaults behind this module's seams, which only hand
// node:fs and node:child_process what the tested caller decided.
/* v8 ignore start */
function defaultExec(command: string, args: string[]): void {
  execFileSync(hostCommand(command), args, { env: hostCommandEnv(command) });
}

function defaultLstat(path: string) {
  try {
    return lstatSync(path);
  } catch {
    return undefined;
  }
}

function defaultStat(path: string) {
  try {
    return statSync(path);
  } catch {
    return undefined;
  }
}

function defaultMkdir(path: string, mode: number): void {
  mkdirSync(path, { mode });
}

function defaultCopyDir(
  source: string,
  destination: string,
  filter?: (path: string) => boolean,
): void {
  cpSync(source, destination, {
    recursive: true,
    preserveTimestamps: true,
    verbatimSymlinks: true,
    filter,
  });
}

function defaultPidAlive(pid: number): boolean {
  try {
    process.kill(pid, 0);
    return true;
  } catch (e) {
    return (e as NodeJS.ErrnoException).code !== "ESRCH";
  }
}

function defaultAccess(path: string): void {
  accessSync(path, constants.W_OK);
}
/* v8 ignore stop */

type NssDbPlan = { destination: string; missing: string[] } | string;

/**
 * The database directory Chromium would read under `home`, and the directories
 * missing on the way, shallowest first; or why it cannot be mounted over. That
 * is ~/.pki/nssdb when it is there, else the XDG database when that is, else a
 * ~/.pki/nssdb to create, which every Chromium reads. A symlink is refused
 * because an earlier step could have pointed it anywhere.
 */
export function planNssDb(
  home: string,
  { lstat = defaultLstat }: Pick<NssDbDeps, "lstat"> = {},
): NssDbPlan {
  const legacy = walkPlan(home, NSS_DB_PATH, lstat);
  if (typeof legacy === "string" || legacy.missing.length === 0) return legacy;
  const xdg = walkPlan(home, NSS_XDG_DB_PATH, lstat);
  if (typeof xdg !== "string" && xdg.missing.length === 0) return xdg;
  return legacy;
}

function walkPlan(home: string, path: string, lstat: NonNullable<NssDbDeps["lstat"]>): NssDbPlan {
  let dir = home;
  const missing: string[] = [];
  for (const component of path.split("/")) {
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
 * Extracts the CA-only template, then gives the runner's database the slot, or
 * covers it when the runner user cannot write it or it is too large to copy,
 * and creates the directories to mount over. Returns undefined, having warned,
 * when there is nowhere to mount either.
 */
export function prepareNssDb(
  containerName: string,
  dir: string,
  home: string | undefined,
  deps: NssDbDeps = {},
): NssDbFiles | undefined {
  const {
    exec = defaultExec,
    lstat = defaultLstat,
    stat = defaultStat,
    realpath = realpathSync,
    mkdir = defaultMkdir,
    copyDir = defaultCopyDir,
    rmdir = rmdirSync,
    warn,
  } = deps;
  // HOME itself may be a symlink the runner was set up with; only what is below it is refused.
  if (!home || stat(home)?.isDirectory() !== true) {
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
  const files: NssDbFiles = { path, template, destination: plan.destination, createdDirs: [] };

  const exists = plan.missing.length === 0;
  let refusal = exists ? whyNotSlot(plan.destination, deps) : undefined;
  if (refusal === undefined) {
    try {
      files.slot = prepareSlot(dir, files, template, exists, deps);
    } catch (e) {
      refusal = `the slot could not be added (${errorMessage(e)})`;
      rmSync(path, { recursive: true, force: true });
    }
  }
  if (refusal !== undefined) {
    deps.info?.(
      `buildcage: ${refusal}, so the NSS database at ${plan.destination} is covered for the ` +
        "command with one trusting only the proxy CA",
    );
    copyDir(template, path);
  }

  // Created here because runc would create them as root in the runner's home.
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

/** Why the runner's own database cannot take the slot, or undefined. Judged
 *  from its modes and sizes alone, so nothing in it is opened. */
function whyNotSlot(
  destination: string,
  { lstat = defaultLstat, access = defaultAccess }: NssDbDeps,
): string | undefined {
  for (const path of [destination, ...NSS_DB_FILES.map((name) => join(destination, name))]) {
    const info = lstat(path);
    if (info === undefined) continue;
    if (info.isSymbolicLink()) return `${path} is a symlink`;
    try {
      access(path);
    } catch {
      return `the runner user cannot write ${path}`;
    }
  }
  let files = 0;
  let bytes = 0;
  try {
    // Staging dirs are passed over before they are read into: another step
    // may remove its own while this walks.
    for (const top of readdirSync(destination, { withFileTypes: true })) {
      if (isStaging(top.name)) continue;
      const below = top.isDirectory()
        ? readdirSync(join(destination, top.name), { recursive: true, withFileTypes: true })
        : [];
      for (const entry of [top, ...below]) {
        files++;
        if (entry.isFile()) bytes += statSync(join(entry.parentPath, entry.name)).size;
        if (files > MAX_MIRROR_FILES || bytes > MAX_MIRROR_BYTES) {
          return `${destination} is too large to copy`;
        }
      }
    }
  } catch (e) {
    return `${destination} cannot be read through (${errorMessage(e)})`;
  }
  return undefined;
}

function prepareSlot(
  dir: string,
  files: NssDbFiles,
  template: string,
  exists: boolean,
  { copyDir = defaultCopyDir }: NssDbDeps,
): NssDbSlot {
  // Readable by the sandbox's user whatever the template's own modes: it holds
  // the CA's certificate and an empty key database, and is mounted read-only.
  const caDb = join(dir, "nssdb-ca");
  copyDir(template, caDb);
  chmodSync(caDb, 0o755);
  for (const name of readdirSync(caDb)) chmodSync(join(caDb, name), 0o644);

  if (exists) {
    // Not another step's write-back in flight, nor one a killed step left.
    copyDir(files.destination, files.path, (path) => !inStaging(files.destination, path));
  } else {
    mkdirSync(files.path, { mode: 0o700 });
  }
  const pkcs11 = join(files.path, "pkcs11.txt");
  const hadPkcs11 = lstatSync(pkcs11, { throwIfNoEntry: false }) !== undefined;
  const appended = appendNssSlot(pkcs11);
  return { caDb, appended, hadPkcs11, snapshot: snapshotDir(files.path) };
}

/** Adds the slot to pkcs11.txt, creating it when missing, and returns what it
 *  appended. Entries are separated by a blank line, which the file gains first
 *  when it does not already end in one. */
export function appendNssSlot(path: string): string {
  // O_NOFOLLOW: a pkcs11.txt that is a symlink could point anywhere.
  const fd = openSync(
    path,
    constants.O_CREAT | constants.O_RDWR | constants.O_APPEND | constants.O_NOFOLLOW,
    0o600,
  );
  try {
    const size = fstatSync(fd).size;
    let appended = "";
    if (size > 0) {
      const tail = Buffer.alloc(Math.min(size, 2));
      readSync(fd, tail, 0, tail.length, size - tail.length);
      const text = tail.toString("latin1");
      if (text.endsWith("\n\n") || text === "\n") appended = "";
      else if (text.endsWith("\n")) appended = "\n";
      else appended = "\n\n";
    }
    appended += NSS_SLOT;
    writeSync(fd, appended);
    return appended;
  } finally {
    closeSync(fd);
  }
}

/** Takes back what appendNssSlot added. NSS rewrites pkcs11.txt only by copying
 *  the entries it keeps byte for byte, so the slot is found where it was left
 *  unless the command itself took it out. The separator goes too only when
 *  nothing follows the slot: an entry after it would otherwise run into the
 *  one before. A pkcs11.txt that is no longer a file carries no slot. One the
 *  injection created is removed once it holds nothing else. */
export function removeNssSlot(path: string, appended: string, created: boolean): void {
  let fd: number;
  try {
    fd = openSync(path, constants.O_RDWR | constants.O_NOFOLLOW | constants.O_NONBLOCK);
  } catch (e) {
    const code = (e as NodeJS.ErrnoException).code;
    if (code === "ENOENT" || code === "ELOOP" || code === "EISDIR" || code === "ENXIO") return;
    throw e;
  }
  try {
    const info = fstatSync(fd);
    if (!info.isFile()) return;
    if (info.size > MAX_PKCS11_TXT_BYTES) {
      throw new Error(
        `${path} is ${info.size} bytes, too large to take the proxy CA's slot back out of`,
      );
    }
    const content = readFileSync(fd).toString("latin1");
    let cut = appended;
    let i = content.lastIndexOf(cut);
    if (i < 0 || i + cut.length < content.length) {
      cut = NSS_SLOT;
      i = content.lastIndexOf(cut);
    }
    if (i < 0) return;
    const kept = content.slice(0, i) + content.slice(i + cut.length);
    if (created && kept === "") {
      rmSync(path);
      return;
    }
    ftruncateSync(fd, 0);
    writeSync(fd, kept, 0, "latin1");
  } finally {
    closeSync(fd);
  }
}

/** Everything under dir, by relative path. */
export function snapshotDir(dir: string): DirSnapshot {
  const snapshot: DirSnapshot = new Map();
  for (const entry of readdirSync(dir, { recursive: true, withFileTypes: true })) {
    const path = join(entry.parentPath, entry.name);
    const rel = relative(dir, path);
    if (entry.isSymbolicLink()) snapshot.set(rel, readlinkSync(path));
    else if (entry.isDirectory()) snapshot.set(rel, null);
    else if (entry.isFile()) snapshot.set(rel, readFileSync(path));
    else snapshot.set(rel, false);
  }
  return snapshot;
}

function sameSnapshot(a: DirSnapshot, b: DirSnapshot): boolean {
  if (a.size !== b.size) return false;
  for (const [rel, value] of a) {
    if (!b.has(rel)) return false;
    const other = b.get(rel);
    if (Buffer.isBuffer(value) && Buffer.isBuffer(other)) {
      if (!value.equals(other)) return false;
    } else if (value !== other) {
      return false;
    }
  }
  return true;
}

/** The DER of the first certificate in pem. */
export function certificateDer(pem: string): Buffer {
  const match = /-----BEGIN CERTIFICATE-----([\s\S]*?)-----END CERTIFICATE-----/.exec(pem);
  return Buffer.from(match?.[1]?.replace(/\s+/g, "") ?? "", "base64");
}

export interface SettleNssDbSlotOptions {
  /** Whether a write to the database's path would have outlived the command. */
  persist: boolean;
  /** The proxy's CA, which must not be written back. */
  caPem: string;
  /** Called with why the write-back would carry the CA; throwing stops it. */
  onResidue: (message: string) => void;
  realpath?: (path: string) => string;
  copyDir?: (source: string, destination: string) => void;
  /** Whether a process with this pid is still there. */
  pidAlive?: (pid: number) => boolean;
}

export type NssDbSlotOutcome = "unchanged" | "discarded" | "written";

/**
 * Writes back what the command changed in a database given the slot, less the
 * slot, where the filesystem mode would have kept the write. A mirror whose
 * destination no longer resolves where it did is not written back: the
 * command may have swapped a directory above it for a symlink.
 */
export function settleNssDbSlot(
  files: NssDbFiles & { slot: NssDbSlot },
  {
    persist,
    caPem,
    onResidue,
    realpath = realpathSync,
    copyDir = defaultCopyDir,
    pidAlive = defaultPidAlive,
  }: SettleNssDbSlotOptions,
): NssDbSlotOutcome {
  let current: DirSnapshot;
  try {
    current = snapshotDir(files.path);
  } catch {
    current = new Map();
  }
  if (sameSnapshot(current, files.slot.snapshot)) return "unchanged";
  if (!persist) return "discarded";

  removeNssSlot(join(files.path, "pkcs11.txt"), files.slot.appended, !files.slot.hadPkcs11);
  const der = certificateDer(caPem);
  for (const [rel, value] of snapshotDir(files.path)) {
    if (Buffer.isBuffer(value) && der.length > 0 && value.includes(der)) {
      onResidue(
        `the command copied the proxy CA into the NSS database at ${files.destination} (${rel})`,
      );
    }
  }

  let resolved: string | undefined;
  try {
    resolved = realpath(files.destination);
  } catch {
    resolved = undefined;
  }
  if (resolved !== files.destination) {
    throw new Error(
      `${files.destination} no longer resolves to itself, so what the command wrote to the NSS ` +
        "database there is not written back",
    );
  }
  // Copied in beside the database first, so a copy that fails partway leaves
  // it as it was. Another step's staging is left alone while that step is
  // still there to finish its own write-back, and removed once it is not.
  const staging = mkdtempSync(join(files.destination, `${STAGING_PREFIX}${process.pid}-`));
  try {
    copyDir(files.path, staging);
  } catch (e) {
    rmSync(staging, { recursive: true, force: true });
    throw e;
  }
  for (const name of readdirSync(files.destination)) {
    const path = join(files.destination, name);
    if (isStaging(name) && (path === staging || stagingOwnerAlive(name, pidAlive))) continue;
    rmSync(path, { recursive: true, force: true });
  }
  for (const name of readdirSync(staging)) {
    if (isStaging(name)) continue;
    renameSync(join(staging, name), join(files.destination, name));
  }
  rmSync(staging, { recursive: true, force: true });
  return "written";
}

/** The copy read-write over the database, since Chromium ignores a database it
 *  cannot open that way, and with the slot, the CA-only database beside it. */
export function nssDbMounts(files: NssDbFiles): MountEntry[] {
  const mounts: MountEntry[] = [
    {
      destination: files.destination,
      type: "none",
      source: files.path,
      options: ["rbind", "rw"],
    },
  ];
  if (files.slot) {
    mounts.push({
      destination: NSS_CA_DB_DESTINATION,
      type: "none",
      source: files.slot.caDb,
      options: ["rbind", "ro", "nosuid", "nodev", "noexec"],
    });
  }
  return mounts;
}

/** Why a covering copy no longer matches the template, or undefined. Compares
 *  names and bytes only, so a chmod or chown of $HOME does not count; a copy
 *  the command made unreadable counts as changed. Chromium reading the
 *  database leaves it byte-identical. */
export function nssDbChange(
  files: NssDbFiles,
  { readDir = readdirSync, readFile = readFileSync }: Pick<NssDbDeps, "readDir" | "readFile"> = {},
): string | undefined {
  let changed: boolean;
  try {
    const names = readDir(files.template).sort();
    const current = readDir(files.path).sort();
    changed =
      names.length !== current.length ||
      names.some(
        (name, i) =>
          current[i] !== name ||
          !readFile(join(files.template, name)).equals(readFile(join(files.path, name))),
      );
  } catch {
    changed = true;
  }
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

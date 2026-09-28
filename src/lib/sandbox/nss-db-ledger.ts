import {
  closeSync,
  constants,
  fstatSync,
  linkSync,
  lstatSync,
  mkdirSync,
  openSync,
  readFileSync,
  renameSync,
  rmSync,
  rmdirSync,
  writeFileSync,
  writeSync,
  type BigIntStats,
} from "node:fs";
import { basename, join } from "node:path";

import { errorMessage } from "#core/lib/errors.ts";

import { retryBriefly } from "../retry-briefly.ts";
import { SANDBOX_SCRATCH_BASE } from "./scratch-dir.ts";

/**
 * The directories made on the runner for Chromium's NSS database to be mounted
 * over, shared by every step of the runner user's, parallel ones and other
 * jobs' included.
 *
 * Removing a directory detaches every mount on it, in every mount namespace, so
 * a step that removed the one it made while another step's sandbox still had
 * its mirror mounted there would take that database away from the other
 * command. Each step therefore registers its use of the database's directory
 * here, and the last one to leave removes the directories Buildcage made.
 *
 * It lives in SANDBOX_SCRATCH_BASE, which the sandbox cannot see or write, so
 * a command cannot mark a directory of the runner's for removal. A directory
 * is known by its device, inode and birth time together: a directory removed
 * and made again may get the inode back, never the birth time, so an entry
 * left behind by a killed run never matches a directory someone made since.
 */

export const NSS_DB_LEDGER_NAME = "nssdb-ledger.json";
const LOCK_NAME = "nssdb-ledger.lock";

/** A few hundred bytes per entry, and a handful of entries at a time. */
const MAX_LEDGER_BYTES = 64 << 10;

/** Held for milliseconds, so one this old whose holder is gone is left over. */
const STALE_LOCK_MS = 10_000;

/** A step's scratch dir name; see scratchDirNameFor. */
const USE_NAME_RE = /^sandbox-[A-Za-z0-9]+$/;

/** A directory's identity: device, inode and birth time, as decimal strings. */
export interface DirId {
  dev: string;
  ino: string;
  /** "0" where the filesystem keeps no birth time. */
  birthtimeNs: string;
}

interface LedgerDir extends DirId {
  createdBy: string;
  createdAt: string;
}

interface LedgerUse extends DirId {
  destination: string;
  startedAt: string;
}

interface Ledger {
  version: 1;
  /** The directories Buildcage made, by path. */
  dirs: Record<string, LedgerDir>;
  /** The steps with a database mounted, by scratch dir name. */
  uses: Record<string, LedgerUse>;
}

type LstatShape = Pick<BigIntStats, "dev" | "ino" | "birthtimeNs"> & {
  isDirectory(): boolean;
  isSymbolicLink(): boolean;
};

export interface NssDbLedgerDeps {
  /** SANDBOX_SCRATCH_BASE, but for tests. */
  base?: string;
  lstat?: (path: string) => LstatShape | undefined;
  mkdir?: (path: string, mode: number) => void;
  rmdir?: (path: string) => void;
  /** Whether a process with this pid is still there. */
  pidAlive?: (pid: number) => boolean;
  now?: () => Date;
  lockAttempts?: number;
  info?: (message: string) => void;
  warn?: (message: string) => void;
}

// Untested by design: the defaults behind this module's seams, which only hand
// node:fs and process.kill what the tested caller decided.
/* v8 ignore start */
function defaultLstat(path: string): LstatShape | undefined {
  return lstatSync(path, { bigint: true, throwIfNoEntry: false });
}

function defaultMkdir(path: string, mode: number): void {
  mkdirSync(path, { mode });
}

function defaultPidAlive(pid: number): boolean {
  try {
    process.kill(pid, 0);
    return true;
  } catch (e) {
    return (e as NodeJS.ErrnoException).code !== "ESRCH";
  }
}
/* v8 ignore stop */

function code(e: unknown): string | undefined {
  return (e as NodeJS.ErrnoException).code;
}

function idOf(info: LstatShape): DirId {
  return { dev: String(info.dev), ino: String(info.ino), birthtimeNs: String(info.birthtimeNs) };
}

function sameId(a: DirId, b: DirId): boolean {
  return a.dev === b.dev && a.ino === b.ino && a.birthtimeNs === b.birthtimeNs;
}

/** The identity of the directory at path, or undefined when there is none. */
export function dirIdOf(
  path: string,
  { lstat = defaultLstat }: Pick<NssDbLedgerDeps, "lstat"> = {},
): DirId | undefined {
  const info = lstat(path);
  return info?.isDirectory() ? idOf(info) : undefined;
}

/** Whether path still holds the directory that was there when id was taken. */
export function stillThere(
  path: string,
  id: DirId,
  deps: Pick<NssDbLedgerDeps, "lstat"> = {},
): boolean {
  const current = dirIdOf(path, deps);
  return current !== undefined && sameId(current, id);
}

/**
 * Takes the lock, by hard-linking a file holding this pid to the lock's name:
 * link fails when the name is taken, so the file appears whole or not at
 * all. A lock whose holder is gone and that is older than any holder keeps it
 * is taken over.
 */
function acquireLock(
  base: string,
  { pidAlive = defaultPidAlive, now = () => new Date(), lockAttempts = 50 }: NssDbLedgerDeps,
): () => void {
  const lock = join(base, LOCK_NAME);
  const mine = join(base, `${LOCK_NAME}.${process.pid}`);
  writeFileSync(mine, String(process.pid), { mode: 0o600 });
  try {
    retryBriefly(
      () => {
        try {
          linkSync(mine, lock);
        } catch (e) {
          takeOverStaleLock(lock, pidAlive, now);
          throw e;
        }
      },
      { attempts: lockAttempts, delayMs: 100, retryOn: (e) => code(e) === "EEXIST" },
    );
  } finally {
    rmSync(mine, { force: true });
  }
  return () => rmSync(lock, { force: true });
}

/** Removes a lock left by a holder that is gone. Two steps that both find the
 *  same one left can still both remove it, the second taking away the lock
 *  the first has just taken; that needs a run killed while holding it, for a
 *  few milliseconds, and costs no more than two steps updating the ledger at
 *  once. */
function takeOverStaleLock(
  lock: string,
  pidAlive: (pid: number) => boolean,
  now: () => Date,
): void {
  let pid: number;
  let age: number;
  try {
    pid = Number(readFileSync(lock, "utf8"));
    age = now().getTime() - lstatSync(lock).mtimeMs;
  } catch {
    return;
  }
  if (age < STALE_LOCK_MS || (Number.isInteger(pid) && pid > 0 && pidAlive(pid))) return;
  rmSync(lock, { force: true });
}

function emptyLedger(): Ledger {
  return { version: 1, dirs: {}, uses: {} };
}

function isId(value: unknown): value is DirId {
  const v = value as Record<string, unknown>;
  return (
    typeof v === "object" &&
    v !== null &&
    [v.dev, v.ino, v.birthtimeNs].every((s) => typeof s === "string" && /^\d+$/.test(s))
  );
}

/** The ledger, or why it cannot be trusted. None at all is an empty one. */
function readLedger(path: string): Ledger | string {
  let fd: number;
  try {
    fd = openSync(path, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK);
  } catch (e) {
    if (code(e) === "ENOENT") return emptyLedger();
    return `${path} cannot be opened (${errorMessage(e)})`;
  }
  try {
    const info = fstatSync(fd);
    // Its owner is not checked: ensureOwnScratchBase keeps the base private
    // to the runner user, so nobody else but root can have put it there.
    if (!info.isFile()) return `${path} is not a file`;
    if (info.size > MAX_LEDGER_BYTES) return `${path} is ${info.size} bytes, too large`;
    const parsed = JSON.parse(readFileSync(fd, "utf8")) as Partial<Ledger>;
    const valid =
      parsed?.version === 1 &&
      typeof parsed.dirs === "object" &&
      parsed.dirs !== null &&
      typeof parsed.uses === "object" &&
      parsed.uses !== null &&
      Object.entries(parsed.dirs).every(([p, d]) => p.startsWith("/") && isId(d)) &&
      Object.entries(parsed.uses).every(([n, u]) => USE_NAME_RE.test(n) && isId(u));
    return valid ? (parsed as Ledger) : `${path} is not a ledger this version can read`;
  } catch (e) {
    return `${path} cannot be read (${errorMessage(e)})`;
  } finally {
    closeSync(fd);
  }
}

/** Written beside it and renamed over it, so a reader never sees half of it. */
function writeLedger(path: string, ledger: Ledger): void {
  const tmp = `${path}.${process.pid}.tmp`;
  rmSync(tmp, { force: true });
  const fd = openSync(
    tmp,
    constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | constants.O_NOFOLLOW,
    0o600,
  );
  try {
    writeSync(fd, `${JSON.stringify(ledger, null, 2)}\n`);
  } finally {
    closeSync(fd);
  }
  renameSync(tmp, path);
}

/**
 * Runs fn on the ledger under the lock and saves what it leaves. Throws when
 * the lock cannot be had; hands fn a reason instead of the ledger when the
 * ledger cannot be trusted, and then saves nothing: remaking it would drop
 * other steps' uses.
 */
function withLedger<T>(fn: (ledger: Ledger | string) => T, deps: NssDbLedgerDeps): T {
  const base = baseOf(deps);
  const path = join(base, NSS_DB_LEDGER_NAME);
  const release = acquireLock(base, deps);
  try {
    const ledger = readLedger(path);
    // Saved even when fn throws, as what it undid on the way out is done.
    try {
      return fn(ledger);
    } finally {
      if (typeof ledger !== "string") writeLedger(path, ledger);
    }
  } finally {
    release();
  }
}

function baseOf({ base }: NssDbLedgerDeps): string {
  return base ?? SANDBOX_SCRATCH_BASE;
}

/** Drops the uses of steps whose scratch dir is gone: the mirror lives in it,
 *  and it goes only once every mount under it has, so nothing of theirs is
 *  mounted any more. */
function dropStaleUses(ledger: Ledger, deps: NssDbLedgerDeps): void {
  const { lstat = defaultLstat } = deps;
  for (const name of Object.keys(ledger.uses)) {
    if (lstat(join(baseOf(deps), name)) === undefined) delete ledger.uses[name];
  }
}

/**
 * Removes the directories Buildcage made once no step uses them, deepest
 * first, as the runner user: one the command filled is left, as it is the
 * runner's now. Each entry goes whatever happens to its directory, since one
 * that is gone or was made again is no longer Buildcage's to remove.
 */
function removeUnusedDirs(ledger: Ledger, deps: NssDbLedgerDeps): void {
  if (Object.keys(ledger.uses).length > 0) return;
  const { rmdir = rmdirSync, info } = deps;
  for (const path of Object.keys(ledger.dirs).sort((a, b) => b.length - a.length)) {
    const entry = ledger.dirs[path]!;
    delete ledger.dirs[path];
    const current = dirIdOf(path, deps);
    if (current === undefined) {
      info?.(
        `buildcage: ${path}, made for Chromium's NSS database by ${entry.createdBy}, had already ` +
          "been removed by something else",
      );
      continue;
    }
    if (!sameId(current, entry)) continue;
    try {
      rmdir(path);
    } catch {
      // Not empty: the command, or Chromium, put something in it.
    }
  }
}

export interface NssDbClaim {
  /** The database directory as it was once claimed, to tell afterwards
   *  whether it was removed while the command ran. */
  destinationId: DirId;
  /** Whether the use went into the ledger, and so has to be released. */
  registered: boolean;
}

/**
 * Makes the directories `missing` (shallowest first) under the lock, marks
 * the ones it made, and registers this step's use of `destination` under
 * `name`, its scratch dir's name. A directory another step made meanwhile is
 * taken as it is, unless it is a symlink. Throws, having undone what it did,
 * when a directory cannot be made or the lock cannot be had.
 *
 * With a ledger that cannot be trusted, the directories are made but neither
 * marked nor registered, so no step removes them: they are left behind.
 */
export function claimNssDb(
  name: string,
  destination: string,
  missing: string[],
  deps: NssDbLedgerDeps = {},
): NssDbClaim {
  const { mkdir = defaultMkdir, lstat = defaultLstat, now = () => new Date(), warn } = deps;
  return withLedger((ledger) => {
    const undo = () => {
      if (typeof ledger !== "string") removeUnusedDirs(ledger, deps);
    };
    if (typeof ledger !== "string") dropStaleUses(ledger, deps);
    try {
      for (const path of missing) {
        try {
          mkdir(path, 0o700);
        } catch (e) {
          const info = code(e) === "EEXIST" ? lstat(path) : undefined;
          if (!info?.isDirectory() || info.isSymbolicLink()) throw e;
          continue;
        }
        const made = lstat(path);
        if (typeof ledger !== "string" && made && made.birthtimeNs !== 0n) {
          ledger.dirs[path] = { ...idOf(made), createdBy: name, createdAt: now().toISOString() };
        }
      }
    } catch (e) {
      undo();
      throw e;
    }
    const current = lstat(destination);
    if (!current?.isDirectory()) {
      undo();
      throw new Error(`${destination} is not a directory`);
    }
    const destinationId = idOf(current);
    if (typeof ledger === "string") {
      warn?.(
        `buildcage: ${ledger}, so the directories made for Chromium's NSS database are left ` +
          "in place after the step",
      );
      return { destinationId, registered: false };
    }
    ledger.uses[name] = { destination, ...destinationId, startedAt: now().toISOString() };
    return { destinationId, registered: true };
  }, deps);
}

/**
 * Ends the use registered under `name` and, once no step uses them, removes
 * the directories Buildcage made. A lock that cannot be had leaves them in
 * place for a later step to remove.
 */
export function releaseNssDb(name: string, deps: NssDbLedgerDeps = {}): void {
  const { lstat = defaultLstat, warn } = deps;
  const path = join(baseOf(deps), NSS_DB_LEDGER_NAME);
  if (lstat(path) === undefined) return;
  try {
    withLedger((ledger) => {
      if (typeof ledger === "string") return;
      delete ledger.uses[name];
      dropStaleUses(ledger, deps);
      removeUnusedDirs(ledger, deps);
    }, deps);
  } catch (e) {
    warn?.(
      `buildcage: could not update ${path} (${errorMessage(e)}), so ` +
        "the directories made for Chromium's NSS database are left in place for a later step to remove",
    );
  }
}

/** The name a step's use is registered under: its scratch dir's own name. */
export function useNameFor(scratchDir: string): string {
  return basename(scratchDir);
}

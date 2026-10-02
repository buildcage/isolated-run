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
  rmdirSync,
  rmSync,
  writeFileSync,
  writeSync,
  type BigIntStats,
} from "node:fs";
import { basename, join } from "node:path";

import { errorMessage } from "#core/lib/errors.ts";

import { retryBriefly } from "../retry-briefly.ts";
import { SANDBOX_SCRATCH_BASE } from "./scratch-dir.ts";

/**
 * Ledger of the directories made for Chromium's NSS database mount, shared by
 * every step of the runner user, across jobs too.
 *
 * rmdir detaches every mount on the directory in every mount namespace, so a
 * step must not remove one another step's sandbox still has its database
 * mounted on. Each step registers its use, and the last to leave removes what
 * Buildcage made.
 *
 * The ledger lives in SANDBOX_SCRATCH_BASE, hidden from the sandbox, so a
 * command cannot mark a runner directory for removal. Directories are
 * identified by device, inode and birth time: a recreated directory may reuse
 * the inode but not the birth time, so a stale entry never matches it.
 */

export const NSS_DB_LEDGER_NAME = "nssdb-ledger.json";
const LOCK_NAME = "nssdb-ledger.lock";
const MAX_LEDGER_BYTES = 64 << 10;
const LOCK_DELAY_MS = 100;

/** Kept well under acquireLock's wait so a lock left by a killed holder is
 *  taken over within it. */
const STALE_LOCK_MS = 2_000;

export interface DirId {
  dev: string;
  ino: string;
  /** "0" where the filesystem keeps no birth time. */
  birthtimeNs: string;
}

type LstatShape = Pick<BigIntStats, "dev" | "ino" | "birthtimeNs"> & {
  isDirectory(): boolean;
  isSymbolicLink(): boolean;
};

// Untested by design: the defaults behind this module's seams, which only hand
// node:fs and process.kill what the tested caller decided.
/* v8 ignore start */
function defaultMkdir(path: string, mode: number): void {
  mkdirSync(path, { mode });
}

function defaultLstat(path: string): LstatShape | undefined {
  return lstatSync(path, { bigint: true, throwIfNoEntry: false });
}

export function defaultPidAlive(pid: number): boolean {
  try {
    process.kill(pid, 0);
    return true;
  } catch (e) {
    return (e as NodeJS.ErrnoException).code !== "ESRCH";
  }
}
/* v8 ignore stop */

/** scratchDirNameFor's shape. */
const USE_NAME_RE = /^sandbox-[A-Za-z0-9]+$/;

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
  /** Directories Buildcage made, by path. */
  dirs: Record<string, LedgerDir>;
  /** Steps with a database mounted, by scratch dir name. */
  uses: Record<string, LedgerUse>;
}

export interface NssDbLedgerDeps {
  base?: string;
  pidAlive?: (pid: number) => boolean;
  now?: () => Date;
  lockAttempts?: number;
  lstat?: (path: string) => LstatShape | undefined;
  mkdir?: (path: string, mode: number) => void;
  rmdir?: (path: string) => void;
  info?: (message: string) => void;
  warn?: (message: string) => void;
}

function emptyLedger(): Ledger {
  return { version: 1, dirs: {}, uses: {} };
}

function isLedger(parsed: unknown): parsed is Ledger {
  const l = parsed as Partial<Ledger> | null;
  return (
    l?.version === 1 &&
    typeof l.dirs === "object" &&
    l.dirs !== null &&
    typeof l.uses === "object" &&
    l.uses !== null &&
    Object.entries(l.dirs).every(([p, d]) => p.startsWith("/") && isId(d)) &&
    Object.entries(l.uses).every(([n, u]) => USE_NAME_RE.test(n) && isId(u))
  );
}

function errnoCode(e: unknown): string | undefined {
  return (e as NodeJS.ErrnoException).code;
}

function idOf(info: LstatShape): DirId {
  return { dev: String(info.dev), ino: String(info.ino), birthtimeNs: String(info.birthtimeNs) };
}

function sameId(a: DirId, b: DirId): boolean {
  return a.dev === b.dev && a.ino === b.ino && a.birthtimeNs === b.birthtimeNs;
}

function isId(value: unknown): value is DirId {
  const v = value as Record<string, unknown>;
  return (
    typeof v === "object" &&
    v !== null &&
    [v.dev, v.ino, v.birthtimeNs].every((s) => typeof s === "string" && /^\d+$/.test(s))
  );
}

export function dirIdOf(
  path: string,
  { lstat = defaultLstat }: { lstat?: (path: string) => LstatShape | undefined } = {},
): DirId | undefined {
  const info = lstat(path);
  return info?.isDirectory() ? idOf(info) : undefined;
}

export function stillThere(
  path: string,
  id: DirId,
  deps: { lstat?: (path: string) => LstatShape | undefined } = {},
): boolean {
  const current = dirIdOf(path, deps);
  return current !== undefined && sameId(current, id);
}

/** link(2) creates the lock with its pid already written, or fails with
 *  EEXIST, so no reader sees an empty lock. */
function acquireLock(
  lock: string,
  { pidAlive = defaultPidAlive, now = () => new Date(), lockAttempts = 50 }: NssDbLedgerDeps,
): () => void {
  const mine = `${lock}.${process.pid}`;
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
      { attempts: lockAttempts, delayMs: LOCK_DELAY_MS, retryOn: (e) => errnoCode(e) === "EEXIST" },
    );
  } catch (e) {
    // link(2) fails otherwise only on a broken scratch base, which no test builds.
    /* v8 ignore next */
    if (errnoCode(e) !== "EEXIST") throw e;
    const waited = ((lockAttempts - 1) * LOCK_DELAY_MS) / 1000;
    throw new Error(`could not take ${lock}: another step held it for over ${waited}s`, {
      cause: e,
    });
  } finally {
    rmSync(mine, { force: true });
  }
  return () => rmSync(lock, { force: true });
}

/** Two waiters can both take over the same stale lock, the second removing
 *  the first's new one. That needs a holder killed within its milliseconds,
 *  and costs at most one overlapping ledger update. */
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

function withLock<T>(base: string, fn: () => T, deps: NssDbLedgerDeps): T {
  const release = acquireLock(join(base, LOCK_NAME), deps);
  try {
    return fn();
  } finally {
    release();
  }
}

/** The ledger, an empty one if there is none yet, or why it cannot be trusted. */
function readLedger(path: string): Ledger | string {
  let fd: number;
  try {
    fd = openSync(path, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK);
  } catch (e) {
    if (errnoCode(e) === "ENOENT") return emptyLedger();
    return `${path} cannot be opened (${errorMessage(e)})`;
  }
  try {
    const info = fstatSync(fd);
    // No owner check: ensureOwnScratchBase keeps the base private to the
    // runner user.
    if (!info.isFile()) return `${path} is not a file`;
    if (info.size > MAX_LEDGER_BYTES) return `${path} is ${info.size} bytes, too large`;
    const parsed: unknown = JSON.parse(readFileSync(fd, "utf8"));
    return isLedger(parsed) ? parsed : `${path} is not a ledger this version can read`;
  } catch (e) {
    return `${path} cannot be read (${errorMessage(e)})`;
  } finally {
    closeSync(fd);
  }
}

/** Renamed into place so a reader never sees a partial write. */
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

/** Runs fn on the ledger under its lock and saves it afterwards, even when fn
 *  throws, since the undo fn ran has taken effect. An untrusted ledger is
 *  handed to fn as the reason and never rewritten: remaking it would drop
 *  other steps' uses. */
function withLedger<T>(fn: (ledger: Ledger | string) => T, deps: NssDbLedgerDeps): T {
  const path = join(baseOf(deps), NSS_DB_LEDGER_NAME);
  return withLock(
    baseOf(deps),
    () => {
      const ledger = readLedger(path);
      try {
        return fn(ledger);
      } finally {
        if (typeof ledger !== "string") writeLedger(path, ledger);
      }
    },
    deps,
  );
}

/** Also held by write-backs, so parallel ones never interleave. */
export function withNssDbLock<T>(fn: () => T, deps: NssDbLedgerDeps = {}): T {
  return withLock(baseOf(deps), fn, deps);
}

function baseOf({ base }: NssDbLedgerDeps): string {
  return base ?? SANDBOX_SCRATCH_BASE;
}

/** A scratch dir is removed only after every mount under it, so a use whose
 *  scratch dir is gone has nothing mounted. */
function dropStaleUses(ledger: Ledger, deps: NssDbLedgerDeps): void {
  const { lstat = defaultLstat } = deps;
  for (const name of Object.keys(ledger.uses)) {
    if (lstat(join(baseOf(deps), name)) === undefined) delete ledger.uses[name];
  }
}

/** A directory that is gone, recreated or no longer empty is not Buildcage's
 *  any more, so its entry is dropped either way. */
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
      // Not empty: now the runner's.
    }
  }
}

export interface NssDbClaim {
  /** To tell afterwards whether it was removed while the command ran. */
  destinationId: DirId;
  registered: boolean;
}

/**
 * Makes whichever of `dirs` (shallowest first) are missing, marks them, and
 * registers this step's use of `destination`. An existing one is taken as it
 * is, unless it is a symlink.
 *
 * Directories are left unmarked, and so never removed, when the ledger cannot
 * be trusted or the filesystem keeps no birth time.
 */
export function claimNssDb(
  name: string,
  destination: string,
  dirs: string[],
  deps: NssDbLedgerDeps = {},
): NssDbClaim {
  const { mkdir = defaultMkdir, lstat = defaultLstat, now = () => new Date(), warn } = deps;
  return withLedger((ledger) => {
    const undo = () => {
      if (typeof ledger !== "string") removeUnusedDirs(ledger, deps);
    };
    if (typeof ledger !== "string") dropStaleUses(ledger, deps);
    try {
      for (const path of dirs) {
        try {
          mkdir(path, 0o700);
        } catch (e) {
          const info = errnoCode(e) === "EEXIST" ? lstat(path) : undefined;
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

/** Without the lock, the directories are left for a later step to remove. */
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

export function useNameFor(scratchDir: string): string {
  return basename(scratchDir);
}

import {
  closeSync,
  constants,
  fstatSync,
  linkSync,
  lstatSync,
  openSync,
  readFileSync,
  renameSync,
  rmSync,
  writeFileSync,
  writeSync,
  type BigIntStats,
} from "node:fs";
import { join } from "node:path";

import { errorMessage } from "#core/lib/errors.ts";

import { retryBriefly } from "../retry-briefly.ts";

/**
 * The file, lock and directory identity shared by the ledgers of directories
 * Buildcage makes on the runner (nss-db-ledger.ts, write-through-ledger.ts).
 *
 * A ledger lives in SANDBOX_SCRATCH_BASE, hidden from the sandbox, so a command
 * cannot mark a runner directory for removal. Directories are identified by
 * device, inode and birth time: a recreated directory may reuse the inode but
 * not the birth time, so a stale entry never matches it.
 */

const MAX_LEDGER_BYTES = 64 << 10;

/** Kept well under acquireLock's wait so a lock left by a killed holder is
 *  taken over within it. */
const STALE_LOCK_MS = 2_000;

export interface DirId {
  dev: string;
  ino: string;
  /** "0" where the filesystem keeps no birth time. */
  birthtimeNs: string;
}

export type LstatShape = Pick<BigIntStats, "dev" | "ino" | "birthtimeNs"> & {
  isDirectory(): boolean;
  isSymbolicLink(): boolean;
};

export interface LockDeps {
  pidAlive?: (pid: number) => boolean;
  now?: () => Date;
  lockAttempts?: number;
  lockDelayMs?: number;
}

// Untested by design: the defaults behind this module's seams, which only hand
// node:fs and process.kill what the tested caller decided.
/* v8 ignore start */
export function defaultLstat(path: string): LstatShape | undefined {
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

export function errnoCode(e: unknown): string | undefined {
  return (e as NodeJS.ErrnoException).code;
}

export function idOf(info: LstatShape): DirId {
  return { dev: String(info.dev), ino: String(info.ino), birthtimeNs: String(info.birthtimeNs) };
}

export function sameId(a: DirId, b: DirId): boolean {
  return a.dev === b.dev && a.ino === b.ino && a.birthtimeNs === b.birthtimeNs;
}

export function isId(value: unknown): value is DirId {
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
  {
    pidAlive = defaultPidAlive,
    now = () => new Date(),
    lockAttempts = 50,
    lockDelayMs = 100,
  }: LockDeps,
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
      { attempts: lockAttempts, delayMs: lockDelayMs, retryOn: (e) => errnoCode(e) === "EEXIST" },
    );
  } catch (e) {
    // EEXIST alone reads as a bug rather than a step holding the lock too long.
    throw new Error(
      `could not take ${lock} within ${(lockAttempts * lockDelayMs) / 1000}s (${errorMessage(e)})`,
      { cause: e },
    );
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

export function withLock<T>(base: string, lockName: string, fn: () => T, deps: LockDeps): T {
  const release = acquireLock(join(base, lockName), deps);
  try {
    return fn();
  } finally {
    release();
  }
}

/** The ledger, `empty()` if there is none yet, or why it cannot be trusted. */
export function readLedgerFile<T>(
  path: string,
  empty: () => T,
  valid: (parsed: unknown) => parsed is T,
): T | string {
  let fd: number;
  try {
    fd = openSync(path, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK);
  } catch (e) {
    if (errnoCode(e) === "ENOENT") return empty();
    return `${path} cannot be opened (${errorMessage(e)})`;
  }
  try {
    const info = fstatSync(fd);
    // No owner check: ensureOwnScratchBase keeps the base private to the
    // runner user.
    if (!info.isFile()) return `${path} is not a file`;
    if (info.size > MAX_LEDGER_BYTES) return `${path} is ${info.size} bytes, too large`;
    const parsed: unknown = JSON.parse(readFileSync(fd, "utf8"));
    return valid(parsed) ? parsed : `${path} is not a ledger this version can read`;
  } catch (e) {
    return `${path} cannot be read (${errorMessage(e)})`;
  } finally {
    closeSync(fd);
  }
}

/** Renamed into place so a reader never sees a partial write. */
export function writeLedgerFile(path: string, ledger: unknown): void {
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
export function withLedgerFile<T, L>(
  base: string,
  fileName: string,
  lockName: string,
  read: (path: string) => L | string,
  fn: (ledger: L | string) => T,
  deps: LockDeps,
): T {
  const path = join(base, fileName);
  return withLock(
    base,
    lockName,
    () => {
      const ledger = read(path);
      try {
        return fn(ledger);
      } finally {
        if (typeof ledger !== "string") writeLedgerFile(path, ledger);
      }
    },
    deps,
  );
}

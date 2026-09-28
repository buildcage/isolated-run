import { mkdirSync, rmdirSync } from "node:fs";
import { basename, join } from "node:path";

import { errorMessage } from "#core/lib/errors.ts";

import {
  defaultLstat,
  dirIdOf,
  errnoCode,
  idOf,
  isId,
  readLedgerFile,
  sameId,
  withLedgerFile,
  withLock,
  type DirId,
  type LockDeps,
  type LstatShape,
} from "./ledger-file.ts";
import { SANDBOX_SCRATCH_BASE } from "./scratch-dir.ts";

export { dirIdOf, stillThere, type DirId } from "./ledger-file.ts";

/**
 * Ledger of the directories made for Chromium's NSS database mount, shared by
 * every step of the runner user, across jobs too.
 *
 * rmdir detaches every mount on the directory in every mount namespace, so a
 * step must not remove one another step's sandbox still has its database
 * mounted on. Each step registers its use, and the last to leave removes what
 * Buildcage made.
 */

export const NSS_DB_LEDGER_NAME = "nssdb-ledger.json";
const LOCK_NAME = "nssdb-ledger.lock";

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

export interface NssDbLedgerDeps extends LockDeps {
  base?: string;
  lstat?: (path: string) => LstatShape | undefined;
  mkdir?: (path: string, mode: number) => void;
  rmdir?: (path: string) => void;
  info?: (message: string) => void;
  warn?: (message: string) => void;
}

// Untested by design: hands node:fs what the tested caller decided.
/* v8 ignore start */
function defaultMkdir(path: string, mode: number): void {
  mkdirSync(path, { mode });
}
/* v8 ignore stop */

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

function withLedger<T>(fn: (ledger: Ledger | string) => T, deps: NssDbLedgerDeps): T {
  return withLedgerFile(
    baseOf(deps),
    NSS_DB_LEDGER_NAME,
    LOCK_NAME,
    (path) => readLedgerFile(path, emptyLedger, isLedger),
    fn,
    deps,
  );
}

/** Also held by write-backs, so parallel ones never interleave. */
export function withNssDbLock<T>(fn: () => T, deps: NssDbLedgerDeps = {}): T {
  return withLock(baseOf(deps), LOCK_NAME, fn, deps);
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

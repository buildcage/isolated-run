import { join } from "node:path";

import { errorMessage } from "#core/lib/errors.ts";

import {
  defaultLstat,
  defaultPidAlive,
  dirIdOf,
  idOf,
  isId,
  readLedgerFile,
  sameId,
  stillThere,
  withLedgerFile,
  type DirId,
  type LockDeps,
  type LstatShape,
} from "./ledger-file.ts";
import { ensureOwnScratchBase, SANDBOX_SCRATCH_BASE } from "./scratch-dir.ts";
import { hostDirOps, rmdirAsOwner, type CreatedDir } from "./write-through.ts";

/**
 * Ledger of the directories made for missing write_through targets, shared by
 * every step of the runner user, across jobs too.
 *
 * rmdir detaches every mount on the directory in every mount namespace, so a
 * step must not remove a directory another step's sandbox still has bound.
 * Each step registers the targets it binds, and a directory Buildcage made is
 * removed once no step binds it or anything under it.
 */

export const WRITE_THROUGH_LEDGER_NAME = "write-through-ledger.json";
const LOCK_NAME = "write-through-ledger.lock";

/** 30s, since holders run a sudo per target. */
const LOCK_ATTEMPTS = 300;

/** scratchDirNameFor's shape. */
const USE_NAME_RE = /^sandbox-[A-Za-z0-9]+$/;

interface LedgerDir extends DirId {
  /** Removed as this owner, as it was made. */
  uid: number;
  gid: number;
  createdBy: string;
  createdAt: string;
}

interface LedgerUse {
  /** The action's own process, alive from before the scratch dir exists. */
  pid: number;
  destinations: string[];
  startedAt: string;
}

interface Ledger {
  version: 1;
  /** Directories Buildcage made, by path. */
  dirs: Record<string, LedgerDir>;
  /** Steps with write_through targets bound, by scratch dir name. */
  uses: Record<string, LedgerUse>;
}

export interface WriteThroughLedgerDeps extends LockDeps {
  base?: string;
  lstat?: (path: string) => LstatShape | undefined;
  rmdir?: (dir: CreatedDir) => void;
  pid?: number;
  info?: (message: string) => void;
  warn?: (message: string) => void;
}

// As the directory's owner, like the mkdir that made it: the command has had
// these paths writable, so a root rmdir by name would remove any empty
// directory on the host. `rmdir`, so one the command wrote to stays.
// Untested by design: hands rmdirAsOwner the real filesystem and sudo.
/* v8 ignore next */
const defaultRmdir = (dir: CreatedDir): void => rmdirAsOwner(dir, hostDirOps());

function emptyLedger(): Ledger {
  return { version: 1, dirs: {}, uses: {} };
}

function isOwner(value: unknown): boolean {
  return Number.isInteger(value) && (value as number) >= 0;
}

function isLedger(parsed: unknown): parsed is Ledger {
  const l = parsed as Partial<Ledger> | null;
  return (
    l?.version === 1 &&
    typeof l.dirs === "object" &&
    l.dirs !== null &&
    typeof l.uses === "object" &&
    l.uses !== null &&
    Object.entries(l.dirs).every(
      ([p, d]) => p.startsWith("/") && isId(d) && isOwner(d.uid) && isOwner(d.gid),
    ) &&
    Object.entries(l.uses).every(
      ([n, u]) =>
        USE_NAME_RE.test(n) &&
        Number.isInteger(u?.pid) &&
        Array.isArray(u.destinations) &&
        u.destinations.every((d) => typeof d === "string"),
    )
  );
}

function baseOf({ base }: WriteThroughLedgerDeps): string {
  return base ?? SANDBOX_SCRATCH_BASE;
}

function withLedger<T>(fn: (ledger: Ledger | string) => T, deps: WriteThroughLedgerDeps): T {
  return withLedgerFile(
    baseOf(deps),
    WRITE_THROUGH_LEDGER_NAME,
    LOCK_NAME,
    (path) => readLedgerFile(path, emptyLedger, isLedger),
    fn,
    { lockAttempts: LOCK_ATTEMPTS, ...deps },
  );
}

/** A use is over once its process is gone and so is its scratch dir, which is
 *  removed only after every mount under it. */
function dropStaleUses(ledger: Ledger, deps: WriteThroughLedgerDeps): void {
  const { lstat = defaultLstat, pidAlive = defaultPidAlive } = deps;
  for (const [name, use] of Object.entries(ledger.uses)) {
    if (!pidAlive(use.pid) && lstat(join(baseOf(deps), name)) === undefined) {
      delete ledger.uses[name];
    }
  }
}

function inUse(ledger: Ledger, path: string): boolean {
  return Object.values(ledger.uses).some((use) =>
    use.destinations.some((d) => d === path || d.startsWith(`${path}/`)),
  );
}

/** A directory that is gone, recreated or no longer empty is not Buildcage's
 *  any more, so its entry is dropped either way. */
function removeUnusedDirs(ledger: Ledger, deps: WriteThroughLedgerDeps): void {
  const { rmdir = defaultRmdir, info } = deps;
  for (const path of Object.keys(ledger.dirs).sort((a, b) => b.length - a.length)) {
    if (inUse(ledger, path)) continue;
    const entry = ledger.dirs[path]!;
    delete ledger.dirs[path];
    const current = dirIdOf(path, deps);
    if (current === undefined) {
      info?.(
        `buildcage: ${path}, made for write_through by ${entry.createdBy}, had already been ` +
          "removed by something else",
      );
      continue;
    }
    if (!sameId(current, entry)) continue;
    try {
      rmdir({ path, uid: entry.uid, gid: entry.gid });
    } catch {
      // Not empty: now the owner's.
    }
  }
}

export interface WriteThroughClaim {
  name: string;
  registered: boolean;
  /** As bound, to tell afterwards whether one was removed while the command ran. */
  targets: { path: string; id: DirId }[];
}

/**
 * Runs `create`, which makes the missing targets, under the ledger's lock, so
 * two steps starting together never both take a directory as theirs. Marks
 * what it made and registers the targets that are directories.
 *
 * Nothing is marked, and so nothing removed, when the ledger cannot be trusted
 * or the filesystem keeps no birth time.
 */
export function claimWriteThrough(
  name: string,
  create: () => { paths: string[]; created: CreatedDir[] },
  deps: WriteThroughLedgerDeps = {},
): WriteThroughClaim {
  const { lstat = defaultLstat, now = () => new Date(), pid = process.pid, warn } = deps;
  // The step's scratch dir, which otherwise makes the base, comes later.
  ensureOwnScratchBase(baseOf(deps));
  return withLedger((ledger) => {
    if (typeof ledger !== "string") dropStaleUses(ledger, deps);
    const { paths, created } = create();
    const targets = paths.flatMap((path) => {
      const id = dirIdOf(path, deps);
      return id ? [{ path, id }] : [];
    });
    const claim = { name, registered: false, targets };
    if (typeof ledger === "string") {
      if (created.length > 0) {
        warn?.(
          `buildcage: ${ledger}, so the directories made for write_through are left in place ` +
            "after the step",
        );
      }
      return claim;
    }
    for (const { path, uid, gid } of created) {
      const made = lstat(path);
      if (made?.isDirectory() && made.birthtimeNs !== 0n) {
        ledger.dirs[path] = {
          ...idOf(made),
          uid,
          gid,
          createdBy: name,
          createdAt: now().toISOString(),
        };
      }
    }
    if (targets.length > 0) {
      ledger.uses[name] = {
        pid,
        destinations: targets.map((t) => t.path),
        startedAt: now().toISOString(),
      };
      claim.registered = true;
    }
    return claim;
  }, deps);
}

/** Without the lock, the directories are left for a later step to remove. */
export function releaseWriteThrough(name: string, deps: WriteThroughLedgerDeps = {}): void {
  const { lstat = defaultLstat, warn } = deps;
  const path = join(baseOf(deps), WRITE_THROUGH_LEDGER_NAME);
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
      `buildcage: could not update ${path} (${errorMessage(e)}), so the directories made for ` +
        "write_through are left in place for a later step to remove",
    );
  }
}

/** The targets removed or replaced on the runner since they were bound.
 *  Buildcage never removes one in use, so something else did. */
export function writeThroughDetached(
  claim: WriteThroughClaim,
  deps: Pick<WriteThroughLedgerDeps, "lstat"> = {},
): string[] {
  return claim.targets.filter(({ path, id }) => !stillThere(path, id, deps)).map((t) => t.path);
}

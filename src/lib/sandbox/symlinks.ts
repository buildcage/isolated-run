import { lstatSync, readlinkSync } from "node:fs";
import { dirname, isAbsolute, join } from "node:path";

export interface SymlinkDeps {
  /** lstat(2), or undefined when it fails, as on a missing path. */
  lstat: (path: string) => { uid: number; isSymbolicLink(): boolean } | undefined;
  /** readlink(2): the target as stored, relative or not. */
  readlink: (path: string) => string;
}

/** A symlink met on the way: `at` is spelled through the real directory it sits in. */
export interface SymlinkHop {
  at: string;
  target: string;
  uid: number;
}

export type ResolvedHostPath =
  | { real: string; links: SymlinkHop[] }
  | { loop: true; links: SymlinkHop[] };

// The kernel's MAXSYMLINKS; also stops a symlink loop.
const MAX_SYMLINK_HOPS = 40;

// Untested by design: the defaults behind this module's seam, which only hand
// node:fs what the tested caller decided.
/* v8 ignore start */
export const realSymlinkDeps: SymlinkDeps = {
  lstat: (path) => {
    try {
      return lstatSync(path);
    } catch {
      return undefined;
    }
  },
  readlink: (path) => readlinkSync(path),
};
/* v8 ignore stop */

/**
 * `path` with its symlinks resolved component by component, as the kernel
 * would, and every symlink passed through. Unlike realpath(3), components past
 * the last existing one are kept as written, so a path still to be created
 * resolves too.
 */
export function resolveHostPath(
  path: string,
  { lstat, readlink }: SymlinkDeps = realSymlinkDeps,
): ResolvedHostPath {
  const pending = path.split("/").filter((c) => c !== "" && c !== ".");
  const links: SymlinkHop[] = [];
  let current = "/";
  while (pending.length > 0) {
    const name = pending.shift()!;
    if (name === "..") {
      current = dirname(current);
      continue;
    }
    const next = join(current, name);
    const info = lstat(next);
    if (!info?.isSymbolicLink()) {
      current = next;
      continue;
    }
    const target = readlink(next);
    links.push({ at: next, target, uid: info.uid });
    if (links.length > MAX_SYMLINK_HOPS) return { loop: true, links };
    pending.unshift(...target.split("/").filter((c) => c !== "" && c !== "."));
    if (isAbsolute(target)) current = "/";
  }
  return { real: current, links };
}

/** `path` with its symlinks resolved, or as given when they loop. A dangling
 *  symlink still leads to its target, where realpath(3) would fail. */
export function realPathOf(path: string, deps: SymlinkDeps = realSymlinkDeps): string {
  const resolved = resolveHostPath(path, deps);
  return "real" in resolved ? resolved.real : path;
}

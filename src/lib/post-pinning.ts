/**
 * What the post step pins against: the base relative write-through paths
 * joined to, and the write-through when config-file set it.
 *
 * The post step cannot work either out again: by the end of the job a later
 * step's sandbox may have rewritten config-file or moved a symlink on the way
 * to the working directory, and pinning against a write-through without the
 * path a command wrote to could trust a binary planted there. GITHUB_STATE is
 * no better, since a process outside the sandbox can write that. The scratch
 * base is hidden from every sandbox, so the main step leaves the values there
 * instead.
 */
import { createHash } from "node:crypto";
import { readFileSync, rmSync, writeFileSync } from "node:fs";
import { join } from "node:path";

import { ownerToken } from "./container.ts";
import { SANDBOX_SCRATCH_BASE, ensureOwnScratchBase } from "./sandbox/scratch-dir.ts";

export interface PostPinning {
  /** The real path relative write-through paths joined to. */
  baseDir?: string;
  /** The merged write-through, when config-file set it. */
  writeThrough?: string;
}

/** One file per step of one run attempt, named from what the runner sets. */
export function postPinningPath(
  env: NodeJS.ProcessEnv,
  scratchBase: string = SANDBOX_SCRATCH_BASE,
): string | undefined {
  const owner = ownerToken(env);
  if (!owner) return undefined;
  const id = createHash("sha256").update(owner).digest("hex").slice(0, 16);
  return join(scratchBase, `pinning-${id}`);
}

/** Without the runner's state file there is no post step to read it. */
export function savePinningForPost(
  env: NodeJS.ProcessEnv,
  pinning: PostPinning,
  scratchBase: string = SANDBOX_SCRATCH_BASE,
): void {
  const path = postPinningPath(env, scratchBase);
  if (!env.GITHUB_STATE || !path) return;
  ensureOwnScratchBase(scratchBase);
  writeFileSync(path, JSON.stringify(pinning), { mode: 0o600 });
}

/**
 * The saved values, removed once read. Undefined when the main step saved
 * none, as a step that failed before reading its inputs does.
 */
export function takePinningForPost(
  env: NodeJS.ProcessEnv,
  scratchBase: string = SANDBOX_SCRATCH_BASE,
): PostPinning | undefined {
  const path = postPinningPath(env, scratchBase);
  if (!path) return undefined;
  try {
    return JSON.parse(readFileSync(path, "utf8")) as PostPinning;
  } catch (e) {
    if ((e as NodeJS.ErrnoException).code === "ENOENT") return undefined;
    throw e;
  } finally {
    rmSync(path, { force: true });
  }
}

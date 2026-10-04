/**
 * The write_through the post step pins against, when config_file set it.
 *
 * The post step cannot read config_file again: by the end of the job a later
 * step's sandbox may have rewritten it, and pinning against a write_through
 * without the path a command wrote to could trust a binary planted there.
 * GITHUB_STATE is no better, since a process outside the sandbox can write
 * that. The scratch base is hidden from every sandbox, so the main step
 * leaves the value there instead.
 */
import { createHash } from "node:crypto";
import { readFileSync, rmSync, writeFileSync } from "node:fs";
import { join } from "node:path";

import { ownerToken } from "./container.ts";
import { SANDBOX_SCRATCH_BASE, ensureOwnScratchBase } from "./sandbox/scratch-dir.ts";

/** One file per step of one run attempt, named from what the runner sets. */
export function postWriteThroughPath(
  env: NodeJS.ProcessEnv,
  scratchBase: string = SANDBOX_SCRATCH_BASE,
): string | undefined {
  const owner = ownerToken(env);
  if (!owner) return undefined;
  const id = createHash("sha256").update(owner).digest("hex").slice(0, 16);
  return join(scratchBase, `write-through-${id}`);
}

/** Without the runner's state file there is no post step to read it. */
export function saveWriteThroughForPost(
  env: NodeJS.ProcessEnv,
  writeThroughInput: string,
  scratchBase: string = SANDBOX_SCRATCH_BASE,
): void {
  const path = postWriteThroughPath(env, scratchBase);
  if (!env.GITHUB_STATE || !path) return;
  ensureOwnScratchBase(scratchBase);
  writeFileSync(path, writeThroughInput, { mode: 0o600 });
}

/**
 * The saved value, removed once read. Undefined when the main step saved
 * none: no config_file, or a step that failed before its command ran.
 */
export function takeWriteThroughForPost(
  env: NodeJS.ProcessEnv,
  scratchBase: string = SANDBOX_SCRATCH_BASE,
): string | undefined {
  const path = postWriteThroughPath(env, scratchBase);
  if (!path) return undefined;
  try {
    return readFileSync(path, "utf8");
  } catch (e) {
    if ((e as NodeJS.ErrnoException).code === "ENOENT") return undefined;
    throw e;
  } finally {
    rmSync(path, { force: true });
  }
}

import { join } from "node:path";

/** Where the tracer writes, under the scratch base so the post step can read
 *  them after the per-step scratch dir is gone. The suffix matches the
 *  container's own, which is already collision-free (see generateContainerName). */
export interface FilesystemAuditPaths {
  outPath: string;
  pidFilePath: string;
  /** The recording with buildcage's own records stripped, as uploaded. */
  stepPath: string;
}

export function filesystemAuditPaths(
  containerName: string,
  scratchBase: string,
): FilesystemAuditPaths {
  const suffix = containerName.split("-").at(-1);
  return {
    outPath: join(scratchBase, `filesystem-audit-${suffix}.jsonl`),
    pidFilePath: join(scratchBase, `filesystem-audit-${suffix}.pid`),
    stepPath: join(scratchBase, `filesystem-audit-${suffix}.step.jsonl`),
  };
}

/** The pid the tracer's pidfile names, NaN for one that holds no number. */
export function readPid(readFile: (path: string) => string, pidFilePath: string): number {
  return Number(readFile(pidFilePath).trim());
}

/**
 * Whether pid is still the tracer: a pidfile that outlived it may name a
 * reused pid. Undefined where /proc does not say, for a pid that is gone or
 * one hidepid hides. comm is truncated to 15 bytes.
 */
export function isTracer(pid: number, readFile: (path: string) => string): boolean | undefined {
  try {
    return readFile(`/proc/${pid}/comm`).startsWith("filesystem-audi");
  } catch {
    return undefined;
  }
}

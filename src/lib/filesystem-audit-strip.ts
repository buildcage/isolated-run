/**
 * Removes buildcage's own sandbox machinery from a recording, so both the
 * summary and the uploaded artifact show only the step's accesses.
 *
 * The sandbox init (the first recorded process) runs buildcage's wrappers
 * (setpriv, env-loader.sh, env), forking helper subshells along the way, and
 * finally execs the step's shell, run-script.sh, from the scratch base. That
 * exec is the boundary: the init's earlier records and any process forked
 * before it are machinery; what comes after is the step. Accesses under the
 * scratch base are buildcage's own files. The step's shell is relabeled bash.
 *
 * The boundary and the shell are found by pid and exec path, never by command
 * name, so a step command named setpriv or run-script.sh (run from the
 * workspace, forked after the boundary, exec'd from a non-scratch path) is left
 * alone and keeps its own name.
 */

const SHELL_COMM = "run-script.sh"; // buildcage's step shell (sandbox/oci-files.ts)
const SHELL_LABEL = "bash";

interface Record_ {
  pid?: number;
  kind?: string;
  comm?: string;
  path?: string;
}

export function stripSandboxMachinery(jsonl: string, scratchBase: string): string {
  const under = (p: unknown): boolean =>
    typeof p === "string" && (p === scratchBase || p.startsWith(`${scratchBase}/`));
  const leaf = (p: string): string => p.slice(p.lastIndexOf("/") + 1);

  const lines = jsonl.split("\n");
  const recs = lines.map((line) => {
    try {
      return JSON.parse(line) as Record_ & Record<string, unknown>;
    } catch {
      return undefined; // a line the tracer left truncated; kept verbatim
    }
  });

  const initPid = recs.find((r) => r !== undefined)?.pid;
  const firstSeen = new Map<number, number>();
  const stepShellPids = new Set<number>(); // execs its own run-script.sh, not buildcage's
  let boundary = -1;
  recs.forEach((r, i) => {
    if (!r || r.pid === undefined) return;
    if (!firstSeen.has(r.pid)) firstSeen.set(r.pid, i);
    if (r.kind === "exec" && typeof r.path === "string") {
      if (r.pid === initPid && under(r.path)) boundary = i;
      if (!under(r.path) && leaf(r.path) === SHELL_COMM) stepShellPids.add(r.pid);
    }
  });

  const out: string[] = [];
  recs.forEach((r, i) => {
    if (r === undefined) {
      if (lines[i] !== "") out.push(lines[i]);
      return;
    }
    if (under(r.path)) return; // a buildcage scratch file
    if (boundary >= 0 && r.pid !== undefined) {
      // The init's own wrapper phase, or a helper it forked before the shell.
      const machinery = r.pid === initPid ? i <= boundary : firstSeen.get(r.pid)! <= boundary;
      if (machinery) return;
    }
    if (
      boundary >= 0 &&
      r.comm === SHELL_COMM &&
      r.pid !== undefined &&
      !stepShellPids.has(r.pid)
    ) {
      out.push(JSON.stringify({ ...r, comm: SHELL_LABEL })); // the step's shell
      return;
    }
    out.push(lines[i]); // a step process, verbatim
  });
  return out.join("\n");
}

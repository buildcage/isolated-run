/**
 * Removes buildcage's own sandbox machinery from a recording, so both the
 * summary and the uploaded artifact show only the step's accesses.
 *
 * buildcage runs the step under setpriv and buildcage-init; buildcage-init stays
 * alive as the sandbox init (forwarding signals, reaping, propagating the exit
 * status) and forks the step's shell, which execs run-script.sh from the
 * scratch base. The sandbox cgroup holds nothing but the init and the step, so
 * from the shell's exec on every record is the step's except those of the init,
 * the parent that exec names. Everything before that exec, the shell's own
 * reads of run-script.sh, and the init's records are machinery. Any other
 * record naming the scratch base is the step's: a prefix match would let a
 * name like <base>/../../home/... hide an access. The step's shell is relabeled
 * bash.
 *
 * The shell is found by the exec of run-script.sh under the scratch base, never
 * by command name, so a step command named setpriv or run-script.sh (run from
 * the workspace, a different pid, exec'd from a non-scratch path) is left alone
 * and keeps its own name. Only the first such exec counts: the step can see and
 * run its own run-script.sh, and a later exec of it must not move the anchor;
 * such an exec is kept, under its own name, as the step's.
 *
 * Nothing the step does with its process tree, such as CLONE_PARENT, setsid or
 * being reparented to the init, changes which records are kept. It assumes a
 * complete recording: without the shell's exec the step is anchored on a later
 * one, or not at all, and then every record is kept. A recording with gaps is
 * marked incomplete in the summary.
 */

const SHELL_COMM = "run-script.sh"; // buildcage's step shell (sandbox/oci-files.ts)
const SHELL_LABEL = "bash";
// How the shell reads its script. Anything else it does to the script, such
// as an open that writes or truncates, is kept.
const readsOnly = (r: { kind?: string; access?: string }): boolean =>
  r.kind === "read" || ((r.kind === "open" || r.kind === "mmap") && r.access === "r");

interface Record_ {
  pid?: number;
  ppid?: number;
  kind?: string;
  comm?: string;
  path?: string;
  access?: string;
  failed?: boolean;
}

/**
 * Strips a recording in two passes over its lines: `observe` each in order,
 * then `filter` each in the same order, which gives the line to keep (with the
 * record it now holds) or undefined to drop it. A line is passed with its
 * parsed record, undefined when it does not parse.
 */
export function createStripper(scratchBase: string): {
  observe: (r: unknown) => void;
  filter: (line: string, r: unknown) => { line: string; record: unknown } | undefined;
} {
  const under = (p: unknown): boolean =>
    typeof p === "string" && (p === scratchBase || p.startsWith(`${scratchBase}/`));
  const leaf = (p: string): string => p.slice(p.lastIndexOf("/") + 1);
  const asRecord = (r: unknown): (Record_ & Record<string, unknown>) | undefined =>
    typeof r === "object" && r !== null ? (r as Record_ & Record<string, unknown>) : undefined;

  const ownShellPids = new Set<number>(); // runs a run-script.sh as other than buildcage's shell
  let shell: number | undefined; // the pid that first execs buildcage's run-script.sh
  let script: string | undefined; // that run-script.sh
  let init: number | undefined; // the shell's parent at that exec
  let boundary = -1;
  let observed = 0;
  let filtered = 0;

  const observe = (rec: unknown): void => {
    const i = observed++;
    const r = asRecord(rec);
    if (!r || r.pid === undefined) return;
    if (r.kind === "exec" && typeof r.path === "string" && leaf(r.path) === SHELL_COMM) {
      if (!under(r.path)) ownShellPids.add(r.pid);
      else if (shell === undefined) [shell, script, boundary, init] = [r.pid, r.path, i, r.ppid];
      else if (r.pid !== shell) ownShellPids.add(r.pid);
    }
  };

  const filter = (line: string, rec: unknown): { line: string; record: unknown } | undefined => {
    const i = filtered++;
    const r = asRecord(rec);
    if (r === undefined) return line === "" ? undefined : { line, record: rec };
    // A child of an ownShellPids process inherits its run-script.sh name, so it keeps it too.
    if (
      r.kind === "fork" &&
      r.pid !== undefined &&
      r.ppid !== undefined &&
      ownShellPids.has(r.ppid)
    )
      ownShellPids.add(r.pid);
    // setpriv, the init, or the shell before and at its exec; after it, the
    // init and the shell reading its script.
    const readsScript = r.pid === shell && r.path === script && !r.failed && readsOnly(r);
    if (
      shell !== undefined &&
      r.pid !== undefined &&
      (i <= boundary || r.pid === init || readsScript)
    )
      return undefined;
    if (
      shell !== undefined &&
      r.comm === SHELL_COMM &&
      r.pid !== undefined &&
      !ownShellPids.has(r.pid)
    ) {
      const record = { ...r, comm: SHELL_LABEL }; // the step's shell
      return { line: JSON.stringify(record), record };
    }
    return { line, record: rec }; // a step process, verbatim
  };
  return { observe, filter };
}

/** A recording held as a string, stripped. */
export function stripSandboxMachinery(jsonl: string, scratchBase: string): string {
  const lines = jsonl.split("\n");
  const parsed = lines.map((line) => {
    try {
      return JSON.parse(line) as unknown;
    } catch {
      return undefined; // a line the tracer left truncated; kept verbatim
    }
  });
  const stripper = createStripper(scratchBase);
  for (const r of parsed) stripper.observe(r);
  const out: string[] = [];
  lines.forEach((line, i) => {
    const kept = stripper.filter(line, parsed[i]);
    if (kept) out.push(kept.line);
  });
  return out.join("\n");
}

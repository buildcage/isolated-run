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

interface Record_ {
  pid?: number;
  ppid?: number;
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

  const ownShellPids = new Set<number>(); // runs a run-script.sh as other than buildcage's shell
  let shell: number | undefined; // the pid that first execs buildcage's run-script.sh
  let script: string | undefined; // that run-script.sh
  let init: number | undefined; // the shell's parent at that exec
  let boundary = -1;
  recs.forEach((r, i) => {
    if (!r || r.pid === undefined) return;
    if (r.kind === "exec" && typeof r.path === "string" && leaf(r.path) === SHELL_COMM) {
      if (!under(r.path)) ownShellPids.add(r.pid);
      else if (shell === undefined) [shell, script, boundary, init] = [r.pid, r.path, i, r.ppid];
      else if (r.pid !== shell) ownShellPids.add(r.pid);
    }
  });

  const out: string[] = [];
  recs.forEach((r, i) => {
    if (r === undefined) {
      if (lines[i] !== "") out.push(lines[i]);
      return;
    }
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
    const readsScript = r.pid === shell && r.path === script && r.kind !== "exec";
    if (
      shell !== undefined &&
      r.pid !== undefined &&
      (i <= boundary || r.pid === init || readsScript)
    )
      return;
    if (
      shell !== undefined &&
      r.comm === SHELL_COMM &&
      r.pid !== undefined &&
      !ownShellPids.has(r.pid)
    ) {
      out.push(JSON.stringify({ ...r, comm: SHELL_LABEL })); // the step's shell
      return;
    }
    out.push(lines[i]); // a step process, verbatim
  });
  return out.join("\n");
}

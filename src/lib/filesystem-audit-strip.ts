/**
 * Removes buildcage's own sandbox machinery from a recording, so both the
 * summary and the uploaded artifact show only the step's accesses.
 *
 * buildcage runs the step under setpriv and env-loader.sh; env-loader.sh stays
 * alive as the sandbox init (forwarding signals, reaping, propagating the exit
 * status) and forks the step's shell, which execs run-script.sh from the
 * scratch base. So the step is that shell and its descendants, from the
 * run-script.sh exec onward; the init, setpriv, the shell's earlier exec
 * phases, and every access under the scratch base are machinery. The step's
 * shell is relabeled bash.
 *
 * The shell is found by the exec of run-script.sh under the scratch base, never
 * by command name, so a step command named setpriv or run-script.sh (run from
 * the workspace, a different pid, exec'd from a non-scratch path) is left alone
 * and keeps its own name.
 *
 * It assumes a complete recording: a missing shell exec leaves the step
 * unanchored (machinery stays in), and a process whose ancestor emitted no
 * record cannot be walked back to the shell. Both need a gap in the stream and
 * only skew an experimental report.
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

  const parent = new Map<number, number>();
  const ownShellPids = new Set<number>(); // execs its own run-script.sh, not buildcage's
  let shell: number | undefined; // the pid that execs buildcage's run-script.sh
  let boundary = -1;
  recs.forEach((r, i) => {
    if (!r || r.pid === undefined) return;
    if (!parent.has(r.pid) && r.ppid !== undefined) parent.set(r.pid, r.ppid);
    if (r.kind === "exec" && typeof r.path === "string" && leaf(r.path) === SHELL_COMM) {
      if (under(r.path)) [shell, boundary] = [r.pid, i];
      else ownShellPids.add(r.pid);
    }
  });

  // A pid belongs to the step if it is the shell or descends from it. The seen
  // set stops the walk if the recorded parents form a cycle.
  const inStep = (pid: number): boolean => {
    const seen = new Set<number>();
    for (let p: number | undefined = pid; p !== undefined && !seen.has(p); p = parent.get(p)) {
      if (p === shell) return true;
      seen.add(p);
    }
    return false;
  };

  const out: string[] = [];
  recs.forEach((r, i) => {
    if (r === undefined) {
      if (lines[i] !== "") out.push(lines[i]);
      return;
    }
    if (under(r.path)) return; // a buildcage scratch file
    if (shell !== undefined && r.pid !== undefined) {
      const stepRecord = r.pid === shell ? i >= boundary : inStep(r.pid);
      if (!stepRecord) return; // the init, setpriv, or the shell's pre-exec phase
    }
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

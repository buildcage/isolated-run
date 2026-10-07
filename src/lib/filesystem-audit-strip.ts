/**
 * Removes buildcage's own sandbox machinery from a recording, so both the
 * summary and the uploaded artifact show only the step's accesses.
 *
 * buildcage runs the step under setpriv and env-loader.sh; env-loader.sh stays
 * alive as the sandbox init (forwarding signals, reaping, propagating the exit
 * status) and forks the step's shell, which execs run-script.sh from the
 * scratch base. The tracer's first record is the init's setpriv exec, and the
 * sandbox cgroup holds nothing but the init and the step, so from the shell's
 * exec on every record is the step's except the init's own. Everything before
 * that exec, every access under the scratch base, and the init's records are
 * machinery. The step's shell is relabeled bash.
 *
 * The shell is found by the exec of run-script.sh under the scratch base, never
 * by command name, so a step command named setpriv or run-script.sh (run from
 * the workspace, a different pid, exec'd from a non-scratch path) is left alone
 * and keeps its own name. Only the first such exec counts: the step can see and
 * run its own run-script.sh, and a later exec of it must not move the anchor.
 *
 * Nothing the step does with its process tree, such as CLONE_PARENT, setsid or
 * being reparented to the init, changes which records are kept.
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

  const ownShellPids = new Set<number>(); // execs its own run-script.sh, not buildcage's
  let init: number | undefined; // the first record's pid: the tracer starts at its setpriv exec
  let shell: number | undefined; // the pid that first execs buildcage's run-script.sh
  let boundary = -1;
  recs.forEach((r, i) => {
    if (!r || r.pid === undefined) return;
    init ??= r.pid;
    if (r.kind === "exec" && typeof r.path === "string" && leaf(r.path) === SHELL_COMM) {
      if (!under(r.path)) ownShellPids.add(r.pid);
      else if (shell === undefined) [shell, boundary] = [r.pid, i];
    }
  });

  const out: string[] = [];
  recs.forEach((r, i) => {
    if (r === undefined) {
      if (lines[i] !== "") out.push(lines[i]);
      return;
    }
    if (under(r.path)) return; // a buildcage scratch file
    // setpriv, the init, or the shell before its exec; after it, the init.
    if (shell !== undefined && r.pid !== undefined && (i < boundary || r.pid === init)) return;
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

/**
 * Removes buildcage's own sandbox machinery from a recording, so both the
 * summary and the uploaded artifact show only the step's accesses.
 *
 * The sandbox init (the first recorded process) execs buildcage's wrappers
 * under one pid (setpriv, env-loader.sh, env) and finally the step's shell,
 * run-script.sh, from the scratch base; everything that pid does up to that
 * last exec is machinery. Every access under the scratch base is a buildcage
 * file. What remains is the step: its shell, relabeled bash, and its commands.
 *
 * Identification is by pid and exec path, never command name, so a step command
 * that happens to be named setpriv or run-script.sh (run from the workspace, a
 * different pid) is left alone and keeps its own name.
 */

const SHELL_LABEL = "bash";

interface Record_ {
  pid?: number;
  kind?: string;
  path?: string;
}

export function stripSandboxMachinery(jsonl: string, scratchBase: string): string {
  const under = (p: unknown): boolean =>
    typeof p === "string" && (p === scratchBase || p.startsWith(`${scratchBase}/`));
  const lines = jsonl.split("\n");
  const recs = lines.map((line) => {
    try {
      return JSON.parse(line) as Record_ & Record<string, unknown>;
    } catch {
      return undefined; // a line the tracer left truncated; kept verbatim
    }
  });

  const initPid = recs.find((r) => r !== undefined)?.pid;
  // The init pid's last exec of a script under the scratch base is the step's
  // shell; its earlier records are the wrapper chain.
  let shellExec = -1;
  if (initPid !== undefined)
    recs.forEach((r, i) => {
      if (r?.pid === initPid && r.kind === "exec" && under(r.path)) shellExec = i;
    });

  const out: string[] = [];
  recs.forEach((r, i) => {
    if (r === undefined) {
      if (lines[i] !== "") out.push(lines[i]);
      return;
    }
    if (under(r.path)) return; // a buildcage scratch file
    if (shellExec >= 0 && r.pid === initPid) {
      if (i <= shellExec) return; // the wrapper chain, before the step's shell
      out.push(JSON.stringify({ ...r, comm: SHELL_LABEL })); // the step's shell
      return;
    }
    out.push(lines[i]); // a step process, verbatim
  });
  return out.join("\n");
}

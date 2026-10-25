import { formatElapsedVariable } from "#core/lib/report/elapsed-time.ts";

import { BIT, ORDER } from "./record.ts";

// What the accesses folded into one line did: the actions that succeeded,
// failed and were refused, as bits, and the first and last access in epoch
// milliseconds with the earliest one's place in the recording, which orders
// the rows.
export interface Agg {
  ok: number;
  failed: number;
  perm: number;
  first: number;
  last: number;
  seq: number;
  /** The commands that made the accesses, each with the earliest one's place
   *  in the recording, where the line keeps them. */
  cmds?: Map<string, number>;
}

export const newAgg = (): Agg => ({
  ok: 0,
  failed: 0,
  perm: 0,
  first: Infinity,
  last: -Infinity,
  seq: Infinity,
});

export const flagBits = (a: Agg): number => a.ok | a.failed;

export function mergeAgg(dst: Agg, src: Agg): void {
  dst.ok |= src.ok;
  dst.failed |= src.failed;
  dst.perm |= src.perm;
  dst.first = Math.min(dst.first, src.first);
  dst.last = Math.max(dst.last, src.last);
  dst.seq = Math.min(dst.seq, src.seq);
  for (const [cmd, seq] of src.cmds ?? []) addCmd(dst, cmd, seq);
}

function addCmd(a: Agg, cmd: string, seq: number): void {
  const had = a.cmds?.get(cmd);
  (a.cmds ??= new Map()).set(cmd, had === undefined ? seq : Math.min(had, seq));
}

// One access, as a line records it. bit is 0 where it prints nothing, as an
// access the rules took does in the proposed rules, and so does not count
// toward a directory's fold.
export interface Access {
  comm: string;
  path: string;
  bit: number;
  failed: boolean;
  perm: boolean;
  t: number;
  seq: number;
  /** The command that made it, for a line that keeps its commands. */
  cmd?: string;
}

export function apply(a: Agg, x: Access): void {
  if (!x.failed) a.ok |= x.bit;
  else {
    a.failed |= x.bit;
    if (x.perm) a.perm |= x.bit;
  }
  if (x.cmd !== undefined) addCmd(a, x.cmd, x.seq);
  if (Number.isNaN(x.t)) return;
  a.first = Math.min(a.first, x.t);
  a.last = Math.max(a.last, x.t);
  a.seq = Math.min(a.seq, x.seq);
}

export function fmtSpan(a: Agg, originMs: number): string {
  if (a.first === Infinity) return "";
  const first = formatElapsedVariable((a.first - originMs) / 1000);
  const last = formatElapsedVariable((a.last - originMs) / 1000);
  return first === last ? first : `${first}-${last}`;
}

// A refusal shows even beside a success, as one in a folded directory would
// otherwise vanish into the reads of its siblings.
export function fmtFlags(a: Agg): string {
  let out = "";
  for (const c of ORDER) if (a.ok & BIT[c]) out += c;
  for (const c of ORDER) {
    if (a.perm & BIT[c]) out += `${c.toLowerCase()}!`;
    else if (a.failed & ~a.ok & BIT[c]) out += c.toLowerCase();
  }
  return out;
}

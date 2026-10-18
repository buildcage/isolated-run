import { apply, flagBits, mergeAgg, newAgg, type Access, type Agg } from "./agg.ts";
import { components, isRunnerFile, MEMFD, MEMFDS, spell, unfoldable } from "./paths.ts";
import { BIT } from "./record.ts";

/**
 * The children of a kept directory, or the lines of a ".." prefix or of a
 * command's memfds, at which they fold too once a table has outgrown `loose`.
 */
const LOOSE_FANOUT = 5;

/** The line that stands for everything at and below `path`. */
const starred = (path: string): string => (path === "/" ? "/**" : `${path}/**`);

// A kept directory's children that a loose fold takes in.
const looseKids = (node: Node): number => {
  let n = 0;
  for (const kid of node.kids?.values() ?? []) if (!kid.kept) n++;
  return n;
};

/**
 * The line a ".." path or a memfd folds into once a table is loosened: the
 * path up to its first "..", or all of a command's memfds. A runner file and
 * a program run never fold.
 */
function climbGroup(path: string, parts = components(path)): string {
  if (path.startsWith(MEMFD)) return MEMFDS;
  if (isRunnerFile(path)) return path;
  return starred(spell(parts.slice(0, parts.indexOf("..") + 1)));
}

// Whether a line shows a program run, which never folds.
const ran = (a: Agg): boolean => ((a.ok | a.failed) & BIT.X) !== 0;

/**
 * Why a part was not printed: it would pass the Job Summary's size limit, or
 * it held too many paths to fold.
 */
export type CutCause = "size" | "paths";

// Rows are keyed per (command, path). NUL cannot occur in a command name, so
// the first one ends it; a marked path may hold another.
const SEP = "\0";
export const keyOf = (comm: string, path: string): string => `${comm}${SEP}${path}`;
export const commOf = (key: string): string => key.slice(0, key.indexOf(SEP));
export const pathOf = (key: string): string => key.slice(key.indexOf(SEP) + 1);

// A path in a tree keyed by component, so no ancestor's whole path is ever
// spelled out: doing that at every level costs the square of a path's depth.
export interface Node {
  kids?: Map<string, Node>;
  /** The accesses of this path itself. */
  own?: Agg;
  /** Once folded, everything at and below it, shown as "path/**". */
  folded?: Agg;
  kept?: boolean;
  /** What its line adds to the size estimate, while it is counted. */
  bytes: number;
}

/**
 * The nodes whose own line only walks to lines below it: every flag it has,
 * one of the lines under it in the same tree has too.
 */
export function walkedNodes(top: Map<string, Node>): Set<Node> {
  const walked = new Set<Node>();
  const below = new Map<Node, number>();
  // Post-order without recursion, as a path can be thousands of components deep.
  const stack: [Node, boolean][] = [...top.values()].map((n) => [n, false]);
  while (stack.length > 0) {
    const [node, done] = stack.pop()!;
    if (!done) {
      stack.push([node, true]);
      for (const kid of node.kids?.values() ?? []) stack.push([kid, false]);
      continue;
    }
    // A kept directory folded loose shows what it folded on its "dir/**" line.
    let bits = node.folded ? flagBits(node.folded) : 0;
    for (const kid of node.kids?.values() ?? []) {
      bits |= below.get(kid)!;
      if (kid.own) bits |= flagBits(kid.own);
      if (kid.folded) bits |= flagBits(kid.folded);
    }
    below.set(node, bits);
    // A refused open of the directory is not how anything below it was reached.
    if (
      node.own &&
      !node.own.perm &&
      (node.kids?.size || node.folded) &&
      (flagBits(node.own) & ~bits) === 0
    )
      walked.add(node);
  }
  return walked;
}

// Every line of a tree that prints, with its path, but walked directories.
// Each node links to its parent's entry, so only a printed line's path is
// ever spelled out.
function* treeLines(top: Map<string, Node>, fanout: number): Generator<[string, Agg]> {
  interface Entry {
    node: Node;
    part: string;
    up?: Entry;
  }
  const walked = walkedNodes(top);
  const pathTo = (e: Entry): string => {
    const parts: string[] = [];
    for (let at: Entry | undefined = e; at; at = at.up) parts.push(at.part);
    return spell(parts.reverse());
  };
  // Reversed onto the stack, so lines come out in the order they were added.
  const stack: Entry[] = [...top].reverse().map(([part, node]) => ({ node, part }));
  while (stack.length > 0) {
    const e = stack.pop()!;
    const { folded, own, kids, kept } = e.node;
    if (folded && flagBits(folded)) yield [starred(pathTo(e)), folded];
    const ownLine = own && flagBits(own) && !walked.has(e.node) ? own : undefined;
    // Its own line counts toward a fold too. Whether that line prints can
    // change until every access is in, so this fold waits for them.
    if (kids?.size && !kept && kids.size + (ownLine ? 1 : 0) >= fanout) {
      yield [starred(pathTo(e)), treeAgg(e.node)];
      continue;
    }
    if (ownLine) yield [pathTo(e), ownLine];
    for (const [part, node] of [...(kids ?? [])].reverse()) stack.push({ node, part, up: e });
  }
}

function forEachInSubtree(node: Node, visit: (n: Node) => void): void {
  const stack = [node];
  while (stack.length > 0) {
    const n = stack.pop()!;
    visit(n);
    for (const kid of n.kids?.values() ?? []) stack.push(kid);
  }
}

// The accesses of a node and everything below it, as one "node/**" line.
function treeAgg(node: Node): Agg {
  const agg = newAgg();
  forEachInSubtree(node, (n) => {
    if (n.own) mergeAgg(agg, n.own);
    if (n.folded) mergeAgg(agg, n.folded);
  });
  return agg;
}

interface LinesOptions {
  fanout: number;
  /** The directories never folded, as components. */
  keep: string[][];
  limit: number;
  /** The size past which it folds what it otherwise keeps whole; at most `limit`. */
  loose: number;
  nodes: number;
  /** The fewest bytes the line of a path prints in. */
  rowBytes: (path: string, comm: string) => number;
}

/**
 * The lines of one table as the accesses arrive, a directory folding into
 * "dir/**" as soon as it has `fanout` children, so a tree of any size costs
 * no more than its folded lines. Kept directories, ".." paths and memfds
 * never fold, until the lines no fold can take away outgrow `loose` bytes:
 * then each folds too once it has LOOSE_FANOUT, a kept directory keeping the
 * kept ones below it, so the table grows coarser rather than vanishing. Past
 * `limit` even so, more than the Job Summary could ever print, it keeps what
 * it holds but takes no new line, and says it was cut. Stops, dropping what it
 * holds, once it holds more than `nodes` paths.
 */
export class Lines {
  private trees = new Map<string, Map<string, Node>>();
  // The unfoldable paths, each a line of its own.
  private climbing = new Map<string, Agg>();
  private bytes = 0;
  private nodes = 0;
  /** Whether the table has outgrown `loose` once, and folds what it kept whole. */
  private loose = false;
  private loosening = false;
  /** Once loose, the lines of each climbing group not yet folded. */
  private members = new Map<string, string[]>();
  /** Whether a new line was turned away while full. */
  private dropped = false;
  /** Whether a line was left out for want of room. */
  private truncated = false;
  /** Why it gave up, once it has. */
  stopped: CutCause | undefined;

  /**
   * Whether it is past `limit`, loose by then: it takes no new line, but one
   * that folds into a line it has.
   */
  private get full(): boolean {
    return this.bytes > this.opts.limit;
  }

  /** Why its lines are not all there: it gave up, or left some out. */
  get cut(): CutCause | undefined {
    return this.stopped ?? (this.truncated ? "size" : undefined);
  }

  private readonly opts: LinesOptions;

  constructor(opts: LinesOptions) {
    this.opts = opts;
  }

  /** `parts` is x.path's components, for a caller that already has them. */
  add(x: Access, parts = components(x.path)): void {
    if (this.stopped || !x.bit) return;
    // A program run is never folded away, nor makes its directory fold.
    if (unfoldable(parts, x.path) || x.bit === BIT.X) {
      // A path's own line, such as a program run's, takes its accesses first.
      let key = keyOf(x.comm, x.path);
      let a = this.climbing.get(key);
      if (!a && this.loose && x.bit !== BIT.X) {
        const folded = keyOf(x.comm, climbGroup(x.path, parts));
        a = this.climbing.get(folded);
        if (a) key = folded;
        else if (folded !== key) {
          // A new line in a group about to fold goes straight into the fold. A
          // line run since it joined the group no longer counts toward it.
          const keys = (this.members.get(folded) ?? []).filter((k) => !ran(this.climbing.get(k)!));
          if (keys.length + 1 >= LOOSE_FANOUT) {
            this.gather(folded, keys);
            a = this.climbing.get((key = folded));
          } else if (!this.full) this.members.set(folded, [...keys, key]);
        }
      }
      if (a) return apply(a, x);
      if (this.full) return void (this.dropped = true);
      // Applied before it counts, as counting may fold it into another line.
      this.climbing.set(key, (a = newAgg()));
      apply(a, x);
      this.count(this.opts.rowBytes(pathOf(key), x.comm));
      return;
    }
    let kids: Map<string, Node> | undefined = this.trees.get(x.comm);
    if (!kids) this.trees.set(x.comm, (kids = new Map()));
    let parent: Node | undefined;
    // Whether every directory above the node is kept, so no fold can ever
    // take its line away, and the estimate may count it.
    let settled = true;
    let parentSettled = true;
    for (let i = 0; i < parts.length; i++) {
      let node: Node | undefined = kids.get(parts[i]);
      if (!node) {
        if (this.full && !this.foldsInto(parent, kids, parts, i)) return void (this.dropped = true);
        node = { bytes: 0, kept: this.isKept(parts, i + 1) || undefined };
        kids.set(parts[i], node);
        this.nodes++;
        if (parent) {
          // No longer a leaf, its own line may be only the walk to this one.
          // A kept directory folded loose keeps the bytes of its "dir/**" line.
          if (!parent.folded) this.setBytes(parent, 0);
          if (!parent.kept && kids.size >= this.opts.fanout) {
            this.fold(parent);
            return this.addFolded(parent, parts.slice(0, i), x, parentSettled);
          }
          if (parent.kept && !node.kept && this.loose && looseKids(parent) >= LOOSE_FANOUT) {
            this.foldLoose(parent, parts.slice(0, i), x.comm);
            return this.addFolded(parent, parts.slice(0, i), x, parentSettled);
          }
        }
        // Only once a fold had its chance to bring the count back down.
        if (this.nodes > this.opts.nodes) return this.stop("paths");
      }
      // A kept directory folded loose still leads to the kept ones below it.
      if (
        node.folded &&
        !(
          node.kept &&
          (i === parts.length - 1 || node.kids?.has(parts[i + 1]) || this.isKept(parts, i + 2))
        )
      )
        return this.addFolded(node, parts.slice(0, i + 1), x, settled);
      if (i === parts.length - 1) {
        node.own ??= newAgg();
        const shown = flagBits(node.own) !== 0;
        apply(node.own, x);
        // A kept directory folded loose has its "dir/**" line counted already.
        if (settled && !shown && flagBits(node.own) && !node.kids?.size)
          this.setBytes(node, node.bytes + this.opts.rowBytes(x.path, x.comm));
        return;
      }
      node.kids ??= new Map();
      kids = node.kids;
      parent = node;
      parentSettled = settled;
      settled &&= Boolean(node.kept);
    }
  }

  // Whether a new child `parts[i]` makes `parent` fold, so taking it shrinks
  // the table.
  private foldsInto(
    parent: Node | undefined,
    kids: Map<string, Node>,
    parts: string[],
    i: number,
  ): boolean {
    if (!parent) return false;
    if (!parent.kept) return kids.size + 1 >= this.opts.fanout;
    return !this.isKept(parts, i + 1) && looseKids(parent) + 1 >= LOOSE_FANOUT;
  }

  // A kept directory's ancestors are kept too, or folding one would hide it.
  private isKept(parts: string[], depth: number): boolean {
    return this.opts.keep.some(
      (k) => k.length >= depth && k.slice(0, depth).every((part, i) => part === parts[i]),
    );
  }

  // Folds the node's own accesses and everything below it into "node/**".
  private fold(node: Node): void {
    const agg = newAgg();
    forEachInSubtree(node, (n) => {
      if (n.own) mergeAgg(agg, n.own);
      if (n.folded) mergeAgg(agg, n.folded);
      this.setBytes(n, 0);
      if (n !== node) this.nodes--;
    });
    node.folded = agg;
    node.own = undefined;
    node.kids = undefined;
  }

  // Folds a kept directory's children but the kept ones into "node/**".
  private foldLoose(node: Node, parts: string[], comm: string): void {
    const agg = newAgg();
    for (const [part, kid] of node.kids!) {
      if (kid.kept) continue;
      forEachInSubtree(kid, (n) => {
        if (n.own) mergeAgg(agg, n.own);
        if (n.folded) mergeAgg(agg, n.folded);
        this.setBytes(n, 0);
        this.nodes--;
      });
      node.kids!.delete(part);
    }
    node.folded = agg;
    this.setBytes(node, this.opts.rowBytes(starred(spell(parts)), comm));
  }

  private addFolded(node: Node, parts: string[], x: Access, settled: boolean): void {
    apply(node.folded!, x);
    if (settled && flagBits(node.folded!) && !node.bytes)
      this.setBytes(node, this.opts.rowBytes(starred(spell(parts)), x.comm));
  }

  // Folds a climbing group's lines, none of them a program run, into its one
  // line.
  private gather(group: string, keys: string[]): void {
    const comm = commOf(group);
    const had = this.climbing.get(group);
    const agg = had ?? newAgg();
    for (const key of keys) {
      mergeAgg(agg, this.climbing.get(key)!);
      this.climbing.delete(key);
      this.count(-this.opts.rowBytes(pathOf(key), comm));
    }
    this.members.delete(group);
    if (had) return;
    this.climbing.set(group, agg);
    this.count(this.opts.rowBytes(pathOf(group), comm));
  }

  // Folds what the table kept whole: each kept directory's other children,
  // and each group of ".." paths or memfds, once there are LOOSE_FANOUT.
  private loosen(): void {
    this.loose = true;
    this.loosening = true;
    for (const [comm, top] of this.trees) {
      const stack: [Node, string[]][] = [...top].map(([part, node]) => [node, [part]]);
      while (stack.length > 0) {
        const [node, parts] = stack.pop()!;
        if (!node.kept) continue;
        if (looseKids(node) >= LOOSE_FANOUT) this.foldLoose(node, parts, comm);
        for (const [part, kid] of node.kids ?? []) stack.push([kid, [...parts, part]]);
      }
    }
    const groups = new Map<string, string[]>();
    for (const [key, a] of this.climbing) {
      const group = ran(a) ? undefined : climbGroup(pathOf(key));
      const folded = group && keyOf(commOf(key), group);
      if (!folded || folded === key) continue;
      const keys = groups.get(folded);
      if (keys) keys.push(key);
      else groups.set(folded, [key]);
    }
    for (const [group, keys] of groups) {
      if (keys.length >= LOOSE_FANOUT) this.gather(group, keys);
      else this.members.set(group, keys);
    }
    this.loosening = false;
  }

  // The node's bytes are set first, so a fold that counting sets off takes
  // them back out.
  private setBytes(node: Node, bytes: number): void {
    const delta = bytes - node.bytes;
    node.bytes = bytes;
    this.count(delta);
  }

  private count(bytes: number): void {
    this.bytes += bytes;
    if (this.loosening) return;
    if (!this.loose && this.bytes > this.opts.loose) this.loosen();
  }

  private stop(cause: CutCause): void {
    this.stopped = cause;
    this.trees = new Map();
    this.climbing = new Map();
  }

  /**
   * Every line with its command, up to `limit`, or undefined once it stopped.
   * Lines past `loose` are loosened first.
   */
  finish(): { comm: string; path: string; agg: Agg }[] | undefined {
    if (this.stopped) return undefined;
    let out = this.within();
    if (!this.loose && (out.cut || out.bytes > this.opts.loose)) {
      this.loosen();
      out = this.within();
    }
    this.truncated = this.dropped || out.cut;
    return out.lines;
  }

  // The lines that fit in `limit`, their size, and whether any were left out.
  private within(): {
    lines: { comm: string; path: string; agg: Agg }[];
    bytes: number;
    cut: boolean;
  } {
    const lines: { comm: string; path: string; agg: Agg }[] = [];
    let bytes = 0;
    for (const line of this.lines()) {
      const size = this.opts.rowBytes(line.path, line.comm);
      if (bytes + size > this.opts.limit) return { lines, bytes, cut: true };
      lines.push(line);
      bytes += size;
    }
    return { lines, bytes, cut: false };
  }

  // Program runs first, so a part cut short keeps them.
  private *lines(): Generator<{ comm: string; path: string; agg: Agg }> {
    for (const [key, agg] of this.climbing)
      if (ran(agg)) yield { comm: commOf(key), path: pathOf(key), agg };
    for (const [comm, top] of this.trees)
      for (const [path, agg] of treeLines(top, this.opts.fanout)) {
        // A command that also ran the file keeps one row for it.
        const run = this.climbing.get(keyOf(comm, path));
        if (run) mergeAgg(run, agg);
        else yield { comm, path, agg };
      }
    for (const [key, agg] of this.climbing)
      if (!ran(agg)) yield { comm: commOf(key), path: pathOf(key), agg };
  }
}

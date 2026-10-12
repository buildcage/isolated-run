import { apply, flagBits, mergeAgg, newAgg, type Access, type Agg } from "./agg.ts";
import { components, spell, unfoldable } from "./paths.ts";
import { BIT } from "./record.ts";

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
    let bits = 0;
    for (const kid of node.kids?.values() ?? []) {
      bits |= below.get(kid)!;
      if (kid.own) bits |= flagBits(kid.own);
      if (kid.folded) bits |= flagBits(kid.folded);
    }
    below.set(node, bits);
    // A refused open of the directory is not how anything below it was reached.
    if (node.own && !node.own.perm && node.kids?.size && (flagBits(node.own) & ~bits) === 0)
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
    if (folded && flagBits(folded)) yield [`${pathTo(e)}/**`, folded];
    const ownLine = own && flagBits(own) && !walked.has(e.node) ? own : undefined;
    // Its own line counts toward a fold too. Whether that line prints can
    // change until every access is in, so this fold waits for them.
    if (kids?.size && !kept && kids.size + (ownLine ? 1 : 0) >= fanout) {
      yield [`${pathTo(e)}/**`, treeAgg(e.node)];
      continue;
    }
    if (ownLine) yield [pathTo(e), ownLine];
    for (const [part, node] of [...(kids ?? [])].reverse()) stack.push({ node, part, up: e });
  }
}

// Visits a node and every node below it.
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
  nodes: number;
  /** The fewest bytes the line of a path prints in. */
  rowBytes: (path: string, comm: string) => number;
}

/**
 * The lines of one table as the accesses arrive, a directory folding into
 * "dir/**" as soon as it has `fanout` children, so a tree of any size costs
 * no more than its folded lines. Stops, dropping what it holds, once the
 * lines no fold can take away outgrow `limit` bytes, or it holds more than
 * `nodes` paths.
 */
export class Lines {
  private trees = new Map<string, Map<string, Node>>();
  // The unfoldable paths, each a line of its own.
  private climbing = new Map<string, Agg>();
  private bytes = 0;
  private nodes = 0;
  /** Why it gave up, once it has. */
  stopped: CutCause | undefined;

  private readonly opts: LinesOptions;

  constructor(opts: LinesOptions) {
    this.opts = opts;
  }

  add(x: Access): void {
    if (this.stopped || !x.bit) return;
    const parts = components(x.path);
    // A program run is never folded away, nor makes its directory fold.
    if (unfoldable(parts, x.path) || x.bit === BIT.X) {
      const key = keyOf(x.comm, x.path);
      let a = this.climbing.get(key);
      if (!a) {
        this.climbing.set(key, (a = newAgg()));
        this.count(this.opts.rowBytes(x.path, x.comm));
      }
      apply(a, x);
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
        node = { bytes: 0, kept: this.isKept(parts, i + 1) || undefined };
        kids.set(parts[i], node);
        this.nodes++;
        if (parent) {
          // No longer a leaf, its own line may be only the walk to this one.
          this.setBytes(parent, 0);
          if (!parent.kept && kids.size >= this.opts.fanout) {
            this.fold(parent);
            return this.addFolded(parent, parts.slice(0, i), x, parentSettled);
          }
        }
        // Only once a fold had its chance to bring the count back down.
        if (this.nodes > this.opts.nodes) return this.stop("paths");
      }
      if (node.folded) return this.addFolded(node, parts.slice(0, i + 1), x, settled);
      if (i === parts.length - 1) {
        node.own ??= newAgg();
        const shown = flagBits(node.own) !== 0;
        apply(node.own, x);
        if (settled && !shown && flagBits(node.own) && !node.kids?.size)
          this.setBytes(node, this.opts.rowBytes(x.path, x.comm));
        return;
      }
      node.kids ??= new Map();
      kids = node.kids;
      parent = node;
      parentSettled = settled;
      settled &&= Boolean(node.kept);
    }
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

  private addFolded(node: Node, parts: string[], x: Access, settled: boolean): void {
    apply(node.folded!, x);
    if (settled && flagBits(node.folded!) && !node.bytes)
      this.setBytes(node, this.opts.rowBytes(`${spell(parts)}/**`, x.comm));
  }

  private setBytes(node: Node, bytes: number): void {
    this.count(bytes - node.bytes);
    node.bytes = bytes;
  }

  private count(bytes: number): void {
    this.bytes += bytes;
    if (this.bytes > this.opts.limit) this.stop("size");
  }

  private stop(cause: CutCause): void {
    this.stopped = cause;
    this.trees = new Map();
    this.climbing = new Map();
  }

  /** Every line with its command, or undefined once it stopped or its lines outgrew the limit. */
  finish(): { comm: string; path: string; agg: Agg }[] | undefined {
    if (this.stopped) return undefined;
    const out: { comm: string; path: string; agg: Agg }[] = [];
    let bytes = 0;
    for (const line of this.lines()) {
      out.push(line);
      bytes += this.opts.rowBytes(line.path, line.comm);
      if (bytes > this.opts.limit) {
        this.stopped = "size";
        return undefined;
      }
    }
    return out;
  }

  private *lines(): Generator<{ comm: string; path: string; agg: Agg }> {
    for (const [comm, top] of this.trees)
      for (const [path, agg] of treeLines(top, this.opts.fanout)) {
        // A command that also ran the file keeps one row for it.
        const ran = this.climbing.get(keyOf(comm, path));
        if (ran) mergeAgg(ran, agg);
        else yield { comm, path, agg };
      }
    for (const [key, agg] of this.climbing) yield { comm: commOf(key), path: pathOf(key), agg };
  }
}

#!/usr/bin/env python3
"""PoC: turn file-audit JSON lines into the Job Summary shape under design.

Usage: file-audit-summarize.py <records.jsonl> <workspace> [--home H]
                               [--fanout N] [--show]

One line per path (or collapsed directory), with access flags:
  R read  W write  X exec  M move  D delete  A attr
A lowercase letter marks an action that only ever failed on that path.
Libraries (files mapped executable) and exec'd binaries drop out of reads;
non-file objects (pipes, sockets) drop out entirely. A directory with
--fanout or more children that saw events collapses to "dir/**", whose flags
union everything beneath it, so a tree's role shows without every leaf.
Paths under the workspace are shown relative to it; under $HOME as ~/...;
otherwise absolute.
"""
import argparse
import json
import re
from collections import defaultdict

# kind -> action letter. mmap and open resolve to a letter in classify().
LETTER = {
    "read": "R", "write": "W", "exec": "X",
    "mkdir": "W", "truncate": "W", "symlink": "W", "link": "W",
    "rename": "M", "unlink": "D", "rmdir": "D", "chmod": "A", "chown": "A",
    "attr": "A",
}
ORDER = "RWXMDA"


def classify(r):
    """Return (letter, path, failed) or None to drop the record."""
    k = r["kind"]
    if k == "open-failed":
        return ("R", r.get("path"), True)  # refused/missing open, intent unknown
    if r.get("failed"):
        # Failed records decode to base names: delete, rename, chmod,
        # chown, attr (see kindNames in main.go).
        letter = {"delete": "D", "rename": "M", "chmod": "A",
                  "chown": "A", "attr": "A"}.get(k)
        return (letter, r.get("path"), True) if letter else None
    if k == "mmap":
        return ("W" if r.get("access") == "w" else "R", r.get("path"), False)
    if k == "open":
        acc = r.get("access", "")
        return ("W", r.get("path"), False) if ("c" in acc or "t" in acc) else None
    if k == "link":
        return ("W", r.get("to"), False)
    letter = LETTER.get(k)
    return (letter, r.get("path"), False) if letter else None


def normalize(path):
    return re.sub(r"^/proc/\d+/", "/proc/<pid>/", path)


def rel(path, ws, home):
    if path == ws:
        return "."
    if path.startswith(ws + "/"):
        return "./" + path[len(ws) + 1:]
    if path == home:
        return "~"
    if path.startswith(home + "/"):
        return "~/" + path[len(home) + 1:]
    return path


def collapse(paths, fanout, keep):
    """Map each path to the line that represents it ("dir/**" or itself)."""
    children = defaultdict(set)
    for p in paths:
        parts = p.split("/")
        for i in range(1, len(parts)):
            children["/".join(parts[:i]) or "/"].add(parts[i])
    shown = {}
    for p in paths:
        parts = p.split("/")
        line = p
        for i in range(1, len(parts)):
            d = "/".join(parts[:i]) or "/"
            if d not in keep and len(children[d]) >= fanout:
                line = d + "/**"
                break
        shown[p] = line
    # A bare "dir" that also appears as "dir/**", or as an ancestor of any
    # shown line, is redundant: fold it into the covering line.
    lines = set(shown.values())
    collapsed = {l[:-3] for l in lines if l.endswith("/**")}
    for p, line in list(shown.items()):
        if line in collapsed:
            shown[p] = line + "/**"
    return shown


PERM_ERRNO = {1, 13, 30}  # EPERM, EACCES, EROFS


def fmt_flags(ok, failed, perm):
    out = ""
    for c in ORDER:
        if c in ok:
            out += c
        elif c in failed:
            out += c.lower() + ("!" if c in perm else "")
    return out


def sort_key(path):
    cat = 2
    if path == "." or path.startswith("./"):
        cat = 0
    elif path == "~" or path.startswith("~/"):
        cat = 1
    return (cat, path)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("records")
    ap.add_argument("workspace")
    ap.add_argument("--home", default="/home/runner")
    ap.add_argument("--fanout", type=int, default=3)
    a = ap.parse_args()

    ok = defaultdict(set)      # path -> letters that succeeded
    failed = defaultdict(set)  # path -> letters that failed
    perm = defaultdict(set)    # path -> letters whose failure was permission-class
    libs, execd = set(), set()
    n = 0
    with open(a.records) as f:
        for line in f:
            n += 1
            r = json.loads(line)
            if r["kind"] == "mmap" and r.get("access") == "x":
                libs.add(r.get("path"))
                continue
            if r["kind"] == "exec":
                execd.add(r.get("path"))
            c = classify(r)
            if not c or not c[0] or not c[1]:
                continue
            letter, path, is_failed = c
            if is_failed:
                failed[path].add(letter)
                if r.get("err", 0) in PERM_ERRNO:
                    perm[path].add(letter)
            else:
                ok[path].add(letter)

    for p in libs | execd | {"/etc/ld.so.cache"}:
        ok.get(p, set()).discard("R")

    keep = {"/", "/home", a.workspace, a.home, "/tmp", "/proc", "/proc/<pid>"}
    paths = {normalize(p) for p in set(ok) | set(failed) if p and p.startswith("/")}
    # Re-key flags onto normalized paths.
    nok, nfailed, nperm = defaultdict(set), defaultdict(set), defaultdict(set)
    for p in set(ok) | set(failed):
        if p and p.startswith("/"):
            nok[normalize(p)] |= ok.get(p, set())
            nfailed[normalize(p)] |= failed.get(p, set())
            nperm[normalize(p)] |= perm.get(p, set())

    shown = collapse(paths, a.fanout, keep)
    line_ok, line_failed, line_perm = defaultdict(set), defaultdict(set), defaultdict(set)
    for p, line in shown.items():
        line_ok[line] |= nok.get(p, set())
        line_failed[line] |= nfailed.get(p, set())
        line_perm[line] |= nperm.get(p, set())

    lines = set(shown.values())

    # Fold a bare directory into its descendants when it adds no flag they
    # lack: its read is the walk that reached them. "dir" and "dir/**" share
    # the base "dir", so a bare parent of a "/**" line folds here too.
    def base(l):
        return l[:-3] if l.endswith("/**") else l
    bases = sorted(lines, key=lambda l: len(base(l)), reverse=True)
    for l in list(lines):
        if l.endswith("/**"):
            continue
        prefix = base(l) + "/"
        desc_ok, desc_failed, has_desc = set(), set(), False
        for d in lines:
            if d is not l and base(d).startswith(prefix):
                has_desc = True
                desc_ok |= line_ok[d]
                desc_failed |= line_failed[d]
        flags = line_ok[l] | line_failed[l]
        if has_desc and flags <= (desc_ok | desc_failed):
            lines.discard(l)

    rows = []
    for line in lines:
        o = line_ok[line]
        fl = line_failed[line] - o
        flags = fmt_flags(o, fl, line_perm[line] & fl)
        if not flags:
            continue  # e.g. a binary seen only as a mapped library
        rows.append((rel(line, a.workspace, a.home), flags))
    rows.sort(key=lambda row: sort_key(row[0]))
    print(f"records: {n}  libraries dropped: {len(libs)}  lines: {len(rows)}")
    for path, flags in rows:
        print(f"  {flags:<7} {path}")


if __name__ == "__main__":
    main()

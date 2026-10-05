#!/usr/bin/env python3
"""PoC: turn file-audit JSON lines into the Job Summary shape under design.

Usage: file-audit-summarize.py <records.jsonl> <workspace> [--fanout N] [--show]

Each path lands in one or more actions: read, write, move, delete, attr,
exec, plus failed opens. Files the loader maps executable (libraries) and
the binaries exec'd are dropped from reads. A directory whose direct
children with events reach --fanout is listed once as "dir/**". Paths
under the workspace are shown relative to it.
"""
import argparse
import json
import re
from collections import defaultdict

LOADER_FILES = {"/etc/ld.so.cache"}
DROP_LISTINGS = False


def rel(path, ws):
    if path == ws:
        return "."
    if path.startswith(ws + "/"):
        return "./" + path[len(ws) + 1:]
    return path


def normalize(path):
    # Per-process /proc entries differ only by pid.
    return re.sub(r"^/proc/\d+/", "/proc/<pid>/", path)


def collect(lines):
    actions = defaultdict(set)  # action -> paths
    failed = defaultdict(set)   # errno -> names
    libs, execd = set(), set()
    moves = []
    for line in lines:
        r = json.loads(line)
        k, p = r["kind"], r.get("path")
        if k == "mmap" and r.get("access") == "x":
            libs.add(p)
        elif k == "mmap" and r.get("access") == "w":
            actions["write"].add(p)
        elif k == "mmap":
            actions["read"].add(p)
        elif k == "read" and p:
            actions["read"].add(p)
        elif k == "write" and p:
            actions["write"].add(p)
        elif k == "open" and p and ("c" in r["access"] or "t" in r["access"]):
            actions["write"].add(p)
        elif k in ("mkdir", "truncate", "symlink"):
            actions["write"].add(p)
        elif k == "link":
            actions["write"].add(r["to"])
        elif k == "rename":
            actions["move"].add(p)
            moves.append((p, r["to"]))
        elif k in ("unlink", "rmdir"):
            actions["delete"].add(p)
        elif k in ("chmod", "chown"):
            actions["attr"].add(p)
        elif k == "exec":
            actions["exec"].add(p)
            execd.add(p)
        elif k == "open-failed" and p:
            failed[r["err"]].add(p)
    actions["read"] -= libs | execd | LOADER_FILES
    # pipe:[n], socket:[n], anon_inode:... are not files.
    for act in actions:
        actions[act] = {p for p in actions[act] if p and p.startswith("/")}
    # Directory listings: approximated as paths with something recorded
    # beneath them; the tracer would flag S_IFDIR instead.
    every = set().union(*actions.values())
    parents = set()
    for p in every:
        parts = p.split("/")
        for i in range(1, len(parts)):
            parents.add("/".join(parts[:i]) or "/")
    listings = actions["read"] & parents
    if DROP_LISTINGS:
        actions["read"] -= listings
    return actions, failed, libs


def collapse(paths, fanout, keep):
    """Top-down: the first directory with >= fanout direct children that saw
    events becomes "dir/**"; dirs in keep (/, the workspace, $HOME) never do."""
    children = defaultdict(set)
    for p in paths:
        parts = p.split("/")
        for i in range(1, len(parts)):
            children["/".join(parts[:i]) or "/"].add(parts[i])
    out = set()
    for p in paths:
        parts = p.split("/")
        shown = p
        for i in range(1, len(parts)):
            d = "/".join(parts[:i]) or "/"
            if d not in keep and len(children[d]) >= fanout:
                shown = d + "/**"
                break
        out.add(shown)
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("records")
    ap.add_argument("workspace")
    ap.add_argument("--home", default="/home/runner")
    ap.add_argument("--fanout", type=int, default=10)
    ap.add_argument("--show", action="store_true")
    ap.add_argument("--drop-listings", action="store_true")
    a = ap.parse_args()
    global DROP_LISTINGS
    DROP_LISTINGS = a.drop_listings
    with open(a.records) as f:
        lines = f.readlines()
    actions, failed, libs = collect(lines)
    keep = {"/", "/home", a.workspace, a.home, "/tmp", "/proc", "/proc/<pid>"}
    total = 0
    print(f"records: {len(lines)}  libraries dropped: {len(libs)}  fanout: {a.fanout}")
    for act in ("read", "write", "move", "delete", "attr", "exec"):
        paths = {normalize(p) for p in actions[act]}
        shown = sorted(rel(p, a.workspace) for p in collapse(paths, a.fanout, keep))
        total += len(shown)
        print(f"  {act:7} {len(paths):6} paths -> {len(shown):4} lines")
        if a.show:
            for s in shown:
                print(f"      {s}")
    for errno, names in sorted(failed.items()):
        paths = {normalize(p) for p in names}
        shown = sorted(rel(p, a.workspace) for p in collapse(paths, a.fanout, keep))
        total += len(shown)
        print(f"  failed(errno {errno}) {len(paths):6} names -> {len(shown):4} lines")
        if a.show:
            for s in shown[:40]:
                print(f"      {s}")
    print(f"summary lines: {total}")


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""PoC: turn file-audit JSON lines into the Job Summary shape under design.

Usage: file-audit-summarize.py <records.jsonl> <workspace> [--home H]
                               [--fanout N] [--show]

Every path lands in one of six actions: read, write, move, delete, attr,
exec, each split into done and failed. Libraries (files mapped executable)
and exec'd binaries drop out of reads; non-file objects (pipes, sockets)
drop out entirely. A directory with --fanout or more children that saw
events collapses to "dir/**", strongly enough that the role of a tree shows
without every leaf. Paths under the workspace are shown relative to it;
under $HOME, as ~/...; otherwise absolute.
"""
import argparse
import json
import re
from collections import defaultdict

DONE = {
    "read": "read", "write": "write",
    "mkdir": "write", "truncate": "write", "symlink": "write", "link": "write",
    "rename": "move", "unlink": "delete", "rmdir": "delete",
    "chmod": "attr", "chown": "attr", "exec": "exec",
}
ACTIONS = ["read", "write", "move", "delete", "attr", "exec"]


def classify(r):
    """Return (action, failed) or None to drop the record."""
    k = r["kind"]
    if k == "open-failed":
        return ("read", True)  # a refused or missing open; intent unknown
    if r.get("failed"):
        return ({"rename": "move", "unlink": "delete", "rmdir": "delete",
                 "chmod": "attr", "chown": "attr"}.get(k), True)
    if k == "mmap":
        return ("write" if r.get("access") == "w" else "read", False)
    if k == "open":
        acc = r.get("access", "")
        return ("write", False) if ("c" in acc or "t" in acc) else None
    act = DONE.get(k)
    return (act, False) if act else None


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
    # Drop a bare directory already covered by a "dir/**" (its own or a
    # deeper one) or by a descendant line.
    collapsed = {p[:-3] for p in out if p.endswith("/**")}
    prefixes = set()
    for p in out:
        base = p[:-3] if p.endswith("/**") else p
        parts = base.split("/")
        for i in range(1, len(parts)):
            prefixes.add("/".join(parts[:i]))
    return {p for p in out
            if p.endswith("/**") or (p not in prefixes and p not in collapsed)}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("records")
    ap.add_argument("workspace")
    ap.add_argument("--home", default="/home/runner")
    ap.add_argument("--fanout", type=int, default=3)
    ap.add_argument("--show", action="store_true")
    a = ap.parse_args()

    done = {act: set() for act in ACTIONS}
    failed = {act: set() for act in ACTIONS}
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
            if not c or not c[0]:
                continue
            act, is_failed = c
            bucket = failed[act] if is_failed else done[act]
            p = r.get("to") if r["kind"] == "link" else r.get("path")
            bucket.add(p)
            if r["kind"] == "rename" and r.get("to"):
                bucket.add(r["to"])

    done["read"] -= libs | execd | {"/etc/ld.so.cache"}

    keep = {"/", "/home", a.workspace, a.home, "/tmp", "/proc", "/proc/<pid>"}

    def clean(paths):
        return {normalize(p) for p in paths if p and p.startswith("/")}

    print(f"records: {n}  libraries dropped: {len(libs)}  fanout: {a.fanout}")
    total = 0
    for act in ACTIONS:
        for label, raw in ((" ", done[act]), (" (failed)", failed[act])):
            paths = clean(raw)
            if not paths:
                continue
            shown = sorted(rel(p, a.workspace, a.home)
                           for p in collapse(paths, a.fanout, keep))
            total += len(shown)
            print(f"  {act}{label}: {len(paths)} paths -> {len(shown)} lines")
            if a.show:
                for s in shown:
                    print(f"      {s}")
    print(f"summary lines: {total}")


if __name__ == "__main__":
    main()

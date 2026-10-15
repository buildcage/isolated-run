"""Prints a Markdown table of the median of each workload's runs per tracer."""
import glob
import os
import re
import statistics
import sys
from collections import defaultdict

res = sys.argv[1]
runs = defaultdict(list)
for wl in glob.glob(os.path.join(res, "*.wl")):
    label, binary, _ = os.path.basename(wl)[:-3].rsplit(".", 2)
    text = open(wl).read()
    log_path = wl[:-3] + ".log"
    log = open(log_path).read() if os.path.exists(log_path) else ""
    r = {}
    m = re.search(r"stress: ops=\d+ rate=(\d+)", text)
    if m:
        r["rate"] = int(m.group(1))
    r["wall_ms"] = int(re.search(r"wall_ms=(\d+)", text).group(1))
    m = re.search(r"dropped=(\d+) untracked=(\d+)", log)
    if m:
        r["dropped"], r["untracked"] = int(m.group(1)), int(m.group(2))
    m = re.search(r"bench: events=(\d+) bytes=(\d+)", log)
    if m:
        r["events"], r["mb"] = int(m.group(1)), int(m.group(2)) / 1e6
    m = re.search(r"cpu user=([\d.]+) sys=([\d.]+)", log)
    if m:
        r["cpu_s"] = float(m.group(1)) + float(m.group(2))
    progs = {p: (int(n), int(ns)) for p, n, ns in re.findall(r"prog=(\S+) runs=(\d+) ns=(\d+)", log)}
    if progs:
        r["bpf_ms"] = sum(ns for _, ns in progs.values()) / 1e6
        for p in ("on_sys_exit", "on_filp_open", "on_do_file_open", "on_open"):
            if p in progs:
                n, ns = progs[p]
                r[p] = ns / n
    runs[(label, binary)].append(r)


def med(rs, k, fmt):
    vals = [r[k] for r in rs if k in r]
    return fmt.format(statistics.median(vals)) if vals else "-"


cols = [
    ("rate", "ops/s", "{:.0f}"),
    ("wall_ms", "wall ms", "{:.0f}"),
    ("dropped", "dropped", "{:.0f}"),
    ("untracked", "untracked", "{:.0f}"),
    ("events", "events", "{:.0f}"),
    ("mb", "ring MB", "{:.1f}"),
    ("cpu_s", "reader CPU s", "{:.2f}"),
    ("bpf_ms", "BPF ms", "{:.0f}"),
    ("on_sys_exit", "sys_exit ns/run", "{:.0f}"),
    ("on_do_file_open", "file_open ns/run", "{:.0f}"),
    ("on_filp_open", "filp_open ns/run", "{:.0f}"),
    ("on_open", "file hook ns/run", "{:.0f}"),
]
print(f"### {os.environ.get('RUNNER_ARCH', '')} {os.uname().release}, {os.cpu_count()} CPUs\n")
print("| workload | tracer | " + " | ".join(c[1] for c in cols) + " |")
print("|" + "---|" * (len(cols) + 2))
order = {"none": 0, "main": 1, "pr": 2}
for label, binary in sorted(runs, key=lambda k: (k[0], order[k[1]])):
    rs = runs[(label, binary)]
    print(f"| {label} | {binary} | " + " | ".join(med(rs, k, f) for k, _, f in cols) + " |")

kinds = defaultdict(lambda: defaultdict(list))
for log in glob.glob(os.path.join(res, "*.log")):
    label, binary, _ = os.path.basename(log)[:-4].rsplit(".", 2)
    for k, n, b in re.findall(r"kind=(\S+) events=(\d+) bytes=(\d+)", open(log).read()):
        kinds[(label, binary)][k].append((int(n), int(b)))
print("\n<details><summary>Events and bytes per kind (median)</summary>\n")
for key in sorted(kinds, key=lambda k: (k[0], order[k[1]])):
    parts = ", ".join(
        f"{k} {statistics.median(n for n, _ in v):.0f}/{statistics.median(b for _, b in v) / 1e6:.1f}MB"
        for k, v in sorted(kinds[key].items())
    )
    print(f"- {key[0]} {key[1]}: {parts}")
print("\n</details>")

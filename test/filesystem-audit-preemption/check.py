"""Fails on a record whose kind, name and command disagree, or that repeats.

Each process makes its own kind of change under names of its own (see
work.py), so a record mixing them, or a name recorded twice, was assembled
from two events at once.
"""

import collections
import json
import re
import sys

# O_CREAT passes security_path_mknod too, so a created file also records as mknod.
EXPECT = {"opener": ({"open", "mknod"}, "a"), "maker": ({"mkdir"}, "b"), "misser": ({"open"}, "c")}
NAME = re.compile(r"^/tmp/w/([abc])/([abc])-(\d+)-(\d+)$")

counts = collections.Counter()
seen = collections.Counter()
bad = []
repeats = []
end = None
for line in open(sys.argv[1], encoding="utf-8", errors="replace"):
    r = json.loads(line)
    if r.get("kind") == "end":
        end = r
        continue
    comm, path = r.get("comm"), r.get("path") or ""
    if comm not in EXPECT or not path.startswith(("/tmp/w/a/", "/tmp/w/b/", "/tmp/w/c/")):
        continue
    kinds, letter = EXPECT[comm]
    counts[comm] += 1
    m = NAME.match(path)
    whose = m and int(m.group(3)) == r.get("pid")
    if not (whose and m.group(1) == letter and m.group(2) == letter and r.get("kind") in kinds):
        counts["mixed"] += 1
        if len(bad) < 10:
            bad.append(r)
    key = (r.get("kind"), path)
    seen[key] += 1
    if seen[key] == 2:
        counts["repeated"] += 1
        if len(repeats) < 10:
            repeats.append(r)

print("records:", dict(counts))
print("end:", end)
for r in bad:
    print("MIXED", json.dumps(r))
for r in repeats:
    print("REPEATED", json.dumps(r))
missing = [comm for comm in EXPECT if counts[comm] == 0]
if end is None or missing or counts["mixed"] or counts["repeated"]:
    print("FAIL: no end line" if end is None else f"FAIL: missing {missing}" if missing else "FAIL")
    sys.exit(1)

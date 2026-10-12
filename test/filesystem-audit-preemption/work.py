"""Makes one kind of change under names of its own until the time is up.

open creates /tmp/w/a/a-<pid>-<n>, mkdir makes /tmp/w/b/b-<pid>-<n>, and
missing opens /tmp/w/c/c-<pid>-<n>, which is never there.
"""

import os
import sys
import time

kind, base, seconds = sys.argv[1], sys.argv[2], float(sys.argv[3])
letter = {"open": "a", "mkdir": "b", "missing": "c"}[kind]
d = os.path.join(base, letter)
os.makedirs(d, exist_ok=True)
end = time.monotonic() + seconds
i = 0
while time.monotonic() < end:
    p = os.path.join(d, f"{letter}-{os.getpid()}-{i}")
    if kind == "open":
        os.close(os.open(p, os.O_CREAT | os.O_WRONLY, 0o644))
    elif kind == "mkdir":
        os.mkdir(p)
    else:
        try:
            os.open(p, os.O_RDONLY)
        except FileNotFoundError:
            pass
    i += 1
print(kind, i, "operations", flush=True)

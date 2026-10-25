# shellcheck shell=bash
# The file accesses test-e2e.yml's filesystem audit step makes for
# test/assert-filesystem-audit*.sh to check. Sourced, not run, so the step's
# own shell makes them.
cat /etc/hostname > /dev/null
# A process's own /proc directory, then another process's.
cat /proc/self/status /proc/1/stat > /dev/null
echo probe > "$GITHUB_WORKSPACE/probe.txt"
mv "$GITHUB_WORKSPACE/probe.txt" "$GITHUB_WORKSPACE/probe2.txt"
rm "$GITHUB_WORKSPACE/probe2.txt"
# A command run from a subshell that itself touches nothing.
# shellcheck disable=SC2015
(cd "$GITHUB_WORKSPACE" && touch subshell.txt || true)
# Times set through a descriptor (futimens), which names no path.
python3 -c 'import os, sys; os.utime(os.open(sys.argv[1], os.O_WRONLY | os.O_CREAT))' "$GITHUB_WORKSPACE/futimens.txt"
# Times set through an empty name and AT_EMPTY_PATH.
python3 -c 'import ctypes, os, sys; fd = os.open(sys.argv[1], os.O_WRONLY | os.O_CREAT)
assert ctypes.CDLL(None, use_errno=True).utimensat(fd, b"", None, 0x1000) == 0' "$GITHUB_WORKSPACE/empty-name.txt"
# Failed calls on relative names: one against a changed working
# directory, one against a directory passed by descriptor.
mkdir -p "$GITHUB_WORKSPACE/sub"
(cd "$GITHUB_WORKSPACE/sub" && : < missing.txt) 2>/dev/null || true
python3 -c 'import os, sys; d = os.open(sys.argv[1], os.O_RDONLY)
try: os.unlink("gone", dir_fd=d)
except FileNotFoundError: pass
try: os.open("absent", os.O_RDONLY, dir_fd=d)
except FileNotFoundError: pass' "$GITHUB_WORKSPACE/sub"
# Changes the kernel refuses after the tracer's hook has seen them.
chmod 777 "$GITHUB_WORKSPACE/root-owned.txt" 2>/dev/null || true
chown 1:2 "$GITHUB_WORKSPACE/root-owned.txt" 2>/dev/null || true
mkdir "$GITHUB_WORKSPACE/root-owned/x" 2>/dev/null || true
# Refused by the read-only root before the tracer's path hook.
mkdir /usr/local/buildcage-ro-probe 2>/dev/null || true
# Changes through a descriptor alone that the kernel refuses before
# the tracer's hook: a chmod and chown on the read-only root, a
# chown there through an empty name and AT_EMPTY_PATH, and a
# truncate through a descriptor not open for writing. Then a
# truncate on /dev/null, which changes no file, and an xattr set
# through a descriptor.
echo data > "$GITHUB_WORKSPACE/fd-truncate.txt"
echo data > "$GITHUB_WORKSPACE/fd-xattr.txt"
python3 -c 'import ctypes, os, sys
ro = os.open("/usr/bin/env", os.O_RDONLY)
libc = ctypes.CDLL(None, use_errno=True)
assert libc.fchownat(ro, b"", 3, 4, 0x1000) == -1 and ctypes.get_errno() == 30
for change in (lambda: os.fchmod(ro, 0o4755), lambda: os.fchown(ro, 1, 2),
               lambda: os.ftruncate(os.open(sys.argv[1], os.O_RDONLY), 0),
               lambda: os.ftruncate(os.open("/dev/null", os.O_WRONLY), 0),
               lambda: os.setxattr(os.open(sys.argv[2], os.O_RDONLY), "user.buildcage", b"1")):
    try: change()
    except OSError: pass' \
  "$GITHUB_WORKSPACE/fd-truncate.txt" "$GITHUB_WORKSPACE/fd-xattr.txt"
# A mkdir on a name already there, which is no change.
mkdir "$GITHUB_WORKSPACE/sub" 2>/dev/null || true
# A script run by a relative name from the directory it sits in.
mkdir -p "$GITHUB_WORKSPACE/A"
printf '#!/bin/sh\n' > "$GITHUB_WORKSPACE/A/run.sh"
chmod +x "$GITHUB_WORKSPACE/A/run.sh"
(cd "$GITHUB_WORKSPACE/A" && ./run.sh)
# A hard link, which names the file it links as well as its new name.
echo data > "$GITHUB_WORKSPACE/link-src.txt"
ln "$GITHUB_WORKSPACE/link-src.txt" "$GITHUB_WORKSPACE/link-dst.txt"
# One across mounts, which fails EXDEV before protected_hardlinks
# is consulted.
ln /etc/hostname "$GITHUB_WORKSPACE/hostname-link" 2>/dev/null || true
# A symlink with the longest target the kernel takes.
ln -s "/$(printf 'x%.0s' $(seq 4094))" "$GITHUB_WORKSPACE/long-link"
# A file mapped executable that is no library.
echo data > "$GITHUB_WORKSPACE/mapped.bin"
python3 -c 'import mmap, sys; f = open(sys.argv[1], "rb")
mmap.mmap(f.fileno(), 0, prot=mmap.PROT_READ | mmap.PROT_EXEC)' "$GITHUB_WORKSPACE/mapped.bin"
# A mapping and an open the kernel refuses after the tracer's hook: a
# shared writable map of a file opened read-only, and a FIFO opened
# for writing with no reader.
echo data > "$GITHUB_WORKSPACE/ro-mapped.bin"
python3 -c 'import mmap, sys; f = open(sys.argv[1], "rb")
try: mmap.mmap(f.fileno(), 0)
except PermissionError: pass' "$GITHUB_WORKSPACE/ro-mapped.bin"
mkfifo "$GITHUB_WORKSPACE/fifo"
python3 -c 'import os, sys
try: os.open(sys.argv[1], os.O_WRONLY | os.O_NONBLOCK)
except OSError: pass' "$GITHUB_WORKSPACE/fifo"
# mprotect adding PROT_WRITE (and PROT_EXEC) to shared mappings.
echo data > "$GITHUB_WORKSPACE/mprotected.bin"
echo data > "$GITHUB_WORKSPACE/mprotected-rwx.bin"
python3 -c 'import ctypes, os, sys
libc = ctypes.CDLL(None)
libc.mmap.restype = ctypes.c_void_p
libc.mmap.argtypes = [ctypes.c_void_p, ctypes.c_size_t, ctypes.c_int, ctypes.c_int, ctypes.c_int, ctypes.c_long]
failed = ctypes.c_void_p(-1).value
def remap(path, prot):
    p = libc.mmap(None, 4096, 1, 1, os.open(path, os.O_RDWR), 0)  # PROT_READ, MAP_SHARED
    assert p != failed and libc.mprotect(ctypes.c_void_p(p), 4096, prot) == 0
    ctypes.memmove(p, b"X", 1)
remap(sys.argv[1], 3)  # PROT_READ | PROT_WRITE
remap(sys.argv[2], 7)  # PROT_READ | PROT_WRITE | PROT_EXEC
p = libc.mmap(None, 4096, 0, 0x21, -1, 0)  # PROT_NONE, MAP_SHARED | MAP_ANONYMOUS
assert p != failed and libc.mprotect(ctypes.c_void_p(p), 4096, 3) == 0' \
  "$GITHUB_WORKSPACE/mprotected.bin" "$GITHUB_WORKSPACE/mprotected-rwx.bin"
# A memfd and a deleted file, each run with no path left to it.
python3 -c 'import os, shutil, sys
m = os.memfd_create("probe-memfd")
os.write(m, open("/usr/bin/true", "rb").read())
shutil.copy("/usr/bin/true", sys.argv[1])
d = os.open(sys.argv[1], os.O_RDONLY)
os.unlink(sys.argv[1])
for fd in (m, d):
    if os.fork() == 0:
        os.execve(fd, ["true"], {})
    os.wait()' "$GITHUB_WORKSPACE/gone-bin"
# Writing through a descriptor a shell already wrote through: a forked
# child (the trailing true keeps bash from exec'ing it), then a
# program the shell execs in place.
(exec 3> "$GITHUB_WORKSPACE/shared.txt"; echo head >&3; sh -c 'echo body >&3'; true)
(exec 3> "$GITHUB_WORKSPACE/execd.txt"; echo head >&3; exec cat /etc/hostname >&3)
# A program, not the builtin, with an argument the record must not keep.
/usr/bin/true buildcage-audit-sentinel-arg
# A user namespace, which the sandbox's seccomp profile refuses.
python3 -c 'import ctypes; assert ctypes.CDLL(None).unshare(0x10000000) == -1'
# A 32-bit syscall (getpid through int 0x80) is numbered apart from
# the calls the tracer reads, so seccomp kills the thread making it:
# SIGSYS, 128+31.
if [ "$(uname -m)" = x86_64 ]; then
  status=0
  "$GITHUB_WORKSPACE/int80" || status=$?
  if [ "$status" -ne 159 ]; then echo "::error::a 32-bit syscall ended with $status, not SIGSYS"; exit 1; fi
fi

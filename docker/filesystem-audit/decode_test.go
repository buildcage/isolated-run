package main

import (
	"encoding/binary"
	"testing"
	"unsafe"

	"golang.org/x/sys/unix"
)

// event builds a raw sample in struct event's layout.
type event struct {
	kind                      filesystemAuditKind
	flags, mode               uint32
	pathRet                   int32
	err                       uint32
	marks                     uint32
	gid                       uint32
	bases                     uint32
	n1, n2, truncated, trunc2 uint8
	pid, ppid                 uint32
	comm                      string
	boot                      uint64
	data                      []byte
}

func (e event) bytes() []byte {
	b := make([]byte, hdrLen)
	le := binary.LittleEndian
	le.PutUint32(b[offKind:], uint32(e.kind))
	le.PutUint32(b[offPid:], e.pid)
	le.PutUint32(b[offPpid:], e.ppid)
	le.PutUint32(b[offFlags:], e.flags)
	le.PutUint32(b[offMode:], e.mode)
	le.PutUint32(b[offPathLen:], uint32(e.pathRet))
	le.PutUint32(b[offBases:], e.bases)
	b[offN1], b[offN2], b[offTruncated], b[offTrunc2] = e.n1, e.n2, e.truncated, e.trunc2
	copy(b[offComm:offComm+commLen], e.comm)
	le.PutUint32(b[offErr:], e.err)
	le.PutUint32(b[offMarks:], e.marks)
	le.PutUint32(b[offGid:], e.gid)
	le.PutUint64(b[offTs:], e.boot)
	return append(b, e.data...)
}

// comps encodes path components leaf first, NUL-terminated, as the BPF side
// stores them.
func comps(leafFirst ...string) []byte {
	var out []byte
	for _, c := range leafFirst {
		out = append(out, []byte(c)...)
		out = append(out, 0)
	}
	return out
}

func TestDecodeShort(t *testing.T) {
	if _, err := decode(make([]byte, hdrLen-1)); err == nil {
		t.Fatal("want error on short event")
	}
}

func TestDecodeHeldRefusal(t *testing.T) {
	r, err := decode(event{kind: filesystemAuditKindK_UNLINK, n1: 2, err: 1, data: comps("f", "tmp")}.bytes())
	if err != nil {
		t.Fatal(err)
	}
	if r.Kind != "unlink" || r.Path != "/tmp/f" || !r.Failed || r.Err != 1 {
		t.Errorf("held refusal decode: %+v", r)
	}
}

func TestDecodeHeldOpenRefusal(t *testing.T) {
	r, err := decode(event{kind: filesystemAuditKindK_OPEN, flags: unix.O_WRONLY | unix.O_NONBLOCK, err: uint32(unix.ENXIO), data: []byte("/tmp/fifo\x00")}.bytes())
	if err != nil {
		t.Fatal(err)
	}
	if r.Kind != "open" || r.Path != "/tmp/fifo" || r.Access != "w" || !r.Failed || r.Err != int32(unix.ENXIO) {
		t.Errorf("held open refusal decode: %+v", r)
	}
}

func TestTidy(t *testing.T) {
	for in, want := range map[string]string{
		"/a/./b//c":       "/a/b/c",
		"/a/l/../b":       "/a/l/../b",
		"/work/l/":        "/work/l/",
		"/work/./l/.":     "/work/l/.",
		"/":               "/",
		".":               ".",
		"":                "",
		"x":               "x",
		"…/deep/./x":      "…/deep/x",
		"/var/tmp/b/../x": "/var/tmp/b/../x",
	} {
		if got := tidy(in); got != want {
			t.Errorf("tidy(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestDecodeBootTime(t *testing.T) {
	r, err := decode(event{kind: filesystemAuditKindK_READ, comm: "cat", boot: 123_456_789_000, data: []byte("/etc/hosts\x00")}.bytes())
	if err != nil {
		t.Fatal(err)
	}
	if r.boot != 123_456_789_000 {
		t.Fatalf("boot = %d, want 123456789000", r.boot)
	}
}

// decode reads each header field at its generated offset with a width of its
// own; this pins the widths to the generated type.
func TestHeaderWidths(t *testing.T) {
	var e filesystemAuditEvent
	for name, c := range map[string]struct{ got, want uintptr }{
		"kind":      {unsafe.Sizeof(e.Kind), 4},
		"pid":       {unsafe.Sizeof(e.Pid), 4},
		"ppid":      {unsafe.Sizeof(e.Ppid), 4},
		"flags":     {unsafe.Sizeof(e.Flags), 4},
		"mode":      {unsafe.Sizeof(e.Mode), 4},
		"path_len":  {unsafe.Sizeof(e.PathLen), 4},
		"bases":     {unsafe.Sizeof(e.Bases), 4},
		"n1":        {unsafe.Sizeof(e.N1), 1},
		"n2":        {unsafe.Sizeof(e.N2), 1},
		"truncated": {unsafe.Sizeof(e.Truncated), 1},
		"trunc2":    {unsafe.Sizeof(e.Trunc2), 1},
		"comm":      {unsafe.Sizeof(e.Comm), 16},
		"err":       {unsafe.Sizeof(e.Err), 4},
		"marks":     {unsafe.Sizeof(e.Marks), 4},
		"gid":       {unsafe.Sizeof(e.Gid), 4},
		"ts":        {unsafe.Sizeof(e.Ts), 8},
	} {
		if c.got != c.want {
			t.Errorf("%s is %d bytes, decode reads %d", name, c.got, c.want)
		}
	}
}

func TestDecode(t *testing.T) {
	cases := []struct {
		name string
		ev   event
		want record
	}{
		{
			name: "open read",
			ev:   event{kind: filesystemAuditKindK_OPEN, pid: 7, ppid: 1, comm: "cat", flags: unix.O_RDONLY, data: []byte("/etc/passwd\x00")},
			want: record{Kind: "open", PID: 7, PPID: 1, Comm: "cat", Path: "/etc/passwd", Access: "r"},
		},
		{
			name: "open create+truncate",
			ev:   event{kind: filesystemAuditKindK_OPEN, comm: "sh", flags: unix.O_WRONLY | unix.O_CREAT | unix.O_TRUNC, data: []byte("/tmp/x\x00")},
			want: record{Kind: "open", Comm: "sh", Path: "/tmp/x", Flags: unix.O_WRONLY | unix.O_CREAT | unix.O_TRUNC, Access: "wct"},
		},
		{
			name: "failed open",
			ev:   event{kind: filesystemAuditKindK_OPEN_FAILED, comm: "node", pathRet: int32(unix.ENOENT), data: []byte("/missing\x00")},
			want: record{Kind: "open", Comm: "node", Path: "/missing", Access: "r", Err: int32(unix.ENOENT), Failed: true},
		},
		{
			name: "failed open to write",
			ev: event{kind: filesystemAuditKindK_OPEN_FAILED, comm: "cp", pathRet: int32(unix.EACCES), flags: unix.O_WRONLY | unix.O_CREAT | unix.O_TRUNC,
				data: []byte("/usr/local/bin/tool\x00")},
			want: record{Kind: "open", Comm: "cp", Path: "/usr/local/bin/tool",
				Flags: unix.O_WRONLY | unix.O_CREAT | unix.O_TRUNC, Access: "wct", Err: int32(unix.EACCES), Failed: true},
		},
		{
			name: "open, path too long for d_path",
			ev: event{kind: filesystemAuditKindK_OPEN, comm: "sh", flags: unix.O_WRONLY, pathRet: -int32(unix.ENAMETOOLONG),
				n1: 2, truncated: 1, data: comps("f", "d")},
			want: record{Kind: "open", Comm: "sh", Path: "…/d/f", Flags: unix.O_WRONLY, Access: "w"},
		},
		{
			name: "refused syscall",
			ev:   event{kind: filesystemAuditKindK_SYSCALL, comm: "node", flags: unix.SYS_IO_URING_SETUP, pathRet: int32(unix.EPERM)},
			want: record{Kind: "syscall", Comm: "node", Syscall: "io_uring_setup", Err: int32(unix.EPERM), Failed: true},
		},
		{
			name: "32-bit syscall killed",
			ev:   event{kind: filesystemAuditKindK_SYSCALL, comm: "a.out", flags: 1, mode: 1},
			want: record{Kind: "syscall", Comm: "a.out", Syscall: compatSyscallNames[1], Compat: true, Killed: true, Failed: true},
		},
		{
			name: "x32 syscall killed",
			ev:   event{kind: filesystemAuditKindK_SYSCALL, comm: "x32", flags: 0x40000000 | 39, mode: 1},
			want: record{Kind: "syscall", Comm: "x32", Syscall: syscallNames[39], Compat: true, Killed: true, Failed: true},
		},
		{
			name: "refused syscall with no name",
			ev:   event{kind: filesystemAuditKindK_SYSCALL, comm: "x", flags: 9999, pathRet: int32(unix.EPERM)},
			want: record{Kind: "syscall", Comm: "x", Syscall: "9999", Err: int32(unix.EPERM), Failed: true},
		},
		{
			name: "mknod",
			ev:   event{kind: filesystemAuditKindK_MKNOD, comm: "mkfifo", n1: 2, data: comps("p", "tmp")},
			want: record{Kind: "mknod", Comm: "mkfifo", Path: "/tmp/p"},
		},
		{
			name: "attr through a descriptor (futimens)",
			ev:   event{kind: filesystemAuditKindK_ATTR, comm: "touch", bases: 1, mode: 2, data: append([]byte("\x00"), comps("f", "tmp")...)},
			want: record{Kind: "attr", Comm: "touch", Path: "/tmp/f"},
		},
		{
			name: "write",
			ev:   event{kind: filesystemAuditKindK_WRITE, comm: "tee", data: []byte("/tmp/out\x00")},
			want: record{Kind: "write", Comm: "tee", Path: "/tmp/out"},
		},
		{
			name: "mmap exec",
			ev:   event{kind: filesystemAuditKindK_MMAP, comm: "ld", mode: unix.PROT_READ | unix.PROT_EXEC, n1: 2, data: comps("libc.so", "lib")},
			want: record{Kind: "mmap", Comm: "ld", Path: "/lib/libc.so", Access: "x"},
		},
		{
			name: "mmap by an exec",
			ev:   event{kind: filesystemAuditKindK_MMAP, comm: "sh", mode: unix.PROT_READ | unix.PROT_EXEC, pathRet: 1, n1: 3, data: comps("bash", "bin", "usr")},
			want: record{Kind: "mmap", Comm: "sh", Path: "/usr/bin/bash", Access: "x", Image: true},
		},
		{
			name: "rename",
			ev:   event{kind: filesystemAuditKindK_RENAME, comm: "mv", n1: 2, n2: 2, data: append(comps("a", "tmp"), comps("b", "tmp")...)},
			want: record{Kind: "rename", Comm: "mv", Path: "/tmp/a", To: "/tmp/b"},
		},
		{
			name: "unlink",
			ev:   event{kind: filesystemAuditKindK_UNLINK, comm: "rm", n1: 2, data: comps("f", "tmp")},
			want: record{Kind: "unlink", Comm: "rm", Path: "/tmp/f"},
		},
		{
			name: "failed unlink, read-only",
			ev:   event{kind: filesystemAuditKindK_UNLINK_FAILED, comm: "rm", pathRet: int32(unix.EROFS), data: []byte("/etc\x00")},
			want: record{Kind: "unlink", Comm: "rm", Path: "/etc", Err: int32(unix.EROFS), Failed: true},
		},
		{
			name: "failed rmdir",
			ev:   event{kind: filesystemAuditKindK_RMDIR_FAILED, comm: "rmdir", pathRet: int32(unix.ENOTEMPTY), data: []byte("/tmp/d\x00")},
			want: record{Kind: "rmdir", Comm: "rmdir", Path: "/tmp/d", Err: int32(unix.ENOTEMPTY), Failed: true},
		},
		{
			name: "failed rename, two paths",
			ev:   event{kind: filesystemAuditKindK_RENAME_FAILED, comm: "mv", pathRet: int32(unix.ENOENT), n1: 1, data: []byte("/a\x00/b\x00")},
			want: record{Kind: "rename", Comm: "mv", Path: "/a", To: "/b", Err: int32(unix.ENOENT), Failed: true},
		},
		{
			name: "failed mkdir on a read-only mount",
			ev:   event{kind: filesystemAuditKindK_MKDIR_FAILED, comm: "mkdir", pathRet: int32(unix.EROFS), data: []byte("/opt/x\x00")},
			want: record{Kind: "mkdir", Comm: "mkdir", Path: "/opt/x", Err: int32(unix.EROFS), Failed: true},
		},
		{
			name: "failed mkdir, relative to the cwd",
			ev: event{kind: filesystemAuditKindK_MKDIR_FAILED, comm: "mkdir", pathRet: int32(unix.EROFS), bases: 1, mode: 1,
				data: append([]byte("x\x00"), comps("opt")...)},
			want: record{Kind: "mkdir", Comm: "mkdir", Path: "/opt/x", Name: "x", Err: int32(unix.EROFS), Failed: true},
		},
		{
			name: "failed link, the new name relative to its base",
			ev: event{kind: filesystemAuditKindK_LINK_FAILED, comm: "ln", pathRet: int32(unix.EROFS), n1: 1, bases: 2, flags: 1,
				data: append([]byte("/a\x00b\x00"), comps("bin")...)},
			want: record{Kind: "link", Comm: "ln", Path: "/a", To: "/bin/b", ToName: "b", Err: int32(unix.EROFS), Failed: true},
		},
		{
			name: "failed mknod",
			ev:   event{kind: filesystemAuditKindK_MKNOD_FAILED, comm: "mkfifo", pathRet: int32(unix.EROFS), data: []byte("/opt/p\x00")},
			want: record{Kind: "mknod", Comm: "mkfifo", Path: "/opt/p", Err: int32(unix.EROFS), Failed: true},
		},
		{
			name: "failed symlink, by the link's name",
			ev:   event{kind: filesystemAuditKindK_SYMLINK_FAILED, comm: "ln", pathRet: int32(unix.EROFS), data: []byte("/usr/local/bin/foo\x00")},
			want: record{Kind: "symlink", Comm: "ln", Path: "/usr/local/bin/foo", Err: int32(unix.EROFS), Failed: true},
		},
		{
			name: "failed truncate",
			ev:   event{kind: filesystemAuditKindK_TRUNCATE_FAILED, comm: "sh", pathRet: int32(unix.EROFS), data: []byte("/etc/hosts\x00")},
			want: record{Kind: "truncate", Comm: "sh", Path: "/etc/hosts", Err: int32(unix.EROFS), Failed: true},
		},
		{
			name: "failed link, old name to new",
			ev:   event{kind: filesystemAuditKindK_LINK_FAILED, comm: "ln", pathRet: int32(unix.EROFS), n1: 1, data: []byte("/a\x00/b\x00")},
			want: record{Kind: "link", Comm: "ln", Path: "/a", To: "/b", Err: int32(unix.EROFS), Failed: true},
		},
		{
			name: "fork",
			ev:   event{kind: filesystemAuditKindK_FORK, pid: 9, ppid: 7, comm: "bash"},
			want: record{Kind: "fork", PID: 9, PPID: 7, Comm: "bash"},
		},
		{
			name: "failed unlink, relative to a dirfd",
			ev: event{kind: filesystemAuditKindK_UNLINK_FAILED, comm: "go", pathRet: int32(unix.ENOENT), bases: 1, mode: 2,
				data: append([]byte("b001\x00"), comps("go-build1", "tmp")...)},
			want: record{Kind: "unlink", Comm: "go", Path: "/tmp/go-build1/b001", Name: "b001", Err: int32(unix.ENOENT), Failed: true},
		},
		{
			name: "failed open, relative to the cwd",
			ev: event{kind: filesystemAuditKindK_OPEN_FAILED, comm: "asm", pathRet: int32(unix.ENOENT), bases: 1, mode: 2,
				data: append([]byte("./textflag.h\x00"), comps("runtime", "src")...)},
			want: record{Kind: "open", Comm: "asm", Path: "/src/runtime/textflag.h", Name: "./textflag.h", Access: "r", Err: int32(unix.ENOENT), Failed: true},
		},
		{
			// Joined as passed: cleaning would drop "link/..", and with it the
			// symlink the kernel followed.
			name: "failed chmod, relative through a symlink",
			ev: event{kind: filesystemAuditKindK_CHMOD_FAILED, comm: "chmod", pathRet: int32(unix.EPERM), bases: 1, mode: 1, flags: 0o104755,
				data: append([]byte("l/../hosts\x00"), comps("work")...)},
			want: record{Kind: "chmod", Comm: "chmod", Path: "/work/l/../hosts", Name: "l/../hosts", Mode: "4755", Err: int32(unix.EPERM), Failed: true},
		},
		{
			name: "failed chown",
			ev:   event{kind: filesystemAuditKindK_CHOWN_FAILED, comm: "chown", pathRet: int32(unix.ENOENT), flags: 1001, mode: 7, gid: 121, data: []byte("/etc/x\x00")},
			want: record{Kind: "chown", Comm: "chown", Path: "/etc/x", Owner: "1001:121", Err: int32(unix.ENOENT), Failed: true},
		},
		{
			name: "chown of the group alone",
			ev:   event{kind: filesystemAuditKindK_CHOWN, comm: "chgrp", flags: 0xffffffff, mode: 121, n1: 2, data: comps("f", "tmp")},
			want: record{Kind: "chown", Comm: "chgrp", Path: "/tmp/f", Owner: "-1:121"},
		},
		{
			name: "relative to the root",
			ev:   event{kind: filesystemAuditKindK_ATTR_FAILED, comm: "touch", pathRet: int32(unix.EROFS), bases: 1, data: []byte("etc\x00")},
			want: record{Kind: "attr", Comm: "touch", Path: "/etc", Name: "etc", Err: int32(unix.EROFS), Failed: true},
		},
		{
			name: "relative under a truncated base",
			ev: event{kind: filesystemAuditKindK_UNLINK_FAILED, comm: "rm", pathRet: int32(unix.ENOENT), bases: 1, mode: 1, truncated: 1,
				data: append([]byte("x\x00"), comps("deep")...)},
			want: record{Kind: "unlink", Comm: "rm", Path: "…/deep/x", Name: "x", Err: int32(unix.ENOENT), Failed: true},
		},
		{
			name: "relative with no base walked",
			ev:   event{kind: filesystemAuditKindK_UNLINK_FAILED, comm: "rm", pathRet: int32(unix.EBADF), data: []byte("x\x00")},
			want: record{Kind: "unlink", Comm: "rm", Path: "x", Err: int32(unix.EBADF), Failed: true},
		},
		{
			name: "failed open, name cut",
			ev:   event{kind: filesystemAuditKindK_OPEN_FAILED, comm: "node", pathRet: int32(unix.ENOENT), n2: 1, data: []byte("/a/b/lon\x00")},
			want: record{Kind: "open", Comm: "node", Path: "/a/b/lon…", Access: "r", Err: int32(unix.ENOENT), Failed: true},
		},
		{
			name: "failed open, relative name cut",
			ev: event{kind: filesystemAuditKindK_OPEN_FAILED, comm: "node", pathRet: int32(unix.ENOENT), n2: 1, bases: 1, mode: 1,
				data: append([]byte("a/lon\x00"), comps("w")...)},
			want: record{Kind: "open", Comm: "node", Path: "/w/a/lon…", Name: "a/lon…", Access: "r", Err: int32(unix.ENOENT), Failed: true},
		},
		{
			name: "failed rename, each name on its own base",
			ev: event{kind: filesystemAuditKindK_RENAME_FAILED, comm: "mv", pathRet: int32(unix.EXDEV), n1: 1, bases: 3, mode: 1, flags: 1,
				data: append(append([]byte("a\x00b\x00"), comps("src")...), comps("dst")...)},
			want: record{Kind: "rename", Comm: "mv", Path: "/src/a", To: "/dst/b", Name: "a", ToName: "b", Err: int32(unix.EXDEV), Failed: true},
		},
		{
			name: "failed rename, only the new name relative",
			ev: event{kind: filesystemAuditKindK_RENAME_FAILED, comm: "mv", pathRet: int32(unix.ENOENT), n1: 1, bases: 2, flags: 1,
				data: append([]byte("/a\x00b\x00"), comps("dst")...)},
			want: record{Kind: "rename", Comm: "mv", Path: "/a", To: "/dst/b", ToName: "b", Err: int32(unix.ENOENT), Failed: true},
		},
		{
			name: "exec",
			ev:   event{kind: filesystemAuditKindK_EXEC, pid: 9, comm: "true", data: []byte("/bin/true\x00")},
			want: record{Kind: "exec", PID: 9, Comm: "true", Path: "/bin/true"},
		},
		{
			name: "chown",
			ev:   event{kind: filesystemAuditKindK_CHOWN, comm: "chown", flags: 1001, mode: 121, n1: 2, data: comps("f", "tmp")},
			want: record{Kind: "chown", Comm: "chown", Path: "/tmp/f", Owner: "1001:121"},
		},
		{
			name: "exec file, resolved",
			ev:   event{kind: filesystemAuditKindK_EXEC_FILE, pid: 9, comm: "sh", n1: 3, data: comps("gradlew", "A", "work")},
			want: record{Kind: "exec-file", PID: 9, Comm: "sh", Path: "/work/A/gradlew"},
		},
		{
			name: "write to a memfd",
			ev: event{kind: filesystemAuditKindK_WRITE, comm: "python3", marks: markInternal,
				data: []byte("/memfd:/usr/bin/x (deleted)\x00")},
			want: record{Kind: "write", Comm: "python3", Path: "memfd:/usr/bin/x", Memfd: true},
		},
		{
			name: "exec file, a memfd",
			ev:   event{kind: filesystemAuditKindK_EXEC_FILE, comm: "python3", marks: markInternal, n1: 1, data: comps("memfd:/usr/bin/x")},
			want: record{Kind: "exec-file", Comm: "python3", Path: "memfd:/usr/bin/x", Memfd: true},
		},
		{
			name: "write to a pipe",
			ev:   event{kind: filesystemAuditKindK_WRITE, comm: "sh", marks: markInternal, data: []byte("pipe:[123]\x00")},
			want: record{Kind: "write", Comm: "sh", Path: "pipe:[123]"},
		},
		{
			name: "attr through a memfd's descriptor (futimens)",
			ev: event{kind: filesystemAuditKindK_ATTR, comm: "touch", bases: 1, mode: 1, marks: markInternal,
				data: append([]byte("\x00"), comps("memfd:x")...)},
			want: record{Kind: "attr", Comm: "touch", Path: "memfd:x", Memfd: true},
		},
		{
			name: "attr on a name under a deleted directory keeps it unmarked",
			ev: event{kind: filesystemAuditKindK_ATTR, comm: "touch", bases: 1, mode: 2, marks: markUnlinked,
				data: append([]byte("f\x00"), comps("d", "tmp")...)},
			want: record{Kind: "attr", Comm: "touch", Path: "/tmp/d/f", Name: "f"},
		},
		{
			name: "link of an O_TMPFILE",
			ev: event{kind: filesystemAuditKindK_LINK, comm: "py", marks: markUnlinked, n1: 2, n2: 2,
				data: append(comps("#12", "tmp"), comps("x", "tmp")...)},
			want: record{Kind: "link", Comm: "py", Path: "/tmp/#12", To: "/tmp/x", Deleted: true},
		},
		{
			name: "mmap of an io_uring ring",
			ev:   event{kind: filesystemAuditKindK_MMAP, comm: "node", marks: markInternal, n1: 1, data: comps("[io_uring]")},
			want: record{Kind: "mmap", Comm: "node", Path: "[io_uring]", Access: "r"},
		},
		{
			name: "chmod of a memfd",
			ev:   event{kind: filesystemAuditKindK_CHMOD, comm: "py", mode: 0o755, marks: markInternal, n1: 1, data: comps("memfd:x")},
			want: record{Kind: "chmod", Comm: "py", Path: "memfd:x", Mode: "0755", Memfd: true},
		},
		{
			name: "write to a deleted file named like a deleted one",
			ev: event{kind: filesystemAuditKindK_WRITE, comm: "sh", marks: markUnlinked,
				data: []byte("/tmp/x (deleted) (deleted)\x00")},
			want: record{Kind: "write", Comm: "sh", Path: "/tmp/x (deleted)", Deleted: true},
		},
		{
			name: "exec file, deleted",
			ev:   event{kind: filesystemAuditKindK_EXEC_FILE, comm: "sh", marks: markUnlinked, n1: 2, data: comps("payload", "tmp")},
			want: record{Kind: "exec-file", Comm: "sh", Path: "/tmp/payload", Deleted: true},
		},
		{
			name: "attr ok",
			ev:   event{kind: filesystemAuditKindK_ATTR, comm: "touch", data: []byte("/tmp/t\x00")},
			want: record{Kind: "attr", Comm: "touch", Path: "/tmp/t"},
		},
		{
			name: "truncated walk",
			ev:   event{kind: filesystemAuditKindK_UNLINK, comm: "rm", n1: 1, truncated: 1, data: comps("deep")},
			want: record{Kind: "unlink", Comm: "rm", Path: "…/deep"},
		},
		{
			name: "rename exchange",
			ev: event{kind: filesystemAuditKindK_RENAME, comm: "mv", flags: unix.RENAME_EXCHANGE, n1: 2, n2: 2,
				data: append(comps("a", "tmp"), comps("b", "tmp")...)},
			want: record{Kind: "rename", Comm: "mv", Path: "/tmp/a", To: "/tmp/b", Exchange: true},
		},
		{
			// Only the rename target was truncated; the source must not
			// inherit the mark.
			name: "rename, only target truncated",
			ev:   event{kind: filesystemAuditKindK_RENAME, comm: "mv", n1: 2, n2: 1, trunc2: 1, data: append(comps("a", "tmp"), comps("b")...)},
			want: record{Kind: "rename", Comm: "mv", Path: "/tmp/a", To: "…/b"},
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, err := decode(c.ev.bytes())
			if err != nil {
				t.Fatal(err)
			}
			if got != c.want {
				t.Errorf("decode mismatch\n got: %+v\nwant: %+v", got, c.want)
			}
		})
	}
}

// Malformed samples must decode to a record or an error, never a panic: the
// ring-buffer bytes are trusted only as far as the kernel wrote them, and the
// fixed-length offsets (a symlink body length, a second path after a NUL) have
// to stay in range even when a sample does not match the layout.
func TestDecodeMalformed(t *testing.T) {
	cases := map[string][]byte{
		"empty":             {},
		"short header":      make([]byte, hdrLen-1),
		"bare header":       make([]byte, hdrLen),
		"symlink bad off":   event{kind: filesystemAuditKindK_SYMLINK, pathRet: 1 << 20, n1: 2, data: []byte("x\x00y\x00")}.bytes(),
		"rename no NUL":     event{kind: filesystemAuditKindK_RENAME_FAILED, n1: 1, data: []byte("no-terminator")}.bytes(),
		"components run-on": event{kind: filesystemAuditKindK_RENAME, n1: 5, n2: 5, data: comps("a", "b")}.bytes(),
	}
	for name, raw := range cases {
		t.Run(name, func(t *testing.T) {
			_, _ = decode(raw) // only that it returns rather than panicking
		})
	}
}

func FuzzDecode(f *testing.F) {
	for _, raw := range [][]byte{
		{},
		make([]byte, hdrLen),
		event{kind: filesystemAuditKindK_SYMLINK, pathRet: 1 << 20, n1: 2, data: []byte("x\x00y\x00")}.bytes(),
		event{kind: filesystemAuditKindK_RENAME_FAILED, n1: 1, data: []byte("no-terminator")}.bytes(),
		// A base component count of 2^32-1 must not size an allocation.
		event{kind: filesystemAuditKindK_RENAME_FAILED, bases: 1, mode: 0xffffffff, data: []byte("a\x00b\x00")}.bytes(),
	} {
		f.Add(raw)
	}
	f.Fuzz(func(_ *testing.T, raw []byte) {
		_, _ = decode(raw)
	})
}

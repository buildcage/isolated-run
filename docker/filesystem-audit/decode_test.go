package main

import (
	"encoding/binary"
	"encoding/json"
	"reflect"
	"strings"
	"testing"
	"time"
	"unicode/utf8"
	"unsafe"

	"golang.org/x/sys/unix"
)

// event builds a raw sample matching struct event's layout in decode.go.
type event struct {
	kind, flags, mode         uint32
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
	le.PutUint32(b[0:], e.kind)
	le.PutUint32(b[4:], e.pid)
	le.PutUint32(b[8:], e.ppid)
	le.PutUint32(b[12:], e.flags)
	le.PutUint32(b[16:], e.mode)
	le.PutUint32(b[20:], uint32(e.pathRet))
	le.PutUint32(b[24:], e.bases)
	b[32], b[33], b[34], b[35] = e.n1, e.n2, e.truncated, e.trunc2
	copy(b[36:52], e.comm)
	le.PutUint32(b[52:], e.err)
	le.PutUint32(b[56:], e.marks)
	le.PutUint32(b[60:], e.gid)
	le.PutUint64(b[64:], e.boot)
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
	r, err := decode(event{kind: 3, n1: 2, err: 1, data: comps("f", "tmp")}.bytes())
	if err != nil {
		t.Fatal(err)
	}
	if r.Kind != "unlink" || r.Path != "/tmp/f" || !r.Failed || r.Err != 1 {
		t.Errorf("held refusal decode: %+v", r)
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
	r, err := decode(event{kind: 13, comm: "cat", boot: 123_456_789_000, data: []byte("/etc/hosts\x00")}.bytes())
	if err != nil {
		t.Fatal(err)
	}
	if r.boot != 123_456_789_000 {
		t.Fatalf("boot = %d, want 123456789000", r.boot)
	}
}

func TestWallTime(t *testing.T) {
	// 1.5 s after boot, with boot at 2026-10-06T00:00:00Z.
	offset := int64(1_791_244_800) * 1_000_000_000
	if got, want := wallTime(1_500_000_000, offset), "2026-10-06T00:00:01.500Z"; got != want {
		t.Fatalf("wallTime = %s, want %s", got, want)
	}
}

func TestBootOffset(t *testing.T) {
	off, err := bootOffset()
	if err != nil {
		t.Fatal(err)
	}
	var boot unix.Timespec
	if err := unix.ClockGettime(unix.CLOCK_BOOTTIME, &boot); err != nil {
		t.Fatal(err)
	}
	got, err := time.Parse(time.RFC3339Nano, wallTime(uint64(boot.Nano()), off))
	if err != nil {
		t.Fatal(err)
	}
	if d := time.Since(got); d < -time.Second || d > time.Second {
		t.Fatalf("boot time now converts to %s, %s from the wall clock", got, d)
	}
}

// decode reads the header by hand; this pins its offsets to the layout the
// compiler gave struct event.
func TestHeaderMatchesEvent(t *testing.T) {
	var e filesystemAuditEvent
	if got := unsafe.Offsetof(e.Marks); got != 56 {
		t.Fatalf("marks at %d, decode reads 56", got)
	}
	if got := unsafe.Offsetof(e.Gid); got != 60 {
		t.Fatalf("gid at %d, decode reads 60", got)
	}
	if got := unsafe.Offsetof(e.Ts); got != 64 {
		t.Fatalf("ts at %d, decode reads 64", got)
	}
	if got := unsafe.Offsetof(e.Data); got != hdrLen {
		t.Fatalf("data at %d, hdrLen is %d", got, hdrLen)
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
			ev:   event{kind: 1, pid: 7, ppid: 1, comm: "cat", flags: unix.O_RDONLY, data: []byte("/etc/passwd\x00")},
			want: record{Kind: "open", PID: 7, PPID: 1, Comm: "cat", Path: "/etc/passwd", Access: "r"},
		},
		{
			name: "open create+truncate",
			ev:   event{kind: 1, comm: "sh", flags: unix.O_WRONLY | unix.O_CREAT | unix.O_TRUNC, data: []byte("/tmp/x\x00")},
			want: record{Kind: "open", Comm: "sh", Path: "/tmp/x", Flags: unix.O_WRONLY | unix.O_CREAT | unix.O_TRUNC, Access: "wct"},
		},
		{
			name: "failed open",
			ev:   event{kind: 12, comm: "node", pathRet: int32(unix.ENOENT), data: []byte("/missing\x00")},
			want: record{Kind: "open", Comm: "node", Path: "/missing", Access: "r", Err: int32(unix.ENOENT), Failed: true},
		},
		{
			name: "failed open to write",
			ev: event{kind: 12, comm: "cp", pathRet: int32(unix.EACCES), flags: unix.O_WRONLY | unix.O_CREAT | unix.O_TRUNC,
				data: []byte("/usr/local/bin/tool\x00")},
			want: record{Kind: "open", Comm: "cp", Path: "/usr/local/bin/tool",
				Flags: unix.O_WRONLY | unix.O_CREAT | unix.O_TRUNC, Access: "wct", Err: int32(unix.EACCES), Failed: true},
		},
		{
			name: "open, path too long for d_path",
			ev: event{kind: 1, comm: "sh", flags: unix.O_WRONLY, pathRet: -int32(unix.ENAMETOOLONG),
				n1: 2, truncated: 1, data: comps("f", "d")},
			want: record{Kind: "open", Comm: "sh", Path: "…/d/f", Flags: unix.O_WRONLY, Access: "w"},
		},
		{
			name: "mknod",
			ev:   event{kind: 24, comm: "mkfifo", n1: 2, data: comps("p", "tmp")},
			want: record{Kind: "mknod", Comm: "mkfifo", Path: "/tmp/p"},
		},
		{
			name: "attr through a descriptor (futimens)",
			ev:   event{kind: 20, comm: "touch", bases: 1, mode: 2, data: append([]byte("\x00"), comps("f", "tmp")...)},
			want: record{Kind: "attr", Comm: "touch", Path: "/tmp/f"},
		},
		{
			name: "write",
			ev:   event{kind: 14, comm: "tee", data: []byte("/tmp/out\x00")},
			want: record{Kind: "write", Comm: "tee", Path: "/tmp/out"},
		},
		{
			name: "mmap exec",
			ev:   event{kind: 15, comm: "ld", mode: unix.PROT_READ | unix.PROT_EXEC, n1: 2, data: comps("libc.so", "lib")},
			want: record{Kind: "mmap", Comm: "ld", Path: "/lib/libc.so", Access: "x"},
		},
		{
			name: "mmap by an exec",
			ev:   event{kind: 15, comm: "sh", mode: unix.PROT_READ | unix.PROT_EXEC, pathRet: 1, n1: 3, data: comps("bash", "bin", "usr")},
			want: record{Kind: "mmap", Comm: "sh", Path: "/usr/bin/bash", Access: "x", Image: true},
		},
		{
			name: "rename",
			ev:   event{kind: 5, comm: "mv", n1: 2, n2: 2, data: append(comps("a", "tmp"), comps("b", "tmp")...)},
			want: record{Kind: "rename", Comm: "mv", Path: "/tmp/a", To: "/tmp/b"},
		},
		{
			name: "unlink",
			ev:   event{kind: 3, comm: "rm", n1: 2, data: comps("f", "tmp")},
			want: record{Kind: "unlink", Comm: "rm", Path: "/tmp/f"},
		},
		{
			name: "failed unlink, read-only",
			ev:   event{kind: 16, comm: "rm", pathRet: int32(unix.EROFS), data: []byte("/etc\x00")},
			want: record{Kind: "unlink", Comm: "rm", Path: "/etc", Err: int32(unix.EROFS), Failed: true},
		},
		{
			name: "failed rmdir",
			ev:   event{kind: 25, comm: "rmdir", pathRet: int32(unix.ENOTEMPTY), data: []byte("/tmp/d\x00")},
			want: record{Kind: "rmdir", Comm: "rmdir", Path: "/tmp/d", Err: int32(unix.ENOTEMPTY), Failed: true},
		},
		{
			name: "failed rename, two paths",
			ev:   event{kind: 17, comm: "mv", pathRet: int32(unix.ENOENT), n1: 1, data: []byte("/a\x00/b\x00")},
			want: record{Kind: "rename", Comm: "mv", Path: "/a", To: "/b", Err: int32(unix.ENOENT), Failed: true},
		},
		{
			name: "failed mkdir on a read-only mount",
			ev:   event{kind: 26, comm: "mkdir", pathRet: int32(unix.EROFS), data: []byte("/opt/x\x00")},
			want: record{Kind: "mkdir", Comm: "mkdir", Path: "/opt/x", Err: int32(unix.EROFS), Failed: true},
		},
		{
			name: "failed mkdir, relative to the cwd",
			ev: event{kind: 26, comm: "mkdir", pathRet: int32(unix.EROFS), bases: 1, mode: 1,
				data: append([]byte("x\x00"), comps("opt")...)},
			want: record{Kind: "mkdir", Comm: "mkdir", Path: "/opt/x", Name: "x", Err: int32(unix.EROFS), Failed: true},
		},
		{
			name: "failed link, the new name relative to its base",
			ev: event{kind: 29, comm: "ln", pathRet: int32(unix.EROFS), n1: 1, bases: 2, flags: 1,
				data: append([]byte("/a\x00b\x00"), comps("bin")...)},
			want: record{Kind: "link", Comm: "ln", Path: "/a", To: "/bin/b", ToName: "b", Err: int32(unix.EROFS), Failed: true},
		},
		{
			name: "failed mknod",
			ev:   event{kind: 27, comm: "mkfifo", pathRet: int32(unix.EROFS), data: []byte("/opt/p\x00")},
			want: record{Kind: "mknod", Comm: "mkfifo", Path: "/opt/p", Err: int32(unix.EROFS), Failed: true},
		},
		{
			name: "failed symlink, by the link's name",
			ev:   event{kind: 28, comm: "ln", pathRet: int32(unix.EROFS), data: []byte("/usr/local/bin/foo\x00")},
			want: record{Kind: "symlink", Comm: "ln", Path: "/usr/local/bin/foo", Err: int32(unix.EROFS), Failed: true},
		},
		{
			name: "failed truncate",
			ev:   event{kind: 30, comm: "sh", pathRet: int32(unix.EROFS), data: []byte("/etc/hosts\x00")},
			want: record{Kind: "truncate", Comm: "sh", Path: "/etc/hosts", Err: int32(unix.EROFS), Failed: true},
		},
		{
			name: "failed link, old name to new",
			ev:   event{kind: 29, comm: "ln", pathRet: int32(unix.EROFS), n1: 1, data: []byte("/a\x00/b\x00")},
			want: record{Kind: "link", Comm: "ln", Path: "/a", To: "/b", Err: int32(unix.EROFS), Failed: true},
		},
		{
			name: "fork",
			ev:   event{kind: 22, pid: 9, ppid: 7, comm: "bash"},
			want: record{Kind: "fork", PID: 9, PPID: 7, Comm: "bash"},
		},
		{
			name: "failed unlink, relative to a dirfd",
			ev: event{kind: 16, comm: "go", pathRet: int32(unix.ENOENT), bases: 1, mode: 2,
				data: append([]byte("b001\x00"), comps("go-build1", "tmp")...)},
			want: record{Kind: "unlink", Comm: "go", Path: "/tmp/go-build1/b001", Name: "b001", Err: int32(unix.ENOENT), Failed: true},
		},
		{
			name: "failed open, relative to the cwd",
			ev: event{kind: 12, comm: "asm", pathRet: int32(unix.ENOENT), bases: 1, mode: 2,
				data: append([]byte("./textflag.h\x00"), comps("runtime", "src")...)},
			want: record{Kind: "open", Comm: "asm", Path: "/src/runtime/textflag.h", Name: "./textflag.h", Access: "r", Err: int32(unix.ENOENT), Failed: true},
		},
		{
			// Joined as passed: cleaning would drop "link/..", and with it the
			// symlink the kernel followed.
			name: "failed chmod, relative through a symlink",
			ev: event{kind: 18, comm: "chmod", pathRet: int32(unix.EPERM), bases: 1, mode: 1, flags: 0o104755,
				data: append([]byte("l/../hosts\x00"), comps("work")...)},
			want: record{Kind: "chmod", Comm: "chmod", Path: "/work/l/../hosts", Name: "l/../hosts", Mode: "4755", Err: int32(unix.EPERM), Failed: true},
		},
		{
			name: "failed chown",
			ev:   event{kind: 19, comm: "chown", pathRet: int32(unix.ENOENT), flags: 1001, mode: 7, gid: 121, data: []byte("/etc/x\x00")},
			want: record{Kind: "chown", Comm: "chown", Path: "/etc/x", Owner: "1001:121", Err: int32(unix.ENOENT), Failed: true},
		},
		{
			name: "chown of the group alone",
			ev:   event{kind: 11, comm: "chgrp", flags: 0xffffffff, mode: 121, n1: 2, data: comps("f", "tmp")},
			want: record{Kind: "chown", Comm: "chgrp", Path: "/tmp/f", Owner: "-1:121"},
		},
		{
			name: "relative to the root",
			ev:   event{kind: 21, comm: "touch", pathRet: int32(unix.EROFS), bases: 1, data: []byte("etc\x00")},
			want: record{Kind: "attr", Comm: "touch", Path: "/etc", Name: "etc", Err: int32(unix.EROFS), Failed: true},
		},
		{
			name: "relative under a truncated base",
			ev: event{kind: 16, comm: "rm", pathRet: int32(unix.ENOENT), bases: 1, mode: 1, truncated: 1,
				data: append([]byte("x\x00"), comps("deep")...)},
			want: record{Kind: "unlink", Comm: "rm", Path: "…/deep/x", Name: "x", Err: int32(unix.ENOENT), Failed: true},
		},
		{
			name: "relative with no base walked",
			ev:   event{kind: 16, comm: "rm", pathRet: int32(unix.EBADF), data: []byte("x\x00")},
			want: record{Kind: "unlink", Comm: "rm", Path: "x", Err: int32(unix.EBADF), Failed: true},
		},
		{
			name: "failed rename, each name on its own base",
			ev: event{kind: 17, comm: "mv", pathRet: int32(unix.EXDEV), n1: 1, bases: 3, mode: 1, flags: 1,
				data: append(append([]byte("a\x00b\x00"), comps("src")...), comps("dst")...)},
			want: record{Kind: "rename", Comm: "mv", Path: "/src/a", To: "/dst/b", Name: "a", ToName: "b", Err: int32(unix.EXDEV), Failed: true},
		},
		{
			name: "failed rename, only the new name relative",
			ev: event{kind: 17, comm: "mv", pathRet: int32(unix.ENOENT), n1: 1, bases: 2, flags: 1,
				data: append([]byte("/a\x00b\x00"), comps("dst")...)},
			want: record{Kind: "rename", Comm: "mv", Path: "/a", To: "/dst/b", ToName: "b", Err: int32(unix.ENOENT), Failed: true},
		},
		{
			name: "exec",
			ev:   event{kind: 2, pid: 9, comm: "true", data: []byte("/bin/true\x00")},
			want: record{Kind: "exec", PID: 9, Comm: "true", Path: "/bin/true"},
		},
		{
			name: "chown",
			ev:   event{kind: 11, comm: "chown", flags: 1001, mode: 121, n1: 2, data: comps("f", "tmp")},
			want: record{Kind: "chown", Comm: "chown", Path: "/tmp/f", Owner: "1001:121"},
		},
		{
			name: "exec file, resolved",
			ev:   event{kind: 23, pid: 9, comm: "sh", n1: 3, data: comps("gradlew", "A", "work")},
			want: record{Kind: "exec-file", PID: 9, Comm: "sh", Path: "/work/A/gradlew"},
		},
		{
			name: "write to a memfd",
			ev: event{kind: 14, comm: "python3", marks: markInternal,
				data: []byte("/memfd:/usr/bin/x (deleted)\x00")},
			want: record{Kind: "write", Comm: "python3", Path: "memfd:/usr/bin/x", Memfd: true},
		},
		{
			name: "exec file, a memfd",
			ev:   event{kind: 23, comm: "python3", marks: markInternal, n1: 1, data: comps("memfd:/usr/bin/x")},
			want: record{Kind: "exec-file", Comm: "python3", Path: "memfd:/usr/bin/x", Memfd: true},
		},
		{
			name: "write to a pipe",
			ev:   event{kind: 14, comm: "sh", marks: markInternal, data: []byte("pipe:[123]\x00")},
			want: record{Kind: "write", Comm: "sh", Path: "pipe:[123]"},
		},
		{
			name: "attr through a memfd's descriptor (futimens)",
			ev: event{kind: 20, comm: "touch", bases: 1, mode: 1, marks: markInternal,
				data: append([]byte("\x00"), comps("memfd:x")...)},
			want: record{Kind: "attr", Comm: "touch", Path: "memfd:x", Memfd: true},
		},
		{
			name: "attr on a name under a deleted directory keeps it unmarked",
			ev: event{kind: 20, comm: "touch", bases: 1, mode: 2, marks: markUnlinked,
				data: append([]byte("f\x00"), comps("d", "tmp")...)},
			want: record{Kind: "attr", Comm: "touch", Path: "/tmp/d/f", Name: "f"},
		},
		{
			name: "link of an O_TMPFILE",
			ev: event{kind: 9, comm: "py", marks: markUnlinked, n1: 2, n2: 2,
				data: append(comps("#12", "tmp"), comps("x", "tmp")...)},
			want: record{Kind: "link", Comm: "py", Path: "/tmp/#12", To: "/tmp/x", Deleted: true},
		},
		{
			name: "mmap of an io_uring ring",
			ev:   event{kind: 15, comm: "node", marks: markInternal, n1: 1, data: comps("[io_uring]")},
			want: record{Kind: "mmap", Comm: "node", Path: "[io_uring]", Access: "r"},
		},
		{
			name: "chmod of a memfd",
			ev:   event{kind: 7, comm: "py", mode: 0o755, marks: markInternal, n1: 1, data: comps("memfd:x")},
			want: record{Kind: "chmod", Comm: "py", Path: "memfd:x", Mode: "0755", Memfd: true},
		},
		{
			name: "write to a deleted file named like a deleted one",
			ev: event{kind: 14, comm: "sh", marks: markUnlinked,
				data: []byte("/tmp/x (deleted) (deleted)\x00")},
			want: record{Kind: "write", Comm: "sh", Path: "/tmp/x (deleted)", Deleted: true},
		},
		{
			name: "exec file, deleted",
			ev:   event{kind: 23, comm: "sh", marks: markUnlinked, n1: 2, data: comps("payload", "tmp")},
			want: record{Kind: "exec-file", Comm: "sh", Path: "/tmp/payload", Deleted: true},
		},
		{
			name: "attr ok",
			ev:   event{kind: 20, comm: "touch", data: []byte("/tmp/t\x00")},
			want: record{Kind: "attr", Comm: "touch", Path: "/tmp/t"},
		},
		{
			name: "truncated walk",
			ev:   event{kind: 3, comm: "rm", n1: 1, truncated: 1, data: comps("deep")},
			want: record{Kind: "unlink", Comm: "rm", Path: "…/deep"},
		},
		{
			name: "rename exchange",
			ev: event{kind: 5, comm: "mv", flags: unix.RENAME_EXCHANGE, n1: 2, n2: 2,
				data: append(comps("a", "tmp"), comps("b", "tmp")...)},
			want: record{Kind: "rename", Comm: "mv", Path: "/tmp/a", To: "/tmp/b", Exchange: true},
		},
		{
			// Only the rename target was truncated; the source must not
			// inherit the mark.
			name: "rename, only target truncated",
			ev:   event{kind: 5, comm: "mv", n1: 2, n2: 1, trunc2: 1, data: append(comps("a", "tmp"), comps("b")...)},
			want: record{Kind: "rename", Comm: "mv", Path: "/tmp/a", To: "…/b"},
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, err := decode(c.ev.bytes())
			if err != nil {
				t.Fatal(err)
			}
			got.Time = "" // stamped by the caller, not decode
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
		"symlink bad off":   event{kind: 8, pathRet: 1 << 20, n1: 2, data: []byte("x\x00y\x00")}.bytes(),
		"rename no NUL":     event{kind: 17, n1: 1, data: []byte("no-terminator")}.bytes(),
		"components run-on": event{kind: 5, n1: 5, n2: 5, data: comps("a", "b")}.bytes(),
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
		event{kind: 8, pathRet: 1 << 20, n1: 2, data: []byte("x\x00y\x00")}.bytes(),
		event{kind: 17, n1: 1, data: []byte("no-terminator")}.bytes(),
		// A base component count of 2^32-1 must not size an allocation.
		event{kind: 17, bases: 1, mode: 0xffffffff, data: []byte("a\x00b\x00")}.bytes(),
	} {
		f.Add(raw)
	}
	f.Fuzz(func(_ *testing.T, raw []byte) {
		_, _ = decode(raw)
	})
}

func TestRecordJSONKeepsBytesThatAreNotUTF8(t *testing.T) {
	r := record{Kind: "open", Comm: "c\xff", Path: "/tmp/a\xfe\xc3\xa9<", To: "\xed\xb3\xbf"}
	got, err := json.Marshal(r)
	if err != nil {
		t.Fatal(err)
	}
	want := `{"t":"","kind":"open","pid":0,"ppid":0,"comm":"c\udcff","path":"/tmp/a\udcfeé\u003c","to":"\udced\udcb3\udcbf"}`
	if string(got) != want {
		t.Fatalf("got  %s\nwant %s", got, want)
	}
}

// A record with a name that is not UTF-8 is written field for field as
// encoding/json writes record, every field set, but for that name's byte.
func TestRecordJSONMatchesItsFields(t *testing.T) {
	type plain record
	var r record
	v := reflect.ValueOf(&r).Elem()
	for i := range v.NumField() {
		f := v.Field(i)
		if !f.CanSet() {
			continue
		}
		switch f.Kind() {
		case reflect.String:
			f.SetString(v.Type().Field(i).Name)
		case reflect.Uint32:
			f.SetUint(1)
		case reflect.Int32:
			f.SetInt(1)
		case reflect.Bool:
			f.SetBool(true)
		default:
			t.Fatalf("field %s: set it here", v.Type().Field(i).Name)
		}
	}
	r.Comm = "c\xff"
	got, err := json.Marshal(r)
	if err != nil {
		t.Fatal(err)
	}
	want, err := json.Marshal(plain(r))
	if err != nil {
		t.Fatal(err)
	}
	if w := strings.Replace(string(want), "c"+string(utf8.RuneError), `c\udcff`, 1); string(got) != w {
		t.Fatalf("got  %s\nwant %s", got, w)
	}
}

func TestExecFilesAttach(t *testing.T) {
	files := execFiles{}
	if !files.attach(&record{Kind: "exec-file", PID: 9, Path: "/work/A/gradlew"}) {
		t.Fatal("an exec-file record should be dropped")
	}
	other := record{Kind: "exec", PID: 7, Path: "/usr/bin/env"}
	if files.attach(&other) || other.Path != "/usr/bin/env" || other.Name != "" {
		t.Fatalf("an exec with no resolved file changed: %+v", other)
	}
	exec := record{Kind: "exec", PID: 9, Path: "./gradlew"}
	if files.attach(&exec) {
		t.Fatal("an exec record should be kept")
	}
	if exec.Path != "/work/A/gradlew" || exec.Name != "./gradlew" {
		t.Fatalf("exec = %+v, want the resolved path with the name it was run by", exec)
	}
	if _, left := files[9]; left {
		t.Fatal("the resolved file should be used once")
	}
	if files.attach(&record{Kind: "read", PID: 9, Path: "/etc/hosts"}) {
		t.Fatal("other records should be kept")
	}
	files.attach(&record{Kind: "exec-file", PID: 9, Path: "memfd:x", Memfd: true})
	memfd := record{Kind: "exec", PID: 9, Path: "/dev/fd/3"}
	files.attach(&memfd)
	if memfd.Path != "memfd:x" || !memfd.Memfd || memfd.Name != "/dev/fd/3" {
		t.Fatalf("exec = %+v, want the memfd it ran", memfd)
	}
}

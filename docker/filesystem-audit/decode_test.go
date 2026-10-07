package main

import (
	"encoding/binary"
	"testing"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"
)

// event builds a raw sample matching struct event's layout in decode.go.
type event struct {
	kind, flags, mode         uint32
	pathRet                   int32
	err                       uint32
	argsLen                   uint32
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
	le.PutUint32(b[24:], e.argsLen)
	b[32], b[33], b[34], b[35] = e.n1, e.n2, e.truncated, e.trunc2
	copy(b[36:52], e.comm)
	le.PutUint32(b[52:], e.err)
	le.PutUint64(b[56:], e.boot)
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
	if got := unsafe.Offsetof(e.Ts); got != 56 {
		t.Fatalf("ts at %d, decode reads 56", got)
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
			want: record{Kind: "open-failed", Comm: "node", Path: "/missing", Err: int32(unix.ENOENT)},
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
			name: "failed delete, read-only",
			ev:   event{kind: 16, comm: "rm", pathRet: int32(unix.EROFS), data: []byte("/etc\x00")},
			want: record{Kind: "delete", Comm: "rm", Path: "/etc", Err: int32(unix.EROFS), Failed: true},
		},
		{
			name: "failed rename, two paths",
			ev:   event{kind: 17, comm: "mv", pathRet: int32(unix.ENOENT), n1: 1, data: []byte("/a\x00/b\x00")},
			want: record{Kind: "rename", Comm: "mv", Path: "/a", To: "/b", Err: int32(unix.ENOENT), Failed: true},
		},
		{
			name: "fork",
			ev:   event{kind: 22, pid: 9, ppid: 7, comm: "bash"},
			want: record{Kind: "fork", PID: 9, PPID: 7, Comm: "bash"},
		},
		{
			name: "failed delete, relative to a dirfd",
			ev: event{kind: 16, comm: "go", pathRet: int32(unix.ENOENT), argsLen: 1, mode: 2,
				data: append([]byte("b001\x00"), comps("go-build1", "tmp")...)},
			want: record{Kind: "delete", Comm: "go", Path: "/tmp/go-build1/b001", Err: int32(unix.ENOENT), Failed: true},
		},
		{
			name: "failed open, relative to the cwd",
			ev: event{kind: 12, comm: "asm", pathRet: int32(unix.ENOENT), argsLen: 1, mode: 2,
				data: append([]byte("./textflag.h\x00"), comps("runtime", "src")...)},
			want: record{Kind: "open-failed", Comm: "asm", Path: "/src/runtime/textflag.h", Err: int32(unix.ENOENT)},
		},
		{
			name: "relative to the root",
			ev:   event{kind: 21, comm: "touch", pathRet: int32(unix.EROFS), argsLen: 1, data: []byte("etc\x00")},
			want: record{Kind: "attr", Comm: "touch", Path: "/etc", Err: int32(unix.EROFS), Failed: true},
		},
		{
			name: "relative under a truncated base",
			ev: event{kind: 16, comm: "rm", pathRet: int32(unix.ENOENT), argsLen: 1, mode: 1, truncated: 1,
				data: append([]byte("x\x00"), comps("deep")...)},
			want: record{Kind: "delete", Comm: "rm", Path: "…/deep/x", Err: int32(unix.ENOENT), Failed: true},
		},
		{
			name: "relative with no base walked",
			ev:   event{kind: 16, comm: "rm", pathRet: int32(unix.EBADF), data: []byte("x\x00")},
			want: record{Kind: "delete", Comm: "rm", Path: "x", Err: int32(unix.EBADF), Failed: true},
		},
		{
			name: "failed rename, each name on its own base",
			ev: event{kind: 17, comm: "mv", pathRet: int32(unix.EXDEV), n1: 1, argsLen: 3, mode: 1, flags: 1,
				data: append(append([]byte("a\x00b\x00"), comps("src")...), comps("dst")...)},
			want: record{Kind: "rename", Comm: "mv", Path: "/src/a", To: "/dst/b", Err: int32(unix.EXDEV), Failed: true},
		},
		{
			name: "failed rename, only the new name relative",
			ev: event{kind: 17, comm: "mv", pathRet: int32(unix.ENOENT), n1: 1, argsLen: 2, flags: 1,
				data: append([]byte("/a\x00b\x00"), comps("dst")...)},
			want: record{Kind: "rename", Comm: "mv", Path: "/a", To: "/dst/b", Err: int32(unix.ENOENT), Failed: true},
		},
		{
			name: "exec file, resolved",
			ev:   event{kind: 23, pid: 9, comm: "sh", n1: 3, data: comps("gradlew", "A", "work")},
			want: record{Kind: "exec-file", PID: 9, Comm: "sh", Path: "/work/A/gradlew"},
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

func TestExecArgs(t *testing.T) {
	data := make([]byte, pathLen)
	copy(data, "/bin/true\x00")
	args := []byte("true\x00--flag\x00arg\x00")
	data = append(data, args...)
	ev := event{kind: 2, comm: "true", argsLen: uint32(len(args)), data: data}
	got, err := decode(ev.bytes())
	if err != nil {
		t.Fatal(err)
	}
	if got.Path != "/bin/true" || got.Args != "true --flag arg" {
		t.Errorf("exec decode: path=%q args=%q", got.Path, got.Args)
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
	} {
		f.Add(raw)
	}
	f.Fuzz(func(_ *testing.T, raw []byte) {
		_, _ = decode(raw)
	})
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
}

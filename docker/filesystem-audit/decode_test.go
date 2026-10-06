package main

import (
	"encoding/binary"
	"testing"

	"golang.org/x/sys/unix"
)

// event builds a raw sample matching struct event's layout in decode.go.
type event struct {
	kind, flags, mode         uint32
	pathRet                   int32
	argsLen                   uint32
	n1, n2, truncated, trunc2 uint8
	pid, ppid                 uint32
	comm                      string
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
			got.TimeNs = 0 // stamped by the caller, not decode
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

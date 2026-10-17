package main

import (
	"encoding/binary"
	"testing"
	"unsafe"
)

// event builds a raw sample in struct event's layout.
type event struct {
	kind                      filesystemAuditKind
	flags, mode               uint32
	pathRet                   int32
	nr                        int32
	marks                     uint32
	gid, tid                  uint32
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
	le.PutUint32(b[offNr:], uint32(e.nr))
	le.PutUint32(b[offMarks:], e.marks)
	le.PutUint32(b[offGid:], e.gid)
	le.PutUint32(b[offTid:], e.tid)
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
		"nr":        {unsafe.Sizeof(e.Nr), 4},
		"marks":     {unsafe.Sizeof(e.Marks), 4},
		"gid":       {unsafe.Sizeof(e.Gid), 4},
		"ts":        {unsafe.Sizeof(e.Ts), 8},
	} {
		if c.got != c.want {
			t.Errorf("%s is %d bytes, decode reads %d", name, c.got, c.want)
		}
	}
}

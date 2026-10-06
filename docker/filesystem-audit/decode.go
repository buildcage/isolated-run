package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"strings"

	"golang.org/x/sys/unix"
)

// record is one line of the JSON output. Kind is the action; Path (and To,
// for the two-path operations) name the target; Access carries the open or
// mmap flags as letters; Failed and Err describe an operation that did not
// succeed.
type record struct {
	Time   string `json:"t"`
	Kind   string `json:"kind"`
	PID    uint32 `json:"pid"`
	PPID   uint32 `json:"ppid"`
	Comm   string `json:"comm"`
	Path   string `json:"path,omitempty"`
	To     string `json:"to,omitempty"`
	Access string `json:"access,omitempty"`
	Flags  uint32 `json:"flags,omitempty"`
	Args   string `json:"args,omitempty"`
	Err    int32  `json:"err,omitempty"`
	Failed bool   `json:"failed,omitempty"`
	// boot is the event's CLOCK_BOOTTIME stamp in nanoseconds; the reader
	// turns it into Time.
	boot uint64
}

// kindNames maps the kind field of struct event to a name. The failed path
// operations (16-21) decode to the base action name with Failed set.
var kindNames = map[uint32]string{
	1: "open", 2: "exec", 3: "unlink", 4: "rmdir", 5: "rename", 6: "mkdir",
	7: "chmod", 8: "symlink", 9: "link", 10: "truncate", 11: "chown",
	12: "open-failed", 13: "read", 14: "write", 15: "mmap",
	16: "delete", 17: "rename", 18: "chmod", 19: "chown", 20: "attr", 21: "attr",
}

// Mirrors the fixed header of struct event in bpf/filesystem_audit.bpf.c:
// eight u32 fields, four u8 fields, comm[16], a u32 pad, the u64 timestamp,
// then the data bytes.
const (
	hdrLen  = 8*4 + 4 + 16 + 4 + 8
	pathLen = 4096
)

const fmodeExec = 0x20 // FMODE_EXEC

func cstr(b []byte) string {
	if i := bytes.IndexByte(b, 0); i >= 0 {
		b = b[:i]
	}
	return string(b)
}

// components joins n NUL-terminated names stored leaf first into an absolute
// path, and returns the bytes left after them. A truncated walk is marked
// with a leading ellipsis.
func components(b []byte, n int, truncated bool) (string, []byte) {
	names := make([]string, 0, n) // leaf first; fewer than n if the buffer ran out
	for i := 0; i < n && len(b) > 0; i++ {
		j := bytes.IndexByte(b, 0)
		if j < 0 {
			j = len(b)
		}
		names = append(names, string(b[:j]))
		if j < len(b) {
			j++
		}
		b = b[j:]
	}
	for l, r := 0, len(names)-1; l < r; l, r = l+1, r-1 {
		names[l], names[r] = names[r], names[l]
	}
	prefix := "/"
	if truncated {
		prefix = "…/"
	}
	return prefix + strings.Join(names, "/"), b
}

// decode turns one raw ring-buffer sample into a record.
func decode(raw []byte) (record, error) {
	if len(raw) < hdrLen {
		return record{}, fmt.Errorf("short event: %d bytes", len(raw))
	}
	le := binary.LittleEndian
	kind := le.Uint32(raw[0:])
	flags := le.Uint32(raw[12:])
	mode := le.Uint32(raw[16:])
	pathRet := int32(le.Uint32(raw[20:]))
	argsLen := le.Uint32(raw[24:])
	n1, n2 := int(raw[32]), int(raw[33])
	truncated, truncated2 := raw[34] != 0, raw[35] != 0
	data := raw[hdrLen:]
	r := record{
		Kind: kindNames[kind],
		PID:  le.Uint32(raw[4:]),
		PPID: le.Uint32(raw[8:]),
		Comm: cstr(raw[36:52]),
		boot: le.Uint64(raw[56:]),
	}
	switch kind {
	case 1: // open
		if pathRet < 0 {
			r.Err = pathRet
		} else {
			r.Path = cstr(data)
		}
		r.Flags = flags
		r.Access = openAccess(flags, mode)
	case 12: // failed open
		r.Path = cstr(data)
		r.Err = pathRet // the positive errno the BPF side stored as -ret
	case 13, 14: // read, write
		if pathRet < 0 {
			r.Err = pathRet
		} else {
			r.Path = cstr(data)
		}
	case 15: // mmap
		r.Path, _ = components(data, n1, truncated)
		r.Access = mmapAccess(mode, flags)
	case 2: // exec
		r.Path = cstr(data)
		if int(pathLen+argsLen) <= len(data) {
			a := data[pathLen : pathLen+argsLen]
			r.Args = strings.TrimRight(strings.ReplaceAll(string(a), "\x00", " "), " ")
		}
	case 3, 4, 6, 10: // unlink, rmdir, mkdir, truncate
		r.Path, _ = components(data, n1, truncated)
	case 7: // chmod
		r.Path, _ = components(data, n1, truncated)
		r.Flags = mode
	case 11: // chown
		r.Path, _ = components(data, n1, truncated)
		r.Flags = flags
		r.Args = fmt.Sprintf("%d:%d", flags, mode)
	case 8: // symlink
		r.To = cstr(data)
		// pathRet is the link body's length, i.e. the offset of the path
		// components; clamp it so a malformed sample cannot slice out of range.
		off := int(pathRet)
		if off < 0 || off > len(data) {
			off = len(data)
		}
		r.Path, _ = components(data[off:], n1, truncated)
	case 5, 9: // rename, link
		var rest []byte
		r.Path, rest = components(data, n1, truncated)
		r.To, _ = components(rest, n2, truncated2)
	case 16, 18, 19: // failed delete / chmod / chown
		r.Path = cstr(data)
		r.Err = pathRet
		r.Failed = true
	case 17: // failed rename
		r.Path = cstr(data)
		// n1 == 1 marks a second path after the first one's NUL; guard the
		// offset so a sample without that NUL cannot slice out of range.
		if n1 == 1 && len(r.Path)+1 <= len(data) {
			r.To = cstr(data[len(r.Path)+1:])
		}
		r.Err = pathRet
		r.Failed = true
	case 20: // attr via utimes / setxattr
		r.Path = cstr(data)
	case 21: // failed attr via utimes / setxattr
		r.Path = cstr(data)
		r.Err = pathRet
		r.Failed = true
	}
	return r, nil
}

// openAccess renders an open's flags as letters: r/w/rw, plus c (create),
// t (truncate) and x (opened to be executed).
func openAccess(flags, mode uint32) string {
	var s string
	switch flags & unix.O_ACCMODE {
	case unix.O_RDONLY:
		s = "r"
	case unix.O_WRONLY:
		s = "w"
	default:
		s = "rw"
	}
	if flags&unix.O_CREAT != 0 {
		s += "c"
	}
	if flags&unix.O_TRUNC != 0 {
		s += "t"
	}
	if mode&fmodeExec != 0 {
		s += "x"
	}
	return s
}

// mmapAccess renders a mapping's protection as one letter: x for an
// executable mapping (a loaded library), w for a shared writable mapping,
// r otherwise.
func mmapAccess(prot, flags uint32) string {
	switch {
	case prot&unix.PROT_EXEC != 0:
		return "x"
	case prot&unix.PROT_WRITE != 0 && flags&unix.MAP_SHARED != 0:
		return "w"
	default:
		return "r"
	}
}

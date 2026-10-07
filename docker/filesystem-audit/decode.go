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
	Time string `json:"t"`
	Kind string `json:"kind"`
	PID  uint32 `json:"pid"`
	PPID uint32 `json:"ppid"`
	Comm string `json:"comm"`
	Path string `json:"path,omitempty"`
	// Name is the name the command passed, where Path is not that name as
	// written: the file an exec resolved to, or a passed name joined to its
	// directory. ToName is the same for To.
	Name   string `json:"name,omitempty"`
	To     string `json:"to,omitempty"`
	ToName string `json:"to_name,omitempty"`
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
	22: "fork", 23: "exec-file", 24: "mknod",
}

// Mirrors the fixed header of struct event in bpf/filesystem_audit.bpf.c:
// eight u32 fields, four u8 fields, comm[16], a u32 err, the u64 timestamp,
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

// after returns what follows a NUL-terminated name of length n, or nothing
// when the sample ends first.
func after(b []byte, n int) []byte {
	if n+1 > len(b) {
		return nil
	}
	return b[n+1:]
}

// joinBase prefixes a relative name with the base directory the BPF side
// walked for it, whose n components lead rest; has says one was walked. It
// joins them as they are: cleaning "dir/link/.." would drop a symlink the
// kernel followed, and the name's own spelling is part of what it records.
func joinBase(name string, rest []byte, has bool, n int, truncated bool) (string, []byte) {
	if !has {
		return name, rest
	}
	base, rest := components(rest, n, truncated)
	if name == "" { // futimens: the descriptor's own path
		return base, rest
	}
	return strings.TrimSuffix(base, "/") + "/" + name, rest
}

// tidy drops the spellings that never change where a path leads: a "."
// segment or a repeated slash before the last name. A trailing "/" or "/."
// stays, since it makes the kernel follow a final symlink, and ".." stays,
// since through a symlink it leads somewhere a lexical clean would not.
func tidy(p string) string {
	parts := strings.Split(p, "/")
	kept := make([]string, 0, len(parts))
	for i, part := range parts {
		last := i == len(parts)-1
		if !last && i > 0 && (part == "." || part == "") {
			continue
		}
		kept = append(kept, part)
	}
	return strings.Join(kept, "/")
}

// filePath decodes an open, read or write's path: the d_path string, or, for
// one too long for d_path, the dentry components the BPF side walked instead
// (n > 0). With neither, the d_path errno is all there is.
func filePath(data []byte, pathRet int32, n int, truncated bool) (string, int32) {
	if pathRet >= 0 {
		return cstr(data), 0
	}
	if n > 0 {
		p, _ := components(data, n, truncated)
		return p, 0
	}
	return "", pathRet
}

// passedName returns the name the command passed, for Name or ToName, when
// it differs from the path recorded for it.
func passedName(name, p string) string {
	if name == p {
		return ""
	}
	return name
}

// passed decodes a name the command passed, followed by its base directory if
// any, into its tidied path and, where that differs, the name itself.
func passed(data []byte, has bool, n int, truncated bool) (string, string) {
	name := cstr(data)
	p, _ := joinBase(name, after(data, len(name)), has, n, truncated)
	p = tidy(p)
	return p, passedName(name, p)
}

// execFiles holds each process's resolved exec target until its exec record
// arrives.
type execFiles map[uint32]string

// attach takes in an exec-file record, keeping its path for the exec that
// follows, and reports true so the caller drops it. An exec record gets that
// path, with the name it was run by moved to Name.
func (f execFiles) attach(r *record) bool {
	switch r.Kind {
	case "exec-file":
		f[r.PID] = r.Path
		return true
	case "exec":
		if p, ok := f[r.PID]; ok {
			delete(f, r.PID)
			r.Name, r.Path = r.Path, p
		}
	}
	return false
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
	// A held path change its syscall refused carries the errno; its path and
	// kind are as for one that succeeded.
	if heldErr := le.Uint32(raw[52:]); heldErr != 0 {
		r.Err = int32(heldErr)
		r.Failed = true
	}
	switch kind {
	case 1: // open
		r.Path, r.Err = filePath(data, pathRet, n1, truncated)
		r.Flags = flags
		r.Access = openAccess(flags, mode)
	case 12: // failed open
		r.Path, r.Name = passed(data, argsLen&1 != 0, int(mode), truncated)
		r.Err = pathRet // the positive errno the BPF side stored as -ret
	case 13, 14: // read, write
		r.Path, r.Err = filePath(data, pathRet, n1, truncated)
	case 15: // mmap
		r.Path, _ = components(data, n1, truncated)
		r.Access = mmapAccess(mode, flags)
	case 2: // exec
		r.Path = cstr(data)
		if int(pathLen+argsLen) <= len(data) {
			a := data[pathLen : pathLen+argsLen]
			r.Args = strings.TrimRight(strings.ReplaceAll(string(a), "\x00", " "), " ")
		}
	case 3, 4, 6, 10, 23, 24: // unlink, rmdir, mkdir, truncate, exec-file, mknod
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
		r.Path, r.Name = passed(data, argsLen&1 != 0, int(mode), truncated)
		r.Err = pathRet
		r.Failed = true
	case 17: // failed rename
		// n1 == 1 marks a second name after the first; both come before the
		// base directories.
		name := cstr(data)
		rest := after(data, len(name))
		to := ""
		if n1 == 1 {
			to = cstr(rest)
			rest = after(rest, len(to))
		}
		r.Path, rest = joinBase(name, rest, argsLen&1 != 0, int(mode), truncated)
		r.Path = tidy(r.Path)
		r.Name = passedName(name, r.Path)
		if n1 == 1 {
			r.To, _ = joinBase(to, rest, argsLen&2 != 0, int(flags), truncated2)
			r.To = tidy(r.To)
			r.ToName = passedName(to, r.To)
		}
		r.Err = pathRet
		r.Failed = true
	case 20: // attr via utimes / setxattr
		r.Path, r.Name = passed(data, argsLen&1 != 0, int(mode), truncated)
	case 21: // failed attr via utimes / setxattr
		r.Path, r.Name = passed(data, argsLen&1 != 0, int(mode), truncated)
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

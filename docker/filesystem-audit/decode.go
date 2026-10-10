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
	Owner  string `json:"owner,omitempty"`
	Err    int32  `json:"err,omitempty"`
	Failed bool   `json:"failed,omitempty"`
	// Image marks a mapping the kernel made while starting a program: the
	// program itself, its dynamic loader, or a script's interpreter.
	Image bool `json:"image,omitempty"`
	// Memfd marks a memfd, whose Path is "memfd:" and the name its creator
	// chose; Deleted a file unlinked while in use, or an O_TMPFILE.
	Memfd   bool `json:"memfd,omitempty"`
	Deleted bool `json:"deleted,omitempty"`
	// Exchange marks a rename that swapped Path and To (RENAME_EXCHANGE).
	Exchange bool `json:"exchange,omitempty"`
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
// eight u32 fields, four u8 fields, comm[16], u32 err and marks, padding to
// align the u64 timestamp, then the data bytes.
const hdrLen = 8*4 + 4 + 16 + 4 + 4 + 4 + 8

const (
	markInternal = 1
	markUnlinked = 2
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
	// Leaf first; fewer than n if the buffer ran out. Each takes at least its
	// NUL, so b bounds the count however large n is.
	names := make([]string, 0, min(n, len(b)+1))
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

// filePath decodes an open, read or write's path: the d_path string, or the
// dentry components walked for one too long for it (n > 0); with neither,
// only the errno.
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

// applyMarks sets Memfd or Deleted from the BPF side's marks and drops the
// " (deleted)" d_path appended (dpath), so Path holds the name alone. Another
// kernel-internal file, such as a pipe or an io_uring ring, is left relative,
// as no path leads to it.
func applyMarks(r *record, marks uint32, dpath bool) {
	if marks&markInternal != 0 {
		name := strings.TrimPrefix(r.Path, "/")
		if dpath {
			name = strings.TrimSuffix(name, " (deleted)")
		}
		r.Path, r.Memfd = name, strings.HasPrefix(name, "memfd:")
		return
	}
	if marks&markUnlinked != 0 {
		if dpath {
			r.Path = strings.TrimSuffix(r.Path, " (deleted)")
		}
		r.Deleted = true
	}
}

// execFiles holds each process's resolved exec target until its exec record
// arrives.
type execFiles map[uint32]record

// attach takes in an exec-file record, keeping its path for the exec that
// follows, and reports true so the caller drops it. An exec record gets that
// path, with the name it was run by moved to Name.
func (f execFiles) attach(r *record) bool {
	switch r.Kind {
	case "exec-file":
		f[r.PID] = *r
		return true
	case "exec":
		if t, ok := f[r.PID]; ok {
			delete(f, r.PID)
			r.Name, r.Path, r.Memfd, r.Deleted = r.Path, t.Path, t.Memfd, t.Deleted
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
	bases := le.Uint32(raw[24:])
	n1, n2 := int(raw[32]), int(raw[33])
	truncated, truncated2 := raw[34] != 0, raw[35] != 0
	data := raw[hdrLen:]
	marks := le.Uint32(raw[56:])
	r := record{
		Kind: kindNames[kind],
		PID:  le.Uint32(raw[4:]),
		PPID: le.Uint32(raw[8:]),
		Comm: cstr(raw[36:52]),
		boot: le.Uint64(raw[64:]),
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
		applyMarks(&r, marks, pathRet >= 0)
		r.Flags = flags
		r.Access = openAccess(flags, mode)
	case 12: // failed open
		r.Path, r.Name = passed(data, bases&1 != 0, int(mode), truncated)
		r.Err = pathRet // the positive errno the BPF side stored as -ret
	case 13, 14: // read, write
		r.Path, r.Err = filePath(data, pathRet, n1, truncated)
		applyMarks(&r, marks, pathRet >= 0)
	case 15: // mmap
		r.Path, _ = components(data, n1, truncated)
		applyMarks(&r, marks, false)
		r.Access = mmapAccess(mode, flags)
		r.Image = pathRet == 1
	case 2: // exec
		r.Path = cstr(data)
	case 3, 4, 6, 24: // unlink, rmdir, mkdir, mknod
		r.Path, _ = components(data, n1, truncated)
	case 10, 23: // truncate, exec-file
		r.Path, _ = components(data, n1, truncated)
		applyMarks(&r, marks, false)
	case 7: // chmod
		r.Path, _ = components(data, n1, truncated)
		applyMarks(&r, marks, false)
		r.Flags = mode
	case 11: // chown
		r.Path, _ = components(data, n1, truncated)
		applyMarks(&r, marks, false)
		r.Owner = fmt.Sprintf("%d:%d", flags, mode)
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
		applyMarks(&r, marks, false) // only a link's source is marked
		r.Exchange = kind == 5 && flags&unix.RENAME_EXCHANGE != 0
	case 16, 18, 19: // failed delete / chmod / chown
		r.Path, r.Name = passed(data, bases&1 != 0, int(mode), truncated)
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
		r.Path, rest = joinBase(name, rest, bases&1 != 0, int(mode), truncated)
		r.Path = tidy(r.Path)
		r.Name = passedName(name, r.Path)
		if n1 == 1 {
			r.To, _ = joinBase(to, rest, bases&2 != 0, int(flags), truncated2)
			r.To = tidy(r.To)
			r.ToName = passedName(to, r.To)
		}
		r.Err = pathRet
		r.Failed = true
	case 20: // attr via utimes / setxattr
		r.Path, r.Name = passed(data, bases&1 != 0, int(mode), truncated)
	case 21: // failed attr via utimes / setxattr
		r.Path, r.Name = passed(data, bases&1 != 0, int(mode), truncated)
		r.Err = pathRet
		r.Failed = true
	}
	// futimens names no file, so its path is the descriptor's own.
	if (kind == 20 || kind == 21) && cstr(data) == "" {
		applyMarks(&r, marks, false)
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

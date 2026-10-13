package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"strconv"
	"strings"
	"unsafe"

	"golang.org/x/sys/unix"
)

// kindNames names each kind of struct event. A failed operation decodes to
// the name of the one that succeeded, with Failed set: the *_FAILED kinds, and
// any path change the kernel refused after its hook saw it.
var kindNames = [...]string{
	filesystemAuditKindK_OPEN:            "open",
	filesystemAuditKindK_EXEC:            "exec",
	filesystemAuditKindK_UNLINK:          "unlink",
	filesystemAuditKindK_RMDIR:           "rmdir",
	filesystemAuditKindK_RENAME:          "rename",
	filesystemAuditKindK_MKDIR:           "mkdir",
	filesystemAuditKindK_CHMOD:           "chmod",
	filesystemAuditKindK_SYMLINK:         "symlink",
	filesystemAuditKindK_LINK:            "link",
	filesystemAuditKindK_TRUNCATE:        "truncate",
	filesystemAuditKindK_CHOWN:           "chown",
	filesystemAuditKindK_OPEN_FAILED:     "open",
	filesystemAuditKindK_READ:            "read",
	filesystemAuditKindK_WRITE:           "write",
	filesystemAuditKindK_MMAP:            "mmap",
	filesystemAuditKindK_UNLINK_FAILED:   "unlink",
	filesystemAuditKindK_RENAME_FAILED:   "rename",
	filesystemAuditKindK_CHMOD_FAILED:    "chmod",
	filesystemAuditKindK_CHOWN_FAILED:    "chown",
	filesystemAuditKindK_ATTR:            "attr",
	filesystemAuditKindK_ATTR_FAILED:     "attr",
	filesystemAuditKindK_FORK:            "fork",
	filesystemAuditKindK_EXEC_FILE:       "exec-file",
	filesystemAuditKindK_MKNOD:           "mknod",
	filesystemAuditKindK_RMDIR_FAILED:    "rmdir",
	filesystemAuditKindK_MKDIR_FAILED:    "mkdir",
	filesystemAuditKindK_MKNOD_FAILED:    "mknod",
	filesystemAuditKindK_SYMLINK_FAILED:  "symlink",
	filesystemAuditKindK_LINK_FAILED:     "link",
	filesystemAuditKindK_TRUNCATE_FAILED: "truncate",
	filesystemAuditKindK_SYSCALL:         "syscall",
}

func kindName(kind filesystemAuditKind) string {
	if int(kind) < len(kindNames) {
		return kindNames[kind]
	}
	return ""
}

// Where struct event's fields sit in a sample, from the type bpf2go generates
// from bpf/event.h, so a change there moves them too.
const (
	offKind      = int(unsafe.Offsetof(filesystemAuditEvent{}.Kind))
	offPid       = int(unsafe.Offsetof(filesystemAuditEvent{}.Pid))
	offPpid      = int(unsafe.Offsetof(filesystemAuditEvent{}.Ppid))
	offFlags     = int(unsafe.Offsetof(filesystemAuditEvent{}.Flags))
	offMode      = int(unsafe.Offsetof(filesystemAuditEvent{}.Mode))
	offPathLen   = int(unsafe.Offsetof(filesystemAuditEvent{}.PathLen))
	offBases     = int(unsafe.Offsetof(filesystemAuditEvent{}.Bases))
	offN1        = int(unsafe.Offsetof(filesystemAuditEvent{}.N1))
	offN2        = int(unsafe.Offsetof(filesystemAuditEvent{}.N2))
	offTruncated = int(unsafe.Offsetof(filesystemAuditEvent{}.Truncated))
	offTrunc2    = int(unsafe.Offsetof(filesystemAuditEvent{}.Trunc2))
	offComm      = int(unsafe.Offsetof(filesystemAuditEvent{}.Comm))
	commLen      = len(filesystemAuditEvent{}.Comm)
	offErr       = int(unsafe.Offsetof(filesystemAuditEvent{}.Err))
	offMarks     = int(unsafe.Offsetof(filesystemAuditEvent{}.Marks))
	offGid       = int(unsafe.Offsetof(filesystemAuditEvent{}.Gid))
	offTs        = int(unsafe.Offsetof(filesystemAuditEvent{}.Ts))
	hdrLen       = int(unsafe.Offsetof(filesystemAuditEvent{}.Data))
)

const (
	markInternal   = 1
	markUnlinked   = 2
	markDescriptor = 4
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
	// Leaf first; fewer than n if the buffer ran out. Each takes at least a
	// byte of b, so b bounds the count however large n is.
	names := make([]string, 0, min(n, len(b)))
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
	if name == "" { // futimens, fchmod: the descriptor's own path
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

// decode turns one raw ring-buffer sample into a record.
func decode(raw []byte) (record, error) {
	if len(raw) < hdrLen {
		return record{}, fmt.Errorf("short event: %d bytes", len(raw))
	}
	le := binary.LittleEndian
	kind := filesystemAuditKind(le.Uint32(raw[offKind:]))
	flags := le.Uint32(raw[offFlags:])
	mode := le.Uint32(raw[offMode:])
	pathRet := int32(le.Uint32(raw[offPathLen:]))
	bases := le.Uint32(raw[offBases:])
	n1, n2 := int(raw[offN1]), int(raw[offN2])
	truncated, truncated2 := raw[offTruncated] != 0, raw[offTrunc2] != 0
	data := raw[hdrLen:]
	marks := le.Uint32(raw[offMarks:])
	gid := le.Uint32(raw[offGid:]) // a failed chown's; a held one's is in mode
	r := record{
		Kind: kindName(kind),
		PID:  le.Uint32(raw[offPid:]),
		PPID: le.Uint32(raw[offPpid:]),
		Comm: cstr(raw[offComm : offComm+commLen]),
		boot: le.Uint64(raw[offTs:]),
	}
	// A held path change or open its syscall refused carries the errno; its
	// path and kind are as for one that succeeded.
	if heldErr := le.Uint32(raw[offErr:]); heldErr != 0 {
		r.Err = int32(heldErr)
		r.Failed = true
	}
	switch kind {
	case filesystemAuditKindK_OPEN:
		var pathErr int32
		r.Path, pathErr = filePath(data, pathRet, n1, truncated)
		if !r.Failed {
			r.Err = pathErr
		}
		applyMarks(&r, marks, pathRet >= 0)
		r.Flags = flags
		r.Access = openAccess(flags, mode)
	case filesystemAuditKindK_OPEN_FAILED:
		r.Path, r.Name = passed(data, bases&1 != 0, int(mode), truncated)
		// n2 marks a name the BPF side had to cut, which lost its end.
		if n2 != 0 {
			r.Path += "…"
			if r.Name != "" {
				r.Name += "…"
			}
		}
		r.Err = pathRet // the positive errno the BPF side stored as -ret
		r.Flags = flags
		r.Access = openAccess(flags, 0)
		r.Failed = true
	case filesystemAuditKindK_READ, filesystemAuditKindK_WRITE:
		r.Path, r.Err = filePath(data, pathRet, n1, truncated)
		applyMarks(&r, marks, pathRet >= 0)
	case filesystemAuditKindK_MMAP:
		r.Path, _ = components(data, n1, truncated)
		applyMarks(&r, marks, false)
		r.Access = mmapAccess(mode, flags)
		r.Image = pathRet == 1
	case filesystemAuditKindK_EXEC:
		r.Path = cstr(data)
	case filesystemAuditKindK_UNLINK, filesystemAuditKindK_RMDIR, filesystemAuditKindK_MKDIR,
		filesystemAuditKindK_MKNOD:
		r.Path, _ = components(data, n1, truncated)
	case filesystemAuditKindK_TRUNCATE, filesystemAuditKindK_EXEC_FILE:
		r.Path, _ = components(data, n1, truncated)
		applyMarks(&r, marks, false)
	case filesystemAuditKindK_CHMOD:
		r.Path, _ = components(data, n1, truncated)
		applyMarks(&r, marks, false)
		r.Mode = permBits(mode)
	case filesystemAuditKindK_CHOWN:
		r.Path, _ = components(data, n1, truncated)
		applyMarks(&r, marks, false)
		r.Owner = owner(flags, mode)
	case filesystemAuditKindK_SYMLINK:
		r.To = cstr(data)
		// pathRet is the link body's length, i.e. the offset of the path
		// components; clamp it so a malformed sample cannot slice out of range.
		off := int(pathRet)
		if off < 0 || off > len(data) {
			off = len(data)
		}
		r.Path, _ = components(data[off:], n1, truncated)
	case filesystemAuditKindK_RENAME, filesystemAuditKindK_LINK:
		var rest []byte
		r.Path, rest = components(data, n1, truncated)
		r.To, _ = components(rest, n2, truncated2)
		applyMarks(&r, marks, false) // only a link's source is marked
		r.Exchange = kind == filesystemAuditKindK_RENAME && flags&unix.RENAME_EXCHANGE != 0
	case filesystemAuditKindK_UNLINK_FAILED, filesystemAuditKindK_CHMOD_FAILED,
		filesystemAuditKindK_CHOWN_FAILED, filesystemAuditKindK_RMDIR_FAILED,
		filesystemAuditKindK_MKDIR_FAILED, filesystemAuditKindK_MKNOD_FAILED,
		filesystemAuditKindK_SYMLINK_FAILED, filesystemAuditKindK_TRUNCATE_FAILED:
		r.Path, r.Name = passed(data, bases&1 != 0, int(mode), truncated)
		r.Err = pathRet
		r.Failed = true
		switch kind {
		case filesystemAuditKindK_CHMOD_FAILED:
			r.Mode = permBits(flags)
		case filesystemAuditKindK_CHOWN_FAILED:
			r.Owner = owner(flags, gid)
		}
	case filesystemAuditKindK_RENAME_FAILED, filesystemAuditKindK_LINK_FAILED: // from one name to another
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
	case filesystemAuditKindK_SYSCALL:
		r.Killed = mode == 1
		// Under the audit, seccomp kills only a 32-bit syscall.
		r.Compat = r.Killed
		r.Syscall = syscallName(int64(flags), r.Compat)
		r.Err = pathRet
		r.Failed = true
	case filesystemAuditKindK_ATTR: // via utimes / setxattr
		r.Path, r.Name = passed(data, bases&1 != 0, int(mode), truncated)
	case filesystemAuditKindK_ATTR_FAILED: // via utimes / setxattr
		r.Path, r.Name = passed(data, bases&1 != 0, int(mode), truncated)
		r.Err = pathRet
		r.Failed = true
	}
	// A change through a descriptor alone (futimens, fchmod) names no file,
	// so its path is the descriptor's own.
	if marks&markDescriptor != 0 {
		applyMarks(&r, marks, false)
	}
	return r, nil
}

// permBits renders a mode's permission bits in octal, four digits at least.
func permBits(mode uint32) string {
	s := strconv.FormatUint(uint64(mode&0o7777), 8)
	return "0000"[len(s):] + s
}

// owner renders a chown's new uid:gid, with -1 for a side it leaves as is.
func owner(uid, gid uint32) string {
	id := func(v uint32) string {
		if v == ^uint32(0) {
			return "-1"
		}
		return strconv.FormatUint(uint64(v), 10)
	}
	return id(uid) + ":" + id(gid)
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

// x32SyscallBit marks an x32 syscall, numbered as the native one it shares.
const x32SyscallBit = 0x40000000

// syscallName is the name of syscall nr, of the 32-bit ABI when compat, or
// its number where the table has none.
func syscallName(nr int64, compat bool) string {
	names := syscallNames
	if compat && nr&x32SyscallBit != 0 {
		nr &^= x32SyscallBit
	} else if compat {
		names = compatSyscallNames
	}
	if n, ok := names[nr]; ok {
		return n
	}
	return strconv.FormatInt(nr, 10)
}

package main

import (
	"encoding/binary"
	"fmt"
	"strings"

	"golang.org/x/sys/unix"
)

// failedOpen is the record of an open(2) that failed before reaching a file:
// its name, cut short when cut, joined to the base directory its result raw
// carries when the name is relative. raw is at least hdrLen long.
func failedOpen(name string, cut bool, raw []byte) record {
	le := binary.LittleEndian
	relative := raw[offBases]&1 != 0 && name != "" && name[0] != '/'
	p, _ := joinBase(name, raw[hdrLen:], relative, int(le.Uint32(raw[offMode:])), raw[offTruncated] != 0)
	c := common(raw)
	r := record{Kind: "open", PID: c.PID, PPID: c.PPID, Comm: c.Comm, boot: c.boot}
	r.Path = tidy(p)
	r.Name = passedName(name, r.Path)
	// A cut name has lost its end, the part that names the file.
	if cut {
		r.Path += "…"
		if r.Name != "" {
			r.Name += "…"
		}
	}
	r.Err = -int32(le.Uint32(raw[offPathLen:]))
	r.Flags = le.Uint32(raw[offFlags:])
	r.Access = openAccess(r.Flags, 0)
	r.Failed = true
	return r
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

// common is the record of a sample at least hdrLen long with only what every
// event carries filled in.
func common(raw []byte) record {
	le := binary.LittleEndian
	return record{
		Kind: kindName(filesystemAuditKind(le.Uint32(raw[offKind:]))),
		PID:  le.Uint32(raw[offPid:]),
		PPID: le.Uint32(raw[offPpid:]),
		Comm: cstr(raw[offComm : offComm+commLen]),
		boot: le.Uint64(raw[offTs:]),
		tid:  le.Uint32(raw[offTid:]),
		nr:   int32(le.Uint32(raw[offNr:])),
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
	gid := le.Uint32(raw[offGid:]) // a failed chown's; a hooked one's is in mode
	r := common(raw)
	switch kind {
	case filesystemAuditKindK_RESULT, filesystemAuditKindK_EXIT, filesystemAuditKindK_OPEN_NAME,
		filesystemAuditKindK_OPEN_CREATE:
		// The recorder takes these from their header; they make no line.
		return record{}, fmt.Errorf("kind %d settles other events and is no line of its own", kind)
	case filesystemAuditKindK_OPEN:
		r.Path, r.Err = filePath(data, pathRet, n1, truncated)
		applyMarks(&r, marks, pathRet >= 0)
		r.Flags = flags
		r.Access = openAccess(flags, mode)
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

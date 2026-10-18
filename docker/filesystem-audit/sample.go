package main

import (
	"encoding/binary"
	"unsafe"
)

// kindNames names each kind of struct event. A failed operation decodes to
// the name of the one that succeeded, with Failed set.
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
	offNr        = int(unsafe.Offsetof(filesystemAuditEvent{}.Nr))
	offMarks     = int(unsafe.Offsetof(filesystemAuditEvent{}.Marks))
	offGid       = int(unsafe.Offsetof(filesystemAuditEvent{}.Gid))
	offTid       = int(unsafe.Offsetof(filesystemAuditEvent{}.Tid))
	offTs        = int(unsafe.Offsetof(filesystemAuditEvent{}.Ts))
	hdrLen       = int(unsafe.Offsetof(filesystemAuditEvent{}.Data))
)

const (
	markInternal   = 1
	markUnlinked   = 2
	markDescriptor = 4
)

const (
	resultOpen    = uint8(filesystemAuditResultBitRESULT_OPEN)
	resultWatched = uint8(filesystemAuditResultBitRESULT_WATCHED)
	resultFD      = uint8(filesystemAuditResultBitRESULT_FD)
)

// hdr is what the reader needs of an event that settles others.
type hdr struct {
	kind   filesystemAuditKind
	tid    uint32
	nr     int32
	ret    int32
	n1, n2 uint8
}

// header reads hdr from a sample at least hdrLen long.
func header(raw []byte) hdr {
	le := binary.LittleEndian
	return hdr{
		kind: filesystemAuditKind(le.Uint32(raw[offKind:])),
		tid:  le.Uint32(raw[offTid:]),
		nr:   int32(le.Uint32(raw[offNr:])),
		ret:  int32(le.Uint32(raw[offPathLen:])),
		n1:   raw[offN1],
		n2:   raw[offN2],
	}
}

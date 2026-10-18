package main

import (
	"strconv"

	"golang.org/x/sys/unix"
)

const fmodeExec = 0x20 // FMODE_EXEC

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

package main

import "golang.org/x/sys/unix"

// syscallNumbers holds the values of the BPF program's nr_ constants (see
// syscalls_amd64.go). arm64 has only the *at forms of the older calls, and
// no futimesat, utime or utimes.
var syscallNumbers = map[string]int64{
	"nr_unlinkat":  unix.SYS_UNLINKAT,
	"nr_renameat2": unix.SYS_RENAMEAT2,
	"nr_renameat":  unix.SYS_RENAMEAT,
	"nr_fchmodat":  unix.SYS_FCHMODAT,
	"nr_fchmodat2": unix.SYS_FCHMODAT2,
	"nr_fchownat":  unix.SYS_FCHOWNAT,
	"nr_utimensat": unix.SYS_UTIMENSAT,
	"nr_setxattr":  unix.SYS_SETXATTR,
	"nr_lsetxattr": unix.SYS_LSETXATTR,
	"nr_mkdirat":   unix.SYS_MKDIRAT,
	"nr_mknodat":   unix.SYS_MKNODAT,
	"nr_symlinkat": unix.SYS_SYMLINKAT,
	"nr_linkat":    unix.SYS_LINKAT,
	"nr_truncate":  unix.SYS_TRUNCATE,
}

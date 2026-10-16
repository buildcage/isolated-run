package main

import "golang.org/x/sys/unix"

// syscallNumbers holds the values of the BPF program's nr_ constants (see
// syscalls_amd64.go). arm64 has only the *at forms of the older calls, and
// no futimesat, utime or utimes.
var syscallNumbers = map[string]int64{
	"nr_unlinkat":          unix.SYS_UNLINKAT,
	"nr_renameat2":         unix.SYS_RENAMEAT2,
	"nr_renameat":          unix.SYS_RENAMEAT,
	"nr_fchmodat":          unix.SYS_FCHMODAT,
	"nr_fchmodat2":         unix.SYS_FCHMODAT2,
	"nr_fchmod":            unix.SYS_FCHMOD,
	"nr_fchownat":          unix.SYS_FCHOWNAT,
	"nr_fchown":            unix.SYS_FCHOWN,
	"nr_utimensat":         unix.SYS_UTIMENSAT,
	"nr_setxattr":          unix.SYS_SETXATTR,
	"nr_lsetxattr":         unix.SYS_LSETXATTR,
	"nr_fsetxattr":         unix.SYS_FSETXATTR,
	"nr_mkdirat":           unix.SYS_MKDIRAT,
	"nr_mknodat":           unix.SYS_MKNODAT,
	"nr_symlinkat":         unix.SYS_SYMLINKAT,
	"nr_linkat":            unix.SYS_LINKAT,
	"nr_truncate":          unix.SYS_TRUNCATE,
	"nr_ftruncate":         unix.SYS_FTRUNCATE,
	"nr_bind":              unix.SYS_BIND,
	"nr_open_by_handle_at": unix.SYS_OPEN_BY_HANDLE_AT,
	"nr_bpf":               unix.SYS_BPF,
	"nr_openat":            unix.SYS_OPENAT,
	"nr_openat2":           unix.SYS_OPENAT2,
	"native_arch":          unix.AUDIT_ARCH_AARCH64,
}

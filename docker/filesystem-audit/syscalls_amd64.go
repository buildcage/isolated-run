package main

import "golang.org/x/sys/unix"

// syscallNumbers holds the values of the BPF program's nr_ constants: the
// path syscalls whose failures and attribute changes it records.
var syscallNumbers = map[string]int64{
	"nr_unlinkat":  unix.SYS_UNLINKAT,
	"nr_unlink":    unix.SYS_UNLINK,
	"nr_rmdir":     unix.SYS_RMDIR,
	"nr_renameat2": unix.SYS_RENAMEAT2,
	"nr_renameat":  unix.SYS_RENAMEAT,
	"nr_rename":    unix.SYS_RENAME,
	"nr_fchmodat":  unix.SYS_FCHMODAT,
	"nr_fchmodat2": unix.SYS_FCHMODAT2,
	"nr_chmod":     unix.SYS_CHMOD,
	"nr_fchownat":  unix.SYS_FCHOWNAT,
	"nr_chown":     unix.SYS_CHOWN,
	"nr_lchown":    unix.SYS_LCHOWN,
	"nr_utimensat": unix.SYS_UTIMENSAT,
	"nr_futimesat": unix.SYS_FUTIMESAT,
	"nr_utime":     unix.SYS_UTIME,
	"nr_utimes":    unix.SYS_UTIMES,
	"nr_setxattr":  unix.SYS_SETXATTR,
	"nr_lsetxattr": unix.SYS_LSETXATTR,
	"nr_mkdirat":   unix.SYS_MKDIRAT,
	"nr_mkdir":     unix.SYS_MKDIR,
	"nr_mknodat":   unix.SYS_MKNODAT,
	"nr_mknod":     unix.SYS_MKNOD,
	"nr_symlinkat": unix.SYS_SYMLINKAT,
	"nr_symlink":   unix.SYS_SYMLINK,
	"nr_linkat":    unix.SYS_LINKAT,
	"nr_link":      unix.SYS_LINK,
	"nr_truncate":  unix.SYS_TRUNCATE,
}

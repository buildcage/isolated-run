// SPDX-License-Identifier: MIT OR GPL-2.0-only
/**
 * @file syscalls.h
 * Path syscalls recorded from their exit, chiefly the ones that fail
 * before the tracer's path hooks. It defines maps, so only
 * filesystem_audit.bpf.c includes it.
 */
#ifndef FILESYSTEM_AUDIT_SYSCALLS_H
#define FILESYSTEM_AUDIT_SYSCALLS_H

#include "record.h"
#include "path.h"

#define AT_REMOVEDIR 0x200
#ifndef EEXIST
#define EEXIST 17
#endif

/** A path syscall as it returned: what it records and what it was given. */
struct path_call {
	u64 p1;
	u64 p2;
	u32 kind;      ///< emitted on failure
	u32 kind_ok;   ///< emitted on success, 0 to skip
	u32 quiet_err; ///< an errno that changed nothing, so is not recorded
	s32 dfd1;      ///< what p1 and p2 resolve against when relative
	s32 dfd2;
	u32 val1;      ///< a chmod's new mode, or a chown's new uid
	u32 val2;      ///< a chown's new gid
};

/**
 * @name Failed path syscalls
 * security_path_* fires only once the path has resolved, so a missing target
 * (the common failure) never reaches it; the syscall's exit catches it, with
 * the arguments the call left in its registers, and emits only when ret < 0,
 * reading the user path(s) they point to. Best-effort: this reads the user
 * buffer, which a concurrent thread could rewrite while the call runs, so a
 * failed op's recorded path is not tamper-proof the way the open path's
 * getname copy is.
 * @{
 */

/**
 * The syscall numbers of the architecture the tracer runs on, set by the
 * loader; -1 for one it lacks (x86_64's older forms on arm64). A negative
 * number is skipped, as the kernel passes -1 for a call that a ptrace or
 * seccomp tracer cancelled. A 32-bit syscall numbers them differently, but
 * under the audit the sandbox kills the thread that makes one before the
 * call runs.
 */
const volatile long nr_unlinkat = -1, nr_unlink = -1, nr_rmdir = -1;
const volatile long nr_renameat2 = -1, nr_renameat = -1, nr_rename = -1;
const volatile long nr_fchmodat = -1, nr_fchmodat2 = -1, nr_chmod = -1;
const volatile long nr_fchownat = -1, nr_chown = -1, nr_lchown = -1;
const volatile long nr_utimensat = -1, nr_futimesat = -1, nr_utime = -1, nr_utimes = -1;
const volatile long nr_setxattr = -1, nr_lsetxattr = -1;
const volatile long nr_mkdirat = -1, nr_mkdir = -1, nr_mknodat = -1, nr_mknod = -1;
const volatile long nr_symlinkat = -1, nr_symlink = -1, nr_linkat = -1, nr_link = -1;
const volatile long nr_truncate = -1;

/**
 * A syscall's argument @p i (0 to 3), from the register it was passed in.
 * They still hold it when the call returns, save arm64's first, which the
 * return value overwrites and orig_x0 keeps.
 */
static __always_inline u64 sys_arg(struct pt_regs *regs, int i)
{
	struct pt_regs___x86 *x = (void *)regs;
	if (bpf_core_field_exists(x->di))
		return i == 0 ? x->di : i == 1 ? x->si : i == 2 ? x->dx : x->r10;
	struct pt_regs___arm64 *a = (void *)regs;
	return i == 0 ? a->orig_x0 : a->regs[i];
}

/** The number of the syscall returning, as tp_btf/sys_exit sees it. */
static __always_inline long sys_nr(struct pt_regs *regs)
{
	struct pt_regs___x86 *x = (void *)regs;
	if (bpf_core_field_exists(x->orig_ax))
		return x->orig_ax;
	return ((struct pt_regs___arm64 *)regs)->syscallno;
}

#define ARG(i) sys_arg(regs, i)
#define OP(k, ok, quiet, d1, a1, d2, a2)						\
	({ p->kind = k; p->kind_ok = ok; p->quiet_err = quiet;				\
	   p->dfd1 = d1; p->p1 = a1; p->dfd2 = d2; p->p2 = a2;			\
	   p->val1 = 0; p->val2 = 0; 1; })
#define VALS(v1, v2) ({ p->val1 = v1; p->val2 = v2; 1; })

/**
 * Making a name. The kernel refuses one on a read-only mount before the
 * security_path_* hook, so the failure is caught here. A name that is already
 * there changed nothing, and mkdir -p meets one at every level it keeps, so
 * EEXIST is not recorded.
 */
#define CREATE(k, d1, a1, d2, a2) OP(k, 0, EEXIST, d1, a1, d2, a2)
#define ENOSYS 38

/**
 * utimensat, utime, utimes, futimesat and {,l}setxattr are the attribute
 * changes with no security_path_* hook of their own; recorded here, success
 * and failure alike. A NULL path (futimens) changes the file dfd refers to;
 * with AT_FDCWD it names nothing and fails.
 */
static __always_inline int attr_op(struct path_call *p, int dfd, u64 path)
{
	if (!path && dfd == AT_FDCWD)
		return 0;
	return OP(K_ATTR_FAILED, K_ATTR, 0, dfd, path, 0, 0);
}

/**
 * Fills p with what syscall nr records, and its arguments from regs, and
 * reports whether it is watched.
 */
static __always_inline int classify(long nr, struct pt_regs *regs, struct path_call *p)
{
	if (nr < 0)
		return 0;
	if (nr == nr_unlinkat)
		return OP(ARG(2) & AT_REMOVEDIR ? K_RMDIR_FAILED : K_UNLINK_FAILED, 0, 0, ARG(0), ARG(1), 0, 0);
	if (nr == nr_unlink)
		return OP(K_UNLINK_FAILED, 0, 0, AT_FDCWD, ARG(0), 0, 0);
	if (nr == nr_rmdir)
		return OP(K_RMDIR_FAILED, 0, 0, AT_FDCWD, ARG(0), 0, 0);
	if (nr == nr_renameat2 || nr == nr_renameat)
		return OP(K_RENAME_FAILED, 0, 0, ARG(0), ARG(1), ARG(2), ARG(3));
	if (nr == nr_rename)
		return OP(K_RENAME_FAILED, 0, 0, AT_FDCWD, ARG(0), AT_FDCWD, ARG(1));
	if (nr == nr_fchmodat)
		return OP(K_CHMOD_FAILED, 0, 0, ARG(0), ARG(1), 0, 0) && VALS(ARG(2), 0);
	if (nr == nr_fchmodat2) // ENOSYS: a kernel before 6.6, so nothing was tried
		return OP(K_CHMOD_FAILED, 0, ENOSYS, ARG(0), ARG(1), 0, 0) && VALS(ARG(2), 0);
	if (nr == nr_chmod)
		return OP(K_CHMOD_FAILED, 0, 0, AT_FDCWD, ARG(0), 0, 0) && VALS(ARG(1), 0);
	if (nr == nr_fchownat)
		return OP(K_CHOWN_FAILED, 0, 0, ARG(0), ARG(1), 0, 0) && VALS(ARG(2), ARG(3));
	if (nr == nr_chown || nr == nr_lchown)
		return OP(K_CHOWN_FAILED, 0, 0, AT_FDCWD, ARG(0), 0, 0) && VALS(ARG(1), ARG(2));
	if (nr == nr_utimensat || nr == nr_futimesat)
		return attr_op(p, ARG(0), ARG(1));
	if (nr == nr_utime || nr == nr_utimes || nr == nr_setxattr || nr == nr_lsetxattr)
		return attr_op(p, AT_FDCWD, ARG(0));
	if (nr == nr_mkdirat)
		return CREATE(K_MKDIR_FAILED, ARG(0), ARG(1), 0, 0);
	if (nr == nr_mkdir)
		return CREATE(K_MKDIR_FAILED, AT_FDCWD, ARG(0), 0, 0);
	if (nr == nr_mknodat)
		return CREATE(K_MKNOD_FAILED, ARG(0), ARG(1), 0, 0);
	if (nr == nr_mknod)
		return CREATE(K_MKNOD_FAILED, AT_FDCWD, ARG(0), 0, 0);
	if (nr == nr_symlinkat) // (target, newdfd, name): the link's name
		return CREATE(K_SYMLINK_FAILED, ARG(1), ARG(2), 0, 0);
	if (nr == nr_symlink)
		return CREATE(K_SYMLINK_FAILED, AT_FDCWD, ARG(1), 0, 0);
	if (nr == nr_linkat)
		return CREATE(K_LINK_FAILED, ARG(0), ARG(1), ARG(2), ARG(3));
	if (nr == nr_link)
		return CREATE(K_LINK_FAILED, AT_FDCWD, ARG(0), AT_FDCWD, ARG(1));
	if (nr == nr_truncate)
		return CREATE(K_TRUNCATE_FAILED, AT_FDCWD, ARG(0), 0, 0);
	return 0;
}

/** Emits the call as it ended with @p ret. */
static __always_inline void op_exit(u32 slot, struct path_call *call, long ret)
{
	if (is_restart(ret) || (ret < 0 && -ret == call->quiet_err))
		return;
	u32 kind = ret < 0 ? call->kind : call->kind_ok;
	// Only an attribute change names its file by descriptor alone (futimens);
	// any other call given no name names nothing.
	if (kind == 0 || (!call->p1 && kind != K_ATTR && kind != K_ATTR_FAILED))
		return;
	struct event *e = start(slot, kind);
	if (!e)
		return;
	if (ret < 0)
		e->path_len = -ret;
	e->flags = call->val1;
	e->gid = call->val2;
	long r = call->p1 ? bpf_probe_read_user_str(e->data, PATH_LEN, (void *)call->p1) : 0;
	u32 off = r > 0 ? r : 0;
	u32 second = off;
	// Mark a second path only when both were read, so a failed read never
	// leaves n1 claiming a name that is not in the buffer.
	if (call->p2 && off > 0) {
		long r2 = bpf_probe_read_user_str(&e->data[off & (DATA_SZ - 1)], PATH_LEN, (void *)call->p2);
		if (r2 > 0) {
			e->n1 = 1;
			off += r2;
		}
	}
	// mode and flags count the base components of the first and second name;
	// flags holds val1 instead for an op with one name.
	u8 nb = 0;
	if (!call->p1) {
		// No name (futimens): the descriptor's path, or no record if it
		// was not open.
		e->data[0] = 0;
		off = add_base(e, 1, call->dfd1, &nb, &e->truncated, 1, 0);
		e->mode = nb;
		if (!(e->bases & 1))
			return;
	} else if (r > 1 && e->data[0] != '/') {
		off = add_base(e, off, call->dfd1, &nb, &e->truncated, 1, e->n1);
		e->mode = nb;
	}
	if (e->n1 && e->data[second & (DATA_SZ - 1)] != '/' && e->data[second & (DATA_SZ - 1)]) {
		nb = 0;
		off = add_base(e, off, call->dfd2, &nb, &e->trunc2, 2, 0);
		e->flags = nb;
	}
	e->data_len = off;
	submit(e);
}

/** @} */

#endif

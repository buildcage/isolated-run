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
#define AT_EMPTY_PATH 0x1000
#ifndef EEXIST
#define EEXIST 17
#endif
#ifndef ENAMETOOLONG
#define ENAMETOOLONG 36
#endif

/**
 * Whether @p ret is one of ERESTARTSYS to ERESTART_RESTARTBLOCK: a signal
 * interrupted the call, which the kernel runs again, and that run records it.
 * One the kernel turns into EINTR instead, as ERESTARTSYS without SA_RESTART,
 * is not run again, and goes unrecorded and uncounted.
 */
static __always_inline int is_restart(long ret)
{
	return ret <= -512 && ret >= -516;
}

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
	u32 empty_dfd; ///< an empty p1 names dfd1's own file (AT_EMPTY_PATH)
	u32 by_fd;     ///< no p1: the call names dfd1's own file
};

/**
 * @name Failed path syscalls
 * security_path_* fires only once the path has resolved, so a missing target
 * (the common failure) never reaches it; the syscall's exit catches it, with
 * the arguments the call left in its registers, and emits only when ret < 0,
 * reading the user path(s) they point to. Best-effort: this reads the user
 * buffer, which a concurrent thread could rewrite while the call runs, so a
 * failed op's recorded path is not tamper-proof the way an open's getname
 * copy is.
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
const volatile long nr_fchmodat = -1, nr_fchmodat2 = -1, nr_chmod = -1, nr_fchmod = -1;
const volatile long nr_fchownat = -1, nr_chown = -1, nr_lchown = -1, nr_fchown = -1;
const volatile long nr_utimensat = -1, nr_futimesat = -1, nr_utime = -1, nr_utimes = -1;
const volatile long nr_setxattr = -1, nr_lsetxattr = -1, nr_fsetxattr = -1;
const volatile long nr_mkdirat = -1, nr_mkdir = -1, nr_mknodat = -1, nr_mknod = -1;
const volatile long nr_symlinkat = -1, nr_symlink = -1, nr_linkat = -1, nr_link = -1;
const volatile long nr_truncate = -1, nr_ftruncate = -1;
const volatile long nr_bind = -1;

/**
 * A syscall's argument @p i (0 to 4), from the register it was passed in.
 * They still hold it when the call returns, save arm64's first, which the
 * return value overwrites and orig_x0 keeps.
 */
static __always_inline u64 sys_arg(struct pt_regs *regs, int i)
{
	struct pt_regs___x86 *x = (void *)regs;
	if (bpf_core_field_exists(x->di))
		return i == 0 ? x->di : i == 1 ? x->si : i == 2 ? x->dx : i == 3 ? x->r10 : x->r8;
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

/** The number of the syscall the current task is in. */
static __always_inline long current_sys_nr(void)
{
	return sys_nr((struct pt_regs *)bpf_task_pt_regs(bpf_get_current_task_btf()));
}

#define ARG(i) sys_arg(regs, i)
#define OP(k, ok, quiet, d1, a1, d2, a2)						\
	({ p->kind = k; p->kind_ok = ok; p->quiet_err = quiet;				\
	   p->dfd1 = d1; p->p1 = a1; p->dfd2 = d2; p->p2 = a2;			\
	   p->val1 = 0; p->val2 = 0; p->empty_dfd = 0; p->by_fd = 0; 1; })
#define VALS(v1, v2) ({ p->val1 = v1; p->val2 = v2; 1; })
#define EMPTY_DFD(f) ({ p->empty_dfd = (f) != 0; 1; })
/**
 * Marks p as made through descriptor @p fd alone, which AT_FDCWD is not: it
 * names no file, so is not taken for the working directory.
 */
static __always_inline int fd_only(struct path_call *p, int fd)
{
	if (fd == AT_FDCWD)
		return 0;
	p->by_fd = 1;
	return 1;
}

/**
 * A change made through descriptor d alone. Its hook records it when it
 * succeeds, but a read-only mount refuses fchmod and fchown, and an
 * append-only file ftruncate, before the hook runs.
 */
#define FD_OP(k, d) (OP(k, 0, 0, d, 0, 0, 0) && fd_only(p, d))

/**
 * Making a name. The kernel refuses one on a read-only mount before the
 * security_path_* hook, so the failure is caught here. A name that is already
 * there changed nothing, and mkdir -p meets one at every level it keeps, so
 * EEXIST is not recorded.
 */
#define CREATE(k, d1, a1, d2, a2) OP(k, 0, EEXIST, d1, a1, d2, a2)
#define ENOSYS 38

/**
 * utimensat, utime, utimes, futimesat and {,l,f}setxattr are the attribute
 * changes with no security_path_* hook of their own; recorded here, success
 * and failure alike. A NULL path (futimens) changes the file dfd refers to;
 * with AT_FDCWD it names nothing and fails.
 */
static __always_inline int attr_op(struct path_call *p, int dfd, u64 path)
{
	return OP(K_ATTR_FAILED, K_ATTR, 0, dfd, path, 0, 0) && (path || fd_only(p, dfd));
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
		return OP(K_CHMOD_FAILED, 0, ENOSYS, ARG(0), ARG(1), 0, 0) && VALS(ARG(2), 0) &&
		       EMPTY_DFD(ARG(3) & AT_EMPTY_PATH);
	if (nr == nr_chmod)
		return OP(K_CHMOD_FAILED, 0, 0, AT_FDCWD, ARG(0), 0, 0) && VALS(ARG(1), 0);
	if (nr == nr_fchmod)
		return FD_OP(K_CHMOD_FAILED, ARG(0)) && VALS(ARG(1), 0);
	if (nr == nr_fchownat)
		return OP(K_CHOWN_FAILED, 0, 0, ARG(0), ARG(1), 0, 0) && VALS(ARG(2), ARG(3)) &&
		       EMPTY_DFD(ARG(4) & AT_EMPTY_PATH);
	if (nr == nr_chown || nr == nr_lchown)
		return OP(K_CHOWN_FAILED, 0, 0, AT_FDCWD, ARG(0), 0, 0) && VALS(ARG(1), ARG(2));
	if (nr == nr_fchown)
		return FD_OP(K_CHOWN_FAILED, ARG(0)) && VALS(ARG(1), ARG(2));
	if (nr == nr_utimensat)
		return attr_op(p, ARG(0), ARG(1)) && EMPTY_DFD(ARG(3) & AT_EMPTY_PATH);
	if (nr == nr_futimesat)
		return attr_op(p, ARG(0), ARG(1));
	if (nr == nr_utime || nr == nr_utimes || nr == nr_setxattr || nr == nr_lsetxattr)
		return attr_op(p, AT_FDCWD, ARG(0));
	if (nr == nr_fsetxattr)
		return attr_op(p, ARG(0), 0);
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
	if (nr == nr_ftruncate)
		return FD_OP(K_TRUNCATE_FAILED, ARG(0));
	return 0;
}

/**
 * Whether the call names its file by descriptor: by no name, or by an empty
 * one with AT_EMPTY_PATH.
 */
static __always_inline int names_fd(struct path_call *p)
{
	char c = 1;
	return p->by_fd ||
	       (p->empty_dfd && bpf_probe_read_user(&c, 1, (void *)p->p1) == 0 && c == 0);
}

/** Emits the call as it ended with @p ret. */
static __always_inline void op_exit(u32 slot, struct path_call *call, long ret)
{
	if (is_restart(ret) || (ret < 0 && -ret == call->quiet_err))
		return;
	u32 kind = ret < 0 ? call->kind : call->kind_ok;
	// A call given no name names nothing, save one made through a
	// descriptor alone.
	if (kind == 0 || (!call->p1 && !call->by_fd))
		return;
	struct event *e = start(slot, kind);
	if (!e)
		return;
	if (ret < 0)
		e->path_len = -ret;
	// Right after the call's K_RESULT, which can tell the reader to keep the
	// path change its hook sent instead (RESULT_FD).
	if (call->kind != K_ATTR_FAILED)
		e->tid = (u32)bpf_get_current_pid_tgid();
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
	// An empty string reads as 1 byte, or as 0 before Linux 6.16.
	if (!call->p1 || (call->empty_dfd && (r == 0 || r == 1))) {
		// No name (futimens, fchmod), or an empty one (AT_EMPTY_PATH): the
		// descriptor's path. One closed by the time the call returned
		// names nothing, so a change made through it counts in untracked.
		e->data[0] = 0;
		off = add_base(e, 1, call->dfd1, 1, 0);
		if (!(e->bases & 1)) {
			if (ret >= 0)
				bump(&untracked);
			return;
		}
		// A pipe, socket, device or memfd is no file a step protects, and
		// dd's ftruncate of /dev/null fails as a matter of course.
		if (ret < 0 && (e->marks & (MARK_INTERNAL | MARK_SPECIAL)))
			return;
		e->marks |= MARK_DESCRIPTOR;
	} else if (r > 1 && e->data[0] != '/') {
		off = add_base(e, off, call->dfd1, 1, e->n1);
	}
	if (e->n1 && e->data[second & (DATA_SZ - 1)] != '/' && e->data[second & (DATA_SZ - 1)]) {
		off = add_base(e, off, call->dfd2, 2, 0);
	}
	e->data_len = off;
	submit(e);
}

/** @} */

/** The open(2) family's syscall numbers, set by the loader as the others are. */
const volatile long nr_open = -1, nr_openat = -1, nr_openat2 = -1, nr_creat = -1;

/**
 * Whether syscall @p nr is of the open(2) family. Only the native numbers are
 * known, as the sandbox kills a thread that makes a 32-bit call before it
 * runs (see nr_unlinkat).
 */
static __always_inline int is_open_nr(long nr)
{
	return nr >= 0 && (nr == nr_open || nr == nr_openat || nr == nr_openat2 || nr == nr_creat);
}

#define O_WRONLY 01
#define O_CREAT 0100
#define O_TRUNC 01000

/**
 * Whether the current task is in an open(2) family call, whose name
 * do_filp_open is given (see open_name()).
 */
static __always_inline int in_open_call(void)
{
	return is_open_nr(current_sys_nr());
}

#ifndef EPERM
#define EPERM 1
#endif
#define SIGSYS 31

/** The native architecture as seccomp names it (AUDIT_ARCH_*), set by the loader. */
const volatile long native_arch = -1;

#define N_REFUSABLE 1024

/**
 * The native syscalls the sandbox's seccomp profile does not allow outright,
 * marked by the loader: one of them failing EPERM is the profile's refusal.
 */
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, N_REFUSABLE);
	__type(key, u32);
	__type(value, u8);
} refusable SEC(".maps");

static __always_inline int is_refusable(long nr)
{
	if (nr < 0 || nr >= N_REFUSABLE)
		return 0;
	u32 k = nr;
	u8 *v = bpf_map_lookup_elem(&refusable, &k);
	return v && *v;
}

/** A program and a syscall it was refused, recorded once. */
struct refused_key {
	struct proc proc;
	u32 nr;
	u32 killed;
};

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 4096);
	__type(key, struct refused_key);
	__type(value, u8);
} refused_seen SEC(".maps");

/**
 * Records the step's syscall @p nr as refused, once per program: with
 * @p killed, a 32-bit one seccomp killed the program for, else one that
 * failed with EPERM.
 */
static __always_inline void syscall_refused(u32 slot, long nr, u32 killed)
{
	struct refused_key k;
	__builtin_memset(&k, 0, sizeof(k));
	k.proc = current_proc();
	k.nr = nr;
	k.killed = killed;
	u8 one = 1;
	if (bpf_map_update_elem(&refused_seen, &k, &one, BPF_NOEXIST))
		return; // recorded already
	struct event *e = start(slot, K_SYSCALL);
	if (!e)
		return;
	e->flags = nr;
	e->mode = killed;
	e->path_len = killed ? 0 : EPERM;
	e->data_len = 0;
	submit(e);
}

#endif

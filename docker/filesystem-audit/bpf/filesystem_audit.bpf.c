// SPDX-License-Identifier: MIT OR GPL-2.0-only
/**
 * @file filesystem_audit.bpf.c
 * Records the file accesses of every task in one cgroup v2 subtree: opens,
 * each program's first read and write of each open file, mmaps, execs, and
 * the path operations (create, move, delete, attribute change), successes and
 * failures alike. It runs on any BTF-enabled kernel from 6.1 on, 6.4 on arm64,
 * the first to let fentry attach to a kernel function there. This file holds
 * the programs; what they share is in the headers it includes.
 */

#include <linux/types.h>
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

/**
 * libbpf's BPF_PROG, with the body also given @p slot, a number of its own
 * that picks its scratch event (see scratch_get()). A program not written
 * with BPF_PROG passes its own __COUNTER__.
 */
#undef BPF_PROG
#define BPF_PROG(name, args...)						    \
name(unsigned long long *ctx);						    \
static __always_inline typeof(name(0))					    \
____##name(u32 slot, unsigned long long *ctx, ##args);			    \
typeof(name(0)) name(unsigned long long *ctx)				    \
{									    \
	_Pragma("GCC diagnostic push")					    \
	_Pragma("GCC diagnostic ignored \"-Wint-conversion\"")		    \
	return ____##name(__COUNTER__, ___bpf_ctx_cast(args));		    \
	_Pragma("GCC diagnostic pop")					    \
}									    \
static __always_inline typeof(name(0))					    \
____##name(u32 slot, unsigned long long *ctx, ##args)

#include "event.h"
#include "kernel.h"
#include "record.h"
#include "path.h"
#include "access.h"
#include "syscalls.h"

/**
 * Sends the path change @p e. Its hook runs before the kernel's own permission
 * checks (may_delete, may_create, notify_change), so whether it happened is
 * known only from the call's K_RESULT.
 */
static __always_inline void send_op(struct event *e)
{
	e->tid = (u32)bpf_get_current_pid_tgid();
	e->nr = current_sys_nr();
	submit(e);
}

/**
 * The file being executed, resolved, while bprm->file is still the one named:
 * by sched_process_exec a script has been swapped for its interpreter, and
 * filename is only the name the caller passed, relative to its cwd or not.
 */
SEC("fentry/security_bprm_creds_for_exec")
int BPF_PROG(on_exec_file, struct linux_binprm *bprm)
{
	if (!in_target())
		return 0;
	struct event *e = start(slot, K_EXEC_FILE);
	if (!e)
		return 0;
	struct file *f = BPF_CORE_READ(bprm, file);
	e->data_len = file_walk(e, f);
	submit(e);
	return 0;
}

/**
 * Lets the reader drop what a thread sent for a syscall whose exit never ran,
 * as for a core dump, rather than give it to a reused thread id.
 */
SEC("tp_btf/sched_process_exit")
int BPF_PROG(on_task_exit, struct task_struct *p)
{
	if (!in_target())
		return 0;
	struct event *e = start(slot, K_EXIT);
	if (!e)
		return 0;
	e->tid = (u32)bpf_get_current_pid_tgid();
	submit(e);
	return 0;
}

#define SYS_SECCOMP 1
#define X32_SYSCALL_BIT 0x40000000

/**
 * seccomp kills a process's last thread for a 32-bit or x32 syscall, which
 * the audit's profile allows none of, with a SIGSYS to that thread naming the
 * syscall it is making and its architecture. A native one comes from a filter
 * of the step's own, and one naming another call was queued by the process
 * itself; one naming the queuing call itself still passes, adding a record
 * only about that process. A thread killed while others live on gets no
 * signal, and is not recorded.
 */
SEC("tp_btf/signal_generate")
int BPF_PROG(on_signal, int sig, struct kernel_siginfo *info, struct task_struct *task)
{
	if (sig != SIGSYS || (unsigned long)info <= 2 || !in_target())
		return 0;
	if (task != bpf_get_current_task_btf() || BPF_CORE_READ(info, si_code) != SYS_SECCOMP)
		return 0;
	long nr = BPF_CORE_READ(info, _sifields._sigsys._syscall);
	if (nr != sys_nr((struct pt_regs *)bpf_task_pt_regs(task)))
		return 0;
	if (BPF_CORE_READ(info, _sifields._sigsys._arch) != (u32)native_arch ||
	    (nr & X32_SYSCALL_BIT))
		syscall_refused(slot, nr, 1);
	return 0;
}

SEC("tp_btf/sched_process_exec")
int BPF_PROG(on_exec, struct task_struct *p, int old_pid, struct linux_binprm *bprm)
{
	if (!in_target())
		return 0;
	struct event *e = start(slot, K_EXEC);
	if (!e)
		return 0;
	e->path_len = bpf_probe_read_kernel_str(e->data, PATH_LEN, BPF_CORE_READ(bprm, filename));
	e->data_len = e->path_len > 0 ? e->path_len : 0;
	submit(e);
	return 0;
}

/**
 * Every new process, so the recording shows who started each one, a subshell
 * that never execs or touches a file included. ppid is the process that made
 * it, not real_parent, which CLONE_PARENT sets to that process's own parent.
 */
SEC("tp_btf/sched_process_fork")
int BPF_PROG(on_fork, struct task_struct *parent, struct task_struct *child)
{
	if (!in_target())
		return 0;
	int tgid = BPF_CORE_READ(child, tgid);
	if (tgid == BPF_CORE_READ(parent, tgid))
		return 0; // a new thread, not a process
	struct event *e = start(slot, K_FORK);
	if (!e)
		return 0;
	e->pid = tgid;
	e->ppid = BPF_CORE_READ(parent, tgid);
	// The child's own name, copied from the thread that forked it.
	BPF_CORE_READ_STR_INTO(&e->comm, child, comm);
	submit(e);
	return 0;
}

/**
 * The security_path_* hooks run once per syscall at the VFS entry, unlike
 * security_inode_*, which overlayfs calls again for each layer it touches.
 *
 * @param name The program's name, short enough to stay whole in the
 *             kernel's 15 characters.
 * @param skip Evaluated only for a watched thread, last; it may act, as
 *             open_creating() does.
 */
#define DIR_ENTRY_HOOK(name, hook, kind_, skip)				\
SEC("fentry/" #hook)								\
int BPF_PROG(name, const struct path *dir, struct dentry *dentry)		\
{										\
	if (!in_target() || (skip))						\
		return 0;							\
	struct event *e = start(slot, kind_);						\
	if (!e)									\
		return 0;							\
	u32 off = leaf(e, 0, dentry, &e->n1);					\
	e->data_len = walk(e, off, BPF_CORE_READ(dir, dentry), BPF_CORE_READ(dir, mnt), &e->n1, &e->truncated); \
	send_op(e);								\
	return 0;								\
}

DIR_ENTRY_HOOK(on_unlink, security_path_unlink, K_UNLINK, 0)
DIR_ENTRY_HOOK(on_rmdir, security_path_rmdir, K_RMDIR, 0)
DIR_ENTRY_HOOK(on_mkdir, security_path_mkdir, K_MKDIR, 0)

SEC("fentry/security_path_symlink")
int BPF_PROG(on_symlink, const struct path *dir, struct dentry *dentry, const char *old_name)
{
	if (!in_target())
		return 0;
	struct event *e = start(slot, K_SYMLINK);
	if (!e)
		return 0;
	// The kernel caps a target at PATH_MAX, so it is read whole.
	long r = bpf_probe_read_kernel_str(e->data, PATH_LEN, old_name);
	u32 off = r > 0 ? r : 0;
	e->path_len = off;
	off = leaf(e, off, dentry, &e->n1);
	e->data_len = walk(e, off, BPF_CORE_READ(dir, dentry), BPF_CORE_READ(dir, mnt), &e->n1, &e->truncated);
	send_op(e);
	return 0;
}

SEC("fentry/security_path_rename")
int BPF_PROG(on_rename, const struct path *old_dir, struct dentry *old_dentry,
	     const struct path *new_dir, struct dentry *new_dentry, unsigned int flags)
{
	if (!in_target())
		return 0;
	struct event *e = start(slot, K_RENAME);
	if (!e)
		return 0;
	e->flags = flags;
	u32 off = leaf(e, 0, old_dentry, &e->n1);
	off = walk_path(e, off, 1, BPF_CORE_READ(old_dir, dentry), BPF_CORE_READ(old_dir, mnt),
			&e->n1, &e->truncated);
	off = leaf(e, off, new_dentry, &e->n2);
	e->data_len = walk(e, off, BPF_CORE_READ(new_dir, dentry), BPF_CORE_READ(new_dir, mnt), &e->n2, &e->trunc2);
	send_op(e);
	return 0;
}

SEC("fentry/security_path_chmod")
int BPF_PROG(on_chmod, const struct path *path, unsigned short mode)
{
	if (!in_target())
		return 0;
	struct event *e = start(slot, K_CHMOD);
	if (!e)
		return 0;
	e->mode = mode;
	e->data_len = path_walk(e, BPF_CORE_READ(path, dentry), BPF_CORE_READ(path, mnt));
	send_op(e);
	return 0;
}

/**
 * A hard link gives an existing inode a second name; opens through the new
 * name record only that name.
 */
SEC("fentry/security_path_link")
int BPF_PROG(on_link, struct dentry *old_dentry, const struct path *new_dir,
	     struct dentry *new_dentry)
{
	if (!in_target())
		return 0;
	struct event *e = start(slot, K_LINK);
	if (!e)
		return 0;
	struct vfsmount *mnt = BPF_CORE_READ(new_dir, mnt); // link(2) stays on one mount
	mark_file(e, old_dentry, mnt); // an O_TMPFILE given its first name
	u32 off = walk_path(e, 0, 1, old_dentry, mnt, &e->n1, &e->truncated);
	off = leaf(e, off, new_dentry, &e->n2);
	e->data_len = walk(e, off, BPF_CORE_READ(new_dir, dentry), mnt, &e->n2, &e->trunc2);
	send_op(e);
	return 0;
}

/** truncate(2) changes a file's contents without opening it. */
SEC("fentry/security_path_truncate")
int BPF_PROG(on_truncate, const struct path *path)
{
	if (!in_target())
		return 0;
	struct event *e = start(slot, K_TRUNCATE);
	if (!e)
		return 0;
	e->data_len = path_walk(e, BPF_CORE_READ(path, dentry), BPF_CORE_READ(path, mnt));
	send_op(e);
	return 0;
}

/**
 * From 6.2, ftruncate(2) and a truncating open reach this rather than
 * security_path_truncate; absent before (see main.go).
 */
SEC("fentry/security_file_truncate")
int BPF_PROG(on_file_truncate, struct file *file)
{
	if (!in_target())
		return 0;
	struct event *e = start(slot, K_TRUNCATE);
	if (!e)
		return 0;
	e->data_len = file_walk(e, file);
	send_op(e);
	return 0;
}

SEC("fentry/security_path_chown")
int BPF_PROG(on_chown, const struct path *path, unsigned int uid, unsigned int gid)
{
	if (!in_target())
		return 0;
	struct event *e = start(slot, K_CHOWN);
	if (!e)
		return 0;
	e->flags = uid;
	e->mode = gid;
	e->data_len = path_walk(e, BPF_CORE_READ(path, dentry), BPF_CORE_READ(path, mnt));
	send_op(e);
	return 0;
}

SEC("fentry/security_file_open")
int BPF_PROG(on_open, struct file *file)
{
	if (!in_target() || on_layer(file))
		return 0;
	struct event *e = start(slot, K_OPEN);
	if (!e)
		return 0;
	e->flags = file->f_flags;
	e->mode = file->f_mode;
	file_path(e, file);
	// The first file an open(2) reaches is its own (see recorder.go).
	if (in_open_call())
		e->tid = (u32)bpf_get_current_pid_tgid();
	submit(e);
	return 0;
}

/**
 * Marks the open(2) the thread is in, if any, as reaching its create step, so
 * one refused afterwards is recorded as both.
 *
 * @return Whether the thread is in one.
 */
static __always_inline int open_creating(u32 slot)
{
	if (!in_open_call())
		return 0;
	struct event *e = start(slot, K_OPEN_CREATE);
	if (e) {
		e->tid = (u32)bpf_get_current_pid_tgid();
		submit(e);
	}
	return 1;
}

/**
 * mknod(2) and bind(2) to a path. A creating open also passes here, from
 * may_o_create, and is skipped: the open records it.
 */
DIR_ENTRY_HOOK(on_mknod, security_path_mknod, K_MKNOD, open_creating(slot))

/**
 * Sends the name of the open(2) the thread is in, to record the open under if
 * it fails before reaching a file: getname's copy, which the caller cannot
 * rewrite, or with @p user the caller's own, for a name getname refused as
 * too long.
 */
static __always_inline void open_name(u32 slot, const char *name, int user)
{
	struct event *e = start(slot, K_OPEN_NAME);
	if (!e)
		return;
	long r = user ? bpf_probe_read_user_str(e->data, PATH_LEN, name) :
			bpf_probe_read_kernel_str(e->data, PATH_LEN, name);
	if (r <= 0) {
		// Only the kernel's copy failing to read loses a record.
		if (!user)
			bump(&untracked);
		return;
	}
	e->tid = (u32)bpf_get_current_pid_tgid();
	e->data_len = r;
	e->n1 = user;
	e->n2 = user && r == PATH_LEN;
	submit(e);
}

/**
 * Sends the name of the open(2) the thread is in, if any, from the struct
 * filename in @p ctx's second argument.
 */
static __always_inline void send_name(u32 slot, u64 *ctx)
{
	if (!in_target() || !in_open_call())
		return;
	u64 name = 0;
	bpf_get_func_arg(ctx, 1, &name); // a number, which unlike a pointer can be range-checked
	// 7.0 passes on getname's error, which on_sys_exit handles.
	if ((long)name < 0 && (long)name >= -4095)
		return;
	open_name(slot, BPF_CORE_READ((struct filename *)name, name), 0);
}

/**
 * Only open(2) and exec reach do_filp_open, renamed do_file_open in 7.0, with
 * the name getname copied; both are optional.
 */
SEC("fentry/do_filp_open")
int BPF_PROG(on_filp_open, int dfd, struct filename *name)
{
	send_name(slot, ctx);
	return 0;
}

SEC("fentry/do_file_open")
int BPF_PROG(on_do_file_open, int dfd, struct filename *name)
{
	send_name(slot, ctx);
	return 0;
}

/**
 * read(2), write(2) and their vector, positional, splice, sendfile and
 * copy_file_range forms all pass through rw_verify_area, which calls this;
 * so does iterate_dir for a directory listing (as a read).
 */
SEC("fentry/security_file_permission")
int BPF_PROG(on_file_permission, struct file *file, int mask)
{
	if (!in_target() || on_layer(file))
		return 0;
	u32 kind;
	u8 bit;
	if (mask & MAY_WRITE) {
		kind = K_WRITE;
		bit = SEEN_WRITE;
	} else if (mask & MAY_READ) {
		kind = K_READ;
		bit = SEEN_READ;
	} else {
		return 0;
	}
	if (!first_time(file, bit))
		return 0;
	struct event *e = start(slot, kind);
	if (!e)
		return 0;
	file_path(e, file);
	submit(e);
	return 0;
}

SEC("fexit/vm_mmap_pgoff")
int BPF_PROG(on_mmap, struct file *file, unsigned long addr, unsigned long len,
	     unsigned long prot, unsigned long flags)
{
	mapped(slot, ctx, file, prot, flags);
	return 0;
}

SEC("fexit/vm_mmap")
int BPF_PROG(on_vm_mmap, struct file *file, unsigned long addr, unsigned long len,
	     unsigned long prot, unsigned long flags)
{
	mapped(slot, ctx, file, prot, flags);
	return 0;
}

/**
 * fexit, so only a change the LSMs allowed is recorded. reqprot is what the
 * caller asked for, as mmap sees it; prot may add PROT_EXEC.
 */
SEC("fexit/security_file_mprotect")
int BPF_PROG(on_mprotect, struct vm_area_struct *vma, unsigned long reqprot, unsigned long prot,
	     int ret)
{
	if (ret != 0 || !in_target())
		return 0;
	unsigned long flags = BPF_CORE_READ(vma, vm_flags) & VM_SHARED ? MAP_SHARED : 0;
	if (!(reqprot & PROT_EXEC) && !((reqprot & PROT_WRITE) && flags))
		return 0;
	struct file *file = BPF_CORE_READ(vma, vm_file);
	// S_PRIVATE marks the file behind shared anonymous memory.
	if (!file || BPF_CORE_READ(file, f_inode, i_flags) & S_PRIVATE)
		return 0;
	// Before 6.7 this is overlayfs's layer file, not the file the mapping was
	// recorded under, so making it executable later records it again.
	struct dentry *d;
	struct vfsmount *mnt;
	if (!step_path_of(file, &d, &mnt)) {
		bump(&skipped_internal);
		return 0;
	}
	map_events(slot, file, d, mnt, reqprot, flags, 0);
	return 0;
}

SEC("fentry/security_file_free")
int BPF_PROG(on_file_free, struct file *file)
{
	u64 key = 0;
	bpf_get_func_arg(ctx, 0, &key); // file, as a number
	u32 *n = seen_count(key);
	if (n && *n && bpf_map_delete_elem(&seen_files, &key) == 0)
		__sync_fetch_and_add(n, -1);
	return 0;
}

/**
 * Sends the return of syscall @p nr, with @p bits (RESULT_*). A failed
 * open(2) adds its flags and the base directory of its descriptor or working
 * directory, which the reader joins to the name only if that is relative.
 */
static __always_inline void send_result(u32 slot, struct pt_regs *regs, long nr, long ret, u8 bits)
{
	struct event *e = start(slot, K_RESULT);
	if (!e)
		return;
	e->tid = (u32)bpf_get_current_pid_tgid();
	e->nr = nr;
	e->path_len = ret;
	e->n1 = bits;
	if ((bits & RESULT_OPEN) && ret < 0 && !is_restart(ret)) {
		int at = nr == nr_openat || nr == nr_openat2;
		if (nr == nr_creat) {
			e->flags = O_CREAT | O_WRONLY | O_TRUNC;
		} else if (nr == nr_openat2) {
			u64 f = 0; // open_how's first field
			bpf_probe_read_user(&f, sizeof(f), (void *)sys_arg(regs, 2));
			e->flags = f;
		} else {
			e->flags = sys_arg(regs, at + 1);
		}
		e->data_len = add_base(e, 0, at ? (int)sys_arg(regs, 0) : AT_FDCWD, 1, 0);
	}
	submit(e);
}

/**
 * Sends the return of each call a hook may have sent from. A failed path
 * syscall's record from its exit (see classify()) stands for the failure,
 * except for a call through a descriptor alone: its hook saw the file, which
 * a thread could swap before the exit.
 */
SEC("tp_btf/sys_exit")
int BPF_PROG(on_sys_exit, struct pt_regs *regs, long ret)
{
	if (!in_target())
		return 0;
	struct path_call call = {}; // so no field reaches the stack unset
	long nr = sys_nr(regs);
	int watched = classify(nr, regs, &call);
	// Before the call's K_RESULT, which decides whether they stand.
	if (watched)
		op_exit(slot, &call, ret);
	if (ret == -EPERM && !watched && !is_open_nr(nr) && is_refusable(nr))
		syscall_refused(slot, nr, 0);
	if (is_open_nr(nr)) {
		// A name refused as too long reached no hook to send it, so a filter
		// or tracer returning ENAMETOOLONG records one too.
		if (ret == -ENAMETOOLONG)
			open_name(slot, (const char *)sys_arg(regs, nr == nr_openat || nr == nr_openat2), 1);
		send_result(slot, regs, nr, ret, RESULT_OPEN);
	} else if ((watched && call.kind != K_ATTR_FAILED) || other_hooked(nr)) {
		u8 bits = watched ? RESULT_WATCHED : 0;
		if (watched && ret < 0 && names_fd(&call))
			bits |= RESULT_FD;
		send_result(slot, regs, nr, ret, bits);
	}
	return 0;
}

char LICENSE[] SEC("license") = "Dual MIT/GPL";

_Static_assert(__COUNTER__ <= N_SLOTS, "a program has no scratch event of its own");

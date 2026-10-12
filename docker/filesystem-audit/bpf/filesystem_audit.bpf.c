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
#include "held.h"
#include "path.h"
#include "access.h"
#include "syscalls.h"

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

SEC("fentry/security_bprm_committing_creds")
int BPF_PROG(on_exec_commit, const struct linux_binprm *bprm)
{
	if (!in_target())
		return 0;
	u64 id = bpf_get_current_pid_tgid();
	u8 one = 1;
	if (bpf_map_update_elem(&in_exec, &id, &one, BPF_ANY) != 0)
		bump(&untracked);
	return 0;
}

/** A thread killed inside an exec never reaches sched_process_exec. */
SEC("tp_btf/sched_process_exit")
int BPF_PROG(on_task_exit, struct task_struct *p)
{
	if (!in_target())
		return 0;
	u64 id = bpf_get_current_pid_tgid();
	bpf_map_delete_elem(&in_exec, &id);
	return 0;
}

SEC("tp_btf/sched_process_exec")
int BPF_PROG(on_exec, struct task_struct *p, int old_pid, struct linux_binprm *bprm)
{
	if (!in_target())
		return 0;
	u64 id = bpf_get_current_pid_tgid();
	bpf_map_delete_elem(&in_exec, &id);
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
 */
#define DIR_ENTRY_HOOK(hook, kind_)						\
SEC("fentry/" #hook)								\
int BPF_PROG(on_##hook, const struct path *dir, struct dentry *dentry)		\
{										\
	if (!in_target())							\
		return 0;							\
	struct event *e = start(slot, kind_);						\
	if (!e)									\
		return 0;							\
	u32 off = leaf(e, 0, dentry, &e->n1);					\
	e->data_len = walk(e, off, BPF_CORE_READ(dir, dentry), BPF_CORE_READ(dir, mnt), &e->n1, &e->truncated); \
	hold(e);								\
	return 0;								\
}

DIR_ENTRY_HOOK(security_path_unlink, K_UNLINK)
DIR_ENTRY_HOOK(security_path_rmdir, K_RMDIR)
DIR_ENTRY_HOOK(security_path_mkdir, K_MKDIR)

SEC("fentry/security_path_symlink")
int BPF_PROG(on_symlink, const struct path *dir, struct dentry *dentry, const char *old_name)
{
	if (!in_target())
		return 0;
	struct event *e = start(slot, K_SYMLINK);
	if (!e)
		return 0;
	long r = bpf_probe_read_kernel_str(e->data, NAME_LEN, old_name);
	u32 off = r > 0 ? r : 0;
	e->path_len = off;
	off = leaf(e, off, dentry, &e->n1);
	e->data_len = walk(e, off, BPF_CORE_READ(dir, dentry), BPF_CORE_READ(dir, mnt), &e->n1, &e->truncated);
	hold(e);
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
	hold(e);
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
	hold(e);
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
	hold(e);
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
	hold(e);
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
	hold(e);
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
	hold(e);
	return 0;
}

/**
 * Open(2) calls of the step's that reached do_filp_open, and ones that reached
 * security_file_open with no hold, which do_filp_open's program, attached but
 * never run, would leave as the only ones.
 */
struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, u32);
	__type(value, u64);
} open_named SEC(".maps"), open_unnamed SEC(".maps");

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
	int r = hold_open(e);
	if (r) {
		submit(e);
		if (r > 0)
			open_recorded(e);
		else if (r == -2 && in_open_call())
			bump(&open_unnamed);
	}
	return 0;
}

/**
 * mknod(2) and bind(2) to a path. A creating open also passes here, from
 * may_o_create, and is skipped: the open records it.
 */
SEC("fentry/security_path_mknod")
int BPF_PROG(on_mknod, const struct path *dir, struct dentry *dentry)
{
	if (!in_target() || open_creating())
		return 0;
	struct event *e = start(slot, K_MKNOD);
	if (!e)
		return 0;
	u32 off = leaf(e, 0, dentry, &e->n1);
	e->data_len = walk(e, off, BPF_CORE_READ(dir, dentry), BPF_CORE_READ(dir, mnt), &e->n1, &e->truncated);
	hold(e);
	return 0;
}

/**
 * Records the failed open assembled in @p e, its name in place, called with
 * @p dfd and @p flags.
 */
static __always_inline void open_failed(u32 slot, struct event *e, long ret, int dfd, u32 flags)
{
	u8 cut = e->truncated;
	u32 off = e->data_len;
	// A name kept cut for want of tails, marked in n2, has lost its end, the
	// part that names the file.
	if (e->n2)
		bump(&untracked);
	// start resets the header of the scratch e is in.
	if (start(slot, K_OPEN_FAILED) != e)
		return;
	e->path_len = -ret;
	e->flags = flags;
	e->truncated = cut;
	if (off > PATH_LEN) // never, but the verifier needs the bound
		return;
	u8 n = 0;
	if (off > 1 && e->data[0] != '/') {
		off = add_base(e, off, dfd, &n, &e->truncated, 1, 0);
		e->mode = n;
	}
	e->data_len = off;
	submit(e);
}

/**
 * Starts holding the open(2) the thread is in, if any, from its name, the
 * struct filename in @p ctx's second argument.
 */
static __always_inline void hold_name(u32 slot, u64 *ctx)
{
	if (!in_target() || !in_open_call())
		return;
	bump(&open_named);
	u64 name = 0;
	bpf_get_func_arg(ctx, 1, &name);
	// 7.0 passes on getname's error, which open_returned() handles.
	if ((long)name < 0 && (long)name >= -4095)
		return;
	open_name(slot, BPF_CORE_READ((struct filename *)name, name), 0);
}

/**
 * Only an open, and exec's open of the program, reach do_filp_open, renamed
 * do_file_open in 7.0, with the name getname copied; both are optional.
 */
SEC("fentry/do_filp_open")
int BPF_PROG(on_filp_open, int dfd, struct filename *name)
{
	hold_name(slot, ctx);
	return 0;
}

SEC("fentry/do_file_open")
int BPF_PROG(on_do_file_open, int dfd, struct filename *name)
{
	hold_name(slot, ctx);
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
	struct dentry *d = BPF_CORE_READ(file, f_path.dentry);
	struct vfsmount *mnt = BPF_CORE_READ(file, f_path.mnt);
	// overlayfs maps its backing file in place of the step's file.
	if (!in_step_ns(mnt)) {
		if (!bpf_core_field_exists(struct backing_file, user_path)) {
			bump(&skipped_internal);
			return 0;
		}
		// FMODE_BACKING's value differs between releases; check the
		// filesystem instead.
		struct backing_file *bf = (void *)file;
		d = BPF_CORE_READ(bf, user_path.dentry);
		mnt = BPF_CORE_READ(bf, user_path.mnt);
		unsigned long magic = d ? BPF_CORE_READ(d, d_sb, s_magic) : 0;
		if ((magic != OVERLAYFS_SUPER_MAGIC && magic != FUSE_SUPER_MAGIC) || !in_step_ns(mnt)) {
			bump(&skipped_internal);
			return 0;
		}
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
 * Ends an open(2) family call's hold as the call returns, recording the open,
 * with the descriptor and flags from its arguments for a failed one. A call
 * with no hold names nothing the kernel looked up, as one a seccomp filter or
 * a tracer stopped, unless getname refused its name as too long, which is then
 * read from the caller.
 */
static __always_inline void open_returned(u32 slot, struct pt_regs *regs, long nr, long ret)
{
	int at = nr == nr_openat || nr == nr_openat2;
	if (ret == -ENAMETOOLONG)
		open_name(slot, (const char *)sys_arg(regs, at), 1);
	struct event *e = open_return(slot, ret);
	if (!e)
		return;
	u32 flags;
	if (nr == nr_creat) {
		flags = O_CREAT | O_WRONLY | O_TRUNC;
	} else if (nr == nr_openat2) {
		u64 f = 0; // open_how's first field
		bpf_probe_read_user(&f, sizeof(f), (void *)sys_arg(regs, 2));
		flags = f;
	} else {
		flags = sys_arg(regs, at + 1);
	}
	open_failed(slot, e, ret, at ? (int)sys_arg(regs, 0) : AT_FDCWD, flags);
}

/**
 * Reports a held path change when its syscall returns: as done if it
 * succeeded (a truncating open returns a descriptor), else as failed with the
 * errno, unless the call is one recorded from its exit (see classify()),
 * whose record then stands for the failure.
 */
SEC("tp_btf/sys_exit")
int BPF_PROG(on_sys_exit, struct pt_regs *regs, long ret)
{
	if (!in_target())
		return 0;
	struct path_call call = {}; // so no field reaches the stack unset
	long nr = sys_nr(regs);
	int watched = classify(nr, regs, &call);
	struct held_key k = held_key(HELD_OP);
	struct event *head = bpf_map_lookup_elem(&heads, &k);
	if (head) {
		u32 t = tails_for(head->data_len);
		if (!is_restart(ret) && (ret >= 0 || !watched))
			report_held(slot, &k, head, ret < 0 ? -ret : 0, 0);
		release(&k, t);
	}
	if (watched)
		op_exit(slot, &call, ret);
	if (is_open_nr(nr))
		open_returned(slot, regs, nr, ret);
	return 0;
}

char LICENSE[] SEC("license") = "Dual MIT/GPL";

_Static_assert(__COUNTER__ <= N_SLOTS, "a program has no scratch event of its own");

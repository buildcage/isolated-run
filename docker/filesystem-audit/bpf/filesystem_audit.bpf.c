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
	if (hold_open(e) != 0)
		submit(e);
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

static __always_inline void open_enter(u32 slot, int dfd, u32 flags)
{
	if (in_target())
		open_begin(slot, dfd, flags);
}

/** Records the failed open assembled in e, its name in place. */
static __always_inline void open_failed(u32 slot, struct event *e, long ret)
{
	u64 ts = e->ts;
	u32 flags = e->flags;
	s32 dfd = e->gid;
	u8 cut = e->truncated;
	u32 off = e->data_len;
	// A name kept cut for want of tails, marked in n2, has lost its end, the
	// part that names the file.
	if (e->n2)
		bump(&untracked);
	// start resets the header of the scratch e is in.
	if (start(slot, K_OPEN_FAILED) != e)
		return;
	e->ts = ts;
	e->path_len = -ret;
	e->flags = flags;
	e->truncated = cut;
	if (off == 0 || off > PATH_LEN) {
		e->data[0] = 0; // the name could not be read: an empty one
		off = 1;
	}
	u8 n = 0;
	if (off > 1 && e->data[0] != '/') {
		off = add_base(e, off, dfd, &n, &e->truncated, 1, 0);
		e->mode = n;
	}
	e->data_len = off;
	submit(e);
}

static __always_inline void open_exit(u32 slot, long ret)
{
	struct event *e = open_end(slot, ret);
	if (e)
		open_failed(slot, e, ret);
}

/**
 * open/openat reach do_sys_openat2 through do_sys_open, which may inline
 * it; hooking both covers either build. When both fire, the inner exit
 * emits and the outer one finds nothing left.
 */
SEC("fentry/do_sys_openat2")
int BPF_PROG(on_openat2_enter, int dfd, const char *filename, struct open_how *how)
{
	open_enter(slot, dfd, BPF_CORE_READ(how, flags));
	return 0;
}

SEC("fentry/do_sys_open")
int BPF_PROG(on_open_enter, int dfd, const char *filename, int flags)
{
	open_enter(slot, dfd, flags);
	return 0;
}

static __always_inline void stash_name(u32 slot, u64 *ctx)
{
	struct filename *ret = 0;
	bpf_get_func_ret(ctx, (u64 *)&ret);
	if ((long)ret < 0 && (long)ret >= -4095)
		return;
	hold_name(slot, BPF_CORE_READ(ret, name));
}

/**
 * Some builds inline getname_flags into getname (6.8), others call
 * getname_flags directly (7.0); either may be absent, so both are optional.
 */
SEC("fexit/getname_flags")
int on_getname(u64 *ctx)
{
	stash_name(__COUNTER__, ctx);
	return 0;
}

SEC("fexit/getname")
int on_getname_outer(u64 *ctx)
{
	stash_name(__COUNTER__, ctx);
	return 0;
}

/**
 * bpf_get_func_ret rather than a declared ret argument: the argument lists
 * of these internal functions change between kernel releases. The return
 * type does too (long, later int), so only the low 32 bits are used.
 */
SEC("fexit/do_sys_openat2")
int on_openat2_exit(u64 *ctx)
{
	u64 ret = 0;
	bpf_get_func_ret(ctx, &ret);
	open_exit(__COUNTER__, (int)ret);
	return 0;
}

SEC("fexit/do_sys_open")
int on_open_exit(u64 *ctx)
{
	u64 ret = 0;
	bpf_get_func_ret(ctx, &ret);
	open_exit(__COUNTER__, (int)ret);
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
	u64 key = (u64)file;
	bpf_map_delete_elem(&seen_files, &key);
	return 0;
}

SEC("tp_btf/sys_enter")
int BPF_PROG(on_sys_enter, struct pt_regs *regs, long nr)
{
	struct pending p;
	// The number first, which rules out nearly every syscall on the host
	// more cheaply than the cgroup check.
	if (!classify(nr, regs, &p) || !in_target())
		return 0;
	p.nr = nr;
	p.ts = bpf_ktime_get_boot_ns();
	u64 id = bpf_get_current_pid_tgid();
	// An op recorded on success too is lost either way; one recorded only on
	// failure is counted at the exit, once the result is known.
	if (bpf_map_update_elem(&pending_ops, &id, &p, BPF_ANY) != 0 && p.kind_ok)
		bump(&untracked);
	return 0;
}

/**
 * Reports a held path change when its syscall returns: as done if it
 * succeeded (a truncating open returns a descriptor), else as failed with the
 * errno, unless the syscall's entry stashed it, whose record then stands for
 * the failure.
 */
SEC("tp_btf/sys_exit")
int BPF_PROG(on_sys_exit, struct pt_regs *regs, long ret)
{
	if (!in_target())
		return 0;
	u64 id = bpf_get_current_pid_tgid();
	long nr = sys_nr(regs);
	struct pending want;
	struct pending *pend = 0;
	if (classify(nr, 0, &want)) {
		pend = bpf_map_lookup_elem(&pending_ops, &id);
		// Only this syscall's own entry: one another left is dropped.
		if (pend && pend->nr != nr) {
			bpf_map_delete_elem(&pending_ops, &id);
			pend = 0;
		}
		// A failure-only op whose entry the full map did not take.
		if (!pend && !want.kind_ok && ret < 0 && -ret != want.quiet_err)
			bump(&untracked);
	}
	struct held_key k = held_key(HELD_OP);
	struct event *head = bpf_map_lookup_elem(&heads, &k);
	if (head) {
		u32 t = tails_for(head->data_len);
		// A failure the syscall's entry recorded stands for this one.
		if (ret >= 0 || !pend)
			report_held(slot, &k, head, ret < 0 ? -ret : 0, 0);
		release(&k, t);
	}
	if (pend) {
		op_exit(slot, pend, ret);
		bpf_map_delete_elem(&pending_ops, &id);
	}
	return 0;
}

char LICENSE[] SEC("license") = "Dual MIT/GPL";

_Static_assert(__COUNTER__ <= N_SLOTS, "a program has no scratch event of its own");

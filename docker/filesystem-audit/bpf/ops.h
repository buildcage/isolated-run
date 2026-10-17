// SPDX-License-Identifier: MIT OR GPL-2.0-only
/**
 * @file ops.h
 * The programs on path changes: create, move, delete, link and attribute
 * changes, each settled by its call's K_RESULT.
 *
 * Programs, included by filesystem_audit.bpf.c after the headers they
 * use and its BPF_PROG.
 */
#ifndef FILESYSTEM_AUDIT_OPS_H
#define FILESYSTEM_AUDIT_OPS_H

#define PF_SIGNALED 0x00000400 ///< Dying of a fatal signal; set before a core dump.

/**
 * Sends the path change @p e. Its hook runs before the kernel's own permission
 * checks (may_delete, may_create, notify_change), so whether it happened is
 * known only from the call's K_RESULT. A core dump creates its file from the
 * dying task, outside any call that sends one, so nothing is sent for it; the
 * file's open, with O_CREAT, records it.
 */
static __always_inline void send_op(struct event *e)
{
	if (bpf_get_current_task_btf()->flags & PF_SIGNALED)
		return;
	e->tid = (u32)bpf_get_current_pid_tgid();
	e->nr = current_sys_nr();
	submit(e);
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

#endif

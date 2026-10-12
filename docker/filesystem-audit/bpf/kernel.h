// SPDX-License-Identifier: GPL-2.0
/**
 * @file kernel.h
 * The kernel types the tracer reads, declared locally with
 * preserve_access_index so one CO-RE object runs on every BTF-enabled kernel.
 */
#ifndef FILESYSTEM_AUDIT_KERNEL_H
#define FILESYSTEM_AUDIT_KERNEL_H

struct qstr {
	const unsigned char *name;
} __attribute__((preserve_access_index));

struct super_block {
	unsigned long s_magic;
} __attribute__((preserve_access_index));

struct hlist_bl_node {
	struct hlist_bl_node *next, **pprev;
} __attribute__((preserve_access_index));

struct dentry {
	struct hlist_bl_node d_hash;
	struct dentry *d_parent;
	struct qstr d_name;
	struct super_block *d_sb;
} __attribute__((preserve_access_index));

struct vfsmount {
	struct dentry *mnt_root;
	int mnt_flags;
} __attribute__((preserve_access_index));

struct mnt_namespace;

struct mount {
	struct mount *mnt_parent;
	struct dentry *mnt_mountpoint;
	struct vfsmount mnt;
	struct mnt_namespace *mnt_ns;
} __attribute__((preserve_access_index));

struct nsproxy {
	struct mnt_namespace *mnt_ns;
} __attribute__((preserve_access_index));

struct path {
	struct vfsmount *mnt;
	struct dentry *dentry;
} __attribute__((preserve_access_index));

struct inode {
	unsigned short i_mode;
	unsigned int i_flags;
} __attribute__((preserve_access_index));

struct file {
	struct path f_path;
	struct inode *f_inode;
	unsigned int f_flags;
	unsigned int f_mode;
} __attribute__((preserve_access_index));

struct open_how {
	__u64 flags;
} __attribute__((preserve_access_index));

/**
 * Since 6.7 a backing file's f_path is on the layer and user_path is the path
 * the step opened; before, f_path was that path.
 */
struct backing_file {
	struct file file;
	struct path user_path;
} __attribute__((preserve_access_index));

struct vm_area_struct {
	unsigned long vm_flags;
	struct file *vm_file;
} __attribute__((preserve_access_index));

struct fs_struct {
	struct path pwd;
} __attribute__((preserve_access_index));

struct fdtable {
	unsigned int max_fds;
	struct file **fd;
} __attribute__((preserve_access_index));

struct files_struct {
	struct fdtable *fdt;
} __attribute__((preserve_access_index));

struct task_struct {
	struct task_struct *real_parent;
	struct task_struct *group_leader;
	u64 start_time;
	u64 self_exec_id;
	int tgid;
	char comm[16];
	struct fs_struct *fs;
	struct files_struct *files;
	struct nsproxy *nsproxy;
} __attribute__((preserve_access_index));

struct filename {
	const char *name;
} __attribute__((preserve_access_index));

struct linux_binprm {
	const char *filename;
	struct file *file;
} __attribute__((preserve_access_index));

/**
 * The registers each architecture passes a syscall's number and first
 * arguments in.
 */
struct pt_regs___x86 {
	unsigned long di, si, dx, r10, orig_ax;
} __attribute__((preserve_access_index));

struct pt_regs___arm64 {
	unsigned long regs[31];
	int syscallno;
} __attribute__((preserve_access_index));

#endif

// SPDX-License-Identifier: MIT OR GPL-2.0-only
/**
 * @file path.h
 * Spelling out the path of a dentry or file, and of the base directory
 * a relative name resolves against.
 */
#ifndef FILESYSTEM_AUDIT_PATH_H
#define FILESYSTEM_AUDIT_PATH_H

#include "record.h"

#define AT_FDCWD -100
#define MAX_COMPONENTS 254 ///< n1 and n2 are u8; a longer walk is marked cut

/**
 * Field offsets are resolved by CO-RE in the caller and handed over, since
 * relocations inside a bpf_loop callback come out poisoned with cilium/ebpf.
 */
struct walk_ctx {
	void *d;
	void *vfs;
	void *mnt;
	struct event *e;
	u32 off;
	u32 n;
	u8 *trunc;
	u8 done; ///< reached the namespace root, or set *trunc itself
	u32 off_mnt_root, off_d_parent, off_d_name, off_mnt_parent, off_mountpoint, off_mnt;
};

static __always_inline void *rd_ptr(void *base, u32 off)
{
	void *v = 0;
	bpf_probe_read_kernel(&v, sizeof(v), base + off);
	return v;
}

/**
 * The first of two paths gets half the buffer, so a deep one leaves the
 * second room.
 */
#define FIRST_PATH_END (DATA_SZ / 2)

/**
 * end is a constant in each caller below: compared with a value from the
 * context instead, the verifier tracks off exactly and runs out of states.
 */
static __always_inline long walk_step_to(struct walk_ctx *c, u32 end)
{
	void *root = rd_ptr(c->vfs, c->off_mnt_root);
	void *parent = rd_ptr(c->d, c->off_d_parent);
	if (c->d == root || c->d == parent) {
		void *up = rd_ptr(c->mnt, c->off_mnt_parent);
		if (c->d != root || up == c->mnt) {
			c->done = 1;
			return 1;
		}
		c->d = rd_ptr(c->mnt, c->off_mountpoint);
		c->mnt = up;
		c->vfs = up + c->off_mnt;
		return 0;
	}
	if (c->off >= end) {
		*c->trunc = 1;
		c->done = 1;
		return 1;
	}
	long r = bpf_probe_read_kernel_str(&c->e->data[c->off & (DATA_SZ - 1)], NAME_LEN,
					   rd_ptr(c->d, c->off_d_name));
	// Count a component only when its name was stored, so n never exceeds the
	// NUL-terminated names the decoder will find.
	if (r > 0) {
		c->off += r;
		c->n++;
	}
	c->d = parent;
	return 0;
}

static long walk_step(u64 i, struct walk_ctx *c)
{
	return walk_step_to(c, DATA_SZ);
}

static long walk_step_first(u64 i, struct walk_ctx *c)
{
	return walk_step_to(c, FIRST_PATH_END);
}

/**
 * Appends the leaf-first path components of a dentry under a mount to
 * e->data at off, crossing mounts up to the namespace root like d_path; the
 * first of two paths stops at FIRST_PATH_END and is marked cut there.
 */
static __always_inline u32 walk_path(struct event *e, u32 off, int first, struct dentry *d,
				     struct vfsmount *vfs, u8 *n, u8 *trunc)
{
	u32 off_mnt = bpf_core_field_offset(struct mount, mnt);
	struct walk_ctx c = {
		.d = d,
		.vfs = vfs,
		.mnt = (void *)vfs - off_mnt,
		.e = e,
		.off = off,
		.n = *n,
		.trunc = trunc,
		.off_mnt_root = bpf_core_field_offset(struct vfsmount, mnt_root),
		.off_d_parent = bpf_core_field_offset(struct dentry, d_parent),
		.off_d_name = bpf_core_field_offset(struct dentry, d_name.name),
		.off_mnt_parent = bpf_core_field_offset(struct mount, mnt_parent),
		.off_mountpoint = bpf_core_field_offset(struct mount, mnt_mountpoint),
		.off_mnt = off_mnt,
	};
	if (first)
		bpf_loop(MAX_COMPONENTS, walk_step_first, &c, 0);
	else
		bpf_loop(MAX_COMPONENTS, walk_step, &c, 0);
	// Out of iterations short of the root, or before checking for it: the path
	// is treated as cut there, which keeps a deeper one from passing as the
	// shorter path it ends with.
	if (!c.done)
		*trunc = 1;
	*n = c.n;
	return c.off;
}

static __always_inline u32 walk(struct event *e, u32 off, struct dentry *d,
				struct vfsmount *vfs, u8 *n, u8 *trunc)
{
	return walk_path(e, off, 0, d, vfs, n, trunc);
}

static __always_inline u32 leaf(struct event *e, u32 off, struct dentry *d, u8 *n)
{
	if (off >= DATA_SZ)
		return off; // no room, rather than wrap onto what is stored
	// Keeps the compiler from dropping the mask below on the strength of the
	// check above, which the verifier does not see.
	asm volatile("" : "+r"(off));
	long r = bpf_probe_read_kernel_str(&e->data[off & (DATA_SZ - 1)], NAME_LEN,
					   BPF_CORE_READ(d, d_name.name));
	if (r <= 0)
		return off; // nothing stored, so do not count the leaf
	*n += 1;
	return off + r;
}

#define MNT_INTERNAL 0x4000
#define MARK_INTERNAL 1   ///< on a kernel-internal mount, as a memfd is
#define MARK_UNLINKED 2   ///< deleted, or an O_TMPFILE never linked
#define MARK_DESCRIPTOR 4 ///< the path is a descriptor's own file, not a name's
#define MARK_SPECIAL 8    ///< neither a regular file nor a directory

#define S_IFMT 0170000
#define S_IFREG 0100000
#define S_IFDIR 0040000

/**
 * Marks a file as d_path would show it (the unlinked test is d_unlinked's),
 * and reports whether it is kernel-internal.
 */
static __always_inline int mark_file(struct event *e, struct dentry *d, struct vfsmount *mnt)
{
	if (BPF_CORE_READ(mnt, mnt_flags) & MNT_INTERNAL) {
		e->marks |= MARK_INTERNAL;
		return 1;
	}
	if (!BPF_CORE_READ(d, d_hash.pprev) && BPF_CORE_READ(d, d_parent) != d)
		e->marks |= MARK_UNLINKED;
	return 0;
}

/**
 * A relative name in a syscall resolves against dfd: the calling task's
 * working directory for AT_FDCWD, else that open directory. Appends the
 * directory's leaf-first components at off and sets bit in e->bases, or
 * leaves both alone when the fd is not open. Read at the syscall's exit, so a
 * thread that closes the fd or changes directory meanwhile can give another
 * directory.
 */
static __always_inline u32 append_base(struct event *e, u32 off, int dfd, u8 *n, u8 *trunc,
				       u32 bit, int first)
{
	struct task_struct *t = bpf_get_current_task_btf();
	struct dentry *d;
	struct vfsmount *m;
	if (dfd == AT_FDCWD) {
		d = BPF_CORE_READ(t, fs, pwd.dentry);
		m = BPF_CORE_READ(t, fs, pwd.mnt);
	} else {
		struct fdtable *fdt = BPF_CORE_READ(t, files, fdt);
		if (dfd < 0 || (unsigned int)dfd >= BPF_CORE_READ(fdt, max_fds))
			return off;
		struct file **fds = BPF_CORE_READ(fdt, fd);
		struct file *f = 0;
		bpf_probe_read_kernel(&f, sizeof(f), &fds[dfd]);
		if (!f)
			return off;
		d = BPF_CORE_READ(f, f_path.dentry);
		m = BPF_CORE_READ(f, f_path.mnt);
	}
	if (!d || !m)
		return off;
	e->bases |= bit;
	if (off >= DATA_SZ) {
		*trunc = 1;
		return off;
	}
	asm volatile("" : "+r"(off)); // as in leaf
	// A descriptor's own file is marked; the reader applies it only where the
	// path is that file (MARK_DESCRIPTOR).
	if (dfd != AT_FDCWD) {
		u32 type = BPF_CORE_READ(d, d_inode, i_mode) & S_IFMT;
		if (type != S_IFREG && type != S_IFDIR)
			e->marks |= MARK_SPECIAL;
		if (mark_file(e, d, m))
			return leaf(e, off, d, n);
	}
	return walk_path(e, off, first, d, m, n, trunc);
}

/**
 * append_base for the first name (@p bit 1) or the second (2), counting the
 * components it appends in e->mode or e->flags respectively.
 *
 * Not inlined, which leaves on_sys_exit smaller and quicker to verify.
 */
static __noinline u32 add_base(struct event *e, u32 off, int dfd, u32 bit, int first)
{
	u8 n = 0;
	off = append_base(e, off, dfd, &n, bit == 2 ? &e->trunc2 : &e->truncated, bit, first);
	if (bit == 2)
		e->flags = n;
	else
		e->mode = n;
	return off;
}

static __always_inline u32 path_walk(struct event *e, struct dentry *d, struct vfsmount *mnt)
{
	// A memfd's dentry has no parent to walk; its name is the whole of it.
	if (mark_file(e, d, mnt))
		return leaf(e, 0, d, &e->n1);
	return walk(e, 0, d, mnt, &e->n1, &e->truncated);
}

static __always_inline u32 file_walk(struct event *e, struct file *file)
{
	return path_walk(e, BPF_CORE_READ(file, f_path.dentry), BPF_CORE_READ(file, f_path.mnt));
}

/**
 * bpf_d_path fails on a path over PATH_LEN; such a path is spelled from its
 * dentries instead, so the access keeps a name (n1 > 0 tells the reader).
 */
static __always_inline void file_path(struct event *e, struct file *file)
{
	// Marked first: a file unlinked in between keeps d_path's suffix in its
	// path rather than lose a real one.
	mark_file(e, BPF_CORE_READ(file, f_path.dentry), BPF_CORE_READ(file, f_path.mnt));
	long r = bpf_d_path(&file->f_path, e->data, PATH_LEN);
	e->path_len = r;
	if (r > 0) {
		e->data_len = r;
		return;
	}
	e->data_len = file_walk(e, file);
}

/**
 * overlayfs reaches its layers through private clones of their mounts, which
 * belong to no namespace the step can open a file in, so an access through one
 * is the overlay's, not the step's. Kernel-internal mounts (pipes, memfd) count.
 */
static __always_inline int in_step_ns(struct vfsmount *vfs)
{
	if (BPF_CORE_READ(vfs, mnt_flags) & MNT_INTERNAL)
		return 1;
	struct mount *m = (void *)vfs - bpf_core_field_offset(struct mount, mnt);
	struct task_struct *t = bpf_get_current_task_btf();
	return BPF_CORE_READ(m, mnt_ns) == t->nsproxy->mnt_ns;
}

#define OVERLAYFS_SUPER_MAGIC 0x794c7630
#define FUSE_SUPER_MAGIC 0x65735546

/**
 * Sets @p d and @p mnt to the path the step reached @p file by. That is the
 * file's own, or for one overlayfs or FUSE uses in place of the step's file,
 * the step's file. FMODE_BACKING's value differs between releases, so the
 * filesystem tells a backing file.
 *
 * @return 0 for a file of a mount the step cannot reach, leaving @p d and
 *         @p mnt unusable.
 */
static __always_inline int step_path_of(struct file *file, struct dentry **d,
					struct vfsmount **mnt)
{
	*d = BPF_CORE_READ(file, f_path.dentry);
	*mnt = BPF_CORE_READ(file, f_path.mnt);
	if (in_step_ns(*mnt))
		return 1;
	if (!bpf_core_field_exists(struct backing_file, user_path))
		return 0;
	struct backing_file *bf = (void *)file;
	*d = BPF_CORE_READ(bf, user_path.dentry);
	*mnt = BPF_CORE_READ(bf, user_path.mnt);
	unsigned long magic = *d ? BPF_CORE_READ(*d, d_sb, s_magic) : 0;
	return (magic == OVERLAYFS_SUPER_MAGIC || magic == FUSE_SUPER_MAGIC) && in_step_ns(*mnt);
}

/**
 * Whether @p file is a layer's rather than the step's. Before 6.7 (no
 * backing_file user_path), overlayfs opened a layer's file under the step's
 * path, so only its inode tells it apart.
 */
static __always_inline int on_layer(struct file *file)
{
	if (in_step_ns(file->f_path.mnt) &&
	    (bpf_core_field_exists(struct backing_file, user_path) ||
	     BPF_CORE_READ(file, f_inode) == BPF_CORE_READ(file, f_path.dentry, d_inode)))
		return 0;
	return 1;
}

#endif

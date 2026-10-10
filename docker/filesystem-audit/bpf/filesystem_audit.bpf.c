// SPDX-License-Identifier: GPL-2.0
// Records the file accesses of every task in one cgroup v2 subtree: opens,
// each program's first read and write of each open file, mmaps, execs, and the path
// operations (create, move, delete, attribute change), successes and
// failures alike. Kernel types are declared locally with preserve_access_index
// so one CO-RE object runs on any BTF-enabled kernel from 6.1 on, 6.4 on
// arm64, the first to let fentry attach to a kernel function there.

#include <linux/types.h>
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

typedef __u8 u8;
typedef __u32 u32;
typedef __s32 s32;
typedef __u64 u64;

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

// Since 6.7 a backing file's f_path is on the layer and user_path is the path
// the step opened; before, f_path was that path.
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

// The registers each architecture passes a syscall's first arguments in.
struct pt_regs___x86 {
	unsigned long di, si, dx, r10;
} __attribute__((preserve_access_index));

struct pt_regs___arm64 {
	unsigned long regs[31];
} __attribute__((preserve_access_index));

#define DATA_SZ 8192
#define PATH_LEN 4096
#define NAME_LEN 256
#define MAX_COMPONENTS 254 // n1 and n2 are u8; a longer walk is marked cut
#define WAKEUP_BYTES (1 << 20)
#define AT_FDCWD -100
#define AT_REMOVEDIR 0x200

enum kind { K_OPEN = 1, K_EXEC = 2, K_UNLINK = 3, K_RMDIR = 4, K_RENAME = 5,
	K_MKDIR = 6, K_CHMOD = 7, K_SYMLINK = 8, K_LINK = 9, K_TRUNCATE = 10, K_CHOWN = 11,
	K_OPEN_FAILED = 12, K_READ = 13, K_WRITE = 14, K_MMAP = 15,
	// Failed path syscalls: data holds the user path(s), NUL-separated (old
	// then new for rename), then the base directories of the relative ones
	// (see add_base); path_len holds the errno.
	K_UNLINK_FAILED = 16, K_RENAME_FAILED = 17, K_CHMOD_FAILED = 18,
	K_CHOWN_FAILED = 19, K_ATTR = 20, K_ATTR_FAILED = 21,
	// A new process: pid is the child, ppid the process that made it, where
	// every other kind's ppid is its current parent; no data.
	K_FORK = 22,
	// The file an exec is about to run, before a script hands over to its
	// interpreter: path components, as for unlink. The reader moves it onto
	// the exec event that follows.
	K_EXEC_FILE = 23,
	// A file, FIFO, device or Unix socket made by mknod(2) or bind(2): path
	// components, as for unlink.
	K_MKNOD = 24,
	// A failed rmdir, or unlinkat with AT_REMOVEDIR; as K_UNLINK_FAILED.
	K_RMDIR_FAILED = 25,
	// A failed mkdir, mknod, symlink (the link's name) or truncate, as
	// K_UNLINK_FAILED; a failed link as K_RENAME_FAILED.
	K_MKDIR_FAILED = 26, K_MKNOD_FAILED = 27, K_SYMLINK_FAILED = 28,
	K_LINK_FAILED = 29, K_TRUNCATE_FAILED = 30 };

// Fixed header (mirrored by hdrLen in decode.go), then data_len bytes of data:
//   open:    d_path result (path_len is its return value)
//   failed open: the name as passed to open(2), then its base directory if
//            it is relative (see add_base); path_len holds the errno
//   read/write: d_path result, once per open file, direction and program
//   mmap:    path components; mode holds prot, flags the map flags, and
//            path_len is 1 when an exec mapped it (see in_exec)
//   exec:    filename; its arguments are not read, as they can hold secrets
//   symlink: link body at 0, then the link's own path components
//   others:  leaf-first NUL-terminated path components, n1 of them, then
//            n2 more for a rename or link target
struct event {
	u32 kind;
	u32 pid;
	u32 ppid;
	u32 flags;
	u32 mode;
	s32 path_len;
	u32 bases; // which relative names add_base found a directory for
	u32 data_len;
	u8 n1;
	u8 n2;
	u8 truncated;  // the path, or the first path of a two-path operation
	u8 trunc2;     // the second path of a rename or link
	char comm[16];
	u32 err; // a held path change's errno when its syscall refused it
	u32 marks; // MARK_* for the file a path was taken from
	u64 ts; // CLOCK_BOOTTIME at the access; a failed syscall at its entry
	char data[DATA_SZ + NAME_LEN]; // slack: masked offset + one component
};

// Keeps struct event in BTF for bpf2go's -type.
const struct event *unused_event __attribute__((unused));

// The watched cgroup, set by the loader. Descent is checked in the kernel's
// own hierarchy, whatever cgroup namespace the loader runs in.
struct {
	__uint(type, BPF_MAP_TYPE_CGROUP_ARRAY);
	__uint(max_entries, 1);
	__type(key, u32);
	__type(value, u32);
} target SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 64 << 20);
} events SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, u32);
	__type(value, u64);
} drops SEC(".maps"), untracked SEC(".maps"), skipped_internal SEC(".maps");

static __always_inline void bump(void *counter)
{
	u32 zero = 0;
	u64 *v = bpf_map_lookup_elem(counter, &zero);
	if (v)
		*v += 1; // per-CPU, no atomics needed
}

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, u32);
	__type(value, struct event);
} scratch SEC(".maps");

struct pending {
	u64 p1;
	u64 p2;
	u64 ts;
	u32 kind;      // emitted on failure
	u32 kind_ok;   // emitted on success, 0 to skip
	u32 quiet_err; // an errno that changed nothing, so is not recorded
	s32 dfd1;      // what p1 and p2 resolve against when relative
	s32 dfd2;
};

// One entry per thread inside a path syscall.
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 65536);
	__type(key, u64);
	__type(value, struct pending);
} pending_ops SEC(".maps");

static __always_inline int in_target(void)
{
	return bpf_current_task_under_cgroup(&target, 0) == 1;
}

static __always_inline struct event *start(u32 kind)
{
	u32 zero = 0;
	struct event *e = bpf_map_lookup_elem(&scratch, &zero);
	if (!e)
		return 0;
	struct task_struct *t = bpf_get_current_task_btf();
	e->kind = kind;
	e->pid = bpf_get_current_pid_tgid() >> 32;
	e->ppid = BPF_CORE_READ(t, real_parent, tgid);
	e->flags = 0;
	e->mode = 0;
	e->path_len = 0;
	e->bases = 0;
	e->data_len = 0;
	e->n1 = 0;
	e->n2 = 0;
	e->truncated = 0;
	e->trunc2 = 0;
	e->marks = 0;
	// The process's name, as ps shows it, not the thread's: a JVM or tokio
	// worker thread names itself after its pool.
	BPF_CORE_READ_STR_INTO(&e->comm, t, group_leader, comm);
	e->err = 0;
	e->ts = bpf_ktime_get_boot_ns();
	return e;
}

static __always_inline void submit(struct event *e)
{
	u32 len = e->data_len;
	if (len > DATA_SZ + NAME_LEN)
		len = DATA_SZ + NAME_LEN;
	u64 size = __builtin_offsetof(struct event, data) + len;
	if (size > sizeof(*e))
		size = sizeof(*e);
	// Waking the reader per event costs more than the event itself; it
	// polls on a timer and is woken only once a backlog builds up.
	u64 flags = bpf_ringbuf_query(&events, BPF_RB_AVAIL_DATA) > WAKEUP_BYTES ?
		    BPF_RB_FORCE_WAKEUP : BPF_RB_NO_WAKEUP;
	if (bpf_ringbuf_output(&events, e, size, flags) != 0)
		bump(&drops);
}

// A path change, held per thread from its security_path_* hook until the
// syscall returns: the hook runs before the kernel's own permission checks
// (may_delete, may_create, notify_change), so whether it happened is known
// only then. Each entry is an event, so allocated on use, and lives only while
// its syscall runs.
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 4096);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__type(key, u64);
	__type(value, struct event);
} held_ops SEC(".maps");

static __always_inline void hold(struct event *e)
{
	u64 id = bpf_get_current_pid_tgid();
	if (bpf_map_update_elem(&held_ops, &id, e, BPF_ANY) != 0)
		bump(&untracked);
}

// Field offsets are resolved by CO-RE in the caller and handed over, since
// relocations inside a bpf_loop callback come out poisoned with cilium/ebpf.
struct walk_ctx {
	void *d;
	void *vfs;
	void *mnt;
	struct event *e;
	u32 off;
	u32 n;
	u8 *trunc;
	u8 done; // reached the namespace root, or set *trunc itself
	u32 off_mnt_root, off_d_parent, off_d_name, off_mnt_parent, off_mountpoint, off_mnt;
};

static __always_inline void *rd_ptr(void *base, u32 off)
{
	void *v = 0;
	bpf_probe_read_kernel(&v, sizeof(v), base + off);
	return v;
}

// The first of two paths gets half the buffer, so a deep one leaves the
// second room.
#define FIRST_PATH_END (DATA_SZ / 2)

// end is a constant in each caller below: compared with a value from the
// context instead, the verifier tracks off exactly and runs out of states.
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

// Appends the leaf-first path components of a dentry under a mount to
// e->data at off, crossing mounts up to the namespace root like d_path; the
// first of two paths stops at FIRST_PATH_END and is marked cut there.
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
#define MARK_INTERNAL 1 // on a kernel-internal mount, as a memfd is
#define MARK_UNLINKED 2 // deleted, or an O_TMPFILE never linked

// Marks a file as d_path would show it (the unlinked test is d_unlinked's),
// and reports whether it is kernel-internal.
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

// A relative name in a syscall resolves against dfd: the calling task's
// working directory for AT_FDCWD, else that open directory. Appends the
// directory's leaf-first components at off and sets bit in e->bases, or
// leaves both alone when the fd is not open. Read at the syscall's exit, so a
// thread that closes the fd or changes directory meanwhile can give another
// directory.
static __always_inline u32 add_base(struct event *e, u32 off, int dfd, u8 *n, u8 *trunc, u32 bit,
				    int first)
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
	// path is that file (futimens).
	if (dfd != AT_FDCWD && mark_file(e, d, m))
		return leaf(e, off, d, n);
	return walk_path(e, off, first, d, m, n, trunc);
}

// Open files already reported as read (1), written (2) or mapped
// executable (4), so each is reported once per direction and program rather
// than per read(2). Keyed by the struct file and cleared when it is freed,
// before the address can be reused.
#define SEEN_READ 1
#define SEEN_WRITE 2
#define SEEN_EXEC 4
#define MAY_WRITE 2
#define MAY_READ 4
#define PROT_WRITE 2
#define PROT_EXEC 4
#define MAP_SHARED 1
#define VM_SHARED 8
#define S_PRIVATE (1 << 9)
#define OVERLAYFS_SUPER_MAGIC 0x794c7630
#define FUSE_SUPER_MAGIC 0x65735546

// A program run by a process: its tgid, its leader's start time, which a
// reused pid does not share, and how many execs it has been through, so a
// program exec'd in place counts as its own.
struct proc {
	u64 start;
	u64 exec;
	u32 tgid;
	u32 pad;
};

struct seen {
	u64 gen;	  // when the entry was made, so a reused address is a new file
	struct proc owner; // the first process to use the file
	u32 bits;	  // what the owner has been reported doing with it
	u32 once;	  // reported once whoever uses it: see first_time
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 65536);
	__type(key, u64);
	__type(value, struct seen);
} seen_files SEC(".maps");

// What each other process sharing an open file, such as a child that
// inherited it, has been reported doing with it. An entry outlives its file,
// but gen keeps it from matching the next file at that address; losing one to
// eviction only reports that access again.
struct shared_key {
	u64 file;
	u64 gen;
	struct proc proc;
};

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 65536);
	__type(key, struct shared_key);
	__type(value, u32);
} shared_seen SEC(".maps");

#define S_IFMT 0170000
#define S_IFREG 0100000
#define S_IFDIR 0040000

// Sets bit in *bits, reporting whether it was clear. Not atomic: two processes
// racing on a shared entry can each report the same bit, never neither.
static __always_inline int set_first(u32 *bits, u32 bit)
{
	if (*bits & bit)
		return 0;
	*bits |= bit;
	return 1;
}

// Reports whether bit was newly recorded for file and the current program:
// false if it was already set, or if a map could not take the entry (so a
// saturated map cannot cause re-emission). That counts in untracked, since
// the access then goes unreported.
static __always_inline int first_time(struct file *file, u8 bit)
{
	u64 key = (u64)file;
	struct seen *v = bpf_map_lookup_elem(&seen_files, &key);
	if (v && v->once)
		return set_first(&v->bits, bit);
	struct task_struct *t = bpf_get_current_task_btf();
	struct proc me = {
		.start = BPF_CORE_READ(t, group_leader, start_time),
		.exec = BPF_CORE_READ(t, group_leader, self_exec_id),
		.tgid = bpf_get_current_pid_tgid() >> 32,
	};
	if (!v) {
		struct seen s;
		__builtin_memset(&s, 0, sizeof(s));
		s.gen = bpf_ktime_get_ns();
		s.owner = me;
		s.bits = bit;
		// Anything but a regular file or a directory, such as a pipe, a
		// socket or /dev/null, is shared by whole process trees and says
		// nothing per command.
		u32 type = BPF_CORE_READ(file, f_inode, i_mode) & S_IFMT;
		s.once = type != S_IFREG && type != S_IFDIR;
		if (bpf_map_update_elem(&seen_files, &key, &s, BPF_NOEXIST) == 0)
			return 1;
		// Another process made the entry first; share it.
		v = bpf_map_lookup_elem(&seen_files, &key);
		if (!v) {
			bump(&untracked);
			return 0;
		}
		if (v->once)
			return set_first(&v->bits, bit);
	}
	if (v->owner.tgid == me.tgid && v->owner.start == me.start && v->owner.exec == me.exec)
		return set_first(&v->bits, bit);
	struct shared_key k;
	__builtin_memset(&k, 0, sizeof(k));
	k.file = key;
	k.gen = v->gen;
	k.proc = me;
	u32 *b = bpf_map_lookup_elem(&shared_seen, &k);
	if (b)
		return set_first(b, bit);
	u32 nb = bit;
	if (bpf_map_update_elem(&shared_seen, &k, &nb, BPF_ANY) == 0)
		return 1;
	bump(&untracked);
	return 0;
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

// bpf_d_path fails on a path over PATH_LEN; such a path is spelled from its
// dentries instead, so the access keeps a name (n1 > 0 tells the reader).
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

// overlayfs reaches its layers through private clones of their mounts, which
// belong to no namespace the step can open a file in, so an access through one
// is the overlay's, not the step's. Kernel-internal mounts (pipes, memfd) count.
static __always_inline int in_step_ns(struct vfsmount *vfs)
{
	if (BPF_CORE_READ(vfs, mnt_flags) & MNT_INTERNAL)
		return 1;
	struct mount *m = (void *)vfs - bpf_core_field_offset(struct mount, mnt);
	struct task_struct *t = bpf_get_current_task_btf();
	return BPF_CORE_READ(m, mnt_ns) == t->nsproxy->mnt_ns;
}

static __always_inline int on_layer(struct file *file)
{
	if (in_step_ns(file->f_path.mnt))
		return 0;
	bump(&skipped_internal);
	return 1;
}

// The file being executed, resolved, while bprm->file is still the one named:
// by sched_process_exec a script has been swapped for its interpreter, and
// filename is only the name the caller passed, relative to its cwd or not.
SEC("fentry/security_bprm_creds_for_exec")
int BPF_PROG(on_exec_file, struct linux_binprm *bprm)
{
	if (!in_target())
		return 0;
	struct event *e = start(K_EXEC_FILE);
	if (!e)
		return 0;
	struct file *f = BPF_CORE_READ(bprm, file);
	e->data_len = file_walk(e, f);
	submit(e);
	return 0;
}

// Threads past an exec's point of no return and not yet through it. Its other
// threads are gone by then and this one runs no code of its own, so whatever
// it maps meanwhile is the kernel loading the new program, its dynamic
// loader and a script's interpreter.
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 65536);
	__type(key, u64);
	__type(value, u8);
} in_exec SEC(".maps");

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

// A thread killed inside an exec never reaches sched_process_exec.
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
	struct event *e = start(K_EXEC);
	if (!e)
		return 0;
	e->path_len = bpf_probe_read_kernel_str(e->data, PATH_LEN, BPF_CORE_READ(bprm, filename));
	e->data_len = e->path_len > 0 ? e->path_len : 0;
	submit(e);
	return 0;
}

// Every new process, so the recording shows who started each one, a subshell
// that never execs or touches a file included. ppid is the process that made
// it, not real_parent, which CLONE_PARENT sets to that process's own parent.
SEC("tp_btf/sched_process_fork")
int BPF_PROG(on_fork, struct task_struct *parent, struct task_struct *child)
{
	if (!in_target())
		return 0;
	int tgid = BPF_CORE_READ(child, tgid);
	if (tgid == BPF_CORE_READ(parent, tgid))
		return 0; // a new thread, not a process
	struct event *e = start(K_FORK);
	if (!e)
		return 0;
	e->pid = tgid;
	e->ppid = BPF_CORE_READ(parent, tgid);
	// The child's own name, copied from the thread that forked it.
	BPF_CORE_READ_STR_INTO(&e->comm, child, comm);
	submit(e);
	return 0;
}

// The security_path_* hooks run once per syscall at the VFS entry, unlike
// security_inode_*, which overlayfs calls again for each layer it touches.
#define DIR_ENTRY_HOOK(hook, kind_)						\
SEC("fentry/" #hook)								\
int BPF_PROG(on_##hook, const struct path *dir, struct dentry *dentry)		\
{										\
	if (!in_target())							\
		return 0;							\
	struct event *e = start(kind_);						\
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
	struct event *e = start(K_SYMLINK);
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
	struct event *e = start(K_RENAME);
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
	struct event *e = start(K_CHMOD);
	if (!e)
		return 0;
	e->mode = mode;
	e->data_len = path_walk(e, BPF_CORE_READ(path, dentry), BPF_CORE_READ(path, mnt));
	hold(e);
	return 0;
}

// A hard link gives an existing inode a second name; opens through the new
// name record only that name.
SEC("fentry/security_path_link")
int BPF_PROG(on_link, struct dentry *old_dentry, const struct path *new_dir,
	     struct dentry *new_dentry)
{
	if (!in_target())
		return 0;
	struct event *e = start(K_LINK);
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

// truncate(2) changes a file's contents without opening it.
SEC("fentry/security_path_truncate")
int BPF_PROG(on_truncate, const struct path *path)
{
	if (!in_target())
		return 0;
	struct event *e = start(K_TRUNCATE);
	if (!e)
		return 0;
	e->data_len = path_walk(e, BPF_CORE_READ(path, dentry), BPF_CORE_READ(path, mnt));
	hold(e);
	return 0;
}

// From 6.2, ftruncate(2) and a truncating open reach this rather than
// security_path_truncate; absent before (see main.go).
SEC("fentry/security_file_truncate")
int BPF_PROG(on_file_truncate, struct file *file)
{
	if (!in_target())
		return 0;
	struct event *e = start(K_TRUNCATE);
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
	struct event *e = start(K_CHOWN);
	if (!e)
		return 0;
	e->flags = uid;
	e->mode = gid;
	e->data_len = path_walk(e, BPF_CORE_READ(path, dentry), BPF_CORE_READ(path, mnt));
	hold(e);
	return 0;
}

// A refused or missing file never reaches security_file_open, so a failed
// open is caught at the syscall. The name is read from the kernel's own copy
// (getname_flags), not the user pointer, which the caller could rewrite
// before the syscall returns.
struct name_buf {
	char name[PATH_LEN];
	u64 ts;
	s32 dfd;
	u32 flags; // the open's flags, so a failure says whether it was to write
	u32 creating; // the open reached its create step (see on_mknod)
};

// One entry per thread inside open(2), each the size of a path, so allocated
// on use rather than up front; fentry and fexit programs may use such a map.
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 65536);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__type(key, u64);
	__type(value, struct name_buf);
} open_names SEC(".maps");

// An open(2) seen at security_file_open, held per thread until the syscall
// returns: the file's own open method, an LSM or the FIFO checks can still
// refuse it after that hook, and a refused one is recorded as failed instead.
// Each entry is an event, so as many as held_ops; an open that finds the map
// full is recorded at once, as before.
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 4096);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__type(key, u64);
	__type(value, struct event);
} held_opens SEC(".maps");

// An open from outside open(2), such as exec opening the program, has no exit
// to wait for here, and is recorded at once, as is one nested in an open
// already held, such as a FUSE passthrough's backing file.
SEC("fentry/security_file_open")
int BPF_PROG(on_open, struct file *file)
{
	if (!in_target() || on_layer(file))
		return 0;
	struct event *e = start(K_OPEN);
	if (!e)
		return 0;
	e->flags = file->f_flags;
	e->mode = file->f_mode;
	file_path(e, file);
	u64 id = bpf_get_current_pid_tgid();
	if (!bpf_map_lookup_elem(&open_names, &id) ||
	    bpf_map_update_elem(&held_opens, &id, e, BPF_NOEXIST) != 0)
		submit(e);
	return 0;
}

// mknod(2) and bind(2) to a path. A creating open also passes here, from
// may_o_create, and is skipped: the open records it.
SEC("fentry/security_path_mknod")
int BPF_PROG(on_mknod, const struct path *dir, struct dentry *dentry)
{
	if (!in_target())
		return 0;
	u64 id = bpf_get_current_pid_tgid();
	struct name_buf *nb = bpf_map_lookup_elem(&open_names, &id);
	if (nb) {
		nb->creating = 1;
		return 0;
	}
	struct event *e = start(K_MKNOD);
	if (!e)
		return 0;
	u32 off = leaf(e, 0, dentry, &e->n1);
	e->data_len = walk(e, off, BPF_CORE_READ(dir, dentry), BPF_CORE_READ(dir, mnt), &e->n1, &e->truncated);
	hold(e);
	return 0;
}

static __always_inline void open_enter(int dfd, u32 flags)
{
	if (!in_target())
		return;
	u64 id = bpf_get_current_pid_tgid();
	u32 zero = 0;
	struct event *e = bpf_map_lookup_elem(&scratch, &zero);
	if (!e)
		return;
	// When both hooks fire, do_sys_open's has already made the entry.
	struct name_buf *nb = bpf_map_lookup_elem(&open_names, &id);
	if (!nb) {
		e->data[0] = 0;
		// Seed from scratch so the hash value starts as an empty string. A full
		// map counts in untracked even if this open then succeeds and is recorded.
		if (bpf_map_update_elem(&open_names, &id, e->data, BPF_ANY) != 0) {
			bump(&untracked);
			return;
		}
		nb = bpf_map_lookup_elem(&open_names, &id);
		if (!nb)
			return;
	}
	nb->name[0] = 0;
	nb->ts = bpf_ktime_get_boot_ns();
	nb->dfd = dfd;
	nb->flags = flags;
	nb->creating = 0;
}

static __always_inline void open_exit(long ret)
{
	u64 id = bpf_get_current_pid_tgid();
	struct name_buf *nb = bpf_map_lookup_elem(&open_names, &id);
	if (!nb)
		return;
	// ERESTARTSYS to ERESTART_RESTARTBLOCK: a signal interrupted the open,
	// which the kernel runs again, and that run records it.
	if (ret <= -512 && ret >= -516) {
		bpf_map_delete_elem(&held_opens, &id);
		bpf_map_delete_elem(&open_names, &id);
		return;
	}
	struct event *held = bpf_map_lookup_elem(&held_opens, &id);
	if (held) {
		// Reaching the file after its create step means it was created,
		// whatever then refused the open.
		if (ret >= 0 || nb->creating)
			submit(held);
		bpf_map_delete_elem(&held_opens, &id);
	}
	if (ret < 0) {
		struct event *e = start(K_OPEN_FAILED);
		if (e) {
			e->ts = nb->ts;
			e->path_len = -ret;
			e->flags = nb->flags;
			long r = bpf_probe_read_kernel_str(e->data, PATH_LEN, nb->name);
			u32 off = r > 0 ? r : 0;
			u8 n = 0;
			if (r > 1 && e->data[0] != '/') {
				off = add_base(e, off, nb->dfd, &n, &e->truncated, 1, 0);
				e->mode = n;
			}
			e->data_len = off;
			submit(e);
		}
	}
	bpf_map_delete_elem(&open_names, &id);
}

// open/openat reach do_sys_openat2 through do_sys_open, which may inline
// it; hooking both covers either build. When both fire, the inner exit
// emits and the outer one finds nothing left.
SEC("fentry/do_sys_openat2")
int BPF_PROG(on_openat2_enter, int dfd, const char *filename, struct open_how *how)
{
	open_enter(dfd, BPF_CORE_READ(how, flags));
	return 0;
}

SEC("fentry/do_sys_open")
int BPF_PROG(on_open_enter, int dfd, const char *filename, int flags)
{
	open_enter(dfd, flags);
	return 0;
}

static __always_inline void stash_name(u64 *ctx)
{
	struct filename *ret = 0;
	bpf_get_func_ret(ctx, (u64 *)&ret);
	u64 id = bpf_get_current_pid_tgid();
	struct name_buf *nb = bpf_map_lookup_elem(&open_names, &id);
	if (!nb || ((long)ret < 0 && (long)ret >= -4095))
		return;
	bpf_probe_read_kernel_str(nb->name, PATH_LEN, BPF_CORE_READ(ret, name));
}

// Some builds inline getname_flags into getname (6.8), others call
// getname_flags directly (7.0); either may be absent, so both are optional.
SEC("fexit/getname_flags")
int on_getname(u64 *ctx)
{
	stash_name(ctx);
	return 0;
}

SEC("fexit/getname")
int on_getname_outer(u64 *ctx)
{
	stash_name(ctx);
	return 0;
}

// bpf_get_func_ret rather than a declared ret argument: the argument lists
// of these internal functions change between kernel releases. The return
// type does too (long, later int), so only the low 32 bits are used.
SEC("fexit/do_sys_openat2")
int on_openat2_exit(u64 *ctx)
{
	u64 ret = 0;
	bpf_get_func_ret(ctx, &ret);
	open_exit((int)ret);
	return 0;
}

SEC("fexit/do_sys_open")
int on_open_exit(u64 *ctx)
{
	u64 ret = 0;
	bpf_get_func_ret(ctx, &ret);
	open_exit((int)ret);
	return 0;
}

// read(2), write(2) and their vector, positional, splice, sendfile and
// copy_file_range forms all pass through rw_verify_area, which calls this;
// so does iterate_dir for a directory listing (as a read).
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
	struct event *e = start(kind);
	if (!e)
		return 0;
	file_path(e, file);
	submit(e);
	return 0;
}

static __always_inline void map_event(struct file *file, struct dentry *d, struct vfsmount *mnt,
				     unsigned long prot, unsigned long flags, u8 bit, int image)
{
	if (!first_time(file, bit))
		return;
	struct event *e = start(K_MMAP);
	if (!e)
		return;
	e->mode = prot;
	e->flags = flags;
	u64 id = bpf_get_current_pid_tgid();
	e->path_len = image && bpf_map_lookup_elem(&in_exec, &id) ? 1 : 0;
	e->data_len = d ? path_walk(e, d, mnt) : file_walk(e, file);
	submit(e);
}

// The write drops PROT_EXEC from its mode so it decodes as a write.
static __always_inline void map_events(struct file *file, struct dentry *d, struct vfsmount *mnt,
				      unsigned long prot, unsigned long flags, int at_mmap)
{
	int exec = prot & PROT_EXEC;
	int write = (prot & PROT_WRITE) && (flags & MAP_SHARED);
	if (exec)
		map_event(file, d, mnt, prot, flags, SEEN_EXEC, at_mmap);
	if (write)
		map_event(file, d, mnt, prot & ~PROT_EXEC, flags, SEEN_WRITE, 0);
	if (!exec && !write && at_mmap)
		map_event(file, d, mnt, prot, flags, SEEN_READ, 1);
}

// fexit, so only a mapping that was made is recorded: after the LSMs,
// do_mmap still refuses a shared writable mapping of a file not open for
// writing, and an executable one on a noexec mount. mmap(2) comes through
// vm_mmap_pgoff, and exec's own mappings through vm_mmap, which calls it but
// may have it inlined; one mapping seen at both is recorded once (first_time).
// The return value is read with bpf_get_func_ret, as for the open exits.
static __always_inline void mapped(u64 *ctx, struct file *file, unsigned long prot,
				   unsigned long flags)
{
	u64 ret = 0;
	bpf_get_func_ret(ctx, &ret);
	if (!file || ret >= (u64)-4095 || !in_target() || on_layer(file))
		return;
	map_events(file, 0, 0, prot, flags, 1);
}

SEC("fexit/vm_mmap_pgoff")
int BPF_PROG(on_mmap, struct file *file, unsigned long addr, unsigned long len,
	     unsigned long prot, unsigned long flags)
{
	mapped(ctx, file, prot, flags);
	return 0;
}

SEC("fexit/vm_mmap")
int BPF_PROG(on_vm_mmap, struct file *file, unsigned long addr, unsigned long len,
	     unsigned long prot, unsigned long flags)
{
	mapped(ctx, file, prot, flags);
	return 0;
}

// fexit, so only a change the LSMs allowed is recorded. reqprot is what the
// caller asked for, as mmap sees it; prot may add PROT_EXEC.
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
	map_events(file, d, mnt, reqprot, flags, 0);
	return 0;
}

SEC("fentry/security_file_free")
int BPF_PROG(on_file_free, struct file *file)
{
	u64 key = (u64)file;
	bpf_map_delete_elem(&seen_files, &key);
	return 0;
}

// Failed path syscalls. security_path_* fires only once the path has
// resolved, so a missing target (the common failure) never reaches it; the
// syscall's entry and exit catch it. The entry stashes the user path pointer(s);
// the exit emits only when ret < 0, reading them back. Best-effort: this reads
// the user buffer, which a concurrent thread could rewrite between entry and
// exit, so a failed op's recorded path is not tamper-proof the way the open
// path's getname copy is.
static __always_inline void stash(u32 kind, u32 kind_ok, u32 quiet_err, int dfd1, u64 p1, int dfd2, u64 p2)
{
	u64 id = bpf_get_current_pid_tgid();
	struct pending pend = {
		.p1 = p1, .p2 = p2, .ts = bpf_ktime_get_boot_ns(), .kind = kind, .kind_ok = kind_ok,
		.quiet_err = quiet_err, .dfd1 = dfd1, .dfd2 = dfd2,
	};
	// Counted before the outcome is known: the call goes unfollowed either way.
	if (bpf_map_update_elem(&pending_ops, &id, &pend, BPF_ANY) != 0)
		bump(&untracked);
}

static __always_inline void failed_op(u32 kind, int dfd1, u64 p1, int dfd2, u64 p2)
{
	stash(kind, 0, 0, dfd1, p1, dfd2, p2);
}

// Making a name. The kernel refuses one on a read-only mount before the
// security_path_* hook, so the failure is caught here. A name that is already
// there changed nothing, and mkdir -p meets one at every level it keeps, so
// EEXIST is not recorded.
#define EEXIST 17
static __always_inline void create_op(u32 kind, int dfd1, u64 p1, int dfd2, u64 p2)
{
	stash(kind, 0, EEXIST, dfd1, p1, dfd2, p2);
}

// utimensat, utime, utimes, futimesat and {,l}setxattr are the attribute
// changes with no security_path_* hook of their own; recorded here, success
// and failure alike. A NULL path (futimens) changes the file dfd refers to;
// with AT_FDCWD it names nothing and fails.
static __always_inline void attr_op(int dfd, u64 p)
{
	if (p || dfd != AT_FDCWD)
		stash(K_ATTR_FAILED, K_ATTR, 0, dfd, p, 0, 0);
}

// The syscall numbers of the architecture the tracer runs on, set by the
// loader; -1 for one it lacks (x86_64's older forms on arm64). A negative
// number is skipped, as the kernel passes -1 for a call that a ptrace or
// seccomp tracer cancelled. A 32-bit syscall numbers them differently, but
// under the audit the sandbox kills the thread that makes one before it
// reaches sys_enter.
const volatile long nr_unlinkat = -1, nr_unlink = -1, nr_rmdir = -1;
const volatile long nr_renameat2 = -1, nr_renameat = -1, nr_rename = -1;
const volatile long nr_fchmodat = -1, nr_fchmodat2 = -1, nr_chmod = -1;
const volatile long nr_fchownat = -1, nr_chown = -1, nr_lchown = -1;
const volatile long nr_utimensat = -1, nr_futimesat = -1, nr_utime = -1, nr_utimes = -1;
const volatile long nr_setxattr = -1, nr_lsetxattr = -1;
const volatile long nr_mkdirat = -1, nr_mkdir = -1, nr_mknodat = -1, nr_mknod = -1;
const volatile long nr_symlinkat = -1, nr_symlink = -1, nr_linkat = -1, nr_link = -1;
const volatile long nr_truncate = -1;

// A syscall's argument i (0 to 3), from the register it is passed in.
static __always_inline u64 sys_arg(struct pt_regs *regs, int i)
{
	struct pt_regs___x86 *x = (void *)regs;
	if (bpf_core_field_exists(x->di))
		return i == 0 ? x->di : i == 1 ? x->si : i == 2 ? x->dx : x->r10;
	return ((struct pt_regs___arm64 *)regs)->regs[i];
}

#define ARG(i) sys_arg(regs, i)
#define ENOSYS 38

SEC("tp_btf/sys_enter")
int BPF_PROG(on_sys_enter, struct pt_regs *regs, long nr)
{
	if (nr < 0 || !in_target())
		return 0;
	if (nr == nr_unlinkat)
		failed_op(ARG(2) & AT_REMOVEDIR ? K_RMDIR_FAILED : K_UNLINK_FAILED, ARG(0), ARG(1), 0, 0);
	else if (nr == nr_unlink)
		failed_op(K_UNLINK_FAILED, AT_FDCWD, ARG(0), 0, 0);
	else if (nr == nr_rmdir)
		failed_op(K_RMDIR_FAILED, AT_FDCWD, ARG(0), 0, 0);
	else if (nr == nr_renameat2 || nr == nr_renameat)
		failed_op(K_RENAME_FAILED, ARG(0), ARG(1), ARG(2), ARG(3));
	else if (nr == nr_rename)
		failed_op(K_RENAME_FAILED, AT_FDCWD, ARG(0), AT_FDCWD, ARG(1));
	else if (nr == nr_fchmodat)
		failed_op(K_CHMOD_FAILED, ARG(0), ARG(1), 0, 0);
	else if (nr == nr_fchmodat2) // ENOSYS: a kernel before 6.6, so nothing was tried
		stash(K_CHMOD_FAILED, 0, ENOSYS, ARG(0), ARG(1), 0, 0);
	else if (nr == nr_chmod)
		failed_op(K_CHMOD_FAILED, AT_FDCWD, ARG(0), 0, 0);
	else if (nr == nr_fchownat)
		failed_op(K_CHOWN_FAILED, ARG(0), ARG(1), 0, 0);
	else if (nr == nr_chown || nr == nr_lchown)
		failed_op(K_CHOWN_FAILED, AT_FDCWD, ARG(0), 0, 0);
	else if (nr == nr_utimensat || nr == nr_futimesat)
		attr_op(ARG(0), ARG(1));
	else if (nr == nr_utime || nr == nr_utimes || nr == nr_setxattr || nr == nr_lsetxattr)
		attr_op(AT_FDCWD, ARG(0));
	else if (nr == nr_mkdirat)
		create_op(K_MKDIR_FAILED, ARG(0), ARG(1), 0, 0);
	else if (nr == nr_mkdir)
		create_op(K_MKDIR_FAILED, AT_FDCWD, ARG(0), 0, 0);
	else if (nr == nr_mknodat)
		create_op(K_MKNOD_FAILED, ARG(0), ARG(1), 0, 0);
	else if (nr == nr_mknod)
		create_op(K_MKNOD_FAILED, AT_FDCWD, ARG(0), 0, 0);
	else if (nr == nr_symlinkat) // (target, newdfd, name): the link's name
		create_op(K_SYMLINK_FAILED, ARG(1), ARG(2), 0, 0);
	else if (nr == nr_symlink)
		create_op(K_SYMLINK_FAILED, AT_FDCWD, ARG(1), 0, 0);
	else if (nr == nr_linkat)
		create_op(K_LINK_FAILED, ARG(0), ARG(1), ARG(2), ARG(3));
	else if (nr == nr_link)
		create_op(K_LINK_FAILED, AT_FDCWD, ARG(0), AT_FDCWD, ARG(1));
	else if (nr == nr_truncate)
		create_op(K_TRUNCATE_FAILED, AT_FDCWD, ARG(0), 0, 0);
	return 0;
}

// Emits the call its entry stashed, as it ended.
static __always_inline void op_exit(struct pending *pend, long ret)
{
	if (ret < 0 && -ret == pend->quiet_err)
		return;
	u32 kind = ret < 0 ? pend->kind : pend->kind_ok;
	if (kind == 0)
		return;
	struct event *e = start(kind);
	if (!e)
		return;
	e->ts = pend->ts;
	if (ret < 0)
		e->path_len = -ret;
	long r = pend->p1 ? bpf_probe_read_user_str(e->data, PATH_LEN, (void *)pend->p1) : 0;
	u32 off = r > 0 ? r : 0;
	u32 second = off;
	// Mark a second path only when both were read, so a failed read never
	// leaves n1 claiming a name that is not in the buffer.
	if (pend->p2 && off > 0) {
		long r2 = bpf_probe_read_user_str(&e->data[off & (DATA_SZ - 1)], PATH_LEN, (void *)pend->p2);
		if (r2 > 0) {
			e->n1 = 1;
			off += r2;
		}
	}
	// mode and flags count the base components of the first and second name.
	u8 nb = 0;
	if (!pend->p1) {
		// No name (futimens): the descriptor's path, or no record if it
		// was not open.
		e->data[0] = 0;
		off = add_base(e, 1, pend->dfd1, &nb, &e->truncated, 1, 0);
		e->mode = nb;
		if (!(e->bases & 1))
			return;
	} else if (r > 1 && e->data[0] != '/') {
		off = add_base(e, off, pend->dfd1, &nb, &e->truncated, 1, e->n1);
		e->mode = nb;
	}
	if (e->n1 && e->data[second & (DATA_SZ - 1)] != '/' && e->data[second & (DATA_SZ - 1)]) {
		nb = 0;
		off = add_base(e, off, pend->dfd2, &nb, &e->trunc2, 2, 0);
		e->flags = nb;
	}
	e->data_len = off;
	submit(e);
}

// Reports a held path change when its syscall returns: as done if it
// succeeded (a truncating open returns a descriptor), else as failed with the
// errno, unless the syscall's entry stashed it, whose record then stands for
// the failure.
SEC("tp_btf/sys_exit")
int BPF_PROG(on_sys_exit, struct pt_regs *regs, long ret)
{
	if (!in_target())
		return 0;
	u64 id = bpf_get_current_pid_tgid();
	struct pending *pend = bpf_map_lookup_elem(&pending_ops, &id);
	struct event *e = bpf_map_lookup_elem(&held_ops, &id);
	if (e) {
		if (ret >= 0) {
			submit(e);
		} else if (!pend) {
			e->err = -ret;
			submit(e);
		}
		bpf_map_delete_elem(&held_ops, &id);
	}
	if (pend) {
		op_exit(pend, ret);
		bpf_map_delete_elem(&pending_ops, &id);
	}
	return 0;
}

char LICENSE[] SEC("license") = "GPL";

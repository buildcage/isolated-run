// SPDX-License-Identifier: GPL-2.0
// Records the file accesses of every task in one cgroup v2 subtree: opens,
// the first read and write of each open file, mmaps, execs, and the path
// operations (create, move, delete, attribute change), successes and
// failures alike. Kernel types are declared locally with preserve_access_index
// so one CO-RE object runs on any BTF-enabled kernel from 5.17 on. The
// overlayfs de-duplication uses backing_file_open, added in 6.7; where it is
// absent the loader drops those two programs (see main.go).

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

struct dentry {
	struct dentry *d_parent;
	struct qstr d_name;
} __attribute__((preserve_access_index));

struct vfsmount {
	struct dentry *mnt_root;
} __attribute__((preserve_access_index));

struct mount {
	struct mount *mnt_parent;
	struct dentry *mnt_mountpoint;
	struct vfsmount mnt;
} __attribute__((preserve_access_index));

struct path {
	struct vfsmount *mnt;
	struct dentry *dentry;
} __attribute__((preserve_access_index));

struct file {
	struct path f_path;
	unsigned int f_flags;
	unsigned int f_mode;
} __attribute__((preserve_access_index));

struct mm_struct {
	unsigned long arg_start;
	unsigned long arg_end;
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
	int tgid;
	struct mm_struct *mm;
	struct fs_struct *fs;
	struct files_struct *files;
} __attribute__((preserve_access_index));

struct filename {
	const char *name;
} __attribute__((preserve_access_index));

struct linux_binprm {
	const char *filename;
} __attribute__((preserve_access_index));

struct trace_event_raw_sys_enter {
	long id;
	unsigned long args[6];
} __attribute__((preserve_access_index));

struct trace_event_raw_sys_exit {
	long id;
	long ret;
} __attribute__((preserve_access_index));

#define DATA_SZ 8192
#define PATH_LEN 4096
#define ARGS_LEN 512
#define NAME_LEN 256
#define MAX_COMPONENTS 64
#define WAKEUP_BYTES (1 << 20)
#define AT_FDCWD -100

enum kind { K_OPEN = 1, K_EXEC = 2, K_UNLINK = 3, K_RMDIR = 4, K_RENAME = 5,
	K_MKDIR = 6, K_CHMOD = 7, K_SYMLINK = 8, K_LINK = 9, K_TRUNCATE = 10, K_CHOWN = 11,
	K_OPEN_FAILED = 12, K_READ = 13, K_WRITE = 14, K_MMAP = 15,
	// Failed path syscalls: data holds the user path(s), NUL-separated (old
	// then new for rename), then the base directories of the relative ones
	// (see add_base); path_len holds the errno.
	K_DELETE_FAILED = 16, K_RENAME_FAILED = 17, K_CHMOD_FAILED = 18,
	K_CHOWN_FAILED = 19, K_ATTR = 20, K_ATTR_FAILED = 21,
	// A new process: pid is the child, ppid its parent; no data.
	K_FORK = 22 };

// Fixed header (mirrored by hdrLen in decode.go), then data_len bytes of data:
//   open:    d_path result (path_len is its return value)
//   open-failed: the name as passed to open(2), then its base directory if
//            it is relative (see add_base); path_len holds the errno
//   read/write: d_path result, once per open file and direction
//   mmap:    path components; mode holds prot, flags the map flags
//   exec:    filename at 0, argv (NUL-separated) at PATH_LEN
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
	u32 args_len;
	u32 data_len;
	u8 n1;
	u8 n2;
	u8 truncated;  // the path, or the first path of a two-path operation
	u8 trunc2;     // the second path of a rename or link
	char comm[16];
	u32 pad;
	u64 ts; // CLOCK_BOOTTIME at the access; a failed syscall at its entry
	char data[DATA_SZ + NAME_LEN]; // slack: masked offset + one component
};

// Keeps struct event in BTF for bpf2go's -type.
const struct event *unused_event __attribute__((unused));

const volatile u64 target_cgid = 0;
const volatile u32 target_level = 0;

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
	u32 kind;    // emitted on failure
	u32 kind_ok; // emitted on success, 0 to skip
	s32 dfd1;    // what p1 and p2 resolve against when relative
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
	return bpf_get_current_ancestor_cgroup_id(target_level) == target_cgid;
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
	e->args_len = 0;
	e->data_len = 0;
	e->n1 = 0;
	e->n2 = 0;
	e->truncated = 0;
	e->trunc2 = 0;
	bpf_get_current_comm(e->comm, sizeof(e->comm));
	e->pad = 0;
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
	u32 off_mnt_root, off_d_parent, off_d_name, off_mnt_parent, off_mountpoint, off_mnt;
};

static __always_inline void *rd_ptr(void *base, u32 off)
{
	void *v = 0;
	bpf_probe_read_kernel(&v, sizeof(v), base + off);
	return v;
}

static long walk_step(u64 i, struct walk_ctx *c)
{
	void *root = rd_ptr(c->vfs, c->off_mnt_root);
	void *parent = rd_ptr(c->d, c->off_d_parent);
	if (c->d == root || c->d == parent) {
		void *up = rd_ptr(c->mnt, c->off_mnt_parent);
		if (c->d != root || up == c->mnt)
			return 1;
		c->d = rd_ptr(c->mnt, c->off_mountpoint);
		c->mnt = up;
		c->vfs = up + c->off_mnt;
		return 0;
	}
	if (c->off >= DATA_SZ) {
		*c->trunc = 1;
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

// Appends the leaf-first path components of a dentry under a mount to
// e->data at off, crossing mounts up to the namespace root like d_path.
static __always_inline u32 walk(struct event *e, u32 off, struct dentry *d,
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
	bpf_loop(MAX_COMPONENTS, walk_step, &c, 0);
	*n = c.n;
	return c.off;
}

static __always_inline u32 leaf(struct event *e, u32 off, struct dentry *d, u8 *n)
{
	long r = bpf_probe_read_kernel_str(&e->data[off & (DATA_SZ - 1)], NAME_LEN,
					   BPF_CORE_READ(d, d_name.name));
	if (r <= 0)
		return off; // nothing stored, so do not count the leaf
	*n += 1;
	return off + r;
}

// A relative name in a syscall resolves against dfd: the calling task's
// working directory for AT_FDCWD, else that open directory. Appends the
// directory's leaf-first components at off and sets bit in e->args_len, or
// leaves both alone when the fd is not open. Read at the syscall's exit, so a
// thread that closes the fd or changes directory meanwhile can give another
// directory.
static __always_inline u32 add_base(struct event *e, u32 off, int dfd, u8 *n, u8 *trunc, u32 bit)
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
	e->args_len |= bit;
	return walk(e, off, d, m, n, trunc);
}

// Open files already reported as read (1), written (2) or mapped
// executable (4), so each is reported once per direction rather than per
// read(2). Keyed by the struct file and cleared when it is freed, before
// the address can be reused.
#define SEEN_READ 1
#define SEEN_WRITE 2
#define SEEN_EXEC 4
#define MAY_WRITE 2
#define MAY_READ 4
#define PROT_WRITE 2
#define PROT_EXEC 4
#define MAP_SHARED 1

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 65536);
	__type(key, u64);
	__type(value, u8);
} seen_files SEC(".maps");

// Reports whether bit was newly recorded for file: false if it was already
// set, or if the map is full (so a saturated map cannot cause re-emission).
// A full map counts in untracked, since that access then goes unreported.
static __always_inline int first_time(struct file *file, u8 bit)
{
	u64 key = (u64)file;
	u8 *v = bpf_map_lookup_elem(&seen_files, &key);
	if (v) {
		if (*v & bit)
			return 0;
		*v |= bit;
		return 1;
	}
	if (bpf_map_update_elem(&seen_files, &key, &bit, BPF_ANY) == 0)
		return 1;
	bump(&untracked);
	return 0;
}

// Marks the thread while it is inside backing_file_open (overlayfs opening a
// layer's real file), so that open is attributed to the overlay open above
// it rather than counted again.
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 4096);
	__type(key, u64);
	__type(value, u8);
} in_backing SEC(".maps");

SEC("fentry/backing_file_open")
int BPF_PROG(on_backing_enter)
{
	if (!in_target())
		return 0;
	u64 id = bpf_get_current_pid_tgid();
	u8 one = 1;
	bpf_map_update_elem(&in_backing, &id, &one, BPF_ANY);
	return 0;
}

SEC("fexit/backing_file_open")
int on_backing_exit(u64 *ctx)
{
	if (!in_target())
		return 0;
	u64 id = bpf_get_current_pid_tgid();
	bpf_map_delete_elem(&in_backing, &id);
	// Reads and writes on the overlay file reach the layer's file too;
	// mark the latter as already reported in every direction.
	u64 ret = 0;
	bpf_get_func_ret(ctx, &ret);
	if ((long)ret < 0 && (long)ret >= -4095)
		return 0;
	u8 all = 0xff;
	bpf_map_update_elem(&seen_files, &ret, &all, BPF_ANY);
	return 0;
}

SEC("fentry/security_file_open")
int BPF_PROG(on_open, struct file *file)
{
	if (!in_target())
		return 0;
	u64 id = bpf_get_current_pid_tgid();
	if (bpf_map_lookup_elem(&in_backing, &id)) {
		bump(&skipped_internal);
		return 0;
	}
	struct event *e = start(K_OPEN);
	if (!e)
		return 0;
	e->flags = file->f_flags;
	e->mode = file->f_mode;
	long r = bpf_d_path(&file->f_path, e->data, PATH_LEN);
	e->path_len = r;
	e->data_len = r > 0 ? r : 0;
	submit(e);
	return 0;
}

SEC("tp_btf/sched_process_exec")
int BPF_PROG(on_exec, struct task_struct *p, int old_pid, struct linux_binprm *bprm)
{
	if (!in_target())
		return 0;
	struct event *e = start(K_EXEC);
	if (!e)
		return 0;
	e->path_len = bpf_probe_read_kernel_str(e->data, PATH_LEN, BPF_CORE_READ(bprm, filename));
	unsigned long a = BPF_CORE_READ(p, mm, arg_start);
	unsigned long b = BPF_CORE_READ(p, mm, arg_end);
	u32 len = b - a;
	if (len > ARGS_LEN - 1)
		len = ARGS_LEN - 1;
	if (bpf_probe_read_user(&e->data[PATH_LEN], len & (ARGS_LEN - 1), (void *)a) == 0)
		e->args_len = len;
	e->data_len = PATH_LEN + e->args_len;
	submit(e);
	return 0;
}

// Every new process, so a parent that forks and never execs or touches a file
// (a subshell) still links its children to the processes above it.
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
	e->ppid = BPF_CORE_READ(child, real_parent, tgid);
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
	submit(e);								\
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
	submit(e);
	return 0;
}

SEC("fentry/security_path_rename")
int BPF_PROG(on_rename, const struct path *old_dir, struct dentry *old_dentry,
	     const struct path *new_dir, struct dentry *new_dentry)
{
	if (!in_target())
		return 0;
	struct event *e = start(K_RENAME);
	if (!e)
		return 0;
	u32 off = leaf(e, 0, old_dentry, &e->n1);
	off = walk(e, off, BPF_CORE_READ(old_dir, dentry), BPF_CORE_READ(old_dir, mnt), &e->n1, &e->truncated);
	off = leaf(e, off, new_dentry, &e->n2);
	e->data_len = walk(e, off, BPF_CORE_READ(new_dir, dentry), BPF_CORE_READ(new_dir, mnt), &e->n2, &e->trunc2);
	submit(e);
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
	e->data_len = walk(e, 0, BPF_CORE_READ(path, dentry), BPF_CORE_READ(path, mnt), &e->n1, &e->truncated);
	submit(e);
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
	u32 off = walk(e, 0, old_dentry, mnt, &e->n1, &e->truncated);
	off = leaf(e, off, new_dentry, &e->n2);
	e->data_len = walk(e, off, BPF_CORE_READ(new_dir, dentry), mnt, &e->n2, &e->trunc2);
	submit(e);
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
	e->data_len = walk(e, 0, BPF_CORE_READ(path, dentry), BPF_CORE_READ(path, mnt), &e->n1, &e->truncated);
	submit(e);
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
	e->data_len = walk(e, 0, BPF_CORE_READ(path, dentry), BPF_CORE_READ(path, mnt), &e->n1, &e->truncated);
	submit(e);
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

static __always_inline void open_enter(int dfd)
{
	if (!in_target())
		return;
	u64 id = bpf_get_current_pid_tgid();
	u32 zero = 0;
	struct event *e = bpf_map_lookup_elem(&scratch, &zero);
	if (!e)
		return;
	// do_sys_open's entry has already made one when do_sys_openat2's fires.
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
}

static __always_inline void open_exit(long ret)
{
	u64 id = bpf_get_current_pid_tgid();
	struct name_buf *nb = bpf_map_lookup_elem(&open_names, &id);
	if (!nb)
		return;
	if (ret < 0) {
		struct event *e = start(K_OPEN_FAILED);
		if (e) {
			e->ts = nb->ts;
			e->path_len = -ret;
			long r = bpf_probe_read_kernel_str(e->data, PATH_LEN, nb->name);
			u32 off = r > 0 ? r : 0;
			u8 n = 0;
			if (r > 1 && e->data[0] != '/') {
				off = add_base(e, off, nb->dfd, &n, &e->truncated, 1);
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
int BPF_PROG(on_openat2_enter, int dfd)
{
	open_enter(dfd);
	return 0;
}

SEC("fentry/do_sys_open")
int BPF_PROG(on_open_enter, int dfd)
{
	open_enter(dfd);
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
	if (!in_target())
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
	long r = bpf_d_path(&file->f_path, e->data, PATH_LEN);
	e->path_len = r;
	e->data_len = r > 0 ? r : 0;
	submit(e);
	return 0;
}

SEC("fentry/security_mmap_file")
int BPF_PROG(on_mmap, struct file *file, unsigned long prot, unsigned long flags)
{
	if (!file || !in_target())
		return 0;
	u8 bit = SEEN_READ;
	if (prot & PROT_EXEC)
		bit = SEEN_EXEC;
	else if ((prot & PROT_WRITE) && (flags & MAP_SHARED))
		bit = SEEN_WRITE;
	if (!first_time(file, bit))
		return 0;
	struct event *e = start(K_MMAP);
	if (!e)
		return 0;
	e->mode = prot;
	e->flags = flags;
	e->data_len = walk(e, 0, BPF_CORE_READ(file, f_path.dentry), BPF_CORE_READ(file, f_path.mnt), &e->n1, &e->truncated);
	submit(e);
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
// syscall tracepoints catch it. The entry stashes the user path pointer(s);
// the exit emits only when ret < 0, reading them back. Best-effort: this reads
// the user buffer, which a concurrent thread could rewrite between entry and
// exit, so a failed op's recorded path is not tamper-proof the way the open
// path's getname copy is.
static __always_inline void op_enter2(u32 kind, u32 kind_ok, int dfd1, u64 p1, int dfd2, u64 p2)
{
	if (!in_target())
		return;
	u64 id = bpf_get_current_pid_tgid();
	struct pending pend = {
		.p1 = p1, .p2 = p2, .ts = bpf_ktime_get_boot_ns(), .kind = kind, .kind_ok = kind_ok,
		.dfd1 = dfd1, .dfd2 = dfd2,
	};
	// An op recorded on success too is lost either way; one recorded only on
	// failure is counted at the exit, once the result is known.
	if (bpf_map_update_elem(&pending_ops, &id, &pend, BPF_ANY) != 0 && kind_ok)
		bump(&untracked);
}

static __always_inline void op_enter(u32 kind, int dfd1, u64 p1, int dfd2, u64 p2)
{
	op_enter2(kind, 0, dfd1, p1, dfd2, p2);
}

// failure_only: the op is recorded only on failure and its entry stashes on
// every call, so a failure that finds no entry is one the full map lost.
static __always_inline void op_exit(long ret, int failure_only)
{
	u64 id = bpf_get_current_pid_tgid();
	struct pending *pend = bpf_map_lookup_elem(&pending_ops, &id);
	if (!pend) {
		if (failure_only && ret < 0 && in_target())
			bump(&untracked);
		return;
	}
	u32 kind = ret < 0 ? pend->kind : pend->kind_ok;
	if (kind == 0) {
		bpf_map_delete_elem(&pending_ops, &id);
		return;
	}
	struct event *e = start(kind);
	if (e) {
		e->ts = pend->ts;
		if (ret < 0)
			e->path_len = -ret;
		long r = bpf_probe_read_user_str(e->data, PATH_LEN, (void *)pend->p1);
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
		if (r > 1 && e->data[0] != '/') {
			off = add_base(e, off, pend->dfd1, &nb, &e->truncated, 1);
			e->mode = nb;
		}
		if (e->n1 && e->data[second & (DATA_SZ - 1)] != '/' && e->data[second & (DATA_SZ - 1)]) {
			nb = 0;
			off = add_base(e, off, pend->dfd2, &nb, &e->trunc2, 2);
			e->flags = nb;
		}
		e->data_len = off;
		submit(e);
	}
	bpf_map_delete_elem(&pending_ops, &id);
}

// unlinkat covers both unlink and rmdir (rmdir(2) is unlinkat+AT_REMOVEDIR
// on current kernels); pathname is arg1.
SEC("tracepoint/syscalls/sys_enter_unlinkat")
int on_unlinkat_enter(struct trace_event_raw_sys_enter *ctx)
{
	op_enter(K_DELETE_FAILED, ctx->args[0], ctx->args[1], 0, 0);
	return 0;
}
SEC("tracepoint/syscalls/sys_exit_unlinkat")
int on_unlinkat_exit(struct trace_event_raw_sys_exit *ctx)
{
	op_exit(ctx->ret, 1);
	return 0;
}

// renameat2(olddfd, oldname=arg1, newdfd, newname=arg3, flags)
SEC("tracepoint/syscalls/sys_enter_renameat2")
int on_renameat2_enter(struct trace_event_raw_sys_enter *ctx)
{
	op_enter(K_RENAME_FAILED, ctx->args[0], ctx->args[1], ctx->args[2], ctx->args[3]);
	return 0;
}
SEC("tracepoint/syscalls/sys_exit_renameat2")
int on_renameat2_exit(struct trace_event_raw_sys_exit *ctx)
{
	op_exit(ctx->ret, 1);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_fchmodat")
int on_fchmodat_enter(struct trace_event_raw_sys_enter *ctx)
{
	op_enter(K_CHMOD_FAILED, ctx->args[0], ctx->args[1], 0, 0);
	return 0;
}
SEC("tracepoint/syscalls/sys_exit_fchmodat")
int on_fchmodat_exit(struct trace_event_raw_sys_exit *ctx)
{
	op_exit(ctx->ret, 1);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_fchmodat2")
int on_fchmodat2_enter(struct trace_event_raw_sys_enter *ctx)
{
	op_enter(K_CHMOD_FAILED, ctx->args[0], ctx->args[1], 0, 0);
	return 0;
}
SEC("tracepoint/syscalls/sys_exit_fchmodat2")
int on_fchmodat2_exit(struct trace_event_raw_sys_exit *ctx)
{
	op_exit(ctx->ret, 1);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_fchownat")
int on_fchownat_enter(struct trace_event_raw_sys_enter *ctx)
{
	op_enter(K_CHOWN_FAILED, ctx->args[0], ctx->args[1], 0, 0);
	return 0;
}
SEC("tracepoint/syscalls/sys_exit_fchownat")
int on_fchownat_exit(struct trace_event_raw_sys_exit *ctx)
{
	op_exit(ctx->ret, 1);
	return 0;
}

// utimensat(dfd, path=arg1, ...) and {,l}setxattr(path=arg0, ...) are the
// attribute changes with no security_path_* hook of their own; captured at
// the syscall, success and failure alike.
SEC("tracepoint/syscalls/sys_enter_utimensat")
int on_utimensat_enter(struct trace_event_raw_sys_enter *ctx)
{
	if (ctx->args[1]) // NULL path updates a dirfd, not a named file
		op_enter2(K_ATTR_FAILED, K_ATTR, ctx->args[0], ctx->args[1], 0, 0);
	return 0;
}
SEC("tracepoint/syscalls/sys_exit_utimensat")
int on_utimensat_exit(struct trace_event_raw_sys_exit *ctx)
{
	op_exit(ctx->ret, 0);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_setxattr")
int on_setxattr_enter(struct trace_event_raw_sys_enter *ctx)
{
	op_enter2(K_ATTR_FAILED, K_ATTR, AT_FDCWD, ctx->args[0], 0, 0);
	return 0;
}
SEC("tracepoint/syscalls/sys_exit_setxattr")
int on_setxattr_exit(struct trace_event_raw_sys_exit *ctx)
{
	op_exit(ctx->ret, 0);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_lsetxattr")
int on_lsetxattr_enter(struct trace_event_raw_sys_enter *ctx)
{
	op_enter2(K_ATTR_FAILED, K_ATTR, AT_FDCWD, ctx->args[0], 0, 0);
	return 0;
}
SEC("tracepoint/syscalls/sys_exit_lsetxattr")
int on_lsetxattr_exit(struct trace_event_raw_sys_exit *ctx)
{
	op_exit(ctx->ret, 0);
	return 0;
}

char LICENSE[] SEC("license") = "GPL";

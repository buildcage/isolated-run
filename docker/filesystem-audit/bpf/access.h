// SPDX-License-Identifier: MIT OR GPL-2.0-only
/**
 * @file access.h
 * Reporting each open file's reads, writes and mappings once per
 * program, and the mappings an exec makes. It defines maps, so only
 * filesystem_audit.bpf.c includes it.
 */
#ifndef FILESYSTEM_AUDIT_ACCESS_H
#define FILESYSTEM_AUDIT_ACCESS_H

#include "record.h"
#include "path.h"

/**
 * @name Seen
 * Open files already reported as read (1), written (2) or mapped
 * executable (4), so each is reported once per direction and program rather
 * than per read(2). Keyed by the struct file and cleared when it is freed,
 * before the address can be reused.
 * @{
 */
#define SEEN_READ 1
#define SEEN_WRITE 2
#define SEEN_EXEC 4
/** @} */
#define MAY_WRITE 2
#define MAY_READ 4
#define PROT_WRITE 2
#define PROT_EXEC 4
#define MAP_SHARED 1
#define VM_SHARED 8
#define S_PRIVATE (1 << 9)
#define OVERLAYFS_SUPER_MAGIC 0x794c7630
#define FUSE_SUPER_MAGIC 0x65735546

/**
 * A program run by a process: its tgid, its leader's start time, which a
 * reused pid does not share, and how many execs it has been through, so a
 * program exec'd in place counts as its own.
 */
struct proc {
	u64 start;
	u64 exec;
	u32 tgid;
	u32 pad;
};

/** The program the current task runs. */
static __always_inline struct proc current_proc(void)
{
	struct task_struct *t = bpf_get_current_task_btf();
	struct proc me = {
		.start = BPF_CORE_READ(t, group_leader, start_time),
		.exec = BPF_CORE_READ(t, group_leader, self_exec_id),
		.tgid = bpf_get_current_pid_tgid() >> 32,
	};
	return me;
}

struct seen {
	u64 gen;	  ///< when the entry was made, so a reused address is a new file
	struct proc owner; ///< the first process to use the file
	u32 bits;	  ///< what the owner has been reported doing with it
	u32 once;	  ///< reported once whoever uses it: see first_time
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 65536);
	__type(key, u64);
	__type(value, struct seen);
} seen_files SEC(".maps");

#define N_SEEN_COUNTS 65536

/**
 * How many seen_files entries each bucket of file addresses holds, so freeing
 * any other file on the host skips the hash delete.
 */
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, N_SEEN_COUNTS);
	__type(key, u32);
	__type(value, u32);
} seen_counts SEC(".maps");

/**
 * The seen_counts bucket of the file at @p addr, which must be a number: the
 * verifier allows no arithmetic on a pointer.
 */
static __always_inline u32 *seen_count(u64 addr)
{
	_Static_assert(N_SEEN_COUNTS == 1 << 16, "the index is the hash's top 16 bits");
	u32 i = ((u32)addr * 0x9e3779b1u) >> 16;
	return bpf_map_lookup_elem(&seen_counts, &i);
}

/**
 * What each other process sharing an open file, such as a child that
 * inherited it, has been reported doing with it. An entry outlives its file,
 * but gen keeps it from matching the next file at that address; losing one to
 * eviction only reports that access again.
 */
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

/**
 * Sets bit in *bits, reporting whether it was clear. Not atomic: two processes
 * racing on a shared entry can each report the same bit, never neither.
 */
static __always_inline int set_first(u32 *bits, u32 bit)
{
	if (*bits & bit)
		return 0;
	*bits |= bit;
	return 1;
}

/**
 * Reports whether bit was newly recorded for file and the current program:
 * false if it was already set, or if a map could not take the entry (so a
 * saturated map cannot cause re-emission). That counts in untracked, since
 * the access then goes unreported.
 */
static __always_inline int first_time(struct file *file, u8 bit)
{
	u64 key = (u64)file;
	struct seen *v = bpf_map_lookup_elem(&seen_files, &key);
	if (v && v->once)
		return set_first(&v->bits, bit);
	struct proc me = current_proc();
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
		if (bpf_map_update_elem(&seen_files, &key, &s, BPF_NOEXIST) == 0) {
			u64 addr = 0;
			bpf_probe_read_kernel(&addr, sizeof(addr), &key);
			u32 *n = seen_count(addr);
			if (n)
				__sync_fetch_and_add(n, 1);
			return 1;
		}
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

/**
 * Whether the current task is in execve, so a mapping it makes is the kernel
 * loading the new program, its dynamic loader and a script's interpreter, not
 * the program mapping a file of its own. Read from the task each time rather
 * than held across the call, so a skipped exec hook cannot leave it set and
 * hide the program's later mappings. in_execve spans the whole call, but the
 * task maps nothing before the exec's point of no return.
 */
static __always_inline int in_execve(void)
{
	return BPF_CORE_READ_BITFIELD_PROBED(bpf_get_current_task_btf(), in_execve);
}

static __always_inline void map_event(u32 slot, struct file *file, struct dentry *d, struct vfsmount *mnt,
				     unsigned long prot, unsigned long flags, u8 bit, int image)
{
	if (!first_time(file, bit))
		return;
	struct event *e = start(slot, K_MMAP);
	if (!e)
		return;
	e->mode = prot;
	e->flags = flags;
	e->path_len = image && in_execve() ? 1 : 0;
	e->data_len = d ? path_walk(e, d, mnt) : file_walk(e, file);
	submit(e);
}

/** The write drops PROT_EXEC from its mode so it decodes as a write. */
static __always_inline void map_events(u32 slot, struct file *file, struct dentry *d, struct vfsmount *mnt,
				      unsigned long prot, unsigned long flags, int at_mmap)
{
	int exec = prot & PROT_EXEC;
	int write = (prot & PROT_WRITE) && (flags & MAP_SHARED);
	if (exec)
		map_event(slot, file, d, mnt, prot, flags, SEEN_EXEC, at_mmap);
	if (write)
		map_event(slot, file, d, mnt, prot & ~PROT_EXEC, flags, SEEN_WRITE, 0);
	if (!exec && !write && at_mmap)
		map_event(slot, file, d, mnt, prot, flags, SEEN_READ, 1);
}

/**
 * fexit, so only a mapping that was made is recorded: after the LSMs,
 * do_mmap still refuses a shared writable mapping of a file not open for
 * writing, and an executable one on a noexec mount. mmap(2) comes through
 * vm_mmap_pgoff, and exec's own mappings through vm_mmap, which calls it but
 * may have it inlined; one mapping seen at both is recorded once (first_time).
 * The return value is read with bpf_get_func_ret, as for the open exits.
 */
static __always_inline void mapped(u32 slot, u64 *ctx, struct file *file, unsigned long prot,
				   unsigned long flags)
{
	u64 ret = 0;
	bpf_get_func_ret(ctx, &ret);
	if (!file || ret >= (u64)-4095 || !in_target() || on_layer(file))
		return;
	map_events(slot, file, 0, 0, prot, flags, 1);
}

#endif

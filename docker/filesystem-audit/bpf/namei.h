// SPDX-License-Identifier: MIT OR GPL-2.0-only
/**
 * @file namei.h
 * Where the kernel took a watched call's name. Each lookup of the call's own
 * name that ends short of it sends K_STOP, as does a parent lookup for a call
 * that acts on the name itself. A call that failed after its latest lookup
 * sent one is marked so (see stop_exit()), and the reader takes that directory
 * and the rest of the name for its path.
 *
 * Programs, included by filesystem_audit.bpf.c after the headers they use and
 * its BPF_PROG.
 */
#ifndef FILESYSTEM_AUDIT_NAMEI_H
#define FILESYSTEM_AUDIT_NAMEI_H

/** The lookups of the call in progress: how many, and the latest that sent K_STOP. */
struct lookups {
	u64 first; ///< the struct filename of the call's first lookup
	u32 count;
	u32 sent;
	u32 sent_type; ///< the STOP_* of the latest K_STOP
};

struct {
	__uint(type, BPF_MAP_TYPE_TASK_STORAGE);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__type(key, int);
	__type(value, struct lookups);
} lookups SEC(".maps");

/**
 * Whether the current call is one whose failure the tracer records by name,
 * giving the names it passed in @p a and @p b (0 for none), its number in
 * @p nr, and in @p named whether it acts on the last component of a name it
 * looks the parent of up, which it never follows: a removal, a move or a
 * creation.
 */
static __always_inline int call_names(long *nr, u64 *a, u64 *b, int *named)
{
	struct pt_regs *regs = (struct pt_regs *)bpf_task_pt_regs(bpf_get_current_task_btf());
	*nr = sys_nr(regs);
	if (is_open_nr(*nr)) {
		*a = sys_arg(regs, *nr == nr_openat || *nr == nr_openat2);
		return 1;
	}
	struct path_call call = {};
	// A utimes or setxattr failure is sent without waiting for its result.
	if (!classify(*nr, regs, &call) || call.kind == K_ATTR_FAILED)
		return 0;
	*a = call.p1;
	*b = call.p2;
	*named = call.kind == K_UNLINK_FAILED || call.kind == K_RMDIR_FAILED ||
		 call.kind == K_RENAME_FAILED || call.kind == K_MKDIR_FAILED ||
		 call.kind == K_MKNOD_FAILED || call.kind == K_SYMLINK_FAILED ||
		 call.kind == K_LINK_FAILED;
	return 1;
}

#define STOP_FAILED 1 ///< a lookup that failed: the name from nd->last on was not found
#define STOP_PARENT 2 ///< a lookup that succeeded: nd->last is the name in nd->path

/**
 * Sends where @p nd stands and what of the call's own name is left from
 * there, unless the lookup found all it looked for.
 */
static __always_inline void stop_at(u32 slot, struct nameidata *nd, u8 type)
{
	if (!in_target())
		return;
	long nr;
	u64 a = 0, b = 0;
	int named = 0;
	if (!call_names(&nr, &a, &b, &named) || (type == STOP_PARENT && !named))
		return;
	struct filename *fn = BPF_CORE_READ(nd, name);
	// A name the kernel made itself is not the call's own; 7.0 dropped uptr,
	// which tells.
	u32 which = 0;
	if (bpf_core_field_exists(fn->uptr)) {
		u64 uptr = (u64)BPF_CORE_READ(fn, uptr);
		which = uptr && uptr == a ? 1 : uptr && uptr == b ? 2 : 0;
		if (!which)
			return;
	}
	struct lookups *s = bpf_task_storage_get(&lookups, bpf_get_current_task_btf(), 0,
						 BPF_LOCAL_STORAGE_GET_F_CREATE);
	if (!s)
		return;
	if (!s->count)
		s->first = (u64)fn;
	struct vfsmount *mnt = BPF_CORE_READ(nd, path.mnt);
	struct dentry *d = BPF_CORE_READ(nd, path.dentry);
	// No path: a lookup that succeeded handed it over, or one already ended
	// (path_openat can end its lookup twice).
	if (!mnt || !d)
		return;
	s->count++; // the call's error comes from its latest lookup
	// A component that names nd->path itself was found, as on every open
	// that succeeds, or failed once stepped into (ENOTDIR, EACCES).
	// last_type does not tell: an error open_last_lookups returns passes
	// through link_path_walk, which sets LAST_ROOT first.
	if (BPF_CORE_READ(d, d_name.hash_len) == BPF_CORE_READ(nd, last.hash_len))
		return;
	const char *name = BPF_CORE_READ(fn, name);
	const char *last = (const char *)BPF_CORE_READ(nd, last.name);
	u64 off = (u64)last - (u64)name;
	// Stopped inside a symlink's body, not the call's own name.
	if ((u64)last < (u64)name || off >= PATH_LEN)
		return;
	struct event *e = start(slot, K_STOP);
	if (!e)
		return;
	long r = bpf_probe_read_kernel_str(e->data, PATH_LEN, name);
	if (r <= 0 || off >= (u64)r - 1)
		return;
	// "." and ".." are never missing: the lookup stopped past them.
	char c0 = e->data[off & (PATH_LEN - 1)], c1 = e->data[(off + 1) & (PATH_LEN - 1)],
	     c2 = e->data[(off + 2) & (PATH_LEN - 1)];
	if (c0 == '.' && (c1 == 0 || c1 == '/' || (c1 == '.' && (c2 == 0 || c2 == '/'))))
		return;
	e->tid = (u32)bpf_get_current_pid_tgid();
	e->nr = nr;
	e->path_len = off;
	e->flags = r;
	e->mode = which ? which : (u64)fn == s->first ? 1 : 2;
	e->n2 = type;
	e->data_len = walk(e, r & (PATH_LEN - 1), d, mnt, &e->n1, &e->truncated);
	s->sent = s->count;
	s->sent_type = type;
	submit(e);
}

/**
 * The kernel ends every lookup here. On failure nd->path is where it got to
 * and nd->last the component it stopped at: missing from nd->path, or for a
 * failure after stepping into it, nd->path itself.
 */
SEC("fentry/terminate_walk")
int BPF_PROG(on_terminate_walk, struct nameidata *nd)
{
	stop_at(slot, nd, STOP_FAILED);
	return 0;
}

/**
 * A parent lookup that succeeded (path_parentat) clears nd->path before
 * terminate_walk, so the directory a removal, move or creation acts in is
 * taken here, as the lookup completes. One that then fails is retried or ends
 * at terminate_walk, whose lookup counts after this one. Any other lookup has
 * stepped into its last component by now.
 */
SEC("fentry/complete_walk")
int BPF_PROG(on_complete_walk, struct nameidata *nd)
{
	stop_at(slot, nd, STOP_PARENT);
	return 0;
}

/**
 * What the latest K_STOP of the call returning @p ret says of its failure:
 * STOP_PARENT for one after a parent lookup, which places the names it acts
 * on, STOP_FAILED for a name found missing, or 0. Forgets the call's lookups
 * either way.
 */
static __noinline int stop_exit(long ret)
{
	struct lookups *s = bpf_task_storage_get(&lookups, bpf_get_current_task_btf(), 0, 0);
	if (!s || !s->count)
		return 0;
	int stopped = 0;
	if (ret < 0 && s->sent == s->count)
		stopped = s->sent_type == STOP_PARENT ? STOP_PARENT : ret == -ENOENT ? STOP_FAILED : 0;
	s->count = 0;
	s->sent = 0;
	s->first = 0;
	s->sent_type = 0;
	return stopped;
}

#endif

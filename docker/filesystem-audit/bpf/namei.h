// SPDX-License-Identifier: MIT OR GPL-2.0-only
/**
 * @file namei.h
 * Where the kernel took a watched call's names. Each lookup of a name the call
 * passed notes where it stopped short of the name, if it did: in a directory
 * that lacks the rest, or in the parent of a name the call acts on without
 * following it. When the call fails, its exit sends K_STOP for each name whose
 * latest lookup says where the failure lies, and marks the failure with which
 * (see stop_exit()); the reader takes that directory and the rest of the name
 * for its path.
 *
 * Programs, included by filesystem_audit.bpf.c after the headers they use and
 * its BPF_PROG.
 */
#ifndef FILESYSTEM_AUDIT_NAMEI_H
#define FILESYSTEM_AUDIT_NAMEI_H

#define STOP_FAILED 1 ///< a lookup that failed: the name from nd->last on was not found
#define STOP_PARENT 2 ///< a parent lookup that succeeded: nd->last is the name it acts on

/** Where the latest lookup of one of a call's names stopped short of it. */
struct name_stop {
	u64 dentry;  ///< the directory, held by the lookup only until it ends
	u64 mnt;
	u32 off;     ///< where in the name the part not looked up starts
	u32 type;    ///< STOP_*
	u32 lookup;  ///< the call's count at the name's latest lookup
	u32 stopped; ///< the call's count at the lookup that noted the above
};

/** The lookups of the call in progress, of its first and second name. */
struct lookups {
	u64 first; ///< the struct filename of the call's first lookup
	u32 count; ///< lookups that got anywhere, numbered from 1
	u32 pad;
	struct name_stop names[2];
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
 * @p nr, and in @p named the names (bit 0 the first, bit 1 the second) whose
 * last component it acts on without following, so a parent lookup places
 * them: both of a rename, the new name of a link, and the one name of a
 * removal or creation. classify() gives each call's kind.
 */
static __always_inline int call_names(long *nr, u64 *a, u64 *b, u32 *named)
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
	switch (call.kind) {
	case K_RENAME_FAILED:
		*named = 3;
		break;
	case K_LINK_FAILED:
		*named = 2;
		break;
	case K_UNLINK_FAILED:
	case K_RMDIR_FAILED:
	case K_MKDIR_FAILED:
	case K_MKNOD_FAILED:
	case K_SYMLINK_FAILED:
		*named = 1;
		break;
	}
	return 1;
}

/**
 * Notes where the lookup @p nd of one of the call's names stands, if it
 * stopped short of the name: a failed lookup (STOP_FAILED) in a directory, or
 * a parent lookup (STOP_PARENT) for a name the call acts on.
 */
static __always_inline void stop_at(struct nameidata *nd, u8 type)
{
	if (!in_target())
		return;
	long nr;
	u64 a = 0, b = 0;
	u32 named = 0;
	if (!call_names(&nr, &a, &b, &named))
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
	if (!which)
		which = (u64)fn == s->first ? 1 : 2;
	struct vfsmount *mnt = BPF_CORE_READ(nd, path.mnt);
	struct dentry *d = BPF_CORE_READ(nd, path.dentry);
	// No path: a lookup that succeeded handed it over, or one already ended
	// (path_openat can end its lookup twice).
	if (!mnt || !d)
		return;
	struct name_stop *ns = &s->names[(which - 1) & 1];
	ns->lookup = ++s->count; // a failure lies with the name's latest lookup
	if (type == STOP_PARENT) {
		// Any other lookup has stepped into its last component by now.
		if (!(named & which))
			return;
	} else if (BPF_CORE_READ(d, d_name.hash_len) == BPF_CORE_READ(nd, last.hash_len)) {
		// A component that names nd->path itself was found, as on every
		// open that succeeds, or failed once stepped into (ENOTDIR,
		// EACCES). last_type does not tell: an error open_last_lookups
		// returns passes through link_path_walk, which sets LAST_ROOT
		// first.
		return;
	}
	const char *name = BPF_CORE_READ(fn, name);
	const char *last = (const char *)BPF_CORE_READ(nd, last.name);
	u64 off = (u64)last - (u64)name;
	// Stopped inside a symlink's body, not the call's own name.
	if ((u64)last < (u64)name || off >= PATH_LEN)
		return;
	// "." and ".." are never missing nor acted on: the lookup stopped past
	// them.
	char c[3] = {};
	bpf_probe_read_kernel(c, sizeof(c), last);
	if (c[0] == '.' && (c[1] == 0 || c[1] == '/' || (c[1] == '.' && (c[2] == 0 || c[2] == '/'))))
		return;
	ns->dentry = (u64)d;
	ns->mnt = (u64)mnt;
	ns->off = off;
	ns->type = type;
	ns->stopped = s->count;
}

/**
 * The kernel ends every lookup here. On failure nd->path is where it got to
 * and nd->last the component it stopped at: missing from nd->path, or for a
 * failure after stepping into it, nd->path itself.
 */
SEC("fentry/terminate_walk")
int BPF_PROG(on_terminate_walk, struct nameidata *nd)
{
	stop_at(nd, STOP_FAILED);
	return 0;
}

/**
 * A parent lookup that succeeded (path_parentat) clears nd->path before
 * terminate_walk, so the directory a removal, move or creation acts in is
 * taken here, as the lookup completes. One that then fails is retried or ends
 * at terminate_walk, whose lookup counts after this one.
 */
SEC("fentry/complete_walk")
int BPF_PROG(on_complete_walk, struct nameidata *nd)
{
	stop_at(nd, STOP_PARENT);
	return 0;
}

/**
 * Sends K_STOP for name @p i of the call ending with @p ret if its latest
 * lookup says where the failure lies: in the parent of a name the call acts
 * on, or, for ENOENT, where the name was found missing.
 */
static __always_inline int send_stop(u32 slot, struct name_stop *ns, int i, long nr, long ret)
{
	if (!ns->lookup || ns->stopped != ns->lookup || (ns->type != STOP_PARENT && ret != -ENOENT))
		return 0;
	struct event *e = start(slot, K_STOP);
	if (!e)
		return 0;
	e->tid = (u32)bpf_get_current_pid_tgid();
	e->nr = nr;
	e->path_len = ns->off;
	e->mode = i + 1;
	e->n2 = ns->type;
	// The lookup dropped its hold on the directory, but a directory stays
	// cached while it is there, and the read is checked either way.
	e->data_len = walk(e, 0, (struct dentry *)ns->dentry, (struct vfsmount *)ns->mnt, &e->n1,
			   &e->truncated);
	return submit(e) ? 1 << i : 0;
}

/**
 * The names (bit 0 the first, bit 1 the second) of the call returning @p ret,
 * syscall @p nr, that its exit sent K_STOP for; forgets the call's lookups
 * either way.
 */
static __noinline int stop_exit(u32 slot, long nr, long ret)
{
	struct lookups *s = bpf_task_storage_get(&lookups, bpf_get_current_task_btf(), 0, 0);
	if (!s || !s->count)
		return 0;
	int sent = 0;
	if (ret < 0 && !is_restart(ret)) {
		sent |= send_stop(slot, &s->names[0], 0, nr, ret);
		sent |= send_stop(slot, &s->names[1], 1, nr, ret);
	}
	__builtin_memset(s, 0, sizeof(*s));
	return sent;
}

#endif

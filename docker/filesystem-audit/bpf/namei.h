// SPDX-License-Identifier: MIT OR GPL-2.0-only
/**
 * @file namei.h
 * Where the kernel took a watched call's names. Each lookup of a name the call
 * passed notes where it stopped: at the file it reached, in the parent of a
 * name the call acts on without following it, or at the component it failed
 * at. When the call fails, or for a time or xattr change at all, its exit
 * sends K_STOP for each name whose latest lookup says where the call took it,
 * and marks the call's record with which (see stop_exit()); the reader takes
 * that file, or that directory and the rest of the name, for its path.
 *
 * Programs, included by filesystem_audit.bpf.c after the headers they use and
 * its BPF_PROG.
 */
#ifndef FILESYSTEM_AUDIT_NAMEI_H
#define FILESYSTEM_AUDIT_NAMEI_H

#define STOP_FAILED 1  ///< a lookup that failed at nd->last
#define STOP_PARENT 2  ///< a parent lookup that succeeded: nd->last is the name the call acts on
#define STOP_REACHED 3 ///< a lookup that reached its file, nd->path

#define IN_DOT 1  ///< nd->last is "." or "..", which the lookup has taken
#define IN_LAST 2 ///< nd->path is what nd->last names: the lookup stepped into it

/** Where the latest lookup of one of a call's names stopped. */
struct name_stop {
	u64 dentry;  ///< nd->path, held by the lookup only until it ends
	u64 mnt;
	u32 off;     ///< where in the name nd->last starts
	u32 len;     ///< nd->last's length
	u32 type;    ///< STOP_*
	u32 in;      ///< IN_* of a failed lookup
	u32 lookup;  ///< the call's count at the name's latest lookup
	u32 stopped; ///< the call's count at the lookup that noted the above
};

/** The lookups of the call in progress, of its first and second name. */
struct lookups {
	u64 first;  ///< the struct filename of the call's first lookup
	u64 walked; ///< the nameidata of a lookup that completed its walk, until it ends
	u32 count;  ///< lookups that got anywhere, numbered from 1
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
 * Whether the current call is one the tracer records by name when it fails,
 * or a time or xattr change, which it records by name either way, giving the
 * names it passed in @p a and @p b (0 for none), its number in @p nr, and in
 * @p named the names (bit 0 the first, bit 1 the second) whose last component
 * it acts on without following, so a parent lookup places them: both of a
 * rename, the new name of a link, and the one name of a removal or creation.
 * classify() gives each call's kind.
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
	if (!classify(*nr, regs, &call))
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
 * Notes where the lookup @p nd of one of the call's names stands: as it
 * completes its walk (@p completed), the file it reached (STOP_REACHED) or,
 * for a name the call acts on, the parent (STOP_PARENT); as it ends without
 * completing, the component it failed at (STOP_FAILED).
 */
static __always_inline void stop_at(struct nameidata *nd, int completed)
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
	// A lookup that completed its walk was noted then: a failure after it
	// lies with what it reached.
	if (completed) {
		s->walked = (u64)nd;
	} else if (s->walked == (u64)nd) {
		s->walked = 0;
		return;
	}
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
	u32 type = !completed ? STOP_FAILED : named & which ? STOP_PARENT : STOP_REACHED;
	u64 off = 0;
	u32 len = 0;
	u32 in = 0;
	if (type != STOP_REACHED) {
		const char *name = BPF_CORE_READ(fn, name);
		const char *last = (const char *)BPF_CORE_READ(nd, last.name);
		u64 hash_len = BPF_CORE_READ(nd, last.hash_len);
		len = hash_len >> 32;
		off = (u64)last - (u64)name;
		// Stopped inside a symlink's body, not the call's own name.
		if (!len || (u64)last < (u64)name || off >= PATH_LEN)
			return;
		char c[2] = {}, end = 0, before = '/';
		bpf_probe_read_kernel(c, sizeof(c), last);
		bpf_probe_read_kernel(&end, 1, last + len);
		if (off)
			bpf_probe_read_kernel(&before, 1, last - 1);
		// Not a component of the name: one left from before this lookup
		// took any, as when the directory it starts in refuses a search.
		if (before != '/' || (end && end != '/'))
			return;
		if (c[0] == '.' && (len == 1 || (len == 2 && c[1] == '.')))
			in = IN_DOT;
		// Stepped into: nd->path has nd->last's name, or is a mount's root.
		// The errno says whether that is where the failure lies (see
		// send_stop()).
		else if (type == STOP_FAILED && (BPF_CORE_READ(d, d_name.hash_len) == hash_len ||
						 BPF_CORE_READ(mnt, mnt_root) == d))
			in = IN_LAST;
	}
	ns->dentry = (u64)d;
	ns->mnt = (u64)mnt;
	ns->off = off;
	ns->len = len;
	ns->type = type;
	ns->in = in;
	ns->stopped = s->count;
}

/**
 * The kernel ends every lookup here. On failure nd->path is where it got to
 * and nd->last the component it stopped at: missing from nd->path, or, for a
 * failure after stepping into it, nd->path itself.
 */
SEC("fentry/terminate_walk")
int BPF_PROG(on_terminate_walk, struct nameidata *nd)
{
	stop_at(nd, 0);
	return 0;
}

/**
 * A lookup that reached what it looks up, or for a removal, move or creation
 * its parent, completes here: before path_parentat clears nd->path, and
 * before an open checks the file's mode.
 */
SEC("fentry/complete_walk")
int BPF_PROG(on_complete_walk, struct nameidata *nd)
{
	stop_at(nd, 1);
	return 0;
}

/**
 * Sends K_STOP for name @p i of the call ending with @p ret if its latest
 * lookup says where the call took it: the file it reached, the parent of a
 * name the call acts on, or the component a failed lookup stopped at. A name
 * missing, or a symlink too deep, lies in the directory the lookup stood in;
 * any other failure in the component it stepped into.
 */
static __always_inline int send_stop(u32 slot, struct name_stop *ns, int i, long nr, long ret)
{
	if (!ns->lookup || ns->stopped != ns->lookup)
		return 0;
	u32 at = ns->off;
	if (ns->type == STOP_FAILED) {
		int in_dir = ret == -ENOENT || ret == -ELOOP;
		if (ret >= 0 || (!in_dir && !ns->in))
			return 0;
		if (ns->in == IN_DOT || (!in_dir && ns->in))
			at += ns->len;
	}
	struct event *e = start(slot, K_STOP);
	if (!e)
		return 0;
	e->tid = (u32)bpf_get_current_pid_tgid();
	e->nr = nr;
	e->path_len = at;
	e->mode = i + 1;
	e->n2 = ns->type;
	// The lookup dropped its hold on the dentry, but one stays cached while
	// it is there, and the read is checked either way.
	e->data_len = walk(e, 0, (struct dentry *)ns->dentry, (struct vfsmount *)ns->mnt, &e->n1,
			   &e->truncated);
	return submit(e) ? 1 << i : 0;
}

/**
 * The names (bit 0 the first, bit 1 the second) of the call returning @p ret,
 * syscall @p nr, that its exit sent K_STOP for: on failure, or with @p every
 * on success too. Forgets the call's lookups either way.
 */
static __noinline int stop_exit(u32 slot, long nr, long ret, int every)
{
	struct lookups *s = bpf_task_storage_get(&lookups, bpf_get_current_task_btf(), 0, 0);
	if (!s || !s->count)
		return 0;
	int sent = 0;
	if ((ret < 0 || every) && !is_restart(ret)) {
		sent |= send_stop(slot, &s->names[0], 0, nr, ret);
		sent |= send_stop(slot, &s->names[1], 1, nr, ret);
	}
	__builtin_memset(s, 0, sizeof(*s));
	return sent;
}

#endif

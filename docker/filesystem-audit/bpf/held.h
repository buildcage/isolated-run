// SPDX-License-Identifier: MIT OR GPL-2.0-only
/**
 * @file held.h
 * Events held per thread until their syscall returns, in heads and tails.
 *
 * A path change's security_path_* hook runs before the kernel's own
 * permission checks (may_delete, may_create, notify_change), so whether it
 * happened is known only then; for an open, see open_begin(). held_test.c
 * builds this with the maps and helpers it uses replaced (HELD_MOCK_MAPS), so
 * its accounting runs without a kernel.
 */
#ifndef FILESYSTEM_AUDIT_HELD_H
#define FILESYSTEM_AUDIT_HELD_H

#ifndef ENOENT
#define ENOENT 2
#endif
#ifndef EEXIST
#define EEXIST 17
#endif

#define HELD_OP 1   ///< A path change, held from its security_path_* hook.
#define HELD_OPEN 2 ///< An open(2), held from its entry.

/** Where a held event's head, or one of its tails, is kept. */
struct held_key {
	u64 id;  ///< The thread, as bpf_get_current_pid_tgid() gives it.
	u32 use; ///< HELD_OP or HELD_OPEN.
	u32 n;   ///< 0 for the head, from 1 a tail.
};

/**
 * @name Heads and tails
 * A held event is cut in pieces: its head holds the event's first HEAD bytes,
 * its header and the start of its path, and tail n the CHUNK bytes after the
 * head and the n - 1 tails before it. Nearly every path, a deep node_modules
 * one included, fits the head alone, and a longer one takes as many tails as
 * it needs, so the tails fill by bytes of path, whatever the paths' lengths.
 * Both are preallocated, so a hold fails only when they are full.
 * @{
 */
#define CHUNK 256
#define HEAD 512
#define HEAD_DATA (HEAD - __builtin_offsetof(struct event, data))
#ifndef N_HEADS
#define N_HEADS 8192
#endif
#ifndef N_TAILS
#define N_TAILS 24576
#endif
#define MAX_TAILS 32 ///< For DATA_SZ + NAME_LEN of data.
/** @} */

_Static_assert((DATA_SZ + NAME_LEN - HEAD_DATA + CHUNK - 1) / CHUNK <= MAX_TAILS,
	       "MAX_TAILS is short of the tails the longest event takes");
_Static_assert(HEAD + MAX_TAILS * CHUNK <= sizeof(struct scratch_buf),
	       "scratch has no room for the last tail");

struct head {
	char b[HEAD];
};

struct chunk {
	char b[CHUNK];
};

/** The tails the heads hold, which the loader reports. */
struct tail_use {
	u64 taken; ///< Held now.
	u64 peak;  ///< The most held at once.
};

#ifndef HELD_MOCK_MAPS
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, N_HEADS);
	__type(key, struct held_key);
	__type(value, struct head);
} heads SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, N_TAILS);
	__type(key, struct held_key);
	__type(value, struct chunk);
} tails SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, u32);
	__type(value, struct tail_use);
} tail_use SEC(".maps");
#endif

/** @return The tails an event with @p data_len bytes of data takes. */
static __always_inline u32 tails_for(u32 data_len)
{
	if (data_len > DATA_SZ + NAME_LEN)
		data_len = DATA_SZ + NAME_LEN;
	return data_len <= HEAD_DATA ? 0 : (data_len - HEAD_DATA + CHUNK - 1) / CHUNK;
}

/**
 * Takes @p n tails, or none when fewer are free, so a hold never runs out
 * halfway.
 *
 * Taking them is one atomic add that never retries; one that would pass the
 * limit is given back at once, and a take on another CPU in that moment may
 * be refused though it would have fit.
 *
 * @return 0 when taken, -1 when not.
 */
static __always_inline int take_tails(u32 n)
{
	if (!n)
		return 0;
	u32 zero = 0;
	struct tail_use *u = bpf_map_lookup_elem(&tail_use, &zero);
	if (!u)
		return -1;
	u64 v = __sync_fetch_and_add(&u->taken, n) + n;
	if (v > N_TAILS) {
		__sync_fetch_and_add(&u->taken, -(u64)n);
		return -1;
	}
	if (v > u->peak)
		u->peak = v; // racy, so a near miss at worst
	return 0;
}

/** Gives back @p n tails. */
static __always_inline void give_tails(u32 n)
{
	if (!n)
		return;
	u32 zero = 0;
	struct tail_use *u = bpf_map_lookup_elem(&tail_use, &zero);
	if (u)
		__sync_fetch_and_add(&u->taken, -(u64)n);
}

/** What a bpf_loop() over a held event's tails works on. */
struct tails_ctx {
	struct held_key k;
	char *buf; ///< The event, laid out as in scratch.
	u32 from;  ///< The first tail.
	u32 to;    ///< One past the last tail.
	int err;   ///< Set by put_tail() or get_tail() when one fails.
	u32 gone;  ///< Tails del_tail() removed or found already gone.
};

/**
 * Finds tail @p i of @p c's range.
 *
 * @param[out] k The tail's key.
 * @return The tail's offset in the event, or -1 past the range.
 */
static __always_inline long tail_at(u64 i, struct tails_ctx *c, struct held_key *k)
{
	u32 n = c->from + i;
	if (n >= c->to)
		return -1;
	u64 off = HEAD + (u64)(n - 1) * CHUNK;
	// Checked after the barrier, so the verifier sees the bound on the very
	// value used.
	asm volatile("" : "+r"(off));
	if (off > HEAD + (MAX_TAILS - 1) * CHUNK)
		return -1;
	*k = c->k;
	k->n = n;
	return off;
}

/** bpf_loop() callback: stores tail @p i from the event in @p c. */
static long put_tail(u64 i, struct tails_ctx *c)
{
	struct held_key k;
	long off = tail_at(i, c, &k);
	if (off < 0)
		return 1;
	if (bpf_map_update_elem(&tails, &k, c->buf + off, BPF_ANY) != 0) {
		c->err = 1;
		return 1;
	}
	return 0;
}

/** bpf_loop() callback: copies tail @p i into the event in @p c. */
static long get_tail(u64 i, struct tails_ctx *c)
{
	struct held_key k;
	long off = tail_at(i, c, &k);
	if (off < 0)
		return 1;
	void *t = bpf_map_lookup_elem(&tails, &k);
	if (!t) {
		c->err = 1;
		return 1;
	}
	__builtin_memcpy(c->buf + off, t, CHUNK);
	return 0;
}

/** bpf_loop() callback: deletes tail @p i. */
static long del_tail(u64 i, struct tails_ctx *c)
{
	struct held_key k;
	if (tail_at(i, c, &k) < 0)
		return 1;
	long r = bpf_map_delete_elem(&tails, &k);
	if (r == 0 || r == -ENOENT)
		c->gone++;
	return 0;
}

/**
 * Runs @p fn over tails @p from to @p to - 1 of the hold at @p k.
 *
 * @return The context @p fn worked on.
 */
static __always_inline struct tails_ctx run_tails(void *fn, struct held_key *k, void *buf, u32 from,
						 u32 to)
{
	struct tails_ctx c = { .k = *k, .buf = buf, .from = from, .to = to, .err = 0, .gone = 0 };
	if (from < to)
		bpf_loop(MAX_TAILS, fn, &c, 0);
	return c;
}

/** @return 0 unless @p fn, run as run_tails() does, failed. */
static __always_inline int tails_loop(void *fn, struct held_key *k, void *buf, u32 from, u32 to)
{
	return run_tails(fn, k, buf, from, to).err;
}

/**
 * Deletes tails @p from to @p to - 1 and gives back those no longer in the
 * map.
 *
 * One the map would not delete stays counted, so the count never falls below
 * what the map holds.
 */
static __always_inline void drop_tails(struct held_key *k, u32 from, u32 to)
{
	give_tails(run_tails(del_tail, k, 0, from, to).gone);
}

/** @return The key of the current thread's head under @p use. */
static __always_inline struct held_key held_key(u32 use)
{
	struct held_key k = { .id = bpf_get_current_pid_tgid(), .use = use, .n = 0 };
	return k;
}

/**
 * Ends a hold: its head, and the @p ntails tails it took.
 *
 * Only the call that deletes the head drops the tails, so no hold gives them
 * back twice. A head the map would not delete keeps its tails, which
 * whatever replaces it then accounts for.
 */
static __always_inline void release(struct held_key *k, u32 ntails)
{
	if (bpf_map_delete_elem(&heads, k) == 0)
		drop_tails(k, 1, ntails + 1);
}

/** Ends the hold at @p k, if any, with the tails its head says it took. */
static __always_inline void drop_held(struct held_key *k)
{
	struct event *head = bpf_map_lookup_elem(&heads, k);
	if (head)
		release(k, tails_for(head->data_len));
}

/**
 * Holds @p e, in scratch, under @p use, in place of a hold that took @p old
 * tails.
 *
 * @param have Tails the caller already took.
 * @return 0 when held, -1 when not.
 */
static __always_inline int hold_as(struct event *e, u32 use, u32 old, u32 have)
{
	struct held_key k = held_key(use);
	u32 t = tails_for(e->data_len);
	u32 need = t > old ? t - old : 0;
	if (have > need) {
		give_tails(have - need);
	} else if (need > have && take_tails(need - have) != 0) {
		give_tails(have);
		return -1;
	}
	if (bpf_map_update_elem(&heads, &k, e, BPF_ANY) != 0) {
		give_tails(need);
		return -1;
	}
	if (tails_loop(put_tail, &k, e, 1, t + 1) != 0) {
		// Refused with the tails already taken, as when the map is busy;
		// the hold is lost.
		release(&k, t > old ? t : old);
		return -1;
	}
	if (old > t)
		drop_tails(&k, t + 1, old + 1);
	return 0;
}

/**
 * Holds @p e in place of a hold left at @p k.
 *
 * One that cannot replace it drops it too: it is no event of this syscall's.
 *
 * @param have Tails the caller already took.
 * @return 0 when held, -1 when not.
 */
static __always_inline int hold_over(struct held_key *k, struct event *e, u32 use, u32 have)
{
	struct event *old = bpf_map_lookup_elem(&heads, k);
	u32 ot = old ? tails_for(old->data_len) : 0;
	if (hold_as(e, use, ot, have) == 0)
		return 0;
	drop_held(k);
	return -1;
}

/**
 * Holds @p e, in scratch, under @p use, where the thread normally holds
 * nothing yet; finding a hold there after all, it replaces it.
 *
 * @return 0 when held, -1 when not.
 */
static __always_inline int hold_new(struct event *e, u32 use)
{
	struct held_key k = held_key(use);
	u32 t = tails_for(e->data_len);
	if (take_tails(t) != 0) {
		// Too few free, but a hold already there frees its own.
		if (!bpf_map_lookup_elem(&heads, &k))
			return -1;
		return hold_over(&k, e, use, 0);
	}
	long r = bpf_map_update_elem(&heads, &k, e, BPF_NOEXIST);
	if (r == 0) {
		if (tails_loop(put_tail, &k, e, 1, t + 1) == 0)
			return 0;
		release(&k, t);
		return -1;
	}
	if (r != -EEXIST) {
		give_tails(t);
		return -1;
	}
	return hold_over(&k, e, use, t);
}

/** Holds the path change @p e, counting it in untracked when it cannot. */
static __always_inline void hold(struct event *e)
{
	if (hold_new(e, HELD_OP) != 0)
		bump(&untracked);
}

/**
 * Assembles the held event whose head is @p head in scratch.
 *
 * @return The event, or 0 when a tail is missing: what is left of a path
 *         cannot be told from a shorter one.
 */
static __always_inline struct event *assemble(u32 slot, struct held_key *k, struct event *head)
{
	struct event *e = scratch_get(slot);
	if (!e)
		return 0;
	__builtin_memcpy(e, head, HEAD);
	if (tails_loop(get_tail, k, e, 1, tails_for(e->data_len) + 1) != 0) {
		bump(&untracked);
		return 0;
	}
	return e;
}

/**
 * Records a held event as done when @p err is 0, else as refused with it; a
 * @p created open refused after its create step is both.
 *
 * @param cap The size of what @p e points into.
 */
static __always_inline void report_at(struct event *e, u32 cap, u32 err, u32 created)
{
	if (!err || created) {
		e->err = 0;
		submit_cap(e, cap);
	}
	if (err) {
		e->err = err;
		submit_cap(e, cap);
	}
}

/**
 * Records the held event whose head is @p head, as report_at() does:
 * straight from the head when it has no tails, else assembled in scratch.
 */
static __always_inline void report_held(u32 slot, struct held_key *k, struct event *head, u32 err, u32 created)
{
	if (!tails_for(head->data_len)) {
		report_at(head, HEAD, err, created);
		return;
	}
	struct event *e = assemble(slot, k, head);
	if (e)
		report_at(e, sizeof(struct event), err, created);
}

/**
 * Starts holding an open(2) called with @p dfd and @p flags.
 *
 * An open holds one event from its entry until it returns. A refused or
 * missing file never reaches security_file_open, so until then the event is
 * the failed open it would be (K_OPEN_FAILED): when the open was called, its
 * flags, and the name from the kernel's own copy (getname_flags), not the
 * user pointer, which the caller could rewrite before the syscall returns.
 * The file's own open method, an LSM or the FIFO checks can still refuse it
 * after that hook, so from there the event is the open (K_OPEN), reported as
 * done or refused once the syscall returns. bases, which neither record uses,
 * says whether the open reached its create step (see open_creating()); before
 * the hook, gid holds the descriptor a relative name resolves against.
 *
 * A full pool counts in untracked even if this open then succeeds and is
 * recorded.
 */
static __always_inline void open_begin(u32 slot, int dfd, u32 flags)
{
	struct event *e = scratch_get(slot);
	if (!e)
		return;
	e->kind = K_OPEN_FAILED;
	e->ts = bpf_ktime_get_boot_ns();
	e->flags = flags;
	e->gid = dfd;
	e->bases = 0;
	e->err = 0;
	e->truncated = 0;
	e->n2 = 0;
	e->data_len = 0;
	e->data[0] = 0;
	struct held_key k = held_key(HELD_OPEN);
	long r = bpf_map_update_elem(&heads, &k, e, BPF_NOEXIST);
	if (r == -EEXIST) {
		// Held already: do_sys_open's, when both hooks fire, or one an
		// earlier open left. Either way this call's values replace it.
		struct event *head = bpf_map_lookup_elem(&heads, &k);
		if (head && head->kind == K_OPEN_FAILED && !head->data_len) {
			__builtin_memcpy(head, e, HEAD);
			return;
		}
		drop_held(&k);
		r = bpf_map_update_elem(&heads, &k, e, BPF_NOEXIST);
	}
	if (r != 0)
		bump(&untracked);
}

/**
 * Reads the @p name an open(2) was given into its head.
 *
 * One that fills the head moves, whole, to tails, or stays there cut, marked
 * in n2, when there are none to take. When both getname programs fire, the
 * second finds the name already read.
 */
static __always_inline void hold_name(u32 slot, const char *name)
{
	struct held_key k = held_key(HELD_OPEN);
	struct event *head = bpf_map_lookup_elem(&heads, &k);
	if (!head || head->kind != K_OPEN_FAILED || head->data_len)
		return;
	long r = bpf_probe_read_kernel_str(head->data, HEAD_DATA, name);
	head->data_len = r > 0 ? r : 0;
	char more = 0;
	if (r == HEAD_DATA)
		bpf_probe_read_kernel(&more, 1, name + HEAD_DATA - 1);
	if (!more)
		return;
	struct event *e = scratch_get(slot);
	if (!e)
		return;
	__builtin_memcpy(e, head, HEAD);
	r = bpf_probe_read_kernel_str(e->data, PATH_LEN, name);
	e->data_len = r > 0 ? r : 0;
	if (hold_as(e, HELD_OPEN, 0, 0) == 0)
		return;
	head = bpf_map_lookup_elem(&heads, &k);
	if (head) {
		head->truncated = 1;
		head->n2 = 1;
	} else {
		bump(&untracked); // lost with its head, so a failure goes unrecorded
	}
}

/**
 * Marks the open(2) the thread is in, if any, as having reached its create
 * step.
 *
 * @return Whether the thread is in one.
 */
static __always_inline int open_creating(void)
{
	struct held_key k = held_key(HELD_OPEN);
	struct event *head = bpf_map_lookup_elem(&heads, &k);
	if (head)
		head->bases = 1;
	return head != 0;
}

/**
 * Holds the open @p e, from security_file_open, in place of the failed open
 * its open(2) held.
 *
 * An open from outside open(2), such as exec opening the program, has no exit
 * to wait for here, nor has one nested in an open already held, such as a FUSE
 * passthrough's backing file, or one with no room to be held.
 *
 * @return 0 when held, nonzero when it is to be recorded at once.
 */
static __always_inline int hold_open(struct event *e)
{
	struct held_key k = held_key(HELD_OPEN);
	struct event *head = bpf_map_lookup_elem(&heads, &k);
	if (!head || head->kind != K_OPEN_FAILED)
		return -1;
	e->bases = head->bases;
	u32 old = tails_for(head->data_len);
	if (!old && !tails_for(e->data_len)) {
		__builtin_memcpy(head, e, HEAD);
		return 0;
	}
	if (hold_as(e, HELD_OPEN, old, 0) == 0)
		return 0;
	// Recorded as done, though something may still refuse it, and not also
	// as the failed open it was held as.
	bump(&untracked);
	e->bases = 0;
	drop_held(&k);
	return -1;
}

/**
 * Ends the open(2) hold as the call returned @p ret, recording a held open.
 *
 * @return The failed open to record, assembled in scratch, or 0.
 */
static __always_inline struct event *open_end(u32 slot, long ret)
{
	struct held_key k = held_key(HELD_OPEN);
	struct event *head = bpf_map_lookup_elem(&heads, &k);
	if (!head)
		return 0;
	u32 t = tails_for(head->data_len);
	struct event *failed = 0;
	// ERESTARTSYS to ERESTART_RESTARTBLOCK: a signal interrupted the open,
	// which the kernel runs again, and that run records it.
	int restart = ret <= -512 && ret >= -516;
	if (!restart && head->kind == K_OPEN) {
		// Reaching the file after its create step means it was created,
		// whatever then refused the open.
		u32 created = head->bases;
		head->bases = 0;
		report_held(slot, &k, head, ret < 0 ? -ret : 0, created);
	} else if (!restart && ret < 0) {
		failed = assemble(slot, &k, head);
	}
	release(&k, t);
	return failed;
}

#endif

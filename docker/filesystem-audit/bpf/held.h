// SPDX-License-Identifier: GPL-2.0
/**
 * @file held.h
 * The tests in held_test.c build this with the maps and helpers it uses
 * replaced (HELD_MOCK_MAPS), so its accounting runs without a kernel.
 */
#ifndef FILESYSTEM_AUDIT_HELD_H
#define FILESYSTEM_AUDIT_HELD_H

/**
 * Events held per thread until their syscall returns. A path change's
 * security_path_* hook runs before the kernel's own permission checks
 * (may_delete, may_create, notify_change), so whether it happened is known
 * only then; for an open, see on_open.
 */
#define HELD_OP 1
#define HELD_OPEN 2

struct held_key {
	u64 id;
	u32 use;
	u32 n; ///< which chunk: 0 for the head, from 1 a tail
};

/**
 * A held event is cut in pieces: its head holds the event's first HEAD
 * bytes, its header and the start of its path, and tail n the CHUNK bytes
 * after the head and the n - 1 tails before it. Nearly every path, a deep
 * node_modules one included, fits the head alone, and a longer one takes as
 * many tails as it needs, so the tails fill by bytes of path, whatever the
 * paths' lengths. Both are preallocated, so a hold fails only when they are
 * full.
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
#define MAX_TAILS 32 ///< for DATA_SZ + NAME_LEN of data

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

/**
 * How many tails the heads hold, and the most they held at once, which the
 * loader reports.
 */
struct tail_use {
	u64 taken;
	u64 peak;
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

static __always_inline u32 tails_for(u32 data_len)
{
	if (data_len > DATA_SZ + NAME_LEN)
		data_len = DATA_SZ + NAME_LEN;
	return data_len <= HEAD_DATA ? 0 : (data_len - HEAD_DATA + CHUNK - 1) / CHUNK;
}

/**
 * Takes n tails, or none when fewer are free, so a hold never runs out
 * halfway. Taking them is one atomic add, which no other CPU can make fail;
 * one that would pass the limit is given back at once.
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

static __always_inline void give_tails(u32 n)
{
	if (!n)
		return;
	u32 zero = 0;
	struct tail_use *u = bpf_map_lookup_elem(&tail_use, &zero);
	if (u)
		__sync_fetch_and_add(&u->taken, -(u64)n);
}

struct tails_ctx {
	struct held_key k;
	char *buf; ///< the event, laid out as in scratch
	u32 from;  ///< tails from..to-1
	u32 to;
	int err;
};

/**
 * Tail i of c's range: its key in k, and its offset in the event, or -1
 * past the range.
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

static long get_tail(u64 i, struct tails_ctx *c)
{
	struct held_key k;
	long off = tail_at(i, c, &k);
	if (off < 0)
		return 1;
	void *t = bpf_map_lookup_elem(&tails, &k);
	if (!t) {
		c->err = 1;
		c->to = c->from + i; // where the event's whole data ends
		return 1;
	}
	__builtin_memcpy(c->buf + off, t, CHUNK);
	return 0;
}

static long del_tail(u64 i, struct tails_ctx *c)
{
	struct held_key k;
	if (tail_at(i, c, &k) < 0)
		return 1;
	bpf_map_delete_elem(&tails, &k);
	return 0;
}

/**
 * Runs fn over tails from..to-1, and returns 0 unless fn failed: for
 * get_tail, the missing tail it stopped at.
 */
static __always_inline u32 tails_loop(void *fn, struct held_key *k, void *buf, u32 from, u32 to)
{
	struct tails_ctx c = { .k = *k, .buf = buf, .from = from, .to = to, .err = 0 };
	if (from < to)
		bpf_loop(MAX_TAILS, fn, &c, 0);
	return c.err ? (c.to ? c.to : 1) : 0;
}

static __always_inline struct held_key held_key(u32 use)
{
	struct held_key k = { .id = bpf_get_current_pid_tgid(), .use = use, .n = 0 };
	return k;
}

/** Ends a hold: its head, and the ntails tails it took. */
static __always_inline void release(struct held_key *k, u32 ntails)
{
	bpf_map_delete_elem(&heads, k);
	tails_loop(del_tail, k, 0, 1, ntails + 1);
	give_tails(ntails);
}

/**
 * Holds e, in scratch, under use, in place of a hold that took old tails,
 * with have tails the caller already took.
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
	if (old > t) {
		tails_loop(del_tail, &k, 0, t + 1, old + 1);
		give_tails(old - t);
	}
	return 0;
}

/**
 * Holds e in place of a hold left there, with have tails already taken. One
 * that cannot replace it drops it too: it is no event of this syscall's.
 */
static __always_inline int hold_over(struct held_key *k, struct event *e, u32 use, u32 have)
{
	struct event *old = bpf_map_lookup_elem(&heads, k);
	u32 ot = old ? tails_for(old->data_len) : 0;
	if (hold_as(e, use, ot, have) == 0)
		return 0;
	if (bpf_map_lookup_elem(&heads, k))
		release(k, ot);
	return -1;
}

/**
 * Holds e, in scratch, under use, where the thread normally holds nothing
 * yet; finding a hold there after all, it replaces it.
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

static __always_inline void hold(struct event *e)
{
	if (hold_new(e, HELD_OP) != 0)
		bump(&untracked);
}

/** Assembles the held event whose head is head in scratch. */
static __always_inline struct event *assemble(struct held_key *k, struct event *head)
{
	u32 zero = 0;
	struct event *e = bpf_map_lookup_elem(&scratch, &zero);
	if (!e)
		return 0;
	__builtin_memcpy(e, head, HEAD);
	u32 missing = tails_loop(get_tail, k, e, 1, tails_for(e->data_len) + 1);
	if (missing) {
		// Cut before the missing tail, ending in a NUL as every name does;
		// the reader takes it as a path too deep to keep whole.
		u32 end = HEAD_DATA + (missing - 1) * CHUNK;
		asm volatile("" : "+r"(end)); // as in tail_at
		if (end > DATA_SZ)
			end = DATA_SZ;
		if (end)
			e->data[end - 1] = 0;
		e->data_len = end;
		e->truncated = 1;
		bump(&untracked);
	}
	return e;
}

/**
 * Records a held event, at e of size cap, as done with err 0 or refused
 * with err; a created open refused after its create step is both.
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
 * Records the held event whose head is head: straight from the head when it
 * has no tails, else assembled once in scratch.
 */
static __always_inline void report_held(struct held_key *k, struct event *head, u32 err, u32 created)
{
	if (!tails_for(head->data_len)) {
		report_at(head, HEAD, err, created);
		return;
	}
	struct event *e = assemble(k, head);
	if (e)
		report_at(e, sizeof(struct event), err, created);
}

#endif

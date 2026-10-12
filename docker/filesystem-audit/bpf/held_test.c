// SPDX-License-Identifier: GPL-2.0
/**
 * @file held_test.c
 * Tests for held.h, built for the host with its maps and helpers replaced by
 * the ones below; the image build compiles and runs it with small pools
 * (N_HEADS, N_TAILS) so their limits are reached.
 */
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <linux/bpf.h>

#include "event.h"

/** A map: fixed-size keys and values, up to max entries, linear search. */
struct map {
	const char *name;
	unsigned key_size, value_size, max;
	int array;      ///< an array: entries exist from the start
	int busy_after; ///< updates left before one fails with EBUSY; -1 for never
	unsigned count;
	unsigned char *used;
	unsigned char *keys;
	unsigned char *values;
};

static struct map heads, tails, tail_use, scratch, untracked;

static void map_init(struct map *m, const char *name, unsigned key_size, unsigned value_size,
		     unsigned max, int array)
{
	free(m->used);
	free(m->keys);
	free(m->values);
	*m = (struct map){ .name = name, .key_size = key_size, .value_size = value_size,
			   .max = max, .array = array, .busy_after = -1 };
	m->used = calloc(max, 1);
	m->keys = calloc(max, key_size);
	m->values = calloc(max, value_size);
	if (array) {
		for (unsigned i = 0; i < max; i++) {
			m->used[i] = 1;
			memcpy(m->keys + i * key_size, &i, key_size);
		}
		m->count = max;
	}
}

static int find(struct map *m, const void *key)
{
	for (unsigned i = 0; i < m->max; i++)
		if (m->used[i] && !memcmp(m->keys + i * m->key_size, key, m->key_size))
			return i;
	return -1;
}

static void *bpf_map_lookup_elem(void *map, const void *key)
{
	struct map *m = map;
	int i = find(m, key);
	return i < 0 ? NULL : m->values + i * m->value_size;
}

static long bpf_map_update_elem(void *map, const void *key, const void *value, __u64 flags)
{
	struct map *m = map;
	if (m->busy_after == 0)
		return -EBUSY;
	if (m->busy_after > 0)
		m->busy_after--;
	int i = find(m, key);
	if (i >= 0 && flags == BPF_NOEXIST)
		return -EEXIST;
	if (i < 0 && flags == BPF_EXIST)
		return -ENOENT;
	if (i < 0) {
		if (m->count == m->max)
			return -E2BIG;
		for (i = 0; m->used[i]; i++)
			;
		m->used[i] = 1;
		m->count++;
		memcpy(m->keys + i * m->key_size, key, m->key_size);
	}
	memcpy(m->values + i * m->value_size, value, m->value_size);
	return 0;
}

static long bpf_map_delete_elem(void *map, const void *key)
{
	struct map *m = map;
	int i = find(m, key);
	if (i < 0)
		return -ENOENT;
	m->used[i] = 0;
	m->count--;
	return 0;
}

static long bpf_loop(__u32 nr, void *fn, void *ctx, __u64 flags)
{
	(void)flags;
	__u32 i;
	for (i = 0; i < nr; i++)
		if (((long (*)(__u64, void *))fn)(i, ctx))
			return i + 1;
	return i;
}

static __u64 current_id = 1;

static __u64 bpf_get_current_pid_tgid(void)
{
	return current_id;
}

static void bump(void *counter)
{
	__u32 zero = 0;
	(*(__u64 *)bpf_map_lookup_elem(counter, &zero))++;
}

/** What submit_cap sent, in order. */
static struct submitted {
	unsigned size;
	struct event e;
} sent[16];
static unsigned nsent;

static void submit_cap(struct event *e, u32 cap)
{
	u32 len = e->data_len;
	if (len > DATA_SZ + NAME_LEN)
		len = DATA_SZ + NAME_LEN;
	unsigned size = __builtin_offsetof(struct event, data) + len;
	if (size > cap)
		size = cap;
	if (nsent < sizeof(sent) / sizeof(sent[0])) {
		memset(&sent[nsent].e, 0, sizeof(sent[nsent].e));
		memcpy(&sent[nsent].e, e, size);
		sent[nsent++].size = size;
	}
}

#define HELD_MOCK_MAPS
#include "held.h"

_Static_assert(N_TAILS >= MAX_TAILS && N_TAILS / 2 + 1 <= MAX_TAILS,
	       "build the tests with -DN_TAILS between MAX_TAILS and twice it");

static int failures;

#define CHECK(cond)                                                                       \
	do {                                                                              \
		if (!(cond)) {                                                            \
			fprintf(stderr, "%s:%d: %s: %s\n", __FILE__, __LINE__, __func__, #cond); \
			failures++;                                                       \
		}                                                                         \
	} while (0)

static struct tail_use *use(void)
{
	__u32 zero = 0;
	return bpf_map_lookup_elem(&tail_use, &zero);
}

static __u64 untracked_count(void)
{
	__u32 zero = 0;
	return *(__u64 *)bpf_map_lookup_elem(&untracked, &zero);
}

static struct event *scratch_event(void)
{
	__u32 zero = 0;
	return bpf_map_lookup_elem(&scratch, &zero);
}

static void reset(void)
{
	map_init(&heads, "heads", sizeof(struct held_key), HEAD, N_HEADS, 0);
	map_init(&tails, "tails", sizeof(struct held_key), CHUNK, N_TAILS, 0);
	map_init(&tail_use, "tail_use", 4, sizeof(struct tail_use), 1, 1);
	map_init(&scratch, "scratch", 4, sizeof(struct scratch_buf), 1, 1);
	map_init(&untracked, "untracked", 4, 8, 1, 1);
	current_id = 1;
	nsent = 0;
}

/**
 * Every tail is accounted for: the count taken is what the heads' lengths
 * call for, and is exactly the tails held.
 */
static void check_accounts(int line)
{
	__u64 want = 0;
	for (unsigned i = 0; i < heads.max; i++)
		if (heads.used[i])
			want += tails_for(((struct event *)(heads.values + i * HEAD))->data_len);
	if (use()->taken != want || tails.count != want) {
		fprintf(stderr, "held_test.c:%d: taken %llu, tails %u, heads call for %llu\n", line,
			(unsigned long long)use()->taken, tails.count, (unsigned long long)want);
		failures++;
	}
}
#define CHECK_ACCOUNTS() check_accounts(__LINE__)

/** An event in scratch whose data is len bytes of a pattern keyed by seed. */
static struct event *make(u32 kind, u32 len, unsigned char seed)
{
	struct event *e = scratch_event();
	memset(e, 0, sizeof(struct scratch_buf));
	e->kind = kind;
	e->data_len = len;
	for (u32 i = 0; i < len && i < DATA_SZ + NAME_LEN; i++)
		e->data[i] = (char)(seed + i * 7);
	return e;
}

static int data_matches(const struct event *e, u32 len, unsigned char seed)
{
	for (u32 i = 0; i < len; i++)
		if (e->data[i] != (char)(seed + i * 7))
			return 0;
	return 1;
}

static struct event *head_of(__u64 id, u32 use_)
{
	struct held_key k = { .id = id, .use = use_, .n = 0 };
	return bpf_map_lookup_elem(&heads, &k);
}

static void test_tails_for(void)
{
	CHECK(tails_for(0) == 0);
	CHECK(tails_for(HEAD_DATA) == 0);
	CHECK(tails_for(HEAD_DATA + 1) == 1);
	CHECK(tails_for(HEAD_DATA + CHUNK) == 1);
	CHECK(tails_for(HEAD_DATA + CHUNK + 1) == 2);
	CHECK(tails_for(DATA_SZ + NAME_LEN) == MAX_TAILS);
	CHECK(tails_for(0xffffffff) == MAX_TAILS);
}

static void test_short_hold(void)
{
	reset();
	CHECK(hold_new(make(K_UNLINK, HEAD_DATA, 1), HELD_OP) == 0);
	CHECK(heads.count == 1 && tails.count == 0 && use()->taken == 0);
	struct held_key k = held_key(HELD_OP);
	report_held(&k, head_of(1, HELD_OP), 0, 0);
	CHECK(nsent == 1 && sent[0].size == HEAD && data_matches(&sent[0].e, HEAD_DATA, 1));
	release(&k, 0);
	CHECK(heads.count == 0);
	CHECK_ACCOUNTS();
}

static void test_long_hold_round_trip(void)
{
	reset();
	u32 len = DATA_SZ + NAME_LEN;
	CHECK(hold_new(make(K_RENAME, len, 9), HELD_OP) == 0);
	CHECK(use()->taken == MAX_TAILS && use()->peak == MAX_TAILS);
	CHECK_ACCOUNTS();
	make(K_OPEN, 0, 0); // scratch reused by another event meanwhile
	struct held_key k = held_key(HELD_OP);
	struct event *e = assemble(&k, head_of(1, HELD_OP));
	CHECK(e && e->kind == K_RENAME && e->data_len == len && data_matches(e, len, 9));
	CHECK(!e->truncated && untracked_count() == 0);
	report_held(&k, head_of(1, HELD_OP), 2, 0);
	CHECK(nsent == 1 && sent[0].e.err == 2 && data_matches(&sent[0].e, len, 9));
	release(&k, MAX_TAILS);
	CHECK(heads.count == 0 && use()->taken == 0);
	CHECK_ACCOUNTS();
}

/**
 * N_TAILS is small here: one hold of over half of them leaves too few for a
 * second, but a hold that needs none still fits.
 */
static void test_pool_limit(void)
{
	reset();
	u32 len = HEAD_DATA + (N_TAILS / 2 + 1) * CHUNK;
	current_id = 2;
	CHECK(hold_new(make(K_UNLINK, len, 3), HELD_OP) == 0);
	CHECK(use()->taken == N_TAILS / 2 + 1);
	current_id = 1;
	hold(make(K_UNLINK, len, 3));
	CHECK(untracked_count() == 1 && head_of(1, HELD_OP) == NULL);
	CHECK(use()->taken == N_TAILS / 2 + 1 && use()->peak == N_TAILS / 2 + 1);
	hold(make(K_UNLINK, HEAD_DATA, 3));
	CHECK(untracked_count() == 1 && head_of(1, HELD_OP) != NULL);
	CHECK_ACCOUNTS();
}

static void test_replace_shorter_and_longer(void)
{
	reset();
	CHECK(hold_new(make(K_OPEN_FAILED, HEAD_DATA + 3 * CHUNK, 5), HELD_OPEN) == 0);
	CHECK(use()->taken == 3);
	CHECK(hold_as(make(K_OPEN, HEAD_DATA + 1, 6), HELD_OPEN, 3, 0) == 0);
	CHECK(use()->taken == 1 && tails.count == 1);
	CHECK_ACCOUNTS();
	CHECK(hold_as(make(K_OPEN, HEAD_DATA + 5 * CHUNK, 7), HELD_OPEN, 1, 0) == 0);
	CHECK(use()->taken == 5);
	CHECK_ACCOUNTS();
	struct held_key k = held_key(HELD_OPEN);
	struct event *e = assemble(&k, head_of(1, HELD_OPEN));
	CHECK(e && e->kind == K_OPEN && data_matches(e, HEAD_DATA + 5 * CHUNK, 7));
}

/**
 * hold_new over a hold left in place replaces it, reusing the tails it took
 * for itself rather than giving them back first.
 */
static void test_new_over_existing(void)
{
	reset();
	CHECK(hold_new(make(K_UNLINK, HEAD_DATA + 2 * CHUNK, 1), HELD_OP) == 0);
	CHECK(hold_new(make(K_RMDIR, HEAD_DATA + 3 * CHUNK, 2), HELD_OP) == 0);
	CHECK(heads.count == 1 && head_of(1, HELD_OP)->kind == K_RMDIR && use()->taken == 3);
	CHECK_ACCOUNTS();
	CHECK(hold_new(make(K_MKDIR, HEAD_DATA, 3), HELD_OP) == 0);
	CHECK(use()->taken == 0 && tails.count == 0);
	CHECK_ACCOUNTS();
}

/**
 * With the pool exactly full, replacing a hold with one of the same size
 * still fits, on the tails the old hold frees.
 */
static void test_new_over_existing_when_full(void)
{
	reset();
	u32 per = N_TAILS / 2;
	u32 len = HEAD_DATA + per * CHUNK;
	current_id = 2;
	CHECK(hold_new(make(K_UNLINK, len, 1), HELD_OP) == 0);
	current_id = 1;
	CHECK(hold_new(make(K_UNLINK, len, 1), HELD_OP) == 0);
	CHECK(use()->taken == 2 * per);
	CHECK(hold_new(make(K_RMDIR, len, 2), HELD_OP) == 0);
	CHECK(head_of(1, HELD_OP)->kind == K_RMDIR && use()->taken == 2 * per);
	CHECK_ACCOUNTS();
}

/**
 * A hold left in place that the new one cannot replace for want of tails is
 * dropped, rather than reported later as this syscall's.
 */
static void test_new_over_existing_short_drops_it(void)
{
	reset();
	current_id = 2;
	CHECK(hold_new(make(K_UNLINK, HEAD_DATA + MAX_TAILS * CHUNK, 1), HELD_OP) == 0);
	current_id = 1;
	CHECK(hold_new(make(K_UNLINK, HEAD_DATA + CHUNK, 1), HELD_OP) == 0);
	// Needs more than the one tail it would free and the few still free.
	hold(make(K_RMDIR, HEAD_DATA + (N_TAILS - MAX_TAILS + 1) * CHUNK, 2));
	CHECK(untracked_count() == 1 && head_of(1, HELD_OP) == NULL && use()->taken == MAX_TAILS);
	CHECK_ACCOUNTS();
}

static void test_head_busy_keeps_old_hold(void)
{
	reset();
	CHECK(hold_new(make(K_OPEN_FAILED, HEAD_DATA + 2 * CHUNK, 4), HELD_OPEN) == 0);
	heads.busy_after = 0;
	CHECK(hold_as(make(K_OPEN, HEAD_DATA + 4 * CHUNK, 5), HELD_OPEN, 2, 0) != 0);
	heads.busy_after = -1;
	CHECK(head_of(1, HELD_OPEN)->kind == K_OPEN_FAILED && use()->taken == 2);
	CHECK_ACCOUNTS();
}

static void test_tail_busy_loses_hold(void)
{
	reset();
	tails.busy_after = 1; // the second tail is refused
	hold(make(K_UNLINK, HEAD_DATA + 3 * CHUNK, 1));
	tails.busy_after = -1;
	CHECK(untracked_count() == 1 && heads.count == 0 && tails.count == 0 && use()->taken == 0);
	CHECK_ACCOUNTS();

	CHECK(hold_new(make(K_OPEN_FAILED, HEAD_DATA + 2 * CHUNK, 1), HELD_OPEN) == 0);
	tails.busy_after = 0;
	CHECK(hold_as(make(K_OPEN, HEAD_DATA + 3 * CHUNK, 2), HELD_OPEN, 2, 0) != 0);
	tails.busy_after = -1;
	CHECK(heads.count == 0 && tails.count == 0 && use()->taken == 0);
	CHECK_ACCOUNTS();
}

static void test_missing_tail_cuts(void)
{
	reset();
	CHECK(hold_new(make(K_UNLINK, HEAD_DATA + 3 * CHUNK, 8), HELD_OP) == 0);
	struct held_key k = held_key(HELD_OP);
	k.n = 2;
	bpf_map_delete_elem(&tails, &k);
	k.n = 0;
	struct event *e = assemble(&k, head_of(1, HELD_OP));
	CHECK(e && e->truncated && e->data_len == HEAD_DATA + CHUNK);
	CHECK(e && data_matches(e, HEAD_DATA + CHUNK - 1, 8) && e->data[HEAD_DATA + CHUNK - 1] == 0);
	CHECK(untracked_count() == 1);
}

static void test_report_outcomes(void)
{
	reset();
	struct event *e = make(K_OPEN, 10, 1);
	report_at(e, HEAD, 0, 0);
	CHECK(nsent == 1 && sent[0].e.err == 0);
	nsent = 0;
	report_at(e, HEAD, 6, 0);
	CHECK(nsent == 1 && sent[0].e.err == 6);
	nsent = 0;
	report_at(e, HEAD, 13, 1); // created, then refused
	CHECK(nsent == 2 && sent[0].e.err == 0 && sent[1].e.err == 13);
	nsent = 0;
	report_at(e, HEAD, 0, 1);
	CHECK(nsent == 1 && sent[0].e.err == 0);
}

int main(void)
{
	test_tails_for();
	test_short_hold();
	test_long_hold_round_trip();
	test_pool_limit();
	test_replace_shorter_and_longer();
	test_new_over_existing();
	test_new_over_existing_when_full();
	test_new_over_existing_short_drops_it();
	test_head_busy_keeps_old_hold();
	test_tail_busy_loses_hold();
	test_missing_tail_cuts();
	test_report_outcomes();
	if (failures) {
		fprintf(stderr, "held_test: %d failed\n", failures);
		return 1;
	}
	printf("held_test: ok\n");
	return 0;
}

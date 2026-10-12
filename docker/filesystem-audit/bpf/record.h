// SPDX-License-Identifier: GPL-2.0
/**
 * @file record.h
 * What every program records through: the watched cgroup, the ring
 * buffer and loss counters, and each program's scratch event.
 */
#ifndef FILESYSTEM_AUDIT_RECORD_H
#define FILESYSTEM_AUDIT_RECORD_H

#define WAKEUP_BYTES (1 << 20)
#define AT_FDCWD -100
#define AT_REMOVEDIR 0x200
#define EEXIST 17

/** Keeps struct event in BTF for bpf2go's -type. */
const struct event *unused_event __attribute__((unused));

/**
 * The watched cgroup, set by the loader. Descent is checked in the kernel's
 * own hierarchy, whatever cgroup namespace the loader runs in.
 */
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
		__sync_fetch_and_add(v, 1); // another program on this CPU may be mid-update
}

#define N_SLOTS 32 ///< Programs that can take a scratch event; checked at the end.

/**
 * The event being assembled, one per program and CPU. Where the kernel has
 * PREEMPT_RCU and preempts in the kernel (full or lazy), a program can be
 * preempted mid-run, and the kernel's recursion check covers only that
 * program, so an event shared by the programs on a CPU could be rewritten by
 * another and record a path spliced from two.
 */
struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, N_SLOTS);
	__type(key, u32);
	__type(value, struct scratch_buf);
} scratch SEC(".maps");

/** The scratch event of the program whose BPF_PROG @p slot is. */
static __always_inline struct event *scratch_get(u32 slot)
{
	return bpf_map_lookup_elem(&scratch, &slot);
}

static __always_inline int in_target(void)
{
	return bpf_current_task_under_cgroup(&target, 0) == 1;
}

static __always_inline struct event *start(u32 slot, u32 kind)
{
	struct event *e = scratch_get(slot);
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
	e->gid = 0;
	// The process's name, as ps shows it, not the thread's: a JVM or tokio
	// worker thread names itself after its pool.
	BPF_CORE_READ_STR_INTO(&e->comm, t, group_leader, comm);
	e->err = 0;
	e->ts = bpf_ktime_get_boot_ns();
	return e;
}

/**
 * Sends @p e to the reader.
 *
 * @param cap The size of what @p e points into, a constant in each caller.
 */
static __always_inline void submit_cap(struct event *e, u32 cap)
{
	u32 len = e->data_len;
	if (len > DATA_SZ + NAME_LEN)
		len = DATA_SZ + NAME_LEN;
	u64 size = __builtin_offsetof(struct event, data) + len;
	if (size > cap)
		size = cap;
	// Waking the reader per event costs more than the event itself; it
	// polls on a timer and is woken only once a backlog builds up.
	u64 flags = bpf_ringbuf_query(&events, BPF_RB_AVAIL_DATA) > WAKEUP_BYTES ?
		    BPF_RB_FORCE_WAKEUP : BPF_RB_NO_WAKEUP;
	if (bpf_ringbuf_output(&events, e, size, flags) != 0)
		bump(&drops);
}

static __always_inline void submit(struct event *e)
{
	submit_cap(e, sizeof(*e));
}

#endif

// SPDX-License-Identifier: MIT OR GPL-2.0-only
/**
 * @file refused.h
 * Syscalls the sandbox's seccomp profile refused, recorded once per program.
 * It defines maps, so only filesystem_audit.bpf.c includes it.
 */
#ifndef FILESYSTEM_AUDIT_REFUSED_H
#define FILESYSTEM_AUDIT_REFUSED_H

#include "record.h"
#include "access.h"

#ifndef EPERM
#define EPERM 1
#endif
#define SIGSYS 31

/** The native architecture as seccomp names it (AUDIT_ARCH_*), set by the loader. */
const volatile long native_arch = -1;

#define N_REFUSABLE 1024

/**
 * The native syscalls the sandbox's seccomp profile does not allow outright,
 * marked by the loader: one of them failing EPERM is the profile's refusal.
 */
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, N_REFUSABLE);
	__type(key, u32);
	__type(value, u8);
} refusable SEC(".maps");

static __always_inline int is_refusable(long nr)
{
	if (nr < 0 || nr >= N_REFUSABLE)
		return 0;
	u32 k = nr;
	u8 *v = bpf_map_lookup_elem(&refusable, &k);
	return v && *v;
}

/** A program and a syscall it was refused, recorded once. */
struct refused_key {
	struct proc proc;
	u32 nr;
	u32 killed;
};

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 4096);
	__type(key, struct refused_key);
	__type(value, u8);
} refused_seen SEC(".maps");

/**
 * Records the step's syscall @p nr as refused, once per program: with
 * @p killed, a 32-bit one seccomp killed the program for, else one that
 * failed with EPERM, with the thread so the reader can drop it for a path
 * change its hook sent.
 */
static __always_inline void syscall_refused(u32 slot, long nr, u32 killed)
{
	struct refused_key k;
	__builtin_memset(&k, 0, sizeof(k));
	k.proc = current_proc();
	k.nr = nr;
	k.killed = killed;
	u8 one = 1;
	if (bpf_map_update_elem(&refused_seen, &k, &one, BPF_NOEXIST))
		return; // recorded already
	struct event *e = start(slot, K_SYSCALL);
	if (!e)
		return;
	if (!killed)
		e->tid = (u32)bpf_get_current_pid_tgid();
	e->flags = nr;
	e->mode = killed;
	e->path_len = killed ? 0 : EPERM;
	e->data_len = 0;
	submit(e);
}

#endif

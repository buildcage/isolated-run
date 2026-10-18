// SPDX-License-Identifier: MIT OR GPL-2.0-only
/**
 * @file filesystem_audit.bpf.c
 * Records the file accesses of every task in one cgroup v2 subtree: opens,
 * each program's first read and write of each open file, mmaps, execs, and
 * the path operations (create, move, delete, attribute change), successes and
 * failures alike. It runs on any BTF-enabled kernel from 6.1 on, 6.4 on arm64,
 * the first to let fentry attach to a kernel function there. The programs are
 * in process.h, ops.h, open.h and io.h by what they follow, and the syscall
 * exit that settles their calls is here; what they share is in the other
 * headers.
 */

#include <linux/types.h>
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

/**
 * libbpf's BPF_PROG, with the body also given @p slot, a number of its own
 * that picks its scratch event (see scratch_get()). A program not written
 * with BPF_PROG passes its own __COUNTER__.
 */
#undef BPF_PROG
#define BPF_PROG(name, args...)						    \
name(unsigned long long *ctx);						    \
static __always_inline typeof(name(0))					    \
____##name(u32 slot, unsigned long long *ctx, ##args);			    \
typeof(name(0)) name(unsigned long long *ctx)				    \
{									    \
	_Pragma("GCC diagnostic push")					    \
	_Pragma("GCC diagnostic ignored \"-Wint-conversion\"")		    \
	return ____##name(__COUNTER__, ___bpf_ctx_cast(args));		    \
	_Pragma("GCC diagnostic pop")					    \
}									    \
static __always_inline typeof(name(0))					    \
____##name(u32 slot, unsigned long long *ctx, ##args)

#include "event.h"
#include "kernel.h"
#include "record.h"
#include "path.h"
#include "access.h"
#include "syscalls.h"
#include "refused.h"

#include "process.h"
#include "ops.h"
#include "open.h"
#include "io.h"

/**
 * Sends the return of syscall @p nr, with @p bits (RESULT_*). A failed
 * open(2) adds its flags and, unless the caller's name starts with '/', the
 * base directory of its descriptor or working directory. The reader joins it
 * to the kernel's copy of the name if that is relative, so a caller rewriting
 * its name can only leave a relative one without its directory.
 */
static __always_inline void send_result(u32 slot, struct pt_regs *regs, long nr, long ret, u8 bits)
{
	struct event *e = start(slot, K_RESULT);
	if (!e)
		return;
	e->tid = (u32)bpf_get_current_pid_tgid();
	e->nr = nr;
	e->path_len = ret;
	e->n1 = bits;
	if ((bits & RESULT_OPEN) && ret < 0 && !is_restart(ret)) {
		int at = nr == nr_openat || nr == nr_openat2;
		if (nr == nr_creat) {
			e->flags = O_CREAT | O_WRONLY | O_TRUNC;
		} else if (nr == nr_openat2) {
			u64 f = 0; // open_how's first field
			bpf_probe_read_user(&f, sizeof(f), (void *)sys_arg(regs, 2));
			e->flags = f;
		} else {
			e->flags = sys_arg(regs, at + 1);
		}
		char c = 0;
		bpf_probe_read_user(&c, 1, (void *)sys_arg(regs, at));
		if (c != '/')
			e->data_len = add_base(e, 0, at ? (int)sys_arg(regs, 0) : AT_FDCWD, 1, 0);
	}
	submit(e);
}

/**
 * Sends the return of each call a hook may have sent from. A failed path
 * syscall's record from its exit (see classify()) stands for the failure,
 * except for a call through a descriptor alone: its hook saw the file, which
 * a thread could swap before the exit.
 */
SEC("tp_btf/sys_exit")
int BPF_PROG(on_sys_exit, struct pt_regs *regs, long ret)
{
	if (!in_target())
		return 0;
	struct path_call call = {}; // so no field reaches the stack unset
	long nr = sys_nr(regs);
	int watched = classify(nr, regs, &call);
	// Before the call's K_RESULT, which decides whether they stand.
	if (watched)
		op_exit(slot, &call, ret);
	if (ret == -EPERM && !watched && !is_open_nr(nr) && is_refusable(nr))
		syscall_refused(slot, nr, 0);
	if (is_open_nr(nr)) {
		// A name refused as too long reached no hook to send it, so a filter
		// or tracer returning ENAMETOOLONG records one too.
		if (ret == -ENAMETOOLONG)
			open_name(slot, (const char *)sys_arg(regs, nr == nr_openat || nr == nr_openat2), 1);
		send_result(slot, regs, nr, ret, RESULT_OPEN);
	} else if ((watched && call.kind != K_ATTR_FAILED) || other_hooked(nr)) {
		u8 bits = watched ? RESULT_WATCHED : 0;
		if (watched && ret < 0 && names_fd(&call))
			bits |= RESULT_FD;
		send_result(slot, regs, nr, ret, bits);
	}
	return 0;
}

char LICENSE[] SEC("license") = "Dual MIT/GPL";

_Static_assert(__COUNTER__ <= N_SLOTS, "a program has no scratch event of its own");

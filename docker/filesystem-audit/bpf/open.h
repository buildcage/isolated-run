// SPDX-License-Identifier: MIT OR GPL-2.0-only
/**
 * @file open.h
 * The programs on opens: the file an open reaches, the name it passed and
 * whether it created the file.
 *
 * Programs, included by filesystem_audit.bpf.c after the headers they
 * use and its BPF_PROG.
 */
#ifndef FILESYSTEM_AUDIT_OPEN_H
#define FILESYSTEM_AUDIT_OPEN_H

SEC("fentry/security_file_open")
int BPF_PROG(on_open, struct file *file)
{
	if (!in_target() || on_layer(file))
		return 0;
	struct event *e = start(slot, K_OPEN);
	if (!e)
		return 0;
	e->flags = file->f_flags;
	e->mode = file->f_mode;
	file_path(e, file);
	// The first file an open(2) reaches is its own (see recorder.go).
	if (in_open_call())
		e->tid = (u32)bpf_get_current_pid_tgid();
	submit(e);
	return 0;
}

/**
 * Marks the open(2) the thread is in, if any, as reaching its create step, so
 * one refused afterwards is recorded as both.
 *
 * @return Whether the thread is in one.
 */
static __always_inline int open_creating(u32 slot)
{
	if (!in_open_call())
		return 0;
	struct event *e = start(slot, K_OPEN_CREATE);
	if (e) {
		e->tid = (u32)bpf_get_current_pid_tgid();
		submit(e);
	}
	return 1;
}

/**
 * mknod(2) and bind(2) to a path. A creating open also passes here, from
 * may_o_create, and is skipped: the open records it.
 */
DIR_ENTRY_HOOK(on_mknod, security_path_mknod, K_MKNOD, open_creating(slot))

/**
 * Sends the name of the open(2) the thread is in, to record the open under if
 * it fails before reaching a file: getname's copy, which the caller cannot
 * rewrite, or with @p user the caller's own, for a name getname refused as
 * too long.
 */
static __always_inline void open_name(u32 slot, const char *name, int user)
{
	struct event *e = start(slot, K_OPEN_NAME);
	if (!e)
		return;
	long r = user ? bpf_probe_read_user_str(e->data, PATH_LEN, name) :
			bpf_probe_read_kernel_str(e->data, PATH_LEN, name);
	if (r <= 0) {
		// Only the kernel's copy failing to read loses a record.
		if (!user)
			bump(&untracked);
		return;
	}
	e->tid = (u32)bpf_get_current_pid_tgid();
	e->data_len = r;
	e->n1 = user;
	e->n2 = user && r == PATH_LEN;
	submit(e);
}

/**
 * Sends the name of the open(2) the thread is in, if any, from the struct
 * filename in @p ctx's second argument.
 */
static __always_inline void send_name(u32 slot, u64 *ctx)
{
	if (!in_target() || !in_open_call())
		return;
	u64 name = 0;
	bpf_get_func_arg(ctx, 1, &name); // a number, which unlike a pointer can be range-checked
	// 7.0 passes on getname's error, which on_sys_exit handles.
	if ((long)name < 0 && (long)name >= -4095)
		return;
	open_name(slot, BPF_CORE_READ((struct filename *)name, name), 0);
}

/**
 * Only open(2) and exec reach do_filp_open, renamed do_file_open in 7.0, with
 * the name getname copied; both are optional.
 */
SEC("fentry/do_filp_open")
int BPF_PROG(on_filp_open, int dfd, struct filename *name)
{
	send_name(slot, ctx);
	return 0;
}

SEC("fentry/do_file_open")
int BPF_PROG(on_do_file_open, int dfd, struct filename *name)
{
	send_name(slot, ctx);
	return 0;
}

#endif

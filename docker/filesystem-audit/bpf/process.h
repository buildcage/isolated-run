// SPDX-License-Identifier: MIT OR GPL-2.0-only
/**
 * @file process.h
 * The programs that follow processes: exec, fork, exit, and the signals
 * seccomp sends.
 *
 * Programs, included by filesystem_audit.bpf.c after the headers they
 * use and its BPF_PROG.
 */
#ifndef FILESYSTEM_AUDIT_PROCESS_H
#define FILESYSTEM_AUDIT_PROCESS_H

/** How deep the kernel nests PID namespaces (MAX_PID_NS_LEVEL). */
#define PID_NS_LEVELS 32

/**
 * A process's number in the PID namespace it was made in, which that
 * namespace's /proc names its directory by.
 *
 * @param t A thread of the process.
 * @return The number, or 0 where it could not be read.
 */
static __always_inline u32 ns_tgid(struct task_struct *t)
{
	struct pid *pid = BPF_CORE_READ(t, group_leader, thread_pid);
	unsigned int level = BPF_CORE_READ(pid, level);
	int nr = 0;
	if (!pid || level > PID_NS_LEVELS)
		return 0;
	// numbers[] holds one upid a level, so its stride is the kernel's upid.
	void *at = (void *)pid + bpf_core_field_offset(struct pid, numbers) +
		   level * bpf_core_type_size(struct upid) + bpf_core_field_offset(struct upid, nr);
	bpf_probe_read_kernel(&nr, sizeof(nr), at);
	return nr;
}

/**
 * The file being executed, resolved, while bprm->file is still the one named:
 * by sched_process_exec a script has been swapped for its interpreter, and
 * filename is only the name the caller passed, relative to its cwd or not.
 */
SEC("fentry/security_bprm_creds_for_exec")
int BPF_PROG(on_exec_file, struct linux_binprm *bprm)
{
	if (!in_target())
		return 0;
	struct event *e = start(slot, K_EXEC_FILE);
	if (!e)
		return 0;
	struct file *f = BPF_CORE_READ(bprm, file);
	e->data_len = file_walk(e, f);
	submit(e);
	return 0;
}

/**
 * Lets the reader drop what a thread sent for a syscall whose exit never ran,
 * as for a core dump, rather than give it to a reused thread id.
 */
SEC("tp_btf/sched_process_exit")
int BPF_PROG(on_task_exit, struct task_struct *p)
{
	if (!in_target())
		return 0;
	struct event *e = start(slot, K_EXIT);
	if (!e)
		return 0;
	e->tid = (u32)bpf_get_current_pid_tgid();
	submit(e);
	return 0;
}

#define SYS_SECCOMP 1
#define X32_SYSCALL_BIT 0x40000000

/**
 * seccomp kills a process's last thread for a 32-bit or x32 syscall, none of
 * which the audit's profile allows, with a SIGSYS to that thread naming the
 * syscall it is making and its architecture. A SIGSYS naming a native syscall
 * comes from the step's own filter, and one naming a syscall the thread is
 * not in was queued by the process itself; both are skipped. One the process
 * queues naming the queuing call itself still passes, but records only that
 * process. A thread killed while others live on gets no signal, so goes
 * unrecorded.
 */
SEC("tp_btf/signal_generate")
int BPF_PROG(on_signal, int sig, struct kernel_siginfo *info, struct task_struct *task)
{
	if (sig != SIGSYS || (unsigned long)info <= 2 || !in_target())
		return 0;
	if (task != bpf_get_current_task_btf() || BPF_CORE_READ(info, si_code) != SYS_SECCOMP)
		return 0;
	long nr = BPF_CORE_READ(info, _sifields._sigsys._syscall);
	if (nr != sys_nr((struct pt_regs *)bpf_task_pt_regs(task)))
		return 0;
	if (BPF_CORE_READ(info, _sifields._sigsys._arch) != (u32)native_arch ||
	    (nr & X32_SYSCALL_BIT))
		syscall_refused(slot, nr, 1);
	return 0;
}

SEC("tp_btf/sched_process_exec")
int BPF_PROG(on_exec, struct task_struct *p, int old_pid, struct linux_binprm *bprm)
{
	if (!in_target())
		return 0;
	struct event *e = start(slot, K_EXEC);
	if (!e)
		return 0;
	e->path_len = bpf_probe_read_kernel_str(e->data, PATH_LEN, BPF_CORE_READ(bprm, filename));
	e->data_len = e->path_len > 0 ? e->path_len : 0;
	e->nspid = ns_tgid(p);
	submit(e);
	return 0;
}

/**
 * Every new process, so the recording shows who started each one, a subshell
 * that never execs or touches a file included. ppid is the process that made
 * it, not real_parent, which CLONE_PARENT sets to that process's own parent.
 */
SEC("tp_btf/sched_process_fork")
int BPF_PROG(on_fork, struct task_struct *parent, struct task_struct *child)
{
	if (!in_target())
		return 0;
	int tgid = BPF_CORE_READ(child, tgid);
	if (tgid == BPF_CORE_READ(parent, tgid))
		return 0; // a new thread, not a process
	struct event *e = start(slot, K_FORK);
	if (!e)
		return 0;
	e->pid = tgid;
	e->ppid = BPF_CORE_READ(parent, tgid);
	// The child's own name, copied from the thread that forked it.
	BPF_CORE_READ_STR_INTO(&e->comm, child, comm);
	e->nspid = ns_tgid(child);
	submit(e);
	return 0;
}

#endif

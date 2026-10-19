// SPDX-License-Identifier: MIT OR GPL-2.0-only
/**
 * @file io.h
 * The programs on what is done with open files: first reads and writes,
 * mappings, and freeing.
 *
 * Programs, included by filesystem_audit.bpf.c after the headers they
 * use and its BPF_PROG.
 */
#ifndef FILESYSTEM_AUDIT_IO_H
#define FILESYSTEM_AUDIT_IO_H

/**
 * read(2), write(2) and their vector, positional, splice, sendfile and
 * copy_file_range forms all pass through rw_verify_area, which calls this;
 * so does iterate_dir for a directory listing (as a read).
 */
SEC("fentry/security_file_permission")
int BPF_PROG(on_file_permission, struct file *file, int mask)
{
	if (!in_target() || on_layer(file))
		return 0;
	u32 kind;
	u8 bit;
	if (mask & MAY_WRITE) {
		kind = K_WRITE;
		bit = SEEN_WRITE;
	} else if (mask & MAY_READ) {
		kind = K_READ;
		bit = SEEN_READ;
	} else {
		return 0;
	}
	if (!first_time(file, bit))
		return 0;
	struct event *e = start(slot, kind);
	if (!e)
		return 0;
	file_path(e, file);
	submit(e);
	return 0;
}

SEC("fexit/vm_mmap_pgoff")
int BPF_PROG(on_mmap, struct file *file, unsigned long addr, unsigned long len,
	     unsigned long prot, unsigned long flags)
{
	mapped(slot, ctx, file, prot, flags);
	return 0;
}

SEC("fexit/vm_mmap")
int BPF_PROG(on_vm_mmap, struct file *file, unsigned long addr, unsigned long len,
	     unsigned long prot, unsigned long flags)
{
	mapped(slot, ctx, file, prot, flags);
	return 0;
}

/**
 * fexit, so only a change the LSMs allowed is recorded. reqprot is what the
 * caller asked for, as mmap sees it; prot may add PROT_EXEC.
 */
SEC("fexit/security_file_mprotect")
int BPF_PROG(on_mprotect, struct vm_area_struct *vma, unsigned long reqprot, unsigned long prot,
	     int ret)
{
	if (ret != 0 || !in_target())
		return 0;
	unsigned long flags = BPF_CORE_READ(vma, vm_flags) & VM_SHARED ? MAP_SHARED : 0;
	if (!(reqprot & PROT_EXEC) && !((reqprot & PROT_WRITE) && flags))
		return 0;
	struct file *file = BPF_CORE_READ(vma, vm_file);
	// S_PRIVATE marks the file behind shared anonymous memory.
	if (!file || BPF_CORE_READ(file, f_inode, i_flags) & S_PRIVATE)
		return 0;
	// Before 6.7 this is overlayfs's layer file, not the file the mapping was
	// recorded under, so making it executable later records it again.
	struct dentry *d;
	struct vfsmount *mnt;
	if (!step_path_of(file, &d, &mnt))
		return 0;
	map_events(slot, file, d, mnt, reqprot, flags, 0);
	return 0;
}

SEC("fentry/security_file_free")
int BPF_PROG(on_file_free, struct file *file)
{
	u64 key = 0;
	bpf_get_func_arg(ctx, 0, &key); // file, as a number
	u32 *n = seen_count(key);
	if (n && *n && bpf_map_delete_elem(&seen_files, &key) == 0)
		__sync_fetch_and_add(n, -1);
	return 0;
}

#endif

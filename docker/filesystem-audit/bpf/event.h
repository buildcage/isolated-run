// SPDX-License-Identifier: GPL-2.0
/**
 * @file event.h
 * The event the tracer records, shared by the BPF program and the userspace
 * tests of held.h.
 */
#ifndef FILESYSTEM_AUDIT_EVENT_H
#define FILESYSTEM_AUDIT_EVENT_H

#include <linux/types.h>

typedef __u8 u8;
typedef __u32 u32;
typedef __s32 s32;
typedef __u64 u64;

#define DATA_SZ 8192
#define PATH_LEN 4096
#define NAME_LEN 256

enum kind { K_OPEN = 1, K_EXEC = 2, K_UNLINK = 3, K_RMDIR = 4, K_RENAME = 5,
	K_MKDIR = 6, K_CHMOD = 7, K_SYMLINK = 8, K_LINK = 9, K_TRUNCATE = 10, K_CHOWN = 11,
	K_OPEN_FAILED = 12, K_READ = 13, K_WRITE = 14, K_MMAP = 15,
	/**
	 * @name Failed path syscalls
	 * data holds the user path(s), NUL-separated (old then new for rename),
	 * then the base directories of the relative ones (see add_base);
	 * path_len holds the errno. A failed chmod's new mode is in flags, a
	 * failed chown's new uid in flags and gid in gid.
	 * @{
	 */
	K_UNLINK_FAILED = 16, K_RENAME_FAILED = 17, K_CHMOD_FAILED = 18,
	K_CHOWN_FAILED = 19, K_ATTR = 20, K_ATTR_FAILED = 21,
	/** @} */
	/**
	 * A new process: pid is the child, ppid the process that made it, where
	 * every other kind's ppid is its current parent; no data.
	 */
	K_FORK = 22,
	/**
	 * The file an exec is about to run, before a script hands over to its
	 * interpreter: path components, as for unlink. The reader moves it onto
	 * the exec event that follows.
	 */
	K_EXEC_FILE = 23,
	/**
	 * A file, FIFO, device or Unix socket made by mknod(2) or bind(2): path
	 * components, as for unlink.
	 */
	K_MKNOD = 24,
	/** A failed rmdir, or unlinkat with AT_REMOVEDIR; as K_UNLINK_FAILED. */
	K_RMDIR_FAILED = 25,
	/**
	 * @name Other failed creations
	 * A failed mkdir, mknod, symlink (the link's name) or truncate, as
	 * K_UNLINK_FAILED; a failed link as K_RENAME_FAILED.
	 * @{
	 */
	K_MKDIR_FAILED = 26, K_MKNOD_FAILED = 27, K_SYMLINK_FAILED = 28,
	K_LINK_FAILED = 29, K_TRUNCATE_FAILED = 30
	/** @} */
};

/**
 * Fixed header (mirrored by hdrLen in decode.go), then data_len bytes of data:
 *
 * - open: d_path result (path_len is its return value)
 * - failed open: the name as passed to open(2), then its base directory if it
 *   is relative (see add_base); path_len holds the errno
 * - read/write: d_path result, once per open file, direction and program
 * - mmap: path components; mode holds prot, flags the map flags, and path_len
 *   is 1 when an exec mapped it (see in_exec)
 * - exec: filename; its arguments are not read, as they can hold secrets
 * - symlink: link body at 0, then the link's own path components
 * - others: leaf-first NUL-terminated path components, n1 of them, then n2
 *   more for a rename or link target
 */
struct event {
	u32 kind;
	u32 pid;
	u32 ppid;
	u32 flags;
	u32 mode;
	s32 path_len;
	u32 bases; ///< Which relative names add_base found a directory for.
	u32 data_len;
	u8 n1;
	u8 n2;
	u8 truncated; ///< The path, or the first path of a two-path operation.
	u8 trunc2;    ///< The second path of a rename or link.
	char comm[16];
	u32 err;   ///< A held path change's or open's errno when its syscall refused it.
	u32 marks; ///< MARK_* for the file a path was taken from.
	u32 gid;   ///< A failed chown's new group.
	u64 ts;    ///< CLOCK_BOOTTIME at the access; a failed syscall at its entry.
	char data[DATA_SZ + NAME_LEN]; ///< Slack: masked offset + one component.
};

/** An event, with room past its end for the whole of its last tail (see held.h). */
struct scratch_buf {
	struct event e;
	char slack[256];
};

#endif

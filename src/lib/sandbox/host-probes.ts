/**
 * The facts buildOciConfig reads off the machine it runs on, behind one
 * collaborator: they all describe the same machine, so a test supplying one
 * without the others would be describing one that cannot exist.
 *
 * Every judgement they make is a pure function here; only the syscalls sit
 * behind the `v8 ignore` below.
 */
import { existsSync, readFileSync, realpathSync, statfsSync } from "node:fs";
import os from "node:os";

import { realPathOf } from "./symlinks.ts";

// runc resolves process.args[0] against the *sandbox's* PATH (the step's own
// env, which a user could override to omit /usr/bin), so resolve setpriv to an
// absolute path up front instead of relying on that lookup. The sandbox rootfs
// is a bind-mount of the host's own `/`, so a path that exists on the host
// resolves to the same binary inside.
export const SETPRIV_CANDIDATE_PATHS = [
  "/usr/bin/setpriv",
  "/bin/setpriv",
  "/usr/sbin/setpriv",
  "/sbin/setpriv",
];

/**
 * Pure: the first candidate that exists, in the documented order. Falls back
 * to bare "setpriv" (a PATH lookup) only if none do; run-isolated.sh has
 * already verified setpriv is on root's PATH.
 */
export function resolveSetprivPath(exists: (path: string) => boolean): string {
  return SETPRIV_CANDIDATE_PATHS.find((p) => exists(p)) ?? "setpriv";
}

const NOFILE_LABEL = "Max open files";

export interface NofileLimit {
  soft: number;
  hard: number;
}

/**
 * Pure: RLIMIT_NOFILE out of a /proc/<pid>/limits dump. `nrOpen` stands in for
 * an "unlimited" column, since RLIM_INFINITY can't round-trip through JSON's
 * number type and /proc/sys/fs/nr_open is the ceiling the kernel enforces
 * anyway; without it such a limit is unreadable rather than guessed at.
 */
export function parseNofileLimit(procLimits: string, nrOpen?: number): NofileLimit | undefined {
  const line = procLimits.split("\n").find((l) => l.startsWith(NOFILE_LABEL));
  if (!line) return undefined;
  const columns = line.slice(NOFILE_LABEL.length).trim().split(/\s+/);
  const [soft, hard] = columns.map((c) =>
    /^\d+$/.test(c) ? Number(c) : c === "unlimited" ? nrOpen : undefined,
  );
  return soft !== undefined && hard !== undefined ? { soft, hard } : undefined;
}

export const SHM_DESTINATION = "/dev/shm";

export const TMPFS_MAGIC = 0x01021994;

/** The three fields of statfs(2) this reads. */
export interface StatfsShape {
  type: number;
  bsize: number;
  blocks: number;
}

/**
 * Pure: /dev/shm's size in bytes from a statfs answer.
 *
 * tmpfs reports f_bsize = PAGE_SIZE and f_blocks = size >> PAGE_SHIFT, so the
 * product round-trips through `size=` exactly. The fstype check is what makes
 * that reasoning hold: where /dev/shm is a plain directory rather than a mount
 * of its own, statfs answers for the containing filesystem instead, and sizing
 * a tmpfs to a whole disk lets a step exhaust the host's memory. Undefined
 * there, and wherever the product isn't a usable size.
 */
export function shmSizeFromStatfs({ type, bsize, blocks }: StatfsShape): number | undefined {
  if (type !== TMPFS_MAGIC) return undefined;
  const size = bsize * blocks;
  return Number.isFinite(size) && size > 0 ? size : undefined;
}

/**
 * Pure: the cgroup v2 path in a /proc/<pid>/cgroup dump, undefined unless v2
 * is the only hierarchy. A cgroup v1 or hybrid host lists a line per v1
 * hierarchy too. Also undefined for a path runc could not create a child
 * under: one outside this cgroup namespace's root ("/../x") or a removed
 * cgroup (" (deleted)").
 */
export function parseCgroupV2Path(procCgroup: string): string | undefined {
  const lines = procCgroup.split("\n").filter((line) => line !== "");
  if (lines.length !== 1 || !lines[0].startsWith("0::/")) return undefined;
  const path = lines[0].slice("0::".length);
  if (/\s/.test(path) || path.split("/").includes("..")) return undefined;
  return path;
}

export interface HostProbes {
  setprivPath(): string;
  nofileRlimit(): NofileLimit | undefined;
  shmSizeBytes(): number | undefined;
  hostname(): string;
  /** /var/run's real path, undefined when it doesn't exist. */
  varRunRealPath(): string | undefined;
  /** `path` with its symlinks resolved, or `path` itself when they loop. */
  realpath(path: string): string;
  /** This process's cgroup on a cgroup v2 host, undefined on any other. */
  cgroupPath(): string | undefined;
  /** Whether the kernel exposes its BTF, which fentry programs need to attach. */
  kernelBtf(): boolean;
}

// Untested by design, down to the end of the file: the syscalls behind the
// seam, which a test could only reach by reading this machine. The wiring
// itself is covered by test/integration-test-host-parity.sh, which checks
// RLIMIT_NOFILE, the hostname and /dev/shm's size against the runner's own
// from inside a real sandbox.
/* v8 ignore start */
function readOptionalFile(path: string): string | undefined {
  try {
    return readFileSync(path, "utf8");
  } catch {
    return undefined;
  }
}

function readNumericFile(path: string): number | undefined {
  const raw = readOptionalFile(path)?.trim();
  return raw !== undefined && /^\d+$/.test(raw) ? Number(raw) : undefined;
}

export const realHostProbes: HostProbes = {
  setprivPath: () => resolveSetprivPath(existsSync),

  // Not this process: Node raises its own soft RLIMIT_NOFILE to the hard limit
  // before any JS runs, so /proc/self/limits reports the raised value rather
  // than the runner's. The parent still holds the real one, being the process
  // that spawned this action and that would have spawned the step unwrapped.
  // Read here, on the near side of run.ts's `sudo`, which drops the soft limit
  // to 1024 on the way to runc.
  nofileRlimit: () => {
    const nrOpen = readNumericFile("/proc/sys/fs/nr_open");
    for (const pid of [process.ppid, "self"]) {
      const limits = readOptionalFile(`/proc/${pid}/limits`);
      const parsed = limits === undefined ? undefined : parseNofileLimit(limits, nrOpen);
      if (parsed) return parsed;
    }
    return undefined;
  },

  shmSizeBytes: () => {
    try {
      return shmSizeFromStatfs(statfsSync(SHM_DESTINATION));
    } catch {
      return undefined;
    }
  },

  hostname: () => os.hostname(),

  varRunRealPath: () => {
    try {
      return realpathSync("/var/run");
    } catch {
      return undefined;
    }
  },

  realpath: (path) => realPathOf(path),

  // This process, the runner's own cgroup: the one the step would run in
  // unwrapped. Read here, before run.ts's `sudo`, which can move its child to
  // a session scope of root's on a distribution whose sudo goes through
  // pam_systemd.
  cgroupPath: () => {
    const procCgroup = readOptionalFile("/proc/self/cgroup");
    return procCgroup === undefined ? undefined : parseCgroupV2Path(procCgroup);
  },
  // A vmlinux file under /boot would do for CO-RE, not for attaching.
  kernelBtf: () => existsSync("/sys/kernel/btf/vmlinux"),
};
/* v8 ignore stop */

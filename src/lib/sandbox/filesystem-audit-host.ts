import { SandboxError } from "../errors.ts";
import { realHostProbes, type HostProbes } from "./host-probes.ts";

const REQUIREMENTS =
  "It needs a cgroup v2 host running Linux 6.1 or newer (6.4 on arm64) with kernel BTF: " +
  "https://github.com/buildcage/isolated-run/blob/main/docs/filesystem-audit.md#troubleshooting";

/** The step's failure when the tracer could not start. */
export function auditUnavailable(reason: string): SandboxError {
  return new SandboxError(
    `filesystem_audit could not start (${reason}); the command was not run.`,
    "FILESYSTEM_AUDIT_UNAVAILABLE",
  );
}

/** auditUnavailable for a host the tracer cannot run on, naming what it needs. */
export function hostCannotAudit(reason: string): SandboxError {
  const e = auditUnavailable(reason);
  return new SandboxError(`${e.message} ${REQUIREMENTS}`, e.code);
}

export const NO_CGROUP_V2_REASON = "the runner is not on cgroup v2";

/** The native seccomp architecture of each runner the tracer supports. */
const NATIVE_ARCH: Partial<Record<NodeJS.Architecture, string>> = {
  x64: "SCMP_ARCH_X86_64",
  arm64: "SCMP_ARCH_AARCH64",
};

/** The seccomp profile with only the native ABI left, of those Docker's
 *  default profile allows. A syscall through a 32-bit one is numbered apart
 *  from the native ones the tracer reads attribute changes and failed path
 *  changes from, so under the audit the kernel kills the thread that makes
 *  one, with SIGSYS. */
export function withoutCompatSyscalls(profile: unknown, arch = process.arch): unknown {
  const p = profile as { architectures?: unknown } | null;
  const native = NATIVE_ARCH[arch];
  if (!p || !Array.isArray(p.architectures) || !native) return profile;
  return { ...p, architectures: p.architectures.filter((a) => a === native) };
}

/** The syscalls a seccomp profile allows, for some arguments at least; the
 *  tracer records any other that fails EPERM as one the profile refused. One
 *  allowed only for some arguments counts as allowed, since the kernel's own
 *  EPERM for it, as for a raw socket, would read as the profile's. */
export function allowedSyscalls(profile: unknown): string[] {
  const p = profile as { syscalls?: unknown } | null;
  if (!p || !Array.isArray(p.syscalls)) return [];
  return p.syscalls.flatMap((s: { names?: unknown; action?: unknown }) =>
    s.action === "SCMP_ACT_ALLOW" && Array.isArray(s.names)
      ? s.names.filter((n): n is string => typeof n === "string")
      : [],
  );
}

/** Fails the step before the proxy starts on a host the tracer cannot watch.
 *  The kernel version is left to the tracer, which checks the kernel by
 *  feature. */
export function checkFilesystemAuditHost(
  probes: Pick<HostProbes, "cgroupPath" | "kernelBtf"> = realHostProbes,
): void {
  if (probes.cgroupPath() === undefined) throw hostCannotAudit(NO_CGROUP_V2_REASON);
  if (!probes.kernelBtf()) throw hostCannotAudit("the kernel exposes no BTF");
}

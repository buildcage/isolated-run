import { describe, it, expect } from "vitest";

import { SandboxError } from "../errors.ts";
import {
  allowedSyscalls,
  auditUnavailable,
  checkFilesystemAuditHost,
  hostCannotAudit,
  withoutCompatSyscalls,
} from "./filesystem-audit-host.ts";

const REQUIREMENTS =
  "It needs a cgroup v2 host running Linux 6.1 or newer (6.4 on arm64) with kernel BTF: " +
  "https://github.com/buildcage/isolated-run/blob/main/docs/filesystem-audit.md#troubleshooting";

describe("allowedSyscalls", () => {
  it("lists the syscalls allowed for any arguments or some", () => {
    const profile = {
      syscalls: [
        { names: ["read", "write"], action: "SCMP_ACT_ALLOW" },
        { names: ["clone"], action: "SCMP_ACT_ALLOW", args: [{ index: 0 }] },
        { names: ["personality"], action: "SCMP_ACT_ALLOW", args: [] },
        { names: ["clone3"], action: "SCMP_ACT_ERRNO" },
        { names: [7, "uname"], action: "SCMP_ACT_ALLOW" },
        { action: "SCMP_ACT_ALLOW" },
      ],
    };
    expect(allowedSyscalls(profile)).toStrictEqual([
      "read",
      "write",
      "clone",
      "personality",
      "uname",
    ]);
    expect(allowedSyscalls(null)).toStrictEqual([]);
    expect(allowedSyscalls({})).toStrictEqual([]);
  });
});

describe("withoutCompatSyscalls", () => {
  it("keeps only the native ABI and the rest of the profile", () => {
    const profile = {
      defaultAction: "SCMP_ACT_ERRNO",
      architectures: ["SCMP_ARCH_X86_64", "SCMP_ARCH_X86", "SCMP_ARCH_X32"],
      syscalls: [{ names: ["read"], action: "SCMP_ACT_ALLOW" }],
    };
    expect(withoutCompatSyscalls(profile, "x64")).toStrictEqual({
      ...profile,
      architectures: ["SCMP_ARCH_X86_64"],
    });
    expect(
      withoutCompatSyscalls({ architectures: ["SCMP_ARCH_AARCH64", "SCMP_ARCH_ARM"] }, "arm64"),
    ).toStrictEqual({ architectures: ["SCMP_ARCH_AARCH64"] });
  });

  it("leaves a profile naming no architectures, or one for a runner it cannot audit, as it is", () => {
    const profile = { defaultAction: "SCMP_ACT_ERRNO" };
    expect(withoutCompatSyscalls(profile, "x64")).toBe(profile);
    expect(withoutCompatSyscalls(null, "x64")).toBeNull();
    const s390 = { architectures: ["SCMP_ARCH_S390X", "SCMP_ARCH_S390"] };
    expect(withoutCompatSyscalls(s390, "s390x")).toBe(s390);
  });
});

describe("auditUnavailable", () => {
  it("says why and that the command did not run", () => {
    expect(auditUnavailable("docker cp failed")).toStrictEqual(
      new SandboxError(
        "filesystem_audit could not start (docker cp failed); the command was not run.",
        "FILESYSTEM_AUDIT_UNAVAILABLE",
      ),
    );
  });
});

describe("hostCannotAudit", () => {
  it("adds what the tracer needs of the host", () => {
    expect(hostCannotAudit("the tracer exited")).toStrictEqual(
      new SandboxError(
        `filesystem_audit could not start (the tracer exited); the command was not run. ${REQUIREMENTS}`,
        "FILESYSTEM_AUDIT_UNAVAILABLE",
      ),
    );
  });
});

describe("checkFilesystemAuditHost", () => {
  const host = (cgroup: string | undefined, btf: boolean) => ({
    cgroupPath: () => cgroup,
    kernelBtf: () => btf,
  });

  it("passes on a cgroup v2 host with kernel BTF", () => {
    expect(() =>
      checkFilesystemAuditHost(host("/system.slice/runner.service", true)),
    ).not.toThrow();
  });

  it("fails the step on a host without cgroup v2", () => {
    expect(() => checkFilesystemAuditHost(host(undefined, true))).toThrow(
      hostCannotAudit("the runner is not on cgroup v2"),
    );
  });

  it("fails the step on a kernel without BTF", () => {
    expect(() => checkFilesystemAuditHost(host("/system.slice/runner.service", false))).toThrow(
      hostCannotAudit("the kernel exposes no BTF"),
    );
  });
});

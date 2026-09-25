import { describe, it, expect } from "vitest";

import { computeReadonlyHostMounts, resolveProtectedPaths } from "./oci-protected-paths.ts";
import { parseMountinfo } from "./mountinfo.ts";
import type { HostMount } from "./types.ts";

// Realistic /proc/self/mountinfo lines; only the mount points matter here.
// The field layout and its parsing are mountinfo.test.ts's business.
const SAMPLE_MOUNTINFO = [
  "1 0 0:1 / / rw,relatime shared:1 - ext4 /dev/root rw",
  "2 1 0:2 / /proc rw,relatime shared:2 - proc proc rw",
  "3 1 0:3 / /run rw,nosuid,relatime shared:3 - tmpfs tmpfs rw,size=100k",
  "4 3 0:4 / /run/user/1000 rw,nosuid,relatime shared:4 - tmpfs tmpfs rw",
  "5 1 0:5 / /mnt rw,relatime shared:5 - ext4 /dev/sdb1 rw",
].join("\n");

describe("computeReadonlyHostMounts", () => {
  const hostMounts = parseMountinfo(SAMPLE_MOUNTINFO);
  const freshMountDestinations = new Set(["/proc"]);

  it("excludes '/' itself (already covered by root.readonly)", () => {
    const result = computeReadonlyHostMounts(hostMounts, new Set(), freshMountDestinations);
    expect(!result.includes("/")).toBeTruthy();
  });

  it("excludes paths runc's own base spec already mounts fresh", () => {
    const result = computeReadonlyHostMounts(hostMounts, new Set(), freshMountDestinations);
    expect(!result.includes("/proc")).toBeTruthy();
  });

  it("excludes writable paths and the mounts nested under them", () => {
    const result = computeReadonlyHostMounts(hostMounts, new Set(["/run"]), freshMountDestinations);
    expect(result).not.toContain("/run");
    expect(result).not.toContain("/run/user/1000");
    expect(result).toContain("/mnt");
  });

  it("compares path components, so a sibling sharing a prefix stays read-only", () => {
    const result = computeReadonlyHostMounts(
      [...hostMounts, { mountPoint: "/runner", fsType: "ext4" }],
      new Set(["/run"]),
      freshMountDestinations,
    );
    expect(result).toContain("/runner");
  });

  it("includes real, non-pseudo, non-protected host mounts (e.g. a separate disk at /mnt)", () => {
    const result = computeReadonlyHostMounts(hostMounts, new Set(), freshMountDestinations);
    expect(result.includes("/mnt")).toBeTruthy();
    expect(result.includes("/run")).toBeTruthy();
    expect(result.includes("/run/user/1000")).toBeTruthy();
  });

  it("includes a pseudo-filesystem-like mount whose path isn't one of runc's own fresh destinations", () => {
    // e.g. securityfs at /sys/kernel/security: it looks like the same
    // "kernel pseudo-fs" class as /proc, but runc's default spec never
    // declares a mount for it, so the host-swept copy must be forced
    // read-only just like any other real mount point.
    const withSecurityfs = [
      ...hostMounts,
      { mountPoint: "/sys/kernel/security", fsType: "securityfs" },
    ];
    const result = computeReadonlyHostMounts(withSecurityfs, new Set(), freshMountDestinations);
    expect(result.includes("/sys/kernel/security")).toBeTruthy();
  });
});

describe("resolveProtectedPaths", () => {
  const base = {
    baseMaskedPaths: ["/proc/kcore"],
    baseReadonlyPaths: ["/proc/bus", "/proc/sysrq-trigger"],
    uid: 1000,
    env: {} as NodeJS.ProcessEnv,
    hostMounts: [] as HostMount[],
    writablePaths: new Set<string>(),
    freshMountDestinations: new Set<string>(),
    disableReadonly: false,
  };

  it("adds this action's own masked paths on top of runc's, rather than replacing them", () => {
    const { maskedPaths } = resolveProtectedPaths(base);
    expect(maskedPaths).toContain("/proc/kcore"); // runc's own
    expect(maskedPaths).toContain("/proc/kallsyms"); // this action's
    expect(maskedPaths).toContain("/run/docker.sock");
    expect(maskedPaths).toContain("/run/netns");
    expect(maskedPaths).toContain("/run/user/1000");
  });

  // A path can reach readonlyPaths two ways; the next two cases cover both.
  it("takes a path it masks out of the readonlyPaths runc's own base spec listed", () => {
    const { readonlyPaths } = resolveProtectedPaths(base);
    expect(readonlyPaths).not.toContain("/proc/sysrq-trigger");
    expect(readonlyPaths).toContain("/proc/bus");
  });

  it("takes a path it masks out of the readonlyPaths the host-mount sweep produced", () => {
    // /run/user/<uid> is a real tmpfs mount on the host, so the sweep would
    // otherwise re-add what perUserRuntimeDirs just masked.
    const { maskedPaths, readonlyPaths } = resolveProtectedPaths({
      ...base,
      hostMounts: [
        { mountPoint: "/run/user/1000", fsType: "tmpfs" },
        { mountPoint: "/mnt", fsType: "ext4" },
      ],
    });
    expect(maskedPaths).toContain("/run/user/1000");
    expect(readonlyPaths).not.toContain("/run/user/1000");
    expect(readonlyPaths).toContain("/mnt");
  });

  it("leaves a path the mount layers keep writable out of readonlyPaths", () => {
    const { readonlyPaths } = resolveProtectedPaths({
      ...base,
      hostMounts: [
        { mountPoint: "/home/runner", fsType: "ext4" },
        { mountPoint: "/mnt", fsType: "ext4" },
      ],
      writablePaths: new Set(["/home/runner"]),
    });
    expect(readonlyPaths).not.toContain("/home/runner");
    expect(readonlyPaths).toContain("/mnt");
  });

  it("masks the rootless runtime sockets only once $XDG_RUNTIME_DIR names a directory", () => {
    expect(resolveProtectedPaths(base).maskedPaths).not.toContain("/run/user/1000/docker.sock");
    const { maskedPaths } = resolveProtectedPaths({
      ...base,
      env: { XDG_RUNTIME_DIR: "/run/user/1000" },
    });
    expect(maskedPaths).toContain("/run/user/1000/docker.sock");
  });

  it("keeps masking an $XDG_RUNTIME_DIR that sits under a default writable dir", () => {
    const { maskedPaths } = resolveProtectedPaths({
      ...base,
      env: { XDG_RUNTIME_DIR: "/tmp/runtime-runner" },
      writablePaths: new Set(["/tmp", "/home/runner"]),
    });
    expect(maskedPaths).toContain("/tmp/runtime-runner");
    expect(maskedPaths).toContain("/tmp/runtime-runner/docker.sock");
  });

  it("lifts the mask on an $XDG_RUNTIME_DIR outside /run only when a writable path names it", () => {
    const { maskedPaths } = resolveProtectedPaths({
      ...base,
      env: { XDG_RUNTIME_DIR: "/tmp/runtime-runner" },
      writablePaths: new Set(["/tmp", "/tmp/runtime-runner"]),
    });
    expect(maskedPaths).not.toContain("/tmp/runtime-runner");
    // The sockets inside are masked on their own.
    expect(maskedPaths).toContain("/tmp/runtime-runner/docker.sock");
  });

  it("lifts every mask under a writable path within /run or /var/run", () => {
    const { maskedPaths } = resolveProtectedPaths({
      ...base,
      env: { XDG_RUNTIME_DIR: "/run/user/1000" },
      writablePaths: new Set(["/run/user", "/var/run"]),
    });
    expect(maskedPaths).not.toContain("/run/user/1000");
    expect(maskedPaths).not.toContain("/run/user/1000/docker.sock");
    expect(maskedPaths).not.toContain("/var/run/netns");
    expect(maskedPaths).toContain("/run/netns");
  });

  it("lifts a /var/run mask under a writable ancestor of /var/run", () => {
    // /var/run is a real directory on a few hosts, where /var re-exposes it.
    const { maskedPaths } = resolveProtectedPaths({ ...base, writablePaths: new Set(["/var"]) });
    expect(maskedPaths).not.toContain("/var/run/netns");
    expect(maskedPaths).toContain("/run/netns");
  });

  it("matches an $XDG_RUNTIME_DIR given with a trailing slash to the writable path naming it", () => {
    const { maskedPaths } = resolveProtectedPaths({
      ...base,
      env: { XDG_RUNTIME_DIR: "/tmp/runtime-runner/" },
      writablePaths: new Set(["/tmp/runtime-runner"]),
    });
    expect(maskedPaths).not.toContain("/tmp/runtime-runner/");
  });

  it("lifts a mask outside /run under `write_through: /`", () => {
    const { maskedPaths } = resolveProtectedPaths({
      ...base,
      env: { XDG_RUNTIME_DIR: "/tmp/runtime-runner" },
      writablePaths: new Set(["/"]),
    });
    expect(maskedPaths).not.toContain("/tmp/runtime-runner");
  });

  it("skips the host-mount sweep under `writable: /`, still masking what it masks", () => {
    const { maskedPaths, readonlyPaths } = resolveProtectedPaths({
      ...base,
      hostMounts: [{ mountPoint: "/mnt", fsType: "ext4" }],
      disableReadonly: true,
    });
    expect(readonlyPaths).not.toContain("/mnt");
    expect(readonlyPaths).toContain("/proc/bus");
    expect(maskedPaths).toContain("/run/user/1000");
  });
});

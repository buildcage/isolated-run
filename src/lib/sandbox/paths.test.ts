import { describe, it, expect } from "vitest";

import {
  isAtOrUnder,
  pathAliases,
  pathsOverlap,
  assertScratchBaseNotWritable,
  WritablePathConflictError,
} from "./paths.ts";
import { SANDBOX_SCRATCH_BASE } from "./scratch-dir.ts";
import type { MountinfoEntry } from "./types.ts";

describe("isAtOrUnder", () => {
  it("is true for the path itself and anything under it", () => {
    expect(isAtOrUnder("/etc/resolv.conf", "/etc/resolv.conf")).toBe(true);
    expect(isAtOrUnder("/etc/ssl/certs/ca-certificates.crt", "/etc")).toBe(true);
    expect(isAtOrUnder("/etc/hosts", "/")).toBe(true);
  });

  it("is false the other way round: an ancestor is not under its own child", () => {
    expect(isAtOrUnder("/etc", "/etc/resolv.conf")).toBe(false);
  });

  it("compares whole path components, not bare string prefixes", () => {
    expect(isAtOrUnder("/etc/resolv.confX", "/etc/resolv.conf")).toBe(false);
    expect(isAtOrUnder("/etcetera/x", "/etc")).toBe(false);
  });

  it("is false for unrelated paths", () => {
    expect(isAtOrUnder("/opt/cache", "/etc")).toBe(false);
  });
});

describe("pathsOverlap", () => {
  it("is true for identical paths", () => {
    expect(pathsOverlap("/var/tmp/buildcage-1000", "/var/tmp/buildcage-1000")).toBe(true);
  });

  it("is true when either side is an ancestor of the other", () => {
    expect(pathsOverlap("/var/tmp", "/var/tmp/buildcage-1000")).toBe(true);
    expect(pathsOverlap("/var/tmp/buildcage-1000/rootfs", "/var/tmp/buildcage-1000")).toBe(true);
    expect(pathsOverlap("/", "/var/tmp/buildcage-1000")).toBe(true);
  });

  it("is false for unrelated paths", () => {
    expect(pathsOverlap("/opt/cache", "/var/tmp/buildcage-1000")).toBe(false);
  });

  it("compares whole path components, not bare string prefixes", () => {
    expect(pathsOverlap("/var/tmp/buildcage-10", "/var/tmp/buildcage-1000")).toBe(false);
    expect(pathsOverlap("/var/tmp/bu", "/var/tmp/buildcage-1000")).toBe(false);
  });

  it("needs its input normalized -- an unresolved '.' segment reads as unrelated", () => {
    // Pinned so resolveWriteThroughEntry's normalization guarantee can't be
    // dropped upstream without a test noticing.
    expect(pathsOverlap("/var/tmp/./buildcage-1000", "/var/tmp/buildcage-1000")).toBe(false);
  });
});

describe("pathAliases", () => {
  const mount = (device: string, root: string, mountPoint: string): MountinfoEntry => ({
    mountPoint,
    fsType: "ext4",
    device,
    root,
  });
  const ROOT = mount("8:1", "/", "/");

  it("finds none without a second mount showing the path", () => {
    expect(pathAliases([ROOT, mount("8:16", "/", "/mnt")], "/var/tmp/b")).toStrictEqual([]);
    expect(pathAliases([ROOT, mount("8:1", "/etc", "/mnt/etc")], "/var/tmp/b")).toStrictEqual([]);
  });

  it("finds the /tmp side of /var/tmp bind-mounted onto /tmp", () => {
    expect(pathAliases([ROOT, mount("8:1", "/tmp", "/var/tmp")], "/var/tmp/b")).toStrictEqual([
      "/tmp/b",
    ]);
  });

  it("finds the /var/tmp side of /tmp bind-mounted onto /var/tmp", () => {
    expect(pathAliases([ROOT, mount("8:1", "/var/tmp", "/tmp")], "/var/tmp/b")).toStrictEqual([
      "/tmp/b",
    ]);
  });

  it("finds a second mount of the whole filesystem, and a bind of the directory itself", () => {
    expect(
      pathAliases(
        [ROOT, mount("8:1", "/", "/srv/root"), mount("8:1", "/var/tmp/b", "/mnt/b")],
        "/var/tmp/b",
      ),
    ).toStrictEqual(["/srv/root/var/tmp/b", "/mnt/b"]);
  });

  it("finds a bind of only part of what is under the path", () => {
    expect(
      pathAliases([ROOT, mount("8:1", "/var/tmp/b/sub", "/mnt/sub")], "/var/tmp/b"),
    ).toStrictEqual(["/mnt/sub"]);
  });

  it("matches by device and root, so a separate /var/tmp filesystem has no /tmp alias", () => {
    const varTmp = mount("8:2", "/", "/var/tmp");
    expect(pathAliases([ROOT, varTmp], "/var/tmp/b")).toStrictEqual([]);
    expect(pathAliases([ROOT, varTmp, mount("8:2", "/", "/data")], "/var/tmp/b")).toStrictEqual([
      "/data/b",
    ]);
  });

  it("leaves out an alias a later mount covers", () => {
    const mounts = [ROOT, mount("8:1", "/tmp", "/var/tmp")];
    expect(pathAliases([...mounts, mount("0:40", "/", "/tmp")], "/var/tmp/b")).toStrictEqual([]);
    expect(pathAliases([...mounts, mount("0:40", "/", "/tmp/b")], "/var/tmp/b")).toStrictEqual([]);
  });

  it("leaves out mounts under the path itself, and aliases inside another alias", () => {
    expect(
      pathAliases(
        [
          ROOT,
          mount("8:1", "/var/tmp/b", "/var/tmp/b/rootfs/x"),
          mount("8:1", "/var/tmp", "/mnt/v"),
          mount("8:1", "/var/tmp/b", "/mnt/v/b/again"),
        ],
        "/var/tmp/b",
      ),
    ).toStrictEqual(["/mnt/v/b"]);
  });

  it("finds none when no mount holds the path", () => {
    expect(pathAliases([], "/var/tmp/b")).toStrictEqual([]);
  });
});

describe("assertScratchBaseNotWritable", () => {
  it("accepts paths outside the scratch base", () => {
    expect(() => assertScratchBaseNotWritable(["/opt/cache", "/home/runner"])).not.toThrow();
    expect(() => assertScratchBaseNotWritable([])).not.toThrow();
  });

  it("rejects the scratch base itself, an ancestor, and a descendant", () => {
    expect(() => assertScratchBaseNotWritable([SANDBOX_SCRATCH_BASE])).toThrow(/overlaps/);
    expect(() => assertScratchBaseNotWritable(["/var/tmp"])).toThrow(/overlaps/);
    expect(() => assertScratchBaseNotWritable([`${SANDBOX_SCRATCH_BASE}/rootfs`])).toThrow(
      /overlaps/,
    );
  });

  it("names the offending path in the error", () => {
    expect(() => assertScratchBaseNotWritable(["/opt/ok", "/var/tmp"])).toThrow(/"\/var\/tmp"/);
  });

  // The class is what lets a caller report the misconfiguration under its own
  // code instead of a generic build failure; see sandboxed-command.ts.
  it("throws WritablePathConflictError", () => {
    expect(() => assertScratchBaseNotWritable(["/var/tmp"])).toThrow(WritablePathConflictError);
  });
});

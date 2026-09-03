import { describe, it, expect } from "vitest";
import { writeFileSync, statSync } from "node:fs";
import { join } from "node:path";

import { resolveSandboxGid } from "./identity.ts";
import { withScratchDir } from "./scratch-dir.ts";

// Every test passes runtimeSocketPaths explicitly (even as []) so a real
// docker.sock/etc on the machine running the test never leaks in -- only
// the fake group file and, where relevant, a fake socket path under the
// scratch dir decide the outcome.

describe("resolveSandboxGid", () => {
  it("leaves a non-privileged primary GID unchanged", () => {
    withScratchDir((dir) => {
      const groupFile = join(dir, "group");
      writeFileSync(groupFile, "runner:x:1000:\n");
      const result = resolveSandboxGid(1000, {}, { groupFile, runtimeSocketPaths: [] });
      expect(result).toStrictEqual({ gid: 1000 });
    });
  });

  it("substitutes a primary GID whose name is privileged (e.g. docker)", () => {
    withScratchDir((dir) => {
      const groupFile = join(dir, "group");
      writeFileSync(groupFile, "docker:x:999:\nnogroup:x:65534:\n");
      const result = resolveSandboxGid(999, {}, { groupFile, runtimeSocketPaths: [] });
      expect(result).toStrictEqual({ gid: 65534, substitutedFrom: 999 });
    });
  });

  it("treats GID 0 as privileged even without consulting the group file", () => {
    const result = resolveSandboxGid(0, {}, { groupFile: "/nonexistent", runtimeSocketPaths: [] });
    expect(result.substitutedFrom).toBe(0);
    expect(result.gid).not.toBe(0);
  });

  it("flags a GID as privileged when it owns a runtime socket, even under a non-standard group name", () => {
    withScratchDir((dir) => {
      const groupFile = join(dir, "group");
      const fakeSocket = join(dir, "fake.sock");
      writeFileSync(fakeSocket, "");
      // Read back the real owning GID (file group inheritance is
      // platform-dependent) and give it a non-standard name, so the
      // substitution can only be explained by socket ownership, not the
      // name list.
      const ownerGid = statSync(fakeSocket).gid;
      writeFileSync(groupFile, `not-a-known-name:x:${ownerGid}:\nnogroup:x:65534:\n`);
      const result = resolveSandboxGid(
        ownerGid,
        {},
        {
          groupFile,
          runtimeSocketPaths: [fakeSocket],
        },
      );
      expect(result).toStrictEqual({ gid: 65534, substitutedFrom: ownerGid });
    });
  });

  it("throws UNSAFE_PRIMARY_GID when every candidate, including nogroup/nobody/65534, is privileged", () => {
    withScratchDir((dir) => {
      const groupFile = join(dir, "group");
      writeFileSync(
        groupFile,
        ["docker:x:500:", "nogroup:x:500:", "nobody:x:500:", "wheel:x:65534:"].join("\n") + "\n",
      );
      expect(() => resolveSandboxGid(500, {}, { groupFile, runtimeSocketPaths: [] })).toThrowError(
        /UNSAFE_PRIMARY_GID|privileged/,
      );
    });
  });

  it("falls back to the runtime-socket check alone when the group file can't be read", () => {
    const result = resolveSandboxGid(
      1000,
      {},
      {
        groupFile: "/definitely/does/not/exist",
        runtimeSocketPaths: [],
      },
    );
    expect(result).toStrictEqual({ gid: 1000 });
  });
});

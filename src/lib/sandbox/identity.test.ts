import { describe, it, expect } from "vitest";

import { assertNonRootUid, resolveSandboxGid, type HostGroups } from "./identity.ts";
import { SandboxError } from "../errors.ts";

// The host is supplied rather than read: a test must not depend on who owns a
// file on the machine running it (a scratch file is wheel-owned on macOS and
// runner-owned on Linux), nor on what the real /etc/group says.
//
// Every test passes runtimeSocketPaths explicitly (even as []) so a real
// docker.sock on that machine never leaks in: only the group file below
// and, where relevant, a named socket path decide the outcome.

/** A host with the given /etc/group contents, socket owners and NSS-only groups. */
function host(
  groupFile: string | null,
  socketOwners: Record<string, number> = {},
  nss: Record<string, string> = {},
): HostGroups {
  return {
    readGroupFile: () => {
      if (groupFile === null) throw new Error("ENOENT");
      return groupFile;
    },
    lookupGroup: (key) => nss[key] ?? null,
    gidOf: (path) => {
      const gid = socketOwners[path];
      if (gid === undefined) throw new Error("ENOENT");
      return gid;
    },
  };
}

describe("resolveSandboxGid", () => {
  it("leaves a non-privileged primary GID unchanged", () => {
    const result = resolveSandboxGid(
      1000,
      {},
      { host: host("runner:x:1000:\n"), runtimeSocketPaths: [] },
    );
    expect(result).toStrictEqual({ gid: 1000 });
  });

  it("substitutes a primary GID whose name is privileged (e.g. docker)", () => {
    const result = resolveSandboxGid(
      999,
      {},
      { host: host("docker:x:999:\nnogroup:x:65534:\n"), runtimeSocketPaths: [] },
    );
    expect(result).toStrictEqual({ gid: 65534, substitutedFrom: 999 });
  });

  it("treats GID 0 as privileged even without consulting the group file", () => {
    const result = resolveSandboxGid(0, {}, { host: host(null), runtimeSocketPaths: [] });
    expect(result.substitutedFrom).toBe(0);
    expect(result.gid).not.toBe(0);
  });

  it("flags a GID as privileged when it owns a runtime socket, even under a non-standard group name", () => {
    // A non-standard name, so the substitution can only be explained by
    // socket ownership and not by the name list.
    const result = resolveSandboxGid(
      1234,
      {},
      {
        host: host("not-a-known-name:x:1234:\nnogroup:x:65534:\n", { "/fake.sock": 1234 }),
        runtimeSocketPaths: ["/fake.sock"],
      },
    );
    expect(result).toStrictEqual({ gid: 65534, substitutedFrom: 1234 });
  });

  it("skips a runtime socket path that doesn't exist rather than failing", () => {
    const result = resolveSandboxGid(
      1000,
      {},
      { host: host("runner:x:1000:\n"), runtimeSocketPaths: ["/gone.sock"] },
    );
    expect(result).toStrictEqual({ gid: 1000 });
  });

  it("ignores group file lines with no name or no numeric GID", () => {
    // The only line that parses puts docker on 1000, so a GID that the
    // malformed lines would also have claimed still resolves from that one.
    const groupFile =
      ["# a comment", "", ":x:1000:", "docker:x:not-a-number:", "docker:x:1000:"].join("\n") + "\n";
    const result = resolveSandboxGid(1000, {}, { host: host(groupFile), runtimeSocketPaths: [] });
    expect(result).toStrictEqual({ gid: 65534, substitutedFrom: 1000 });
  });

  it("moves on to nobody when the group file has no nogroup", () => {
    const result = resolveSandboxGid(
      999,
      {},
      { host: host("docker:x:999:\nnobody:x:65500:\n"), runtimeSocketPaths: [] },
    );
    expect(result).toStrictEqual({ gid: 65500, substitutedFrom: 999 });
  });

  it("throws UNSAFE_PRIMARY_GID when every candidate, including nogroup/nobody/65534, is privileged", () => {
    const groupFile =
      ["docker:x:500:", "nogroup:x:500:", "nobody:x:500:", "wheel:x:65534:"].join("\n") + "\n";
    expect(() =>
      resolveSandboxGid(500, {}, { host: host(groupFile), runtimeSocketPaths: [] }),
    ).toThrowError(/UNSAFE_PRIMARY_GID|privileged/);
  });

  it("reads /etc/group and the standard socket paths when given neither", () => {
    const readPaths: string[] = [];
    const statted: string[] = [];
    const result = resolveSandboxGid(
      999,
      {},
      {
        host: {
          readGroupFile: (path) => {
            readPaths.push(path);
            return "docker:x:999:\nnogroup:x:65534:\n";
          },
          lookupGroup: () => null,
          gidOf: (path) => {
            statted.push(path);
            throw new Error("ENOENT");
          },
        },
      },
    );

    expect(result).toStrictEqual({ gid: 65534, substitutedFrom: 999 });
    expect(readPaths).toStrictEqual(["/etc/group"]);
    expect(statted).toContain("/var/run/docker.sock");
  });

  it("falls back to the runtime-socket check alone when the group file can't be read", () => {
    const result = resolveSandboxGid(1000, {}, { host: host(null), runtimeSocketPaths: [] });
    expect(result).toStrictEqual({ gid: 1000 });
  });
});

describe("resolveSandboxGid: groups served through NSS", () => {
  it("substitutes a privileged primary GID that only NSS knows the name of", () => {
    const result = resolveSandboxGid(
      2000,
      {},
      {
        host: host("nogroup:x:65534:\n", {}, { "2000": "docker:*:2000:runner\n" }),
        runtimeSocketPaths: [],
      },
    );
    expect(result).toStrictEqual({ gid: 65534, substitutedFrom: 2000 });
  });

  it("finds the substitute through NSS when the group file can't be read", () => {
    const result = resolveSandboxGid(
      2000,
      {},
      {
        host: host(null, {}, { "2000": "docker:*:2000:\n", nogroup: "nogroup:x:65534:\n" }),
        runtimeSocketPaths: [],
      },
    );
    expect(result).toStrictEqual({ gid: 65534, substitutedFrom: 2000 });
  });
});

describe("assertNonRootUid", () => {
  it("throws ROOT_RUNNER for uid 0", () => {
    let code: string | undefined;
    try {
      assertNonRootUid(0);
    } catch (e) {
      code = (e as SandboxError).code;
    }
    expect(code).toBe("ROOT_RUNNER");
  });

  it("is a no-op for any non-root uid", () => {
    expect(() => assertNonRootUid(1001)).not.toThrow();
  });
});

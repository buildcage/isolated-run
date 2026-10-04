import { describe, it, expect } from "vitest";

import { resolveHostPath } from "./symlinks.ts";

/** Every path exists; `links` are the symlinks, each to its stored target. */
function fs(links: Record<string, string>) {
  return {
    lstat: (p: string) => ({ isSymbolicLink: () => p in links }),
    readlink: (p: string) => links[p]!,
  };
}

describe("resolveHostPath", () => {
  it("returns a path with no symlinks on it unchanged, normalized", () => {
    expect(resolveHostPath("/a/./b//c/", fs({}))).toStrictEqual({ real: "/a/b/c", links: [] });
  });

  it("lists each symlink passed through, spelled by the real directory it sits in", () => {
    const resolved = resolveHostPath(
      "/home/runner/bin/tool",
      fs({
        "/home": "/data/home",
        "/data/home/runner/bin": "../opt/bin",
      }),
    );

    expect(resolved).toStrictEqual({
      real: "/data/home/opt/bin/tool",
      links: [
        { at: "/home", target: "/data/home" },
        { at: "/data/home/runner/bin", target: "../opt/bin" },
      ],
    });
  });

  it("keeps a component lstat fails on as written", () => {
    const missing = { lstat: () => undefined, readlink: () => "" };

    expect(resolveHostPath("/a/b", missing)).toStrictEqual({ real: "/a/b", links: [] });
  });

  it("stops at a loop, keeping the symlinks met so far", () => {
    const resolved = resolveHostPath("/a", fs({ "/a": "/b", "/b": "a" }));

    expect(resolved).toMatchObject({ loop: true });
    expect(resolved.links[0]).toStrictEqual({ at: "/a", target: "/b" });
  });
});

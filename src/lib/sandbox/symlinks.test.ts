import { mkdirSync, mkdtempSync, realpathSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { afterAll, beforeAll, describe, it, expect } from "vitest";

import { realSymlinkDeps, resolveHostPath } from "./symlinks.ts";

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

    // The exact count, MAX_SYMLINK_HOPS + 1, is the contract.
    expect(resolved).toStrictEqual({
      loop: true,
      links: Array.from({ length: 41 }, (_, i) =>
        i % 2 === 0 ? { at: "/a", target: "/b" } : { at: "/b", target: "a" },
      ),
    });
  });
});

describe("resolveHostPath on the real filesystem", () => {
  // Real so that macOS's /var -> /private/var link is not among the hops.
  let root: string;

  beforeAll(() => {
    root = realpathSync(mkdtempSync(join(tmpdir(), "buildcage-symlinks-")));
    mkdirSync(join(root, "real/dir"), { recursive: true });
    mkdirSync(join(root, "real/other"));
    writeFileSync(join(root, "real/dir/file"), "");
    symlinkSync(join(root, "real"), join(root, "mid"));
    symlinkSync("real/dir", join(root, "rel"));
    symlinkSync(join(root, "real/dir/file"), join(root, "abs"));
    symlinkSync("../../mid/other", join(root, "real/dir/back"));
    symlinkSync("c2", join(root, "c1"));
    symlinkSync(join(root, "c3"), join(root, "c2"));
    symlinkSync("mid/dir", join(root, "c3"));
    symlinkSync("loop2", join(root, "loop1"));
    symlinkSync("loop1", join(root, "loop2"));
    symlinkSync("missing/x", join(root, "dangling"));
  });

  afterAll(() => rmSync(root, { recursive: true, force: true }));

  it.each([
    ["no symlink", "real/dir/file"],
    ["an intermediate component that is a link", "mid/dir/file"],
    ["a relative target", "rel/file"],
    ["an absolute target", "abs"],
    ["a relative target climbing out of a nested directory", "real/dir/back"],
    [".. after a link, taken from where the link leads", "rel/../other"],
    ["chained links", "c1/file"],
  ])("agrees with realpath(3) through %s", (_shape, path) => {
    // Against realpath(3), not join() or the JS realpathSync(), which fold ".." before following a link.
    const full = `${root}/${path}`;

    expect(resolveHostPath(full, realSymlinkDeps)).toMatchObject({
      real: realpathSync.native(full),
    });
  });

  it("keeps components past the last existing one, through a link", () => {
    expect(resolveHostPath(join(root, "mid/new/child"), realSymlinkDeps)).toMatchObject({
      real: join(root, "real/new/child"),
    });
  });

  it("follows a dangling link to its target", () => {
    expect(resolveHostPath(join(root, "dangling"), realSymlinkDeps)).toStrictEqual({
      real: join(root, "missing/x"),
      links: [{ at: join(root, "dangling"), target: "missing/x" }],
    });
  });

  it("stops at a loop", () => {
    expect(resolveHostPath(join(root, "loop1/x"), realSymlinkDeps)).toMatchObject({
      loop: true,
    });
  });
});

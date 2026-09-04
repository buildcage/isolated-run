import { describe, it, expect, vi, afterEach } from "vitest";
import { readFileSync } from "node:fs";
import { join } from "node:path";

import {
  withScratchDir,
  cleanupScratchDir,
  scratchDirFor,
  parseMountsUnder,
} from "./scratch-dir.ts";
import { writeRunScript } from "./oci-config.ts";

describe("scratchDirFor", () => {
  it("derives a path under /var/tmp/buildcage from the container name (not under a writable exception)", () => {
    const dir = scratchDirFor("buildcage-proxy-abcd1234");
    expect(dir).toBe("/var/tmp/buildcage/sandbox-abcd1234");
  });

  it("is deterministic for the same container name (so post.ts can reconstruct it)", () => {
    expect(scratchDirFor("buildcage-proxy-xyz")).toBe(scratchDirFor("buildcage-proxy-xyz"));
  });
});

describe("parseMountsUnder", () => {
  const mountinfo = [
    "1 0 0:1 / / rw,relatime shared:1 - ext4 /dev/root rw",
    "2 1 0:2 / /tmp/buildcage-sandbox-abc rw,relatime shared:2 - tmpfs tmpfs rw",
    "3 2 0:3 / /tmp/buildcage-sandbox-abc/rootfs rw,relatime shared:3 - ext4 /dev/root rw",
    "4 1 0:4 / /tmp/other-dir rw,relatime shared:4 - tmpfs tmpfs rw",
  ].join("\n");

  it("finds only mount points nested under the given directory", () => {
    const result = parseMountsUnder(mountinfo, "/tmp/buildcage-sandbox-abc");
    expect(result.sort()).toStrictEqual(
      ["/tmp/buildcage-sandbox-abc", "/tmp/buildcage-sandbox-abc/rootfs"].sort(),
    );
  });

  it("orders deepest paths first, so children are unmounted before their parents", () => {
    const result = parseMountsUnder(mountinfo, "/tmp/buildcage-sandbox-abc");
    expect(result).toStrictEqual([
      "/tmp/buildcage-sandbox-abc/rootfs",
      "/tmp/buildcage-sandbox-abc",
    ]);
  });

  it("does not match a sibling directory with a similar prefix", () => {
    const result = parseMountsUnder(mountinfo, "/tmp/buildcage-sandbox-ab");
    expect(result).toStrictEqual([]);
  });
});

describe("withScratchDir", () => {
  afterEach(() => {
    vi.restoreAllMocks();
  });

  it("removes the directory after the callback returns", () => {
    let capturedDir: string;
    withScratchDir((dir) => {
      capturedDir = dir;
      writeRunScript("echo hi", dir);
    });
    expect(() => readFileSync(join(capturedDir, "run-script.sh"))).toThrow();
  });

  it("removes the directory even if the callback throws", () => {
    let capturedDir: string;
    expect(() => {
      withScratchDir((dir) => {
        capturedDir = dir;
        throw new Error("boom");
      });
    }).toThrow();
    expect(() => readFileSync(join(capturedDir, "run-script.sh"))).toThrow();
  });

  it("logs a discard line for ephemeralRoots on the way out, once", () => {
    const log = vi.spyOn(console, "log").mockImplementation(() => {});
    withScratchDir(() => {}, undefined, ["/home/runner", "/tmp"]);
    const discardCalls = log.mock.calls.filter((args) =>
      String(args[0]).startsWith("Discarded ephemeral writes under"),
    );
    expect(discardCalls).toStrictEqual([["Discarded ephemeral writes under /home/runner, /tmp"]]);
  });

  it("logs nothing for a plain persistent-mode run (no ephemeralRoots)", () => {
    const log = vi.spyOn(console, "log").mockImplementation(() => {});
    withScratchDir(() => {});
    expect(log.mock.calls.some((args) => String(args[0]).startsWith("Discarded"))).toBe(false);
  });
});

describe("cleanupScratchDir", () => {
  it("does not log when ephemeralRoots is an empty array", () => {
    const log = vi.spyOn(console, "log").mockImplementation(() => {});
    withScratchDir(() => {}, undefined, []);
    expect(log.mock.calls.some((args) => String(args[0]).startsWith("Discarded"))).toBe(false);
    log.mockRestore();
  });

  it("no-ops safely on a directory that doesn't exist (post.ts's own usage pattern)", () => {
    expect(() => cleanupScratchDir("/var/tmp/buildcage/does-not-exist-xyz")).not.toThrow();
  });
});

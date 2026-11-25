import { describe, it, expect, vi } from "vitest";

import { artifactName, waitUntilListed } from "./artifact-upload.ts";

describe("artifactName", () => {
  it("puts the container's own random suffix after the prefix, so concurrent steps don't collide", () => {
    expect(artifactName("buildcage-traffic", "buildcage-proxy-deadbeef")).toBe(
      "buildcage-traffic-deadbeef",
    );
    expect(artifactName("buildcage-filesystem-audit", "buildcage-proxy-0badcafe")).toBe(
      "buildcage-filesystem-audit-0badcafe",
    );
  });
});

describe("waitUntilListed", () => {
  /** A clock that only moves when the code under test sleeps. */
  function clock() {
    let t = 0;
    const sleeps: number[] = [];
    return {
      sleeps,
      now: () => t,
      sleep: async (ms: number) => {
        sleeps.push(ms);
        t += ms;
      },
    };
  }

  /** Rejects the first `misses` lookups, then resolves. */
  function listedAfter(misses: number) {
    const names: string[] = [];
    const find = async (name: string) => {
      names.push(name);
      if (names.length <= misses) throw new Error(`Artifact not found for name: ${name}`);
      return { artifact: { name } };
    };
    return { find, names };
  }

  it("returns at once when the artifact is already listed", async () => {
    const c = clock();
    const { find, names } = listedAfter(0);
    await expect(waitUntilListed("a", find, c)).resolves.toBe(true);
    expect(names).toEqual(["a"]);
    expect(c.sleeps).toEqual([]);
  });

  it("looks again every interval until the artifact is listed", async () => {
    const c = clock();
    const { find, names } = listedAfter(3);
    await expect(waitUntilListed("a", find, { ...c, intervalMs: 500 })).resolves.toBe(true);
    expect(names).toHaveLength(4);
    expect(c.sleeps).toEqual([500, 500, 500]);
  });

  it("gives up once the timeout has passed", async () => {
    const c = clock();
    const { find, names } = listedAfter(Infinity);
    await expect(
      waitUntilListed("a", find, { ...c, timeoutMs: 3_000, intervalMs: 1_000 }),
    ).resolves.toBe(false);
    expect(names).toHaveLength(4);
    expect(c.sleeps).toEqual([1_000, 1_000, 1_000]);
  });

  it("waits 30 seconds at one-second intervals by default", async () => {
    const c = clock();
    const { find, names } = listedAfter(Infinity);
    await expect(waitUntilListed("a", find, { now: c.now, sleep: c.sleep })).resolves.toBe(false);
    expect(names).toHaveLength(31);
    expect(new Set(c.sleeps)).toEqual(new Set([1_000]));
  });

  it("sleeps for real when given no sleep", async () => {
    vi.useFakeTimers();
    try {
      const { find } = listedAfter(1);
      const done = waitUntilListed("a", find, { intervalMs: 10 });
      await vi.advanceTimersByTimeAsync(10);
      await expect(done).resolves.toBe(true);
    } finally {
      vi.useRealTimers();
    }
  });
});

import { existsSync, mkdirSync, mkdtempSync, readdirSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { afterEach, beforeEach, describe, expect, it } from "vitest";

import { postPinningPath, savePinningForPost, takePinningForPost } from "./post-pinning.ts";
import { STEP_OWNER_ENV } from "./test/runner-host.ts";

const ENV = { ...STEP_OWNER_ENV, GITHUB_STATE: "/home/runner/work/_temp/state" };

let root: string;
let base: string;

beforeEach(() => {
  root = mkdtempSync(join(tmpdir(), "post-pinning-"));
  base = join(root, "scratch");
});

afterEach(() => {
  rmSync(root, { recursive: true, force: true });
});

describe("postPinningPath", () => {
  it("names one file per step under the scratch base", () => {
    const path = postPinningPath(ENV, base);
    expect(path).toMatch(new RegExp(`^${base}/pinning-[0-9a-f]{16}$`));
    expect(postPinningPath({ ...ENV, GITHUB_ACTION: "other" }, base)).not.toBe(path);
    expect(postPinningPath({ ...ENV, RUNNER_TEMP: "/runner-2/_work/_temp" }, base)).not.toBe(path);
  });

  it("is undefined outside a real step, whose owner can't be told", () => {
    expect(postPinningPath({ GITHUB_RUN_ID: "1" }, base)).toBeUndefined();
  });
});

describe("savePinningForPost and takePinningForPost", () => {
  it("hand the post step the values the main step saved, once", () => {
    savePinningForPost(ENV, { baseDir: "/real/app", writeThrough: "/opt/cache\n./dist" }, base);

    expect(takePinningForPost(ENV, base)).toStrictEqual({
      baseDir: "/real/app",
      writeThrough: "/opt/cache\n./dist",
    });
    expect(takePinningForPost(ENV, base)).toBeUndefined();
    expect(readdirSync(base)).toStrictEqual([]);
  });

  it("save an empty write-through as such, not as nothing saved", () => {
    savePinningForPost(ENV, { writeThrough: "" }, base);

    expect(takePinningForPost(ENV, base)).toStrictEqual({ writeThrough: "" });
  });

  it("save nothing when the runner set no state file", () => {
    const { GITHUB_STATE: _, ...env } = ENV;
    savePinningForPost(env, { baseDir: "/real/app" }, base);

    expect(existsSync(base)).toBe(false);
  });

  it("save nothing outside a real step", () => {
    savePinningForPost({ GITHUB_STATE: ENV.GITHUB_STATE }, { baseDir: "/real/app" }, base);

    expect(existsSync(base)).toBe(false);
  });

  it("take nothing outside a real step", () => {
    expect(takePinningForPost({}, base)).toBeUndefined();
  });

  it("let an error other than a missing file through", () => {
    mkdirSync(postPinningPath(ENV, base)!, { recursive: true });

    expect(() => takePinningForPost(ENV, base)).toThrow();
  });

  it("let a file that does not parse through, and remove it", () => {
    mkdirSync(base);
    writeFileSync(postPinningPath(ENV, base)!, "not json");

    expect(() => takePinningForPost(ENV, base)).toThrow();
    expect(readdirSync(base)).toStrictEqual([]);
  });
});

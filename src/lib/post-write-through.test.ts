import { existsSync, mkdirSync, mkdtempSync, readdirSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { afterEach, beforeEach, describe, expect, it } from "vitest";

import {
  postWriteThroughPath,
  saveWriteThroughForPost,
  takeWriteThroughForPost,
} from "./post-write-through.ts";

/** A real Actions step's environment, which ownerToken joins into a token. */
const ENV = {
  GITHUB_RUN_ID: "1",
  GITHUB_RUN_ATTEMPT: "1",
  GITHUB_JOB: "build",
  GITHUB_ACTION: "buildcage",
  RUNNER_NAME: "runner-1",
  GITHUB_STATE: "/home/runner/work/_temp/state",
};

let root: string;
let base: string;

beforeEach(() => {
  root = mkdtempSync(join(tmpdir(), "post-write-through-"));
  base = join(root, "scratch");
});

afterEach(() => {
  rmSync(root, { recursive: true, force: true });
});

describe("postWriteThroughPath", () => {
  it("names one file per step under the scratch base", () => {
    const path = postWriteThroughPath(ENV, base);
    expect(path).toMatch(new RegExp(`^${base}/write-through-[0-9a-f]{16}$`));
    expect(postWriteThroughPath({ ...ENV, GITHUB_ACTION: "other" }, base)).not.toBe(path);
    expect(postWriteThroughPath({ ...ENV, RUNNER_NAME: "runner-2" }, base)).not.toBe(path);
  });

  it("is undefined outside a real step, whose owner can't be told", () => {
    expect(postWriteThroughPath({ GITHUB_RUN_ID: "1" }, base)).toBeUndefined();
  });
});

describe("saveWriteThroughForPost and takeWriteThroughForPost", () => {
  it("hand the post step the value the main step saved, once", () => {
    saveWriteThroughForPost(ENV, "/opt/cache\n./dist", base);

    expect(takeWriteThroughForPost(ENV, base)).toBe("/opt/cache\n./dist");
    expect(takeWriteThroughForPost(ENV, base)).toBeUndefined();
    expect(readdirSync(base)).toStrictEqual([]);
  });

  it("save an empty write_through as such, not as nothing saved", () => {
    saveWriteThroughForPost(ENV, "", base);

    expect(takeWriteThroughForPost(ENV, base)).toBe("");
  });

  it("save nothing when the runner set no state file", () => {
    const { GITHUB_STATE: _, ...env } = ENV;
    saveWriteThroughForPost(env, "/opt/cache", base);

    expect(existsSync(base)).toBe(false);
  });

  it("save nothing outside a real step", () => {
    saveWriteThroughForPost({ GITHUB_STATE: ENV.GITHUB_STATE }, "/opt/cache", base);

    expect(existsSync(base)).toBe(false);
  });

  it("take nothing outside a real step", () => {
    expect(takeWriteThroughForPost({}, base)).toBeUndefined();
  });

  it("let an error other than a missing file through", () => {
    mkdirSync(postWriteThroughPath(ENV, base)!, { recursive: true });

    expect(() => takeWriteThroughForPost(ENV, base)).toThrow();
  });
});

import { describe, it, expect } from "vitest";

import { filesystemAuditPaths, readPid } from "./filesystem-audit-paths.ts";

const CONTAINER = "buildcage-proxy-abcd1234";

describe("filesystemAuditPaths", () => {
  it("names the files by the container's own suffix, under the scratch base", () => {
    expect(filesystemAuditPaths(CONTAINER, "/var/tmp/buildcage-0")).toStrictEqual({
      outPath: "/var/tmp/buildcage-0/filesystem-audit-abcd1234.jsonl",
      pidFilePath: "/var/tmp/buildcage-0/filesystem-audit-abcd1234.pid",
      stepPath: "/var/tmp/buildcage-0/filesystem-audit-abcd1234.step.jsonl",
      rulesPath: "/var/tmp/buildcage-0/filesystem-audit-expected-rules-abcd1234.yml",
    });
  });
});

describe("readPid", () => {
  it("reads the pidfile's number, and NaN for anything else", () => {
    expect(readPid(() => "1234\n", "/p")).toBe(1234);
    expect(readPid(() => "junk", "/p")).toBeNaN();
  });
});

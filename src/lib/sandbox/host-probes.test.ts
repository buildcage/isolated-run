import { describe, it, expect } from "vitest";

import {
  parseCgroupV2Path,
  parseNofileLimit,
  resolveSetprivPath,
  shmSizeFromStatfs,
  SETPRIV_CANDIDATE_PATHS,
  TMPFS_MAGIC,
} from "./host-probes.ts";

describe("resolveSetprivPath", () => {
  it("returns the candidate that exists", () => {
    expect(resolveSetprivPath((p) => p === "/usr/bin/setpriv")).toBe("/usr/bin/setpriv");
  });

  it("takes the first candidate in the documented order", () => {
    expect(resolveSetprivPath((p) => p === "/bin/setpriv" || p === "/sbin/setpriv")).toBe(
      "/bin/setpriv",
    );
  });

  it("falls back to a bare PATH lookup when no candidate exists", () => {
    expect(resolveSetprivPath(() => false)).toBe("setpriv");
  });

  it("looks only at the documented candidates", () => {
    const asked: string[] = [];
    resolveSetprivPath((p) => {
      asked.push(p);
      return false;
    });
    expect(asked).toStrictEqual(SETPRIV_CANDIDATE_PATHS);
  });
});

describe("shmSizeFromStatfs", () => {
  it("multiplies the block size by the block count", () => {
    expect(shmSizeFromStatfs({ type: TMPFS_MAGIC, bsize: 4096, blocks: 1024 })).toBe(4096 * 1024);
  });

  it("returns undefined for a filesystem that is not tmpfs", () => {
    expect(shmSizeFromStatfs({ type: 0xef53, bsize: 4096, blocks: 1e9 })).toBeUndefined();
  });

  it("returns undefined when the reported size is not a usable number", () => {
    expect(shmSizeFromStatfs({ type: TMPFS_MAGIC, bsize: 4096, blocks: 0 })).toBeUndefined();
    expect(
      shmSizeFromStatfs({ type: TMPFS_MAGIC, bsize: Number.NaN, blocks: 1024 }),
    ).toBeUndefined();
  });
});

describe("parseNofileLimit", () => {
  const header = "Limit                     Soft Limit           Hard Limit           Units";

  it("reads both columns", () => {
    const limits = [
      header,
      "Max open files            1024                 65536                files",
    ].join("\n");
    expect(parseNofileLimit(limits)).toStrictEqual({ soft: 1024, hard: 65536 });
  });

  it("substitutes nr_open for an unlimited column", () => {
    const limits = [
      header,
      "Max open files            1024                 unlimited            files",
    ].join("\n");
    expect(parseNofileLimit(limits, 1073741816)).toStrictEqual({ soft: 1024, hard: 1073741816 });
  });

  it("returns undefined for an unlimited column with no nr_open to stand in", () => {
    const limits = [
      header,
      "Max open files            unlimited            unlimited            files",
    ].join("\n");
    expect(parseNofileLimit(limits)).toBeUndefined();
  });

  it("returns undefined when the file carries no such line", () => {
    expect(
      parseNofileLimit([header, "Max processes  1024  2048  processes"].join("\n")),
    ).toBeUndefined();
  });

  it("returns undefined for an empty dump", () => {
    expect(parseNofileLimit("")).toBeUndefined();
  });
});

describe("parseCgroupV2Path", () => {
  it("reads the path off a cgroup v2 host's single line", () => {
    expect(parseCgroupV2Path("0::/system.slice/actions.runner.service\n")).toBe(
      "/system.slice/actions.runner.service",
    );
  });

  it("reads the root of a cgroup namespace", () => {
    expect(parseCgroupV2Path("0::/\n")).toBe("/");
  });

  it("reads nothing off a hybrid host, which lists its v1 hierarchies too", () => {
    const hybrid =
      "12:pids:/system.slice/a.service\n1:name=systemd:/system.slice/a.service\n0::/system.slice/a.service\n";
    expect(parseCgroupV2Path(hybrid)).toBeUndefined();
  });

  it("reads nothing off a cgroup v1 host", () => {
    expect(parseCgroupV2Path("3:memory:/user.slice\n2:cpu,cpuacct:/user.slice\n")).toBeUndefined();
  });

  it("reads nothing off an empty or malformed dump", () => {
    expect(parseCgroupV2Path("")).toBeUndefined();
    expect(parseCgroupV2Path("0::relative\n")).toBeUndefined();
  });

  it("reads nothing for a cgroup outside this process's cgroup namespace", () => {
    expect(parseCgroupV2Path("0::/../system.slice/actions.runner.service\n")).toBeUndefined();
  });

  it("reads nothing for a cgroup already removed", () => {
    expect(parseCgroupV2Path("0::/system.slice/old.scope (deleted)\n")).toBeUndefined();
  });
});

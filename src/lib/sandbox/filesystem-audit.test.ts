import { describe, it, expect, vi } from "vitest";

import {
  cgroupFsPath,
  extractTracer,
  filesystemAuditPaths,
  startFilesystemAudit,
  type AuditChild,
} from "./filesystem-audit.ts";

const CONTAINER = "buildcage-proxy-abcd1234";
const DEST = "/var/tmp/buildcage-0/sandbox-abcd1234";

describe("filesystemAuditPaths", () => {
  it("names the files by the container's own suffix, under the scratch base", () => {
    expect(filesystemAuditPaths(CONTAINER, "/var/tmp/buildcage-0")).toStrictEqual({
      outPath: "/var/tmp/buildcage-0/filesystem-audit-abcd1234.jsonl",
      pidFilePath: "/var/tmp/buildcage-0/filesystem-audit-abcd1234.pid",
    });
  });
});

describe("cgroupFsPath", () => {
  it("joins the cgroupsPath onto the cgroup root", () => {
    expect(cgroupFsPath("/system.slice/runner.service/buildcage-proxy-abcd1234")).toBe(
      "/sys/fs/cgroup/system.slice/runner.service/buildcage-proxy-abcd1234",
    );
  });
});

describe("extractTracer", () => {
  it("copies the tracer out of the proxy container and makes it executable", () => {
    const exec = vi.fn();
    const chmod = vi.fn();
    const path = extractTracer(CONTAINER, DEST, { exec, chmod });

    expect(path).toBe(`${DEST}/filesystem-audit`);
    expect(exec).toHaveBeenCalledWith("docker", [
      "cp",
      `${CONTAINER}:/opt/buildcage/bin/filesystem-audit`,
      `${DEST}/filesystem-audit`,
    ]);
    expect(chmod).toHaveBeenCalledWith(`${DEST}/filesystem-audit`, 0o755);
  });
});

const START_OPTIONS = {
  tracerPath: `${DEST}/filesystem-audit`,
  cgroupsPath: "/system.slice/runner.service/buildcage-proxy-abcd1234",
  outPath: "/var/tmp/buildcage-0/filesystem-audit-abcd1234.jsonl",
  pidFilePath: "/var/tmp/buildcage-0/filesystem-audit-abcd1234.pid",
  readyPath: `${DEST}/filesystem-audit.ready`,
};

/** A tracer that never exits on its own; resolves only once killed. */
function liveChild(): { child: AuditChild; kill: ReturnType<typeof vi.fn> } {
  const kill = vi.fn();
  let resolveExit: () => void;
  const exited = new Promise<void>((r) => {
    resolveExit = r;
  });
  kill.mockImplementation(() => resolveExit());
  return { child: { exited, kill }, kill };
}

describe("startFilesystemAudit", () => {
  it("spawns the tracer over the cgroup and returns a handle once it is ready", async () => {
    const { child, kill } = liveChild();
    const spawn = vi.fn(() => child);
    const remove = vi.fn();
    const warn = vi.fn();

    const handle = await startFilesystemAudit(START_OPTIONS, warn, {
      spawn,
      exists: () => true,
      remove,
    });

    expect(spawn).toHaveBeenCalledWith("sudo", [
      "-n",
      "--",
      START_OPTIONS.tracerPath,
      "--cgroup",
      "/sys/fs/cgroup/system.slice/runner.service/buildcage-proxy-abcd1234",
      "--out",
      START_OPTIONS.outPath,
      "--pidfile",
      START_OPTIONS.pidFilePath,
      "--ready",
      START_OPTIONS.readyPath,
    ]);
    expect(warn).not.toHaveBeenCalled();

    await handle.stop();
    expect(kill).toHaveBeenCalledWith("SIGTERM");
    expect(remove).toHaveBeenCalledWith(START_OPTIONS.pidFilePath);
  });

  it("waits for the ready file before returning", async () => {
    const { child } = liveChild();
    let ready = false;
    const exists = vi.fn(() => ready);
    const sleep = vi.fn(async () => {
      ready = true;
    });

    await startFilesystemAudit(START_OPTIONS, vi.fn(), { spawn: () => child, exists, sleep });

    expect(exists).toHaveBeenCalledTimes(2);
    expect(sleep).toHaveBeenCalledTimes(1);
  });

  it("warns and records nothing when the tracer never becomes ready", async () => {
    const { child, kill } = liveChild();
    const warn = vi.fn();
    const remove = vi.fn();

    const handle = await startFilesystemAudit(START_OPTIONS, warn, {
      spawn: () => child,
      exists: () => false,
      sleep: async () => {},
      remove,
    });

    expect(warn).toHaveBeenCalledOnce();
    expect(kill).toHaveBeenCalledWith("SIGTERM");
    expect(remove).toHaveBeenCalledWith(START_OPTIONS.pidFilePath);
    expect(remove).toHaveBeenCalledWith(START_OPTIONS.outPath);
    await handle.stop(); // the returned no-op handle does nothing more
    expect(remove).toHaveBeenCalledTimes(2);
  });

  it("stops waiting as soon as the tracer exits on its own", async () => {
    const kill = vi.fn();
    const child: AuditChild = { exited: Promise.resolve(), kill };
    const warn = vi.fn();
    const sleep = vi.fn(async () => {});

    await startFilesystemAudit(START_OPTIONS, warn, {
      spawn: () => child,
      exists: () => false,
      sleep,
      remove: vi.fn(),
    });

    // One yield in the ready loop before the exit is seen, then one in stop's
    // grace race.
    expect(sleep).toHaveBeenCalledTimes(2);
    expect(warn).toHaveBeenCalledOnce();
  });

  it("kills the tracer directly when it outlives the SIGTERM grace", async () => {
    let resolveExit: () => void;
    const exited = new Promise<void>((r) => {
      resolveExit = r;
    });
    const kill = vi.fn(); // SIGTERM to the sudo wrapper does not end a wedged tracer
    const exec = vi.fn(() => {
      resolveExit();
      return "";
    });
    const remove = vi.fn();

    const handle = await startFilesystemAudit(START_OPTIONS, vi.fn(), {
      spawn: () => ({ exited, kill }),
      exists: () => true,
      sleep: async () => {},
      remove,
      exec,
      readFile: () => "999\n",
    });
    await handle.stop();

    expect(kill).toHaveBeenCalledWith("SIGTERM");
    expect(exec).toHaveBeenCalledWith("sudo", ["-n", "kill", "-KILL", "999"]);
    expect(remove).toHaveBeenCalledWith(START_OPTIONS.pidFilePath);
  });

  it("does not signal anything when the pidfile holds no usable pid", async () => {
    let resolveExit: () => void;
    const exited = new Promise<void>((r) => {
      resolveExit = r;
    });
    const exec = vi.fn();

    const handle = await startFilesystemAudit(START_OPTIONS, vi.fn(), {
      spawn: () => ({ exited, kill: vi.fn() }),
      exists: () => true,
      sleep: async () => {},
      remove: vi.fn(),
      exec,
      // The pidfile is junk; the tracer turns out to have already gone.
      readFile: () => {
        queueMicrotask(() => resolveExit());
        return "not-a-pid\n";
      },
    });
    await handle.stop();

    expect(exec).not.toHaveBeenCalled();
  });

  it("swallows a pidfile that cannot be read while escalating", async () => {
    let resolveExit: () => void;
    const exited = new Promise<void>((r) => {
      resolveExit = r;
    });
    const exec = vi.fn();

    const handle = await startFilesystemAudit(START_OPTIONS, vi.fn(), {
      spawn: () => ({ exited, kill: vi.fn() }),
      exists: () => true,
      sleep: async () => {},
      remove: vi.fn(),
      exec,
      readFile: () => {
        queueMicrotask(() => resolveExit());
        throw new Error("ENOENT");
      },
    });
    await handle.stop();

    expect(exec).not.toHaveBeenCalled();
  });
});

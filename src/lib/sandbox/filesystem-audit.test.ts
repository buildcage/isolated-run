import { describe, it, expect, vi } from "vitest";

import { SandboxError } from "../errors.ts";
import {
  auditUnavailable,
  cgroupFsPath,
  checkFilesystemAuditHost,
  exitReason,
  extractTracer,
  filesystemAuditPaths,
  hostCannotAudit,
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
      stepPath: "/var/tmp/buildcage-0/filesystem-audit-abcd1234.step.jsonl",
    });
  });
});

const REQUIREMENTS =
  "It needs a cgroup v2 host running Linux 6.1 or newer (6.4 on arm64) with kernel BTF and " +
  "tracefs mounted: https://github.com/buildcage/isolated-run/blob/main/docs/filesystem-audit.md#troubleshooting";

describe("auditUnavailable", () => {
  it("says why and that the command did not run", () => {
    expect(auditUnavailable("docker cp failed")).toStrictEqual(
      new SandboxError(
        "filesystem_audit could not start (docker cp failed); the command was not run.",
        "FILESYSTEM_AUDIT_UNAVAILABLE",
      ),
    );
  });
});

describe("hostCannotAudit", () => {
  it("adds what the tracer needs of the host", () => {
    expect(hostCannotAudit("the tracer exited")).toStrictEqual(
      new SandboxError(
        `filesystem_audit could not start (the tracer exited); the command was not run. ${REQUIREMENTS}`,
        "FILESYSTEM_AUDIT_UNAVAILABLE",
      ),
    );
  });
});

describe("checkFilesystemAuditHost", () => {
  const host = (cgroup: string | undefined, btf: boolean) => ({
    cgroupPath: () => cgroup,
    kernelBtf: () => btf,
  });

  it("passes on a cgroup v2 host with kernel BTF", () => {
    expect(() =>
      checkFilesystemAuditHost(host("/system.slice/runner.service", true)),
    ).not.toThrow();
  });

  it("fails the step on a host without cgroup v2", () => {
    expect(() => checkFilesystemAuditHost(host(undefined, true))).toThrow(
      hostCannotAudit("the runner is not on cgroup v2"),
    );
  });

  it("fails the step on a kernel without BTF", () => {
    expect(() => checkFilesystemAuditHost(host("/system.slice/runner.service", false))).toThrow(
      hostCannotAudit("the kernel exposes no BTF"),
    );
  });
});

describe("cgroupFsPath", () => {
  it("joins the cgroupsPath onto the cgroup root", () => {
    expect(cgroupFsPath("/system.slice/runner.service/buildcage-proxy-abcd1234")).toBe(
      "/sys/fs/cgroup/system.slice/runner.service/buildcage-proxy-abcd1234",
    );
  });
});

describe("exitReason", () => {
  it("prefers the tracer's own fatal line, joined across chunks", () => {
    const reason = exitReason();
    reason.push("filesystem-audit: cgroup /sys/fs/cgroup/x id=1\nfilesystem-audit: fat");
    reason.push("al: attach on_unlinkat_enter: no tracefs\nfilesystem-audit: total=0\n");

    expect(reason.value()).toBe("attach on_unlinkat_enter: no tracefs");
  });

  it("falls back to the last line written, then to an unterminated one", () => {
    const reason = exitReason();
    expect(reason.value()).toBe("");
    reason.push("sudo: a pass");
    expect(reason.value()).toBe("sudo: a pass");
    reason.push("word is required\n\n");
    expect(reason.value()).toBe("sudo: a password is required");
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
  watchPid: 4242,
};

/** A tracer that never exits on its own; resolves only once killed. */
function liveChild(): { child: AuditChild; kill: ReturnType<typeof vi.fn> } {
  const kill = vi.fn();
  let resolveExit: () => void;
  const exited = new Promise<void>((r) => {
    resolveExit = r;
  });
  kill.mockImplementation(() => resolveExit());
  return { child: { exited, kill, reason: () => "" }, kill };
}

describe("startFilesystemAudit", () => {
  it("spawns the tracer over the cgroup and returns a handle once it is ready", async () => {
    const { child, kill } = liveChild();
    const spawn = vi.fn(() => child);
    const remove = vi.fn();

    const handle = await startFilesystemAudit(START_OPTIONS, {
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
      "--watch-pid",
      "4242",
    ]);

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

    await startFilesystemAudit(START_OPTIONS, { spawn: () => child, exists, sleep });

    expect(exists).toHaveBeenCalledTimes(2);
    expect(sleep).toHaveBeenCalledTimes(1);
  });

  it("fails the step when the tracer never becomes ready", async () => {
    const { child, kill } = liveChild();
    const remove = vi.fn();

    const start = startFilesystemAudit(START_OPTIONS, {
      spawn: () => child,
      exists: () => false,
      sleep: async () => {},
      remove,
    });

    await expect(start).rejects.toThrow(auditUnavailable("the tracer did not attach in time"));
    expect(kill).toHaveBeenCalledWith("SIGTERM");
    expect(remove).toHaveBeenCalledWith(START_OPTIONS.pidFilePath);
    expect(remove).toHaveBeenCalledWith(START_OPTIONS.outPath);
  });

  it("stops waiting and the tracer once the step is cancelled", async () => {
    const { child, kill } = liveChild();
    const remove = vi.fn();
    const cancel = new AbortController();
    const sleep = vi.fn(async () => cancel.abort());

    const start = startFilesystemAudit(
      { ...START_OPTIONS, cancel: cancel.signal },
      { spawn: () => child, exists: () => false, sleep, remove },
    );

    await expect(start).rejects.toThrow(
      new SandboxError("The step was cancelled before the command ran.", "CANCELLED_BEFORE_RUN"),
    );
    expect(kill).toHaveBeenCalledWith("SIGTERM");
    expect(remove).toHaveBeenCalledWith(START_OPTIONS.outPath);
    // One wait before the cancel is seen, then one in stop's grace race.
    expect(sleep).toHaveBeenCalledTimes(2);
  });

  it("names why the tracer failed even if the step was cancelled too", async () => {
    const cancel = new AbortController();
    const child: AuditChild = {
      exited: Promise.resolve(),
      kill: vi.fn(),
      reason: () => "read kernel BTF: no such file",
    };
    // Both are seen in the same poll.
    const sleep = async () => cancel.abort();
    const start = startFilesystemAudit(
      { ...START_OPTIONS, cancel: cancel.signal },
      { spawn: () => child, exists: () => false, sleep, remove: vi.fn() },
    );

    await expect(start).rejects.toThrow(
      "filesystem_audit could not start (read kernel BTF: no such file); the command was not run.",
    );
  });

  it("stops waiting as soon as the tracer exits on its own, and names why", async () => {
    const child: AuditChild = {
      exited: Promise.resolve(),
      kill: vi.fn(),
      reason: () => "attach on_unlinkat_enter: neither debugfs nor tracefs are mounted",
    };
    const sleep = vi.fn(async () => {});

    const start = startFilesystemAudit(START_OPTIONS, {
      spawn: () => child,
      exists: () => false,
      sleep,
      remove: vi.fn(),
    });

    await expect(start).rejects.toThrow(
      hostCannotAudit("attach on_unlinkat_enter: neither debugfs nor tracefs are mounted"),
    );
    // One yield in the ready loop before the exit is seen; stopping a tracer
    // already gone waits for nothing.
    expect(sleep).toHaveBeenCalledTimes(1);
  });

  it("says only that the tracer exited when it wrote nothing", async () => {
    const child: AuditChild = { exited: Promise.resolve(), kill: vi.fn(), reason: () => "" };

    await expect(
      startFilesystemAudit(START_OPTIONS, {
        spawn: () => child,
        exists: () => false,
        sleep: async () => {},
        remove: vi.fn(),
      }),
    ).rejects.toThrow("filesystem_audit could not start (the tracer exited);");
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

    const handle = await startFilesystemAudit(START_OPTIONS, {
      spawn: () => ({ exited, kill, reason: () => "" }),
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

  it("leaves a tracer whose record is complete to exit, and drops its pidfile once it has", async () => {
    let resolveExit: () => void;
    const exited = new Promise<void>((r) => {
      resolveExit = r;
    });
    const exec = vi.fn();
    const remove = vi.fn();
    let tail = '{"kind":"open"}\n';
    // The detach grace never runs out here.
    const sleep = vi.fn((ms: number) => {
      if (ms > 1_000) return new Promise<void>(() => {});
      tail += '{"kind":"end","dropped":0,"untracked":0,"host_missed":0}\n';
      return Promise.resolve();
    });

    const handle = await startFilesystemAudit(START_OPTIONS, {
      spawn: () => ({ exited, kill: vi.fn(), reason: () => "" }),
      exists: () => true,
      sleep,
      remove,
      exec,
      readTail: () => tail,
    });
    await handle.stop();

    expect(sleep.mock.calls).toStrictEqual([[100], [10_000]]);
    expect(remove).not.toHaveBeenCalled();
    resolveExit!();
    await vi.waitFor(() => expect(remove).toHaveBeenCalledWith(START_OPTIONS.pidFilePath));
    expect(exec).not.toHaveBeenCalled();
  });

  it("kills a tracer that does not exit within 10 seconds of finishing its record", async () => {
    let resolveExit: () => void;
    const exited = new Promise<void>((r) => {
      resolveExit = r;
    });
    const exec = vi.fn(() => {
      resolveExit();
      return "";
    });
    const remove = vi.fn(() => {
      throw new Error("EBUSY"); // left to the post step
    });

    const handle = await startFilesystemAudit(START_OPTIONS, {
      spawn: () => ({ exited, kill: vi.fn(), reason: () => "" }),
      exists: () => true,
      sleep: async () => {},
      remove,
      exec,
      readFile: () => "999\n",
      readTail: () => '{"kind":"end","dropped":0,"untracked":0,"host_missed":0}\n',
    });
    await handle.stop();

    await vi.waitFor(() => expect(remove).toHaveBeenCalled());
    expect(exec).toHaveBeenCalledWith("sudo", ["-n", "kill", "-KILL", "999"]);
  });

  it("cuts a long wait short when the step is cancelled during it", async () => {
    let resolveExit: () => void;
    const exited = new Promise<void>((r) => {
      resolveExit = r;
    });
    const cancel = new AbortController();
    let waits = 0;
    const handle = await startFilesystemAudit(
      { ...START_OPTIONS, cancel: cancel.signal },
      {
        spawn: () => ({ exited, kill: vi.fn(), reason: () => "" }),
        exists: () => true,
        sleep: async () => {
          if (++waits === 50) cancel.abort(); // 5 seconds in
        },
        remove: vi.fn(),
        exec: () => {
          resolveExit();
          return "";
        },
        readFile: () => "999\n",
        readTail: () => "",
      },
    );
    await handle.stop();

    expect(waits).toBe(50);
  });

  it("gives a tracer 30 seconds to finish its record, and 2 once the step is cancelled", async () => {
    const stopAfter = async (cancelled: boolean): Promise<number> => {
      const cancel = new AbortController();
      let resolveExit: () => void;
      const exited = new Promise<void>((r) => {
        resolveExit = r;
      });
      const sleep = vi.fn(async () => {});
      const handle = await startFilesystemAudit(
        { ...START_OPTIONS, cancel: cancel.signal },
        {
          spawn: () => ({ exited, kill: vi.fn(), reason: () => "" }),
          exists: () => true,
          sleep,
          remove: vi.fn(),
          exec: () => {
            resolveExit();
            return "";
          },
          readFile: () => "999\n",
          readTail: () => '{"kind":"open"}\n',
        },
      );
      if (cancelled) cancel.abort();
      await handle.stop();
      return sleep.mock.calls.length;
    };

    expect(await stopAfter(false)).toBe(300);
    expect(await stopAfter(true)).toBe(20);
  });

  it("reads a recording that is not there yet as unfinished", async () => {
    const { child } = liveChild();
    const handle = await startFilesystemAudit(START_OPTIONS, {
      spawn: () => child,
      exists: () => true,
      sleep: async () => {},
      remove: vi.fn(),
      readTail: () => {
        throw new Error("ENOENT");
      },
    });
    await expect(handle.stop()).resolves.toBeUndefined();
  });

  it("does not signal anything when the pidfile holds no usable pid", async () => {
    let resolveExit: () => void;
    const exited = new Promise<void>((r) => {
      resolveExit = r;
    });
    const exec = vi.fn();

    const handle = await startFilesystemAudit(START_OPTIONS, {
      spawn: () => ({ exited, kill: vi.fn(), reason: () => "" }),
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

    const handle = await startFilesystemAudit(START_OPTIONS, {
      spawn: () => ({ exited, kill: vi.fn(), reason: () => "" }),
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

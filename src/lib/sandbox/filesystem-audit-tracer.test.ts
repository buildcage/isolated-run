import { describe, it, expect, vi } from "vitest";

import { SandboxError } from "../errors.ts";
import { auditUnavailable, hostCannotAudit } from "./filesystem-audit-host.ts";
import {
  cgroupFsPath,
  followStderr,
  extractTracer,
  haltTracer,
  startFilesystemAudit,
  type AuditChild,
} from "./filesystem-audit-tracer.ts";

const CONTAINER = "buildcage-proxy-abcd1234";
const DEST = "/var/tmp/buildcage-0/sandbox-abcd1234";

/** The pidfile, and /proc/<pid>/comm naming the tracer. */
const tracerFiles = (pidfile: string) => (path: string) =>
  path.endsWith("/comm") ? "filesystem-audi\n" : pidfile;

describe("cgroupFsPath", () => {
  it("joins the cgroupsPath onto the cgroup root", () => {
    expect(cgroupFsPath("/system.slice/runner.service/buildcage-proxy-abcd1234")).toBe(
      "/sys/fs/cgroup/system.slice/runner.service/buildcage-proxy-abcd1234",
    );
  });
});

describe("followStderr", () => {
  it("prefers the tracer's own fatal line, joined across chunks", () => {
    const reason = followStderr();
    reason.push("filesystem-audit: cgroup /sys/fs/cgroup/x id=1\nfilesystem-audit: fat");
    reason.push("al: attach on_sys_exit: permission denied\nfilesystem-audit: total=0\n");

    expect(reason.value()).toBe("attach on_sys_exit: permission denied");
  });

  it("falls back to the last line written, then to an unterminated one", () => {
    const reason = followStderr();
    expect(reason.value()).toBe("");
    reason.push("sudo: a pass");
    expect(reason.value()).toBe("sudo: a pass");
    reason.push("word is required\n\n");
    expect(reason.value()).toBe("sudo: a password is required");
  });

  it("takes no workflow command as the reason", () => {
    const reason = followStderr();
    reason.push(
      "::group::buildcage: starting filesystem audit\nfilesystem-audit: attached\n::endgroup::\n",
    );
    expect(reason.value()).toBe("filesystem-audit: attached");
  });

  it("notes the end of the totals group alone, through a pty's carriage returns", async () => {
    const reason = followStderr();
    let logged = false;
    void reason.totalsLogged.then(() => (logged = true));
    reason.push("::group::buildcage: starting filesystem audit\r\n::endgroup::\r\n");
    await Promise.resolve();
    expect(logged).toBe(false);
    reason.push(
      "::group::buildcage: filesystem audit totals\r\nfilesystem-audit: total=0\r\n::endgroup::\r\n",
    );
    await expect(reason.totalsLogged).resolves.toBeUndefined();
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
  allowedSyscalls: ["read", "write"],
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
      "--allowed-syscalls",
      "read,write",
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
      "filesystem-audit could not start (read kernel BTF: no such file); the command was not run.",
    );
  });

  it("stops waiting as soon as the tracer exits on its own, and names why", async () => {
    const child: AuditChild = {
      exited: Promise.resolve(),
      kill: vi.fn(),
      reason: () => "the kernel is older than Linux 6.1",
    };
    const sleep = vi.fn(async () => {});

    const start = startFilesystemAudit(START_OPTIONS, {
      spawn: () => child,
      exists: () => false,
      sleep,
      remove: vi.fn(),
    });

    await expect(start).rejects.toThrow(hostCannotAudit("the kernel is older than Linux 6.1"));
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
    ).rejects.toThrow("filesystem-audit could not start (the tracer exited);");
  });

  it("kills the tracer directly when it outlives the SIGTERM grace", async () => {
    let resolveExit: () => void;
    const exited = new Promise<void>((r) => {
      resolveExit = r;
    });
    const kill = vi.fn(); // SIGTERM to the sudo wrapper does not end a wedged tracer
    const exec = vi.fn((_command: string, args: string[]) => {
      if (args[2] === "-KILL") resolveExit();
      return "";
    });
    const remove = vi.fn();

    const handle = await startFilesystemAudit(START_OPTIONS, {
      spawn: () => ({ exited, kill, reason: () => "" }),
      exists: () => true,
      sleep: async () => {},
      remove,
      exec,
      readFile: tracerFiles("999\n"),
    });
    await handle.stop();

    expect(kill).toHaveBeenCalledWith("SIGTERM");
    expect(exec.mock.calls).toStrictEqual([
      ["sudo", ["-n", "kill", "-TERM", "999"]],
      ["sudo", ["-n", "kill", "-KILL", "999"]],
    ]);
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

    expect(sleep.mock.calls).toStrictEqual([[100], [10_000, true]]);
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
    const exec = vi.fn((_command: string, args: string[]) => {
      if (args[2] === "-KILL") resolveExit();
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
      readFile: tracerFiles("999\n"),
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
        exec: (_command: string, args: string[]) => {
          if (args[2] === "-KILL") resolveExit();
          return "";
        },
        readFile: tracerFiles("999\n"),
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
          exec: (_command: string, args: string[]) => {
            if (args[2] === "-KILL") resolveExit();
            return "";
          },
          readFile: tracerFiles("999\n"),
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

describe("haltTracer", () => {
  const OPTIONS = { outPath: START_OPTIONS.outPath, pidFilePath: START_OPTIONS.pidFilePath };
  const END = '{"kind":"end"}\n';

  /** A tracer that exits only when told to; SIGTERM alone does not stop it. */
  function stubborn() {
    let resolveExit!: () => void;
    let exited = false;
    const done = new Promise<void>((r) => {
      resolveExit = () => {
        exited = true;
        r();
      };
    });
    const kill = vi.fn();
    return {
      tracer: { child: { exited: done, kill, reason: () => "" }, exited: () => exited },
      kill,
      exit: resolveExit,
    };
  }

  /** The seams, with a sudo kill -KILL that ends `s`. */
  function deps(s: ReturnType<typeof stubborn>, tail: () => string, pidfile = "777\n") {
    return {
      sleep: vi.fn(async (_ms: number, _detached?: boolean) => {}),
      remove: vi.fn(),
      exec: vi.fn((_command: string, args: string[]) => {
        if (args[2] === "-KILL") s.exit();
        return "";
      }),
      readFile: vi.fn(tracerFiles(pidfile)),
      readTail: vi.fn(tail),
    };
  }

  it("returns once the record is whole, and removes the pidfile when the tracer exits", async () => {
    const s = stubborn();
    const d = deps(s, () => END);
    let parked!: () => void;
    d.sleep.mockImplementation((_ms: number, detached?: boolean) =>
      detached ? new Promise<void>((r) => (parked = r)) : Promise.resolve(),
    );
    await haltTracer(s.tracer, true, OPTIONS, d);
    expect(s.kill).toHaveBeenCalledWith("SIGTERM");
    expect(d.remove).not.toHaveBeenCalled();
    s.exit();
    await vi.waitFor(() => expect(d.remove).toHaveBeenCalledWith(OPTIONS.pidFilePath));
    parked();
    expect(d.exec.mock.calls).toStrictEqual([["sudo", ["-n", "kill", "-TERM", "777"]]]);
  });

  it("waits for the totals group to be logged once the record is whole", async () => {
    const s = stubborn();
    const d = deps(s, () => END);
    let logTotals!: () => void;
    const tracer = {
      ...s.tracer,
      child: { ...s.tracer.child, totalsLogged: new Promise<void>((r) => (logTotals = r)) },
    };
    d.sleep.mockImplementation((_ms: number, detached?: boolean) =>
      detached ? new Promise<void>(() => {}) : Promise.resolve(),
    );
    let returned = false;
    const halted = haltTracer(tracer, true, OPTIONS, d).then(() => (returned = true));
    await new Promise((r) => setTimeout(r, 0));
    expect(returned).toBe(false);
    expect(d.sleep).toHaveBeenCalledWith(2_000, true);
    logTotals();
    await halted;
    s.exit();
  });

  it("sends SIGTERM to the tracer itself, which an older sudo would not pass on", async () => {
    const s = stubborn();
    const d = deps(s, () => "");
    d.exec.mockImplementation((_command: string, args: string[]) => {
      if (args[2] === "-TERM") s.exit();
      return "";
    });
    await haltTracer(s.tracer, true, OPTIONS, d);
    expect(d.exec.mock.calls).toStrictEqual([["sudo", ["-n", "kill", "-TERM", "777"]]]);
    expect(d.sleep).not.toHaveBeenCalled();
    expect(d.remove).toHaveBeenCalledWith(OPTIONS.pidFilePath);
  });

  it("kills a tracer whose record is whole but that does not exit after the detach grace", async () => {
    const s = stubborn();
    const d = deps(s, () => END);
    await haltTracer(s.tracer, true, OPTIONS, d);
    await vi.waitFor(() => expect(d.remove).toHaveBeenCalledWith(OPTIONS.pidFilePath));
    expect(d.exec).toHaveBeenCalledWith("sudo", ["-n", "kill", "-KILL", "777"]);
  });

  it("waits for a tracer still writing, and kills it once the grace runs out", async () => {
    const s = stubborn();
    const d = deps(s, () => "");
    await haltTracer(s.tracer, true, OPTIONS, d);
    expect(d.sleep).toHaveBeenCalledTimes(300);
    expect(d.exec).toHaveBeenCalledWith("sudo", ["-n", "kill", "-KILL", "777"]);
    expect(d.remove).toHaveBeenCalledWith(OPTIONS.pidFilePath);
  });

  it("gives a tracer that never attached the short grace, and kills none for a junk pidfile", async () => {
    const s = stubborn();
    const d = deps(s, () => END, "junk");
    const halted = haltTracer(s.tracer, false, OPTIONS, d);
    await vi.waitFor(() => expect(d.sleep).toHaveBeenCalledTimes(20));
    expect(d.exec).not.toHaveBeenCalled();
    s.exit();
    await halted;
    expect(d.remove).toHaveBeenCalledWith(OPTIONS.pidFilePath);
  });

  it("sends no signal through sudo to a tracer that died during the step", async () => {
    const s = stubborn();
    s.exit();
    const d = deps(s, () => "");
    await haltTracer(s.tracer, true, OPTIONS, d);
    expect(d.exec).not.toHaveBeenCalled();
    expect(d.remove).toHaveBeenCalledWith(OPTIONS.pidFilePath);
  });

  it("sends no signal to a pid that is no longer the tracer", async () => {
    const s = stubborn();
    const d = deps(s, () => "");
    d.readFile.mockImplementation((path: string) => (path.endsWith("/comm") ? "bash\n" : "777\n"));
    const halted = haltTracer(s.tracer, true, OPTIONS, d);
    await vi.waitFor(() => expect(d.sleep).toHaveBeenCalledTimes(300));
    s.exit();
    await halted;
    expect(d.exec).not.toHaveBeenCalled();
  });

  it("signals a pid whose comm cannot be read, as on a /proc mounted with hidepid", async () => {
    const s = stubborn();
    const d = deps(s, () => "");
    d.readFile.mockImplementation((path: string) => {
      if (path.endsWith("/comm")) throw new Error("ENOENT");
      return "777\n";
    });
    await haltTracer(s.tracer, true, OPTIONS, d);
    expect(d.exec).toHaveBeenCalledWith("sudo", ["-n", "kill", "-KILL", "777"]);
  });

  it("shortens the wait once the step is cancelled", async () => {
    const s = stubborn();
    const d = deps(s, () => "");
    await haltTracer(s.tracer, true, { ...OPTIONS, cancel: AbortSignal.abort() }, d);
    expect(d.sleep).toHaveBeenCalledTimes(20);
    expect(d.exec).toHaveBeenCalledWith("sudo", ["-n", "kill", "-KILL", "777"]);
  });
});

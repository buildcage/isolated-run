import { afterEach, describe, it, expect, vi } from "vitest";

import { CANCEL_GRACE_MS, runIsolated, type Exit, type RunIsolatedOptions } from "./run.ts";

// run-isolated.sh is the process under `sudo` here, so what this module can be
// held to is the argument list it builds, how it reads the child's exit, and
// what it sends the child on a cancel.
type Call = [string, string[], Buffer];

/** Records what was asked to run, copied and sent, and exits as told to. */
function recorder() {
  const calls: Call[] = [];
  const copies: [string, string][] = [];
  const signals: NodeJS.Signals[] = [];
  let exit!: (how: Exit) => void;
  const exited = new Promise<Exit>((resolve) => {
    exit = resolve;
  });
  return {
    calls,
    copies,
    signals,
    exit,
    deps: {
      spawn: (command: string, args: string[], input: Buffer) => {
        calls.push([command, args, input]);
        return { exited, kill: (signal: NodeJS.Signals) => void signals.push(signal) };
      },
      copyScript: (from: string, to: string) => {
        copies.push([from, to]);
      },
    },
  };
}

function options(overrides: Partial<RunIsolatedOptions> = {}): RunIsolatedOptions {
  return {
    runcPath: "/var/tmp/scratch/runc",
    proxyNetns: "buildcage-proxy-netns",
    bundleDir: "/var/tmp/scratch/bundle",
    containerId: "buildcage-step-abcd1234",
    netnsName: "buildcage-abcd1234",
    rootfsBindDir: "/var/tmp/scratch/rootfs",
    gateway: "10.0.0.1",
    targetIp: "10.0.0.3",
    envBlob: Buffer.from("PATH=/usr/bin\0"),
    ...overrides,
  };
}

/**
 * The flag/value pairs of a sudo invocation, as a lookup. Skips the leading
 * `-n -- <script>`, whose `--` is sudo's own separator.
 */
function flagsOf(calls: Call[]): Record<string, string> {
  const args = calls[0][1].slice(3);
  const flags: Record<string, string> = {};
  for (let i = 0; i < args.length - 1; i += 2) {
    flags[args[i]] = args[i + 1];
  }
  return flags;
}

afterEach(() => {
  vi.useRealTimers();
});

describe("runIsolated", () => {
  it("runs a copy of run-isolated.sh in the bundle dir under non-interactive sudo", async () => {
    const { calls, copies, exit, deps } = recorder();
    exit({ status: 0 });
    await runIsolated(options(), deps);

    const [command, args] = calls[0];
    expect(command).toBe("sudo");
    expect(args.slice(0, 2)).toStrictEqual(["-n", "--"]);
    expect(args[2]).toBe("/var/tmp/scratch/bundle/run-isolated.sh");
    expect(copies).toHaveLength(1);
    expect(copies[0][0]).toMatch(/\/scripts\/run-isolated\.sh$/);
    expect(copies[0][1]).toBe(args[2]);
  });

  it("passes every namespace and address the script needs", async () => {
    const { calls, exit, deps } = recorder();
    exit({ status: 0 });
    await runIsolated(options(), deps);

    expect(flagsOf(calls)).toStrictEqual({
      "--proxy-netns": "buildcage-proxy-netns",
      "--runc": "/var/tmp/scratch/runc",
      "--bundle": "/var/tmp/scratch/bundle",
      "--container-id": "buildcage-step-abcd1234",
      "--netns-name": "buildcage-abcd1234",
      "--rootfs-bind-dir": "/var/tmp/scratch/rootfs",
      "--gateway": "10.0.0.1",
      "--target-ip": "10.0.0.3",
    });
  });

  it("hands the environment over on stdin rather than in argv", async () => {
    const { calls, exit, deps } = recorder();
    exit({ status: 0 });
    const envBlob = Buffer.from("SECRET=value\0");
    await runIsolated(options({ envBlob }), deps);

    const [, args, input] = calls[0];
    expect(input).toBe(envBlob);
    expect(args.join(" ")).not.toContain("SECRET");
  });

  it("returns the isolated command's own exit code rather than throwing", async () => {
    const { exit, deps } = recorder();
    exit({ status: 42 });
    await expect(runIsolated(options(), deps)).resolves.toBe(42);
  });

  it("returns 0 when the isolated command succeeds", async () => {
    const { exit, deps } = recorder();
    exit({ status: 0 });
    await expect(runIsolated(options(), deps)).resolves.toBe(0);
  });

  it("fails rather than report a status when a signal ended the sandbox", async () => {
    const { exit, deps } = recorder();
    exit({ signal: "SIGKILL" });
    await expect(runIsolated(options(), deps)).rejects.toThrow(
      expect.objectContaining({
        code: "SANDBOX_TERMINATED",
        message: expect.stringContaining("SIGKILL"),
      }),
    );
  });

  it("fails rather than report a status when the sandbox never started", async () => {
    const { exit, deps } = recorder();
    exit({ error: new Error("spawn sudo ENOENT") });
    await expect(runIsolated(options(), deps)).rejects.toThrow(
      expect.objectContaining({
        code: "SANDBOX_LAUNCH_FAILED",
        message: expect.stringContaining("spawn sudo ENOENT"),
      }),
    );
  });

  it("stops listening for a cancel once the sandbox has failed", async () => {
    vi.useFakeTimers();
    const { signals, exit, deps } = recorder();
    const cancel = new AbortController();
    exit({ signal: "SIGKILL" });
    await expect(runIsolated(options({ cancel: cancel.signal }), deps)).rejects.toThrow();
    cancel.abort();

    expect(signals).toStrictEqual([]);
  });

  it("sends nothing when the step is not cancelled", async () => {
    const { signals, exit, deps } = recorder();
    const cancel = new AbortController();
    const run = runIsolated(options({ cancel: cancel.signal }), deps);
    exit({ status: 0 });
    await run;
    cancel.abort();

    expect(signals).toStrictEqual([]);
  });

  it("sends SIGTERM on a cancel, and again once the grace period runs out", async () => {
    vi.useFakeTimers();
    const { signals, exit, deps } = recorder();
    const cancel = new AbortController();
    const run = runIsolated(options({ cancel: cancel.signal }), deps);

    cancel.abort();
    expect(signals).toStrictEqual(["SIGTERM"]);
    vi.advanceTimersByTime(CANCEL_GRACE_MS - 1);
    expect(signals).toStrictEqual(["SIGTERM"]);
    vi.advanceTimersByTime(1);
    expect(signals).toStrictEqual(["SIGTERM", "SIGTERM"]);

    exit({ status: 137 });
    await expect(run).resolves.toBe(137);
  });

  it("sends no second signal to a child that exited within the grace period", async () => {
    vi.useFakeTimers();
    const { signals, exit, deps } = recorder();
    const cancel = new AbortController();
    const run = runIsolated(options({ cancel: cancel.signal }), deps);

    cancel.abort();
    exit({ status: 143 });
    await expect(run).resolves.toBe(143);
    vi.advanceTimersByTime(CANCEL_GRACE_MS);

    expect(signals).toStrictEqual(["SIGTERM"]);
  });

  it("stops the sandbox straight away when the step was cancelled before it started", async () => {
    const { signals, exit, deps } = recorder();
    const cancel = new AbortController();
    cancel.abort();
    const run = runIsolated(options({ cancel: cancel.signal }), deps);

    expect(signals).toStrictEqual(["SIGTERM"]);
    exit({ status: 143 });
    await run;
  });
});

import { describe, it, expect } from "vitest";

import { SandboxError } from "./errors.ts";
import { checkPasswordlessSudo, describeSudoFailure } from "./sudo-preflight.ts";

describe("describeSudoFailure", () => {
  const noSlimRunner = { env: {}, exists: () => false };

  it("mirrors the docs' passwordless-sudo phrasing", () => {
    const msg = describeSudoFailure({ status: 1 }, noSlimRunner);
    expect(msg).toMatch(/requires a Linux runner with passwordless sudo/);
  });

  it("includes captured stderr detail when present", () => {
    expect(
      describeSudoFailure({ status: 1, stderr: "sudo: a password is required" }, noSlimRunner),
    ).toMatch(/a password is required/);
  });

  it("handles a thrown value that is not an object at all", () => {
    // There is no stderr to quote on a bare string, so it is dropped rather
    // than pasted into the message.
    const msg = describeSudoFailure("sudo: command not found", noSlimRunner);
    expect(msg).toMatch(/requires a Linux runner with passwordless sudo/);
    expect(msg).not.toContain("sudo: command not found");
  });

  it("adds a detection note when the runner looks like a container-based image", () => {
    const withNote = describeSudoFailure(
      { status: 1 },
      { env: { ImageOS: "Linux" }, exists: () => true },
    );
    const withoutNote = describeSudoFailure({ status: 1 }, noSlimRunner);
    expect(withNote).toMatch(/Detected a container-based GitHub-hosted runner image/);
    expect(withoutNote).not.toMatch(/Detected a container-based GitHub-hosted runner image/);
  });
});

describe("checkPasswordlessSudo", () => {
  /** Records what the probe was asked to run, and answers as sudo would. */
  function recordingExecFile(answer: () => void = () => {}) {
    const calls: [string, string[]][] = [];
    return {
      calls,
      execFile: (command: string, args: string[]) => {
        calls.push([command, args]);
        answer();
      },
    };
  }

  it("probes with a command that changes nothing", () => {
    const { calls, execFile } = recordingExecFile();
    checkPasswordlessSudo({ execFile });

    expect(calls).toStrictEqual([["sudo", ["-n", "true"]]]);
  });

  it("passes silently when sudo answers without a password", () => {
    const { execFile } = recordingExecFile();
    expect(() => checkPasswordlessSudo({ execFile })).not.toThrow();
  });

  // Fails here rather than later, so a runner without passwordless sudo is
  // never misreported as the user's own `run:` command failing.
  it("turns a refusal into PASSWORDLESS_SUDO_REQUIRED, carrying the captured stderr", () => {
    const { execFile } = recordingExecFile(() => {
      throw Object.assign(new Error("Command failed"), {
        status: 1,
        stderr: "sudo: a password is required",
      });
    });

    try {
      checkPasswordlessSudo({ execFile });
      throw new Error("should have thrown");
    } catch (err) {
      expect(err).toBeInstanceOf(SandboxError);
      expect((err as SandboxError).code).toBe("PASSWORDLESS_SUDO_REQUIRED");
      expect((err as Error).message).toMatch(/requires a Linux runner with passwordless sudo/);
      expect((err as Error).message).toContain("a password is required");
    }
  });
});

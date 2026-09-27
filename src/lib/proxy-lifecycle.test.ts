import { describe, it, expect, vi } from "vitest";

import { createAnnotation } from "#core/lib/actions/annotation.ts";
import {
  buildComposeUpArgs,
  buildComposeDownArgs,
  buildComposeLogsArgs,
} from "#core/lib/docker/args.ts";

import { SandboxError } from "./errors.ts";
import { startSandboxProxy, stopSandboxProxy, type ProxyLifecycleDeps } from "./proxy-lifecycle.ts";

const CONTAINER = "buildcage-proxy-deadbeef";

const OPTIONS = {
  composeFile: "/action/docker/compose.action.yaml",
  projectName: "buildcage-deadbeef",
  containerName: CONTAINER,
  pullPolicy: "always",
  composeEnv: { PROXY_CONTAINER_NAME: CONTAINER },
};

/** A container that came up but never passed its healthcheck. */
const UNHEALTHY_STATE = JSON.stringify({
  Status: "running",
  ExitCode: 0,
  Health: { Status: "unhealthy", Log: [{ Output: "haproxy is not listening yet" }] },
});

interface Overrides {
  /** What `docker inspect` answers, or the failure it raises. */
  state?: string | Error;
  /** Raised by `docker inspect` as-is, for a failure that is not an Error. */
  stateThrows?: unknown;
  /** Raised by the `compose up`/`compose down`/`compose logs` call. */
  print?: Error;
  /** Limits `print` to the call whose first argument matches, so `compose up`
   *  can fail while the log that diagnoses it still prints. */
  printFailsOn?: string;
}

/** Records every docker invocation, so one fake covers both seams. */
function fakeDocker(overrides: Overrides = {}): {
  deps: ProxyLifecycleDeps;
  calls: string[][];
} {
  const calls: string[][] = [];
  return {
    calls,
    deps: {
      captureDocker(args) {
        calls.push(args);
        if ("stateThrows" in overrides) throw overrides.stateThrows;
        if (overrides.state instanceof Error) throw overrides.state;
        return overrides.state ?? "";
      },
      printDocker(args) {
        calls.push(args);
        if (!overrides.print) return;
        if (overrides.printFailsOn && !args.includes(overrides.printFailsOn)) return;
        throw overrides.print;
      },
    },
  };
}

const COMPOSE_UP_FAILED = Object.assign(new Error("exit 1"), { status: 1, stderr: "" });

describe("startSandboxProxy", () => {
  it("brings the container up with the resolved pull policy", async () => {
    vi.spyOn(console, "log").mockImplementation(() => {});
    const { deps, calls } = fakeDocker();

    await startSandboxProxy(OPTIONS, deps);

    expect(calls).toStrictEqual([buildComposeUpArgs(OPTIONS)]);
  });

  it("blames Docker itself when there is no container to ask", async () => {
    vi.spyOn(console, "log").mockImplementation(() => {});
    const { deps } = fakeDocker({
      print: COMPOSE_UP_FAILED,
      printFailsOn: "up",
      state: new Error("no container"),
    });

    await expect(startSandboxProxy(OPTIONS, deps)).rejects.toMatchObject({
      constructor: SandboxError,
      code: "DOCKER_UNAVAILABLE",
    });
  });

  it("reports why the container is not ready, and prints its log", async () => {
    const log = vi.spyOn(console, "log").mockImplementation(() => {});
    const { deps, calls } = fakeDocker({
      print: COMPOSE_UP_FAILED,
      printFailsOn: "up",
      state: UNHEALTHY_STATE,
    });

    const error = await startSandboxProxy(OPTIONS, deps).then(
      () => null,
      (e: unknown) => e as SandboxError,
    );

    expect(error?.code).toBe("PROXY_NOT_READY");
    expect(error?.message).toContain("haproxy is not listening yet");
    expect(calls[2]).toStrictEqual(buildComposeLogsArgs({ ...OPTIONS, tail: 100 }));
    // The caller is already inside a group; the log must not open a second one.
    expect(log.mock.calls).toStrictEqual([
      ["::group::buildcage: starting sandbox proxy"],
      ["::endgroup::"],
    ]);
  });

  it("still reports why the container is not ready when its log cannot be read", async () => {
    const log = vi.spyOn(console, "log").mockImplementation(() => {});
    const { deps } = fakeDocker({ print: COMPOSE_UP_FAILED, state: UNHEALTHY_STATE });

    await expect(startSandboxProxy(OPTIONS, deps)).rejects.toMatchObject({
      code: "PROXY_NOT_READY",
    });
    expect(log).toHaveBeenCalledWith("The sandbox proxy container's log could not be read.");
  });

  it("stays quiet about the missing container it expects", async () => {
    const log = vi.spyOn(console, "log").mockImplementation(() => {});
    const { deps } = fakeDocker({
      print: COMPOSE_UP_FAILED,
      printFailsOn: "up",
      state: Object.assign(new Error("exit 1"), {
        stderr: `Error: No such object: ${CONTAINER}\n`,
      }),
    });

    await expect(startSandboxProxy(OPTIONS, deps)).rejects.toThrow();

    expect(log.mock.calls).toStrictEqual([
      ["::group::buildcage: starting sandbox proxy"],
      ["::endgroup::"],
    ]);
  });

  it("says nothing when the state could not be read and there is no stderr to quote", async () => {
    const log = vi.spyOn(console, "log").mockImplementation(() => {});
    const { deps } = fakeDocker({
      print: COMPOSE_UP_FAILED,
      printFailsOn: "up",
      stateThrows: "docker: command not found",
    });

    await expect(startSandboxProxy(OPTIONS, deps)).rejects.toThrow();

    expect(log.mock.calls).toStrictEqual([
      ["::group::buildcage: starting sandbox proxy"],
      ["::endgroup::"],
    ]);
  });

  it("surfaces any other reason the state could not be read", async () => {
    const log = vi.spyOn(console, "log").mockImplementation(() => {});
    const { deps } = fakeDocker({
      print: COMPOSE_UP_FAILED,
      printFailsOn: "up",
      state: Object.assign(new Error("exit 1"), { stderr: "  permission denied\n" }),
    });

    await expect(startSandboxProxy(OPTIONS, deps)).rejects.toThrow();

    expect(log).toHaveBeenCalledWith(
      "buildcage: could not read the sandbox proxy container's state: permission denied",
    );
  });
});

describe("stopSandboxProxy", () => {
  const stopOptions = {
    composeFile: OPTIONS.composeFile,
    projectName: OPTIONS.projectName,
    composeEnv: OPTIONS.composeEnv,
  };

  it("takes the container down", async () => {
    vi.spyOn(console, "log").mockImplementation(() => {});
    const { deps, calls } = fakeDocker();

    await stopSandboxProxy({ ...stopOptions, annotation: createAnnotation(false) }, deps);

    expect(calls).toStrictEqual([buildComposeDownArgs(stopOptions)]);
  });

  it("warns rather than throwing, since the command has already run", async () => {
    const log = vi.spyOn(console, "log").mockImplementation(() => {});
    const { deps } = fakeDocker({ print: Object.assign(new Error("exit 1"), { status: 1 }) });

    await expect(
      stopSandboxProxy({ ...stopOptions, annotation: createAnnotation(true) }, deps),
    ).resolves.toBeUndefined();

    expect(log.mock.calls.map(([line]) => line as string)).toContainEqual(
      expect.stringContaining("::warning::Failed to stop the sandbox proxy container:"),
    );
  });
});

import { describe, it, expect, vi, beforeEach } from "vitest";

import { runSandboxStep, type SandboxStepDeps } from "./sandbox-step.ts";
import { SandboxError } from "./errors.ts";

// What is left to check here is the order they run in, what each one is
// handed, and which of them still run when an earlier step fails.
const annotation = { notice: vi.fn(), warning: vi.fn(), error: vi.fn() };

const mocks = {
  readRunCommand: vi.fn(),
  readEngineInputs: vi.fn(),
  readFilesystemInputs: vi.fn(),
  readRuleInputs: vi.fn(),
  validateFilesystemInputs: vi.fn(),
  checkPasswordlessSudo: vi.fn(),
  checkOverlayfsSupport: vi.fn(),
  createAnnotation: vi.fn(),
  resolveFilesystemPlan: vi.fn(),
  pinHostCommands: vi.fn(),
  readLocalImageOverride: vi.fn(),
  verifyImageDigestOrThrow: vi.fn(),
  checkUrlAndTlsRuleSupport: vi.fn(),
  checkKnownBlockedUrlRuleSupport: vi.fn(),
  checkIpRuleSupport: vi.fn(),
  logRules: vi.fn(),
  withLogGroup: vi.fn(),
  generateContainerName: vi.fn(),
  getContainerNetns: vi.fn(),
  startSandboxProxy: vi.fn(),
  stopSandboxProxy: vi.fn(),
  runSandboxedCommand: vi.fn(),
  reportStepTraffic: vi.fn(),
  removeCreatedDirsIfEmpty: vi.fn(),
  saveState: vi.fn(),
  info: vi.fn(),
  log: vi.fn(),
  notice: vi.fn(),
  warn: vi.fn(),
};

// Every step is replaced, so the cast only says what the shape already is.
const deps = mocks as unknown as SandboxStepDeps;

const DIGEST = "sha256:" + "a".repeat(64);
const CREATED_DIRS = [{ path: "/opt/build-output", uid: 1000, gid: 1000 }];

const ENV = {
  GITHUB_WORKSPACE: "/home/runner/work/repo/repo",
  HOME: "/home/runner",
  GITHUB_STEP_SUMMARY: "/home/runner/work/_temp/summary",
  GITHUB_STATE: "/home/runner/work/_temp/state",
  GITHUB_ACTION_REF: "v1.2.3",
  GITHUB_ACTION_REPOSITORY: "buildcage/isolated-run",
};

beforeEach(() => {
  vi.resetAllMocks();
  mocks.readRunCommand.mockReturnValue("echo hello");
  mocks.readEngineInputs.mockReturnValue({ proxyEngine: "universal" });
  mocks.readFilesystemInputs.mockReturnValue({
    filesystemMode: "persistent",
    writeThroughInput: "",
  });
  mocks.readRuleInputs.mockReturnValue({
    proxyMode: "restrict",
    httpsRules: ["example.com:443"],
    httpRules: [],
    ipRules: [],
    urlRules: [],
    tlsRules: [],
    knownBlockedRules: [],
  });
  mocks.createAnnotation.mockReturnValue(annotation);
  mocks.resolveFilesystemPlan.mockReturnValue({
    overlayRoots: [],
    writeThroughPaths: [],
    createdDirs: CREATED_DIRS,
  });
  mocks.readLocalImageOverride.mockResolvedValue(null);
  mocks.verifyImageDigestOrThrow.mockResolvedValue(DIGEST);
  // The real one runs the callback; a test that cares asserts on logRules.
  mocks.withLogGroup.mockImplementation((_title: string, fn: () => void) => fn());
  mocks.generateContainerName.mockReturnValue("buildcage-proxy-deadbeef");
  mocks.getContainerNetns.mockReturnValue("/var/run/docker/netns/abc123");
  mocks.startSandboxProxy.mockResolvedValue(undefined);
  mocks.stopSandboxProxy.mockResolvedValue(undefined);
  mocks.runSandboxedCommand.mockReturnValue(0);
  mocks.reportStepTraffic.mockResolvedValue(undefined);
});

/** Call order of a step that ran, for comparing two steps against each other. */
function orderOf(mock: { mock: { invocationCallOrder: number[] } }): number {
  const [first] = mock.mock.invocationCallOrder;
  expect(first).toBeDefined();
  return first!;
}

describe("runSandboxStep", () => {
  it("returns the isolated command's own exit code", async () => {
    mocks.runSandboxedCommand.mockReturnValue(42);

    expect(await runSandboxStep(ENV, deps)).toBe(42);
  });

  it("hands the sandboxed command the resolved plan, not the raw input", async () => {
    mocks.readFilesystemInputs.mockReturnValue({
      filesystemMode: "ephemeral",
      writeThroughInput: "./dist",
    });
    mocks.resolveFilesystemPlan.mockReturnValue({
      overlayRoots: ["/home/runner"],
      writeThroughPaths: ["/home/runner/work/repo/repo/dist"],
      createdDirs: [],
    });

    await runSandboxStep(ENV, deps);

    expect(mocks.runSandboxedCommand.mock.calls[0][0]).toMatchObject({
      runInput: "echo hello",
      proxyNetns: "/var/run/docker/netns/abc123",
      containerName: "buildcage-proxy-deadbeef",
      filesystemMode: "ephemeral",
      overlayRoots: ["/home/runner"],
      writeThroughPaths: ["/home/runner/work/repo/repo/dist"],
    });
  });

  it("pins docker and sudo outside what any sandboxed command can write, before the preflights", async () => {
    await runSandboxStep(ENV, deps);

    expect(mocks.pinHostCommands).toHaveBeenCalledWith(
      ["/home/runner/work/repo/repo", "/home/runner", "/tmp"],
      ENV,
    );
    expect(orderOf(mocks.validateFilesystemInputs)).toBeLessThan(orderOf(mocks.pinHostCommands));
    expect(orderOf(mocks.pinHostCommands)).toBeLessThan(orderOf(mocks.checkPasswordlessSudo));
  });

  // An earlier step's writes under $HOME survive this step's ephemeral mode.
  it("pins against persistent mode's paths plus write_through in ephemeral mode too", async () => {
    mocks.readFilesystemInputs.mockReturnValue({
      filesystemMode: "ephemeral",
      writeThroughInput: "/opt/out",
    });

    await runSandboxStep(ENV, deps);

    expect(mocks.pinHostCommands).toHaveBeenCalledWith(
      ["/home/runner/work/repo/repo", "/home/runner", "/tmp", "/opt/out"],
      ENV,
    );
  });

  // A plain input mistake must not cost the caller a sudo/unshare/mount probe
  // first, and the sudo check must come before the plan resolution, which
  // shells out to sudo itself and would otherwise report the vaguer error.
  it("checks the inputs, then the runner, then resolves the plan, then starts the proxy", async () => {
    await runSandboxStep(ENV, deps);

    expect(orderOf(mocks.validateFilesystemInputs)).toBeLessThan(
      orderOf(mocks.checkPasswordlessSudo),
    );
    expect(orderOf(mocks.checkPasswordlessSudo)).toBeLessThan(orderOf(mocks.resolveFilesystemPlan));
    expect(orderOf(mocks.resolveFilesystemPlan)).toBeLessThan(
      orderOf(mocks.verifyImageDigestOrThrow),
    );
    expect(orderOf(mocks.verifyImageDigestOrThrow)).toBeLessThan(orderOf(mocks.startSandboxProxy));
  });

  it("validates the raw write_through lines before anything resolves them", async () => {
    mocks.readFilesystemInputs.mockReturnValue({
      filesystemMode: "ephemeral",
      writeThroughInput: " /opt/cache \n\n/\n",
    });

    await runSandboxStep(ENV, deps);

    expect(mocks.validateFilesystemInputs).toHaveBeenCalledWith("ephemeral", ["/opt/cache", "/"]);
  });

  it("probes overlayfs only in ephemeral mode", async () => {
    await runSandboxStep(ENV, deps);
    expect(mocks.checkOverlayfsSupport).not.toHaveBeenCalled();

    mocks.readFilesystemInputs.mockReturnValue({
      filesystemMode: "ephemeral",
      writeThroughInput: "",
    });
    await runSandboxStep(ENV, deps);
    expect(mocks.checkOverlayfsSupport).toHaveBeenCalledTimes(1);
  });

  it("logs the filesystem plan only in ephemeral mode", async () => {
    await runSandboxStep(ENV, deps);
    expect(mocks.info).not.toHaveBeenCalled();

    mocks.readFilesystemInputs.mockReturnValue({
      filesystemMode: "ephemeral",
      writeThroughInput: "",
    });
    mocks.resolveFilesystemPlan.mockReturnValue({
      overlayRoots: ["/home/runner"],
      writeThroughPaths: ["/opt/cache"],
      createdDirs: [],
    });
    await runSandboxStep(ENV, deps);

    expect(mocks.info.mock.calls.map(([line]) => line)).toStrictEqual([
      "Filesystem mode: ephemeral",
      "Ephemeral (writes discarded at step end): /home/runner",
      "Writable (persisted):                    /opt/cache",
    ]);
  });

  it("pulls the image by verified digest, under the action's own repository", async () => {
    await runSandboxStep(ENV, deps);

    expect(mocks.verifyImageDigestOrThrow).toHaveBeenCalledWith({
      actionRef: "v1.2.3",
      actionRepo: "buildcage/isolated-run",
      proxyEngine: "universal",
    });
    expect(mocks.startSandboxProxy.mock.calls[0][0]).toMatchObject({
      pullPolicy: "always",
      composeFile: expect.stringContaining("compose.action.yaml"),
    });
    expect(mocks.startSandboxProxy.mock.calls[0][0].composeEnv).toMatchObject({
      BUILDCAGE_PROXY_IMAGE_REF: `ghcr.io/buildcage/isolated-run@${DIGEST}`,
    });
  });

  // A local-path `uses: ./` invocation sets neither, and the integration
  // scripts drive this action the same way.
  it("falls back to v1 and this repository when the runner names neither", async () => {
    await runSandboxStep({ ...ENV, GITHUB_ACTION_REF: "", GITHUB_ACTION_REPOSITORY: "" }, deps);

    expect(mocks.verifyImageDigestOrThrow.mock.calls[0][0]).toMatchObject({
      actionRef: "v1",
      actionRepo: "buildcage/isolated-run",
    });
  });

  it("skips provenance verification and takes the compose file from a local override", async () => {
    mocks.readLocalImageOverride.mockResolvedValue({
      imageRef: "local:dev",
      pullPolicy: "never",
      composeFile: "/repo/test/compose.test-inspect.yaml",
    });

    await runSandboxStep(ENV, deps);

    expect(mocks.verifyImageDigestOrThrow).not.toHaveBeenCalled();
    expect(mocks.startSandboxProxy.mock.calls[0][0]).toMatchObject({
      pullPolicy: "never",
      composeFile: "/repo/test/compose.test-inspect.yaml",
    });
  });

  // A renamed input still works, so its migration message is the only warning
  // the run gets; suppressing it with the rest of the annotations would leave
  // a workflow on the old spelling with nothing to go on.
  it("sends a renamed input's notice to the emitter the annotation gate cannot suppress", async () => {
    await runSandboxStep({ ...ENV, GITHUB_STEP_SUMMARY: "" }, deps);

    expect(mocks.readFilesystemInputs.mock.calls[0][0]).toBe(mocks.notice);
    expect(mocks.readFilesystemInputs.mock.calls[0][0]).not.toBe(annotation.notice);
  });

  it("gives the sandbox the emitter the annotation gate cannot suppress", async () => {
    await runSandboxStep({ ...ENV, GITHUB_STEP_SUMMARY: "" }, deps);

    expect(mocks.runSandboxedCommand.mock.calls[0][0].warn).toBe(mocks.warn);
    expect(mocks.runSandboxedCommand.mock.calls[0][0].warn).not.toBe(annotation.warning);
  });

  it("suppresses annotations when this is not a real action run", async () => {
    await runSandboxStep(ENV, deps);
    expect(mocks.createAnnotation).toHaveBeenCalledWith(true);

    await runSandboxStep({ ...ENV, GITHUB_STEP_SUMMARY: "" }, deps);
    expect(mocks.createAnnotation).toHaveBeenLastCalledWith(false);
  });

  it("reports an unsupported rule kind as a warning rather than failing the step", async () => {
    mocks.checkUrlAndTlsRuleSupport.mockImplementation(
      (_args: unknown, warn: (message: string) => void) =>
        warn("url rules need the inspect engine"),
    );

    expect(await runSandboxStep(ENV, deps)).toBe(0);
    expect(annotation.warning).toHaveBeenCalledWith("url rules need the inspect engine");
  });

  it("checks known_blocked_rules URL lines against the engine, host lines excluded", async () => {
    mocks.readRuleInputs.mockReturnValue({
      proxyMode: "restrict",
      httpsRules: [],
      httpRules: [],
      ipRules: [],
      urlRules: [],
      tlsRules: [],
      knownBlockedRules: ["telemetry.example.com:*", "POST https://api.example.com/telemetry"],
    });

    await runSandboxStep(ENV, deps);

    expect(mocks.checkKnownBlockedUrlRuleSupport.mock.calls[0]![0]).toStrictEqual({
      proxyEngine: "universal",
      proxyMode: "restrict",
      knownBlockedUrlRules: ["POST https://api.example.com/telemetry"],
    });
  });

  it("checks allowed_ip_rules against the engine", async () => {
    mocks.readRuleInputs.mockReturnValue({
      proxyMode: "restrict",
      httpsRules: [],
      httpRules: [],
      ipRules: ["10.0.0.0/8:443"],
      urlRules: [],
      tlsRules: [],
      knownBlockedRules: [],
    });

    await runSandboxStep(ENV, deps);

    expect(mocks.checkIpRuleSupport.mock.calls[0]![0]).toStrictEqual({
      proxyEngine: "universal",
      proxyMode: "restrict",
      ipRules: ["10.0.0.0/8:443"],
    });
    expect(mocks.checkIpRuleSupport.mock.calls[0]![1]).toBe(annotation.warning);
  });

  describe("the state post.ts cleans up from", () => {
    it("records the container name, and the overlay roots in ephemeral mode", async () => {
      mocks.readFilesystemInputs.mockReturnValue({
        filesystemMode: "ephemeral",
        writeThroughInput: "",
      });
      mocks.resolveFilesystemPlan.mockReturnValue({
        overlayRoots: ["/home/runner", "/tmp"],
        writeThroughPaths: [],
        createdDirs: [],
      });

      await runSandboxStep(ENV, deps);

      expect(mocks.saveState.mock.calls).toStrictEqual([
        ["container_name", "buildcage-proxy-deadbeef"],
        ["ephemeral_overlay_roots", '["/home/runner","/tmp"]'],
      ]);
    });

    it("records no overlay roots in persistent mode, which has none", async () => {
      await runSandboxStep(ENV, deps);

      expect(mocks.saveState.mock.calls).toStrictEqual([
        ["container_name", "buildcage-proxy-deadbeef"],
      ]);
    });

    it("records nothing when the runner set no state file", async () => {
      await runSandboxStep({ ...ENV, GITHUB_STATE: "" }, deps);

      expect(mocks.saveState).not.toHaveBeenCalled();
      expect(mocks.startSandboxProxy).toHaveBeenCalledTimes(1);
    });

    // Written before the container is started, so a kill during startup still
    // leaves the post step something to tear down.
    it("records the container name before starting it", async () => {
      await runSandboxStep(ENV, deps);

      expect(orderOf(mocks.saveState)).toBeLessThan(orderOf(mocks.startSandboxProxy));
    });
  });

  describe("teardown", () => {
    it("reports and stops the proxy when the command fails", async () => {
      mocks.runSandboxedCommand.mockImplementation(() => {
        throw new Error("runc: exec failed");
      });

      await expect(runSandboxStep(ENV, deps)).rejects.toThrow("runc: exec failed");
      expect(mocks.reportStepTraffic).toHaveBeenCalledTimes(1);
      expect(mocks.stopSandboxProxy).toHaveBeenCalledTimes(1);
      expect(orderOf(mocks.reportStepTraffic)).toBeLessThan(orderOf(mocks.stopSandboxProxy));
    });

    it("stops the proxy that started but never became usable", async () => {
      mocks.getContainerNetns.mockReturnValue(null);

      const error = await runSandboxStep(ENV, deps).catch((e: SandboxError) => e);

      expect(error).toBeInstanceOf(SandboxError);
      expect((error as SandboxError).code).toBe("PROXY_NOT_RUNNING");
      expect(mocks.runSandboxedCommand).not.toHaveBeenCalled();
      expect(mocks.stopSandboxProxy).toHaveBeenCalledTimes(1);
    });

    it("gives back the directories it created for write_through targets", async () => {
      await runSandboxStep(ENV, deps);

      expect(mocks.removeCreatedDirsIfEmpty).toHaveBeenCalledWith(CREATED_DIRS);
    });

    it("gives them back even when the step fails before the proxy starts", async () => {
      mocks.verifyImageDigestOrThrow.mockRejectedValue(new Error("no signature found"));

      await expect(runSandboxStep(ENV, deps)).rejects.toThrow("no signature found");
      expect(mocks.startSandboxProxy).not.toHaveBeenCalled();
      expect(mocks.removeCreatedDirsIfEmpty).toHaveBeenCalledWith(CREATED_DIRS);
    });

    it("creates nothing when docker or sudo cannot be pinned", async () => {
      mocks.pinHostCommands.mockImplementation(() => {
        throw new SandboxError("no docker", "HOST_COMMAND_UNPINNABLE");
      });

      await expect(runSandboxStep(ENV, deps)).rejects.toThrow("no docker");
      expect(mocks.checkPasswordlessSudo).not.toHaveBeenCalled();
      expect(mocks.resolveFilesystemPlan).not.toHaveBeenCalled();
    });

    it("warns rather than failing the step when they cannot be removed", async () => {
      mocks.runSandboxedCommand.mockReturnValue(7);
      mocks.removeCreatedDirsIfEmpty.mockImplementation(() => {
        throw new Error("EACCES: permission denied");
      });

      expect(await runSandboxStep(ENV, deps)).toBe(7);
      expect(annotation.warning.mock.calls[0][0]).toContain("EACCES: permission denied");
    });
  });
});

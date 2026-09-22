import { describe, it, expect, vi, beforeEach } from "vitest";

import {
  assembleBundle,
  runSandboxedCommand,
  type RunSandboxedCommandDeps,
  type RunSandboxedCommandOptions,
} from "./sandboxed-command.ts";
import { SandboxError } from "../errors.ts";
import { WritablePathConflictError } from "./paths.ts";

// Every collaborator is tested in its own file; what is left to check here is
// the order they run in, what runSandboxedCommand hands each one, and which
// SandboxError each failure turns into.
const mocks = {
  withScratchDir: vi.fn(),
  extractRuncBootstrap: vi.fn(),
  extractCaCert: vi.fn(),
  writeCaTrustFiles: vi.fn(),
  writeJvmKeystoreFiles: vi.fn(),
  createOverlayScratchDirs: vi.fn(),
  writeRunScript: vi.fn(),
  writeResolvConf: vi.fn(),
  buildOciConfig: vi.fn(),
  writeOciConfig: vi.fn(),
  buildEnvBlob: vi.fn(),
  resolveSandboxEnv: vi.fn(),
  writeEnvLoader: vi.fn(),
  resolveSandboxGid: vi.fn(),
  listHostMounts: vi.fn(),
  runIsolated: vi.fn(),
  mkdir: vi.fn(),
  info: vi.fn(),
  warn: vi.fn(),
};

// A bag of doubles, not a partially-typed stand-in: every step is replaced, so
// the cast says what the shape already is.
const deps = mocks as unknown as RunSandboxedCommandDeps;

const CONTAINER = "buildcage-proxy-deadbeef";
const SCRATCH = "/var/tmp/buildcage-1001/buildcage-proxy-deadbeef";

const BOOTSTRAP = {
  runcPath: `${SCRATCH}/runc`,
  seccompProfile: { defaultAction: "SCMP_ACT_ERRNO" },
  baseSpec: { mounts: [], linux: { namespaces: [] }, process: {} },
};

function options(overrides: Partial<RunSandboxedCommandOptions> = {}): RunSandboxedCommandOptions {
  return {
    containerName: CONTAINER,
    proxyNetns: "/var/run/docker/netns/abc123",
    runInput: "echo hello",
    writeThroughPaths: [],
    env: { GITHUB_WORKSPACE: "/home/runner/work/repo/repo", HOME: "/home/runner" },
    proxyEngine: "universal",
    filesystemMode: "persistent",
    overlayRoots: [],
    warn: mocks.warn,
    ...overrides,
  };
}

beforeEach(() => {
  vi.resetAllMocks();
  // withScratchDir's own behavior is tested in scratch-dir.test.ts; here it
  // only has to hand the body a directory.
  mocks.withScratchDir.mockImplementation((fn: (dir: string) => unknown) => fn(SCRATCH));
  mocks.extractRuncBootstrap.mockReturnValue(BOOTSTRAP);
  mocks.extractCaCert.mockReturnValue(`${SCRATCH}/ca.crt`);
  mocks.writeCaTrustFiles.mockReturnValue({ bundlePath: `${SCRATCH}/ca-bundle.crt` });
  mocks.writeJvmKeystoreFiles.mockReturnValue([]);
  mocks.createOverlayScratchDirs.mockReturnValue([]);
  mocks.writeResolvConf.mockReturnValue(`${SCRATCH}/resolv.conf`);
  mocks.writeRunScript.mockReturnValue(`${SCRATCH}/exec/run.sh`);
  mocks.writeEnvLoader.mockReturnValue(`${SCRATCH}/exec/env-loader.sh`);
  mocks.listHostMounts.mockReturnValue([]);
  mocks.resolveSandboxGid.mockReturnValue({ gid: 1001, substitutedFrom: undefined });
  mocks.buildOciConfig.mockReturnValue({ process: {} });
  mocks.resolveSandboxEnv.mockReturnValue({ PATH: "/usr/bin" });
  mocks.buildEnvBlob.mockReturnValue(Buffer.from(""));
  mocks.runIsolated.mockReturnValue(0);
});

describe("runSandboxedCommand", () => {
  it("returns the isolated command's own exit code", () => {
    mocks.runIsolated.mockReturnValue(42);

    expect(runSandboxedCommand(options(), deps)).toBe(42);
  });

  it("writes the bundle before running it, into the scratch dir it was given", () => {
    runSandboxedCommand(options(), deps);

    expect(mocks.writeOciConfig).toHaveBeenCalledWith({ process: {} }, SCRATCH);
    expect(mocks.writeOciConfig.mock.invocationCallOrder[0]).toBeLessThan(
      mocks.runIsolated.mock.invocationCallOrder[0],
    );
  });

  it("wires the sandbox to the proxy's fixed addresses", () => {
    runSandboxedCommand(options(), deps);

    expect(mocks.runIsolated.mock.calls[0][0]).toMatchObject({
      gateway: "172.20.0.1",
      dns: "172.20.0.1",
      targetIp: "172.20.0.101",
    });
  });

  // The netns is a different ID namespace from Docker's, but derived from the
  // container name so `ip netns` and `docker ps` stay correlated per step.
  it("names the sandbox netns after the proxy container", () => {
    runSandboxedCommand(options(), deps);

    expect(mocks.runIsolated.mock.calls[0][0]).toMatchObject({
      netnsName: "buildcage-sandbox-deadbeef",
      containerId: CONTAINER,
      rootfsBindDir: `${SCRATCH}/rootfs`,
      runcPath: BOOTSTRAP.runcPath,
    });
    expect(mocks.buildOciConfig.mock.calls[0][1].runtime.netnsPath).toBe(
      "/var/run/netns/buildcage-sandbox-deadbeef",
    );
  });

  it("trusts the proxy's CA under the inspect engine", () => {
    runSandboxedCommand(options({ proxyEngine: "inspect" }), deps);

    expect(mocks.extractCaCert).toHaveBeenCalledWith(CONTAINER, SCRATCH);
    expect(mocks.buildOciConfig.mock.calls[0][1].caTrust).toStrictEqual({
      bundlePath: `${SCRATCH}/ca-bundle.crt`,
      jvmKeystores: [],
    });
  });

  it("extracts no CA under an engine that does not terminate TLS", () => {
    runSandboxedCommand(options(), deps);

    expect(mocks.extractCaCert).not.toHaveBeenCalled();
    expect(mocks.buildOciConfig.mock.calls[0][1].caTrust).toBeUndefined();
  });

  it("builds the overlay only in ephemeral mode, from the already-folded roots", () => {
    const overlayRoots = ["/usr"];
    mocks.createOverlayScratchDirs.mockReturnValue([{ path: "/usr", upper: `${SCRATCH}/upper0` }]);

    runSandboxedCommand(
      options({ filesystemMode: "ephemeral", overlayRoots, writeThroughPaths: ["/opt/cache"] }),
      deps,
    );

    expect(mocks.createOverlayScratchDirs).toHaveBeenCalledWith(SCRATCH, overlayRoots);
    expect(mocks.buildOciConfig.mock.calls[0][1].ephemeral).toStrictEqual({
      overlayRoots: [{ path: "/usr", upper: `${SCRATCH}/upper0` }],
      allowWrite: ["/opt/cache"],
    });
    // The scratch dir has to be told which roots it discarded writes for.
    expect(mocks.withScratchDir.mock.calls[0][1].ephemeralRoots).toStrictEqual(["/usr"]);
  });

  // Both of the sandbox's own warnings come from modules it calls, so the sink
  // has to reach each of them rather than being resolved here.
  it("hands its warning sink to the scratch dir and the environment resolver", () => {
    runSandboxedCommand(options(), deps);

    expect(mocks.withScratchDir.mock.calls[0][1].warn).toBe(mocks.warn);
    expect(mocks.resolveSandboxEnv).toHaveBeenCalledWith(expect.anything(), undefined, mocks.warn);
  });

  it("leaves persistent mode with no overlay at all", () => {
    runSandboxedCommand(options(), deps);

    expect(mocks.createOverlayScratchDirs).not.toHaveBeenCalled();
    expect(mocks.buildOciConfig.mock.calls[0][1].ephemeral).toBeUndefined();
    expect(mocks.withScratchDir.mock.calls[0][1].ephemeralRoots).toBeUndefined();
  });

  // Every one of these is set by a real runner, but this action is also driven
  // directly by this repo's own integration scripts.
  it("leaves the writable paths empty when the runner set none of them", () => {
    runSandboxedCommand(options({ env: {} }), deps);

    expect(mocks.buildOciConfig.mock.calls[0][1].writable).toStrictEqual({
      workdir: "",
      home: "",
      runnerTemp: "",
      writablePaths: [],
    });
  });

  it("says so when the runner's primary group forced a GID substitution", () => {
    mocks.resolveSandboxGid.mockReturnValue({ gid: 65534, substitutedFrom: 118 });

    runSandboxedCommand(options(), deps);

    expect(mocks.info).toHaveBeenCalledWith(expect.stringContaining("(118 -> 65534)"));
    expect(mocks.buildOciConfig.mock.calls[0][1].identity.gid).toBe(65534);
  });

  function failureFrom(
    overrides: Partial<RunSandboxedCommandOptions> = {},
  ): SandboxError | undefined {
    try {
      runSandboxedCommand(options(overrides), deps);
    } catch (e) {
      return e as SandboxError;
    }
  }

  it.each([
    ["extractRuncBootstrap", () => mocks.extractRuncBootstrap, "RUNC_EXTRACT_FAILED", {}],
    ["extractCaCert", () => mocks.extractCaCert, "CA_EXTRACT_FAILED", { proxyEngine: "inspect" }],
    ["buildOciConfig", () => mocks.buildOciConfig, "OCI_CONFIG_BUILD_FAILED", {}],
  ])("turns a %s failure into its own SandboxError", (_name, target, code, overrides) => {
    target().mockImplementation(() => {
      throw new Error("boom");
    });

    const error = failureFrom(overrides as Partial<RunSandboxedCommandOptions>);

    expect(error).toBeInstanceOf(SandboxError);
    expect(error!.code).toBe(code);
    expect(error!.message).toContain("boom");
  });

  it.each([
    ["extractRuncBootstrap", () => mocks.extractRuncBootstrap, {}],
    ["extractCaCert", () => mocks.extractCaCert, { proxyEngine: "inspect" }],
    ["resolveSandboxGid", () => mocks.resolveSandboxGid, {}],
  ])("lets a SandboxError from %s through untouched", (_name, target, overrides) => {
    const thrown = new SandboxError("the primary group is privileged", "UNSAFE_PRIMARY_GID");
    target().mockImplementation(() => {
      throw thrown;
    });

    expect(failureFrom(overrides as Partial<RunSandboxedCommandOptions>)).toBe(thrown);
  });

  // Same misconfiguration, same code whichever check catches it first: the
  // early one in resolveFilesystemPlan, or buildOciConfig's authoritative one.
  it("reports a writable-path conflict as FILESYSTEM_INPUT_CONFLICT", () => {
    mocks.buildOciConfig.mockImplementation(() => {
      throw new WritablePathConflictError('writable path "/proc" is inside "/proc"');
    });

    const error = failureFrom();

    expect(error!.code).toBe("FILESYSTEM_INPUT_CONFLICT");
    expect(error!.message).toBe('writable path "/proc" is inside "/proc"');
  });
});

describe("assembleBundle", () => {
  it("assembles the bundle without running anything", () => {
    const bundle = assembleBundle(SCRATCH, options(), deps);

    expect(bundle).toStrictEqual({
      config: { process: {} },
      runcPath: BOOTSTRAP.runcPath,
      caTrust: undefined,
      netnsName: "buildcage-sandbox-deadbeef",
      rootfsBindDir: `${SCRATCH}/rootfs`,
    });
    expect(mocks.writeOciConfig).not.toHaveBeenCalled();
    expect(mocks.runIsolated).not.toHaveBeenCalled();
  });

  // Why the order matters: see writeBundleFiles.
  it("writes the files the config points at before building it", () => {
    assembleBundle(SCRATCH, options({ filesystemMode: "ephemeral", overlayRoots: ["/tmp"] }), deps);

    for (const step of [
      mocks.createOverlayScratchDirs,
      mocks.writeResolvConf,
      mocks.mkdir,
      mocks.writeRunScript,
      mocks.writeEnvLoader,
    ]) {
      expect(step.mock.invocationCallOrder[0]).toBeLessThan(
        mocks.buildOciConfig.mock.invocationCallOrder[0]!,
      );
    }
  });

  // The caller wires runIsolated up from what comes back here, so the two
  // have to describe the same sandbox.
  it("reports the same netns and rootfs the config was built against", () => {
    const bundle = assembleBundle(SCRATCH, options(), deps);
    const { runtime } = mocks.buildOciConfig.mock.calls[0][1];

    expect(runtime.netnsPath).toBe(`/var/run/netns/${bundle.netnsName}`);
    expect(runtime.rootfsBindDir).toBe(bundle.rootfsBindDir);
  });

  it("points the sandbox's resolver at the proxy", () => {
    assembleBundle(SCRATCH, options(), deps);

    expect(mocks.writeResolvConf).toHaveBeenCalledWith("172.20.0.1", SCRATCH);
  });

  it("hands back the CA trust files the inspect engine needs, for the caller to pass on", () => {
    const bundle = assembleBundle(SCRATCH, options({ proxyEngine: "inspect" }), deps);

    expect(bundle.caTrust).toStrictEqual({
      bundlePath: `${SCRATCH}/ca-bundle.crt`,
      jvmKeystores: [],
    });
  });
});

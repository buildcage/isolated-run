import { describe, it, expect, vi, beforeEach } from "vitest";

import { SandboxError } from "../errors.ts";
import { WritablePathConflictError } from "./paths.ts";
import {
  assembleBundle,
  runSandboxedCommand,
  type RunSandboxedCommandDeps,
  type RunSandboxedCommandOptions,
} from "./sandboxed-command.ts";
import { SANDBOX_SCRATCH_BASE } from "./scratch-dir.ts";

// Every collaborator is tested in its own file; what is left to check here is
// the order they run in, what runSandboxedCommand hands each one, and which
// SandboxError each failure turns into.
const mocks = {
  withScratchDir: vi.fn(),
  extractRuncBootstrap: vi.fn(),
  extractCaCert: vi.fn(),
  writeCaTrustFiles: vi.fn(),
  jvmTools: vi.fn(),
  prepareNssDb: vi.fn(),
  settleNssDbSlot: vi.fn(),
  nssDbDetached: vi.fn(),
  releaseNssDbDirs: vi.fn(),
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
  extractTracer: vi.fn(),
  startFilesystemAudit: vi.fn(),
  mkdir: vi.fn(),
  touch: vi.fn(),
  readFile: vi.fn(),
  realpath: vi.fn(),
  lstat: vi.fn(),
  readlink: vi.fn(),
  info: vi.fn(),
  warn: vi.fn(),
  // The handle startFilesystemAudit resolves to; kept here to assert its stop.
  auditStop: vi.fn(),
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
    failOnCaResidue: true,
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
  mocks.writeCaTrustFiles.mockReturnValue({ ownCaPath: `${SCRATCH}/buildcage-ca.pem`, stores: [] });
  mocks.jvmTools.mockReturnValue({ java: undefined, keytool: undefined });
  mocks.createOverlayScratchDirs.mockReturnValue([]);
  mocks.writeResolvConf.mockReturnValue(`${SCRATCH}/resolv.conf`);
  mocks.writeRunScript.mockReturnValue(`${SCRATCH}/exec/run.sh`);
  mocks.writeEnvLoader.mockReturnValue(`${SCRATCH}/exec/buildcage-init`);
  mocks.listHostMounts.mockReturnValue([]);
  mocks.resolveSandboxGid.mockReturnValue({ gid: 1001, substitutedFrom: undefined });
  mocks.buildOciConfig.mockReturnValue({ process: {} });
  mocks.resolveSandboxEnv.mockReturnValue({ PATH: "/usr/bin" });
  mocks.buildEnvBlob.mockReturnValue(Buffer.from(""));
  mocks.runIsolated.mockResolvedValue(0);
  mocks.extractTracer.mockReturnValue(`${SCRATCH}/filesystem-audit`);
  mocks.auditStop = vi.fn().mockResolvedValue(undefined);
  mocks.startFilesystemAudit.mockResolvedValue({ stop: mocks.auditStop });
  mocks.realpath.mockImplementation((p: string) => p);
  mocks.lstat.mockReturnValue(undefined);
});

describe("runSandboxedCommand", () => {
  it("returns the isolated command's own exit code", async () => {
    mocks.runIsolated.mockResolvedValue(42);

    await expect(runSandboxedCommand(options(), deps)).resolves.toBe(42);
  });

  it("writes the bundle before running it, into the scratch dir it was given", async () => {
    await runSandboxedCommand(options(), deps);

    expect(mocks.writeOciConfig).toHaveBeenCalledWith({ process: {} }, SCRATCH);
    expect(mocks.writeOciConfig.mock.invocationCallOrder[0]).toBeLessThan(
      mocks.runIsolated.mock.invocationCallOrder[0],
    );
  });

  it("wires the sandbox to the proxy's fixed addresses", async () => {
    await runSandboxedCommand(options(), deps);

    expect(mocks.runIsolated.mock.calls[0][0]).toMatchObject({
      gateway: "198.19.255.1",
      targetIp: "198.19.255.101",
    });
  });

  it("hands the step's cancellation to the sandbox", async () => {
    const cancel = new AbortController().signal;
    await runSandboxedCommand(options({ cancel }), deps);

    expect(mocks.runIsolated.mock.calls[0][0].cancel).toBe(cancel);
  });

  describe("filesystem_audit", () => {
    const AUDIT = {
      outPath: "/var/tmp/buildcage-1001/filesystem-audit-deadbeef.jsonl",
      pidFilePath: "/var/tmp/buildcage-1001/filesystem-audit-deadbeef.pid",
    };

    function auditing() {
      mocks.buildOciConfig.mockReturnValue({
        process: {},
        linux: { cgroupsPath: "/system.slice/runner.service/buildcage-proxy-deadbeef" },
      });
      return options({ filesystemAudit: AUDIT });
    }

    it("starts the tracer over the sandbox cgroup and stops it after the command", async () => {
      await runSandboxedCommand(auditing(), deps);

      expect(mocks.extractTracer).toHaveBeenCalledWith(CONTAINER, SCRATCH);
      expect(mocks.startFilesystemAudit.mock.calls[0][0]).toStrictEqual({
        tracerPath: `${SCRATCH}/filesystem-audit`,
        cgroupsPath: "/system.slice/runner.service/buildcage-proxy-deadbeef",
        outPath: AUDIT.outPath,
        pidFilePath: AUDIT.pidFilePath,
        readyPath: `${SCRATCH}/filesystem-audit.ready`,
      });
      expect(mocks.startFilesystemAudit.mock.invocationCallOrder[0]).toBeLessThan(
        mocks.runIsolated.mock.invocationCallOrder[0],
      );
      expect(mocks.auditStop.mock.invocationCallOrder[0]).toBeGreaterThan(
        mocks.runIsolated.mock.invocationCallOrder[0],
      );
    });

    it("stops the tracer even when the command's run fails", async () => {
      mocks.runIsolated.mockRejectedValue(new SandboxError("x", "SANDBOX_TERMINATED"));

      await expect(runSandboxedCommand(auditing(), deps)).rejects.toThrow("x");
      expect(mocks.auditStop).toHaveBeenCalledOnce();
    });

    it("does nothing when filesystem_audit is off", async () => {
      await runSandboxedCommand(options(), deps);

      expect(mocks.extractTracer).not.toHaveBeenCalled();
      expect(mocks.startFilesystemAudit).not.toHaveBeenCalled();
    });

    it("warns and skips the tracer without a cgroup v2 host", async () => {
      // buildOciConfig leaves cgroupsPath undefined on a non-v2 host.
      mocks.buildOciConfig.mockReturnValue({ process: {}, linux: {} });
      await runSandboxedCommand(options({ filesystemAudit: AUDIT }), deps);

      expect(mocks.startFilesystemAudit).not.toHaveBeenCalled();
      expect(mocks.warn).toHaveBeenCalledWith(expect.stringContaining("cgroup v2"));
    });

    it("leaves the exit code untouched when the tracer cannot start", async () => {
      mocks.runIsolated.mockResolvedValue(7);
      mocks.extractTracer.mockImplementation(() => {
        throw new Error("docker cp failed");
      });

      await expect(runSandboxedCommand(auditing(), deps)).resolves.toBe(7);
      expect(mocks.warn).toHaveBeenCalledWith(expect.stringContaining("could not start"));
    });
  });

  // The netns is a different ID namespace from Docker's, but derived from the
  // container name so `ip netns` and `docker ps` stay correlated per step.
  it("names the sandbox netns after the proxy container", async () => {
    await runSandboxedCommand(options(), deps);

    expect(mocks.runIsolated.mock.calls[0][0]).toMatchObject({
      netnsName: "buildcage-sandbox-deadbeef",
      containerId: CONTAINER,
      rootfsBindDir: `${SCRATCH}/rootfs`,
      runcPath: BOOTSTRAP.runcPath,
    });
    expect(mocks.buildOciConfig.mock.calls[0][1].runtime.netnsPath).toBe(
      "/var/run/netns/buildcage-sandbox-deadbeef",
    );
    expect(mocks.buildOciConfig.mock.calls[0][1].runtime.cgroupName).toBe(CONTAINER);
  });

  it("hands the scratch base's aliases from the host mount table to the config", async () => {
    mocks.listHostMounts.mockReturnValue([
      { mountPoint: "/", fsType: "ext4", device: "8:1", root: "/" },
      { mountPoint: "/var/tmp", fsType: "ext4", device: "8:1", root: "/tmp" },
    ]);
    await runSandboxedCommand(options(), deps);

    expect(mocks.buildOciConfig.mock.calls[0][1].runtime.scratchBaseAliases).toStrictEqual([
      SANDBOX_SCRATCH_BASE.replace(/^\/var\/tmp\//, "/tmp/"),
    ]);
  });

  it("trusts the proxy's CA under the inspect engine", async () => {
    await runSandboxedCommand(options({ proxyEngine: "inspect" }), deps);

    expect(mocks.extractCaCert).toHaveBeenCalledWith(CONTAINER, SCRATCH);
    expect(mocks.buildOciConfig.mock.calls[0][1].caTrust).toStrictEqual({
      ownCaPath: `${SCRATCH}/buildcage-ca.pem`,
      stores: [],
      nssDb: undefined,
    });
    expect(mocks.prepareNssDb).toHaveBeenCalledWith(
      CONTAINER,
      SCRATCH,
      "/home/runner",
      { warn: mocks.warn, info: mocks.info },
      { homeUpper: undefined },
    );
  });

  it.each([
    ["HOME is an ephemeral overlay root", {}, `${SCRATCH}/ephemeral/b1cbc5f347543a03/upper`],
    ["HOME is not an overlay root", { overlayRoots: ["/tmp"] }, undefined],
    ["the database is written through", { writeThroughPaths: ["/home/runner/.pki"] }, undefined],
  ])(
    "makes the database's directories in HOME's overlay when %s",
    async (_label, overrides, upper) => {
      await runSandboxedCommand(
        options({
          proxyEngine: "inspect",
          filesystemMode: "ephemeral",
          overlayRoots: ["/home/runner", "/tmp"],
          ...overrides,
        }),
        deps,
      );

      expect(mocks.prepareNssDb.mock.calls[0][4]).toStrictEqual({ homeUpper: upper });
    },
  );

  describe("Chromium's NSS database", () => {
    const NSS_DB = {
      path: `${SCRATCH}/nssdb`,
      destination: "/home/runner/.pki/nssdb",
      slot: {
        caDb: `${SCRATCH}/nssdb-ca`,
        appended: "SLOT",
        hadPkcs11: true,
        snapshot: new Map(),
      },
    };
    const RELEASE = { info: mocks.info, warn: mocks.warn };
    const OWN_CA = `${SCRATCH}/buildcage-ca.pem`;

    beforeEach(() => {
      mocks.prepareNssDb.mockReturnValue(NSS_DB);
      mocks.writeCaTrustFiles.mockReturnValue({ ownCaPath: OWN_CA, stores: [] });
      mocks.readFile.mockReturnValue("THE CA PEM");
      mocks.settleNssDbSlot.mockReturnValue("written");
    });

    it("takes back the directories it made once the command has run", async () => {
      await runSandboxedCommand(options({ proxyEngine: "inspect" }), deps);

      expect(mocks.releaseNssDbDirs).toHaveBeenCalledWith(NSS_DB, RELEASE);
      expect(mocks.releaseNssDbDirs.mock.invocationCallOrder[0]).toBeGreaterThan(
        mocks.runIsolated.mock.invocationCallOrder[0],
      );
    });

    it("warns when the database's directory was removed while the command ran", async () => {
      mocks.nssDbDetached.mockReturnValue("DETACHED");

      await runSandboxedCommand(options({ proxyEngine: "inspect" }), deps);

      expect(mocks.nssDbDetached).toHaveBeenCalledWith(NSS_DB);
      expect(mocks.warn).toHaveBeenCalledWith("DETACHED");
      expect(mocks.nssDbDetached.mock.invocationCallOrder[0]).toBeLessThan(
        mocks.releaseNssDbDirs.mock.invocationCallOrder[0],
      );
    });

    it("does not look for a detached mount where writes are discarded", async () => {
      await runSandboxedCommand(
        options({ proxyEngine: "inspect", filesystemMode: "ephemeral" }),
        deps,
      );

      expect(mocks.nssDbDetached).not.toHaveBeenCalled();
    });

    it("still takes the directories back when the sandbox fails to run", async () => {
      mocks.runIsolated.mockImplementation(() => {
        throw new Error("runc failed");
      });

      await expect(runSandboxedCommand(options({ proxyEngine: "inspect" }), deps)).rejects.toThrow(
        "runc failed",
      );
      expect(mocks.releaseNssDbDirs).toHaveBeenCalledWith(NSS_DB, RELEASE);
      expect(mocks.settleNssDbSlot).not.toHaveBeenCalled();
    });

    it("takes the directories back when the bundle cannot be built", async () => {
      mocks.buildOciConfig.mockImplementation(() => {
        throw new Error("bad spec");
      });

      await expect(runSandboxedCommand(options({ proxyEngine: "inspect" }), deps)).rejects.toThrow(
        expect.objectContaining({ code: "OCI_CONFIG_BUILD_FAILED" }),
      );
      expect(mocks.releaseNssDbDirs).toHaveBeenCalledWith(NSS_DB, RELEASE);
      expect(mocks.runIsolated).not.toHaveBeenCalled();
    });

    it("takes the directories back when the OCI config cannot be written", async () => {
      mocks.writeOciConfig.mockImplementation(() => {
        throw new Error("disk full");
      });

      await expect(runSandboxedCommand(options({ proxyEngine: "inspect" }), deps)).rejects.toThrow(
        "disk full",
      );
      expect(mocks.releaseNssDbDirs).toHaveBeenCalledOnce();
      expect(mocks.runIsolated).not.toHaveBeenCalled();
    });

    it("has nothing to check when there was nowhere to mount it", async () => {
      mocks.prepareNssDb.mockReturnValue(undefined);
      mocks.runIsolated.mockImplementation(() => {
        throw new Error("runc failed");
      });

      await expect(runSandboxedCommand(options({ proxyEngine: "inspect" }), deps)).rejects.toThrow(
        "runc failed",
      );
      expect(mocks.releaseNssDbDirs).not.toHaveBeenCalled();
    });

    it.each([
      ["persistent mode, under $HOME", {}, true],
      ["ephemeral mode", { filesystemMode: "ephemeral" as const }, false],
      [
        "ephemeral mode, under a write_through entry",
        { filesystemMode: "ephemeral" as const, writeThroughPaths: ["/home/runner/.pki"] },
        true,
      ],
      [
        "ephemeral mode, under a write_through entry beside it",
        { filesystemMode: "ephemeral" as const, writeThroughPaths: ["/home/runner/.pk"] },
        false,
      ],
      [
        "ephemeral mode, write_through: /",
        { filesystemMode: "ephemeral" as const, writeThroughPaths: ["/"] },
        true,
      ],
      [
        "ephemeral mode, the database itself written through",
        { filesystemMode: "ephemeral" as const, writeThroughPaths: ["/home/runner/.pki/nssdb"] },
        true,
      ],
    ])("writes back in %s: %s", async (_label, overrides, persist) => {
      await runSandboxedCommand(options({ proxyEngine: "inspect", ...overrides }), deps);

      expect(mocks.readFile).toHaveBeenCalledWith(OWN_CA);
      expect(mocks.settleNssDbSlot).toHaveBeenCalledWith(
        NSS_DB,
        expect.objectContaining({ persist, caPem: "THE CA PEM" }),
      );
      expect(mocks.releaseNssDbDirs.mock.invocationCallOrder[0]).toBeGreaterThan(
        mocks.settleNssDbSlot.mock.invocationCallOrder[0],
      );
    });

    it("writes nothing back to a database whose mount went away", async () => {
      mocks.nssDbDetached.mockReturnValue("DETACHED");

      await runSandboxedCommand(options({ proxyEngine: "inspect" }), deps);

      expect(mocks.warn).toHaveBeenCalledWith("DETACHED");
      expect(mocks.settleNssDbSlot).not.toHaveBeenCalled();
      expect(mocks.releaseNssDbDirs).toHaveBeenCalledWith(NSS_DB, RELEASE);
    });

    it("says so when what the command wrote is discarded", async () => {
      mocks.settleNssDbSlot.mockReturnValue("discarded");

      await runSandboxedCommand(options({ proxyEngine: "inspect" }), deps);

      expect(mocks.info).toHaveBeenCalledWith(
        expect.stringContaining("NSS database at /home/runner/.pki/nssdb is discarded"),
      );
    });

    it("fails the step on a copy of the CA, pointing at fail_on_ca_residue", async () => {
      mocks.settleNssDbSlot.mockImplementation((_files, { onResidue }) => onResidue("COPIED"));

      await expect(runSandboxedCommand(options({ proxyEngine: "inspect" }), deps)).rejects.toThrow(
        expect.objectContaining({
          code: "NSS_DATABASE_CA_COPIED",
          message: expect.stringMatching(/COPIED.*fail_on_ca_residue: false/),
        }),
      );
      expect(mocks.releaseNssDbDirs).toHaveBeenCalledWith(NSS_DB, RELEASE);
    });

    it("only warns about a copy of the CA under fail_on_ca_residue: false", async () => {
      mocks.settleNssDbSlot.mockImplementation((_files, { onResidue }) => {
        onResidue("COPIED");
        return "written";
      });

      await runSandboxedCommand(options({ proxyEngine: "inspect", failOnCaResidue: false }), deps);

      expect(mocks.warn).toHaveBeenCalledWith(
        expect.stringMatching(/COPIED.*fail_on_ca_residue is false/),
      );
    });

    it("fails the step when what the command wrote cannot be written back", async () => {
      mocks.settleNssDbSlot.mockImplementation(() => {
        throw new Error("EIO");
      });

      await expect(runSandboxedCommand(options({ proxyEngine: "inspect" }), deps)).rejects.toThrow(
        expect.objectContaining({
          code: "NSS_DATABASE_WRITE_BACK_FAILED",
          message: expect.stringContaining("/home/runner/.pki/nssdb: EIO"),
        }),
      );
      expect(mocks.releaseNssDbDirs).toHaveBeenCalledWith(NSS_DB, RELEASE);
    });
  });

  // An earlier step's sandbox may have written to $HOME even when this one's
  // writes are discarded.
  it("pins keytool against persistent mode's paths even in ephemeral mode", async () => {
    const tools = { java: "/usr/bin/java", keytool: "/usr/bin/keytool" };
    mocks.jvmTools.mockReturnValue(tools);
    const opts = options({
      proxyEngine: "inspect",
      filesystemMode: "ephemeral",
      writeThroughPaths: ["/opt/out"],
    });

    await runSandboxedCommand(opts, deps);

    expect(mocks.jvmTools).toHaveBeenCalledWith(opts.env, [
      "/home/runner/work/repo/repo",
      "/home/runner",
      "/tmp",
      "/opt/out",
    ]);
    expect(mocks.writeCaTrustFiles).toHaveBeenCalledWith(
      `${SCRATCH}/ca.crt`,
      SCRATCH,
      opts.env,
      tools,
      { warn: mocks.warn },
    );
  });

  it("warns once about a CA variable the step set elsewhere, under inspect only", async () => {
    const env = {
      HOME: "/home/runner",
      GIT_SSL_CAINFO: "/opt/corp-ca.pem",
      PIP_CERT: "/opt/pip.pem",
    };

    await runSandboxedCommand(options({ proxyEngine: "inspect", env }), deps);
    expect(mocks.warn).toHaveBeenCalledTimes(1);
    expect(mocks.warn).toHaveBeenCalledWith(
      expect.stringContaining("GIT_SSL_CAINFO (/opt/corp-ca.pem), PIP_CERT (/opt/pip.pem)"),
    );

    mocks.warn.mockClear();
    await runSandboxedCommand(options({ env }), deps);
    expect(mocks.warn).not.toHaveBeenCalled();
  });

  it("extracts no CA under an engine that does not terminate TLS", async () => {
    await runSandboxedCommand(options(), deps);

    expect(mocks.extractCaCert).not.toHaveBeenCalled();
    expect(mocks.buildOciConfig.mock.calls[0][1].caTrust).toBeUndefined();
  });

  it("builds the overlay only in ephemeral mode, from the already-folded roots", async () => {
    const overlayRoots = ["/usr"];
    mocks.createOverlayScratchDirs.mockReturnValue([{ path: "/usr", upper: `${SCRATCH}/upper0` }]);

    await runSandboxedCommand(
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
  it("hands its warning sink to the scratch dir and the environment resolver", async () => {
    await runSandboxedCommand(options(), deps);

    expect(mocks.withScratchDir.mock.calls[0][1].warn).toBe(mocks.warn);
    expect(mocks.resolveSandboxEnv).toHaveBeenCalledWith(expect.anything(), undefined, mocks.warn);
  });

  it("leaves persistent mode with no overlay at all", async () => {
    await runSandboxedCommand(options(), deps);

    expect(mocks.createOverlayScratchDirs).not.toHaveBeenCalled();
    expect(mocks.buildOciConfig.mock.calls[0][1].ephemeral).toBeUndefined();
    expect(mocks.withScratchDir.mock.calls[0][1].ephemeralRoots).toBeUndefined();
  });

  // Every one of these is set by a real runner, but this action is also driven
  // directly by this repo's own integration scripts.
  it("leaves the writable paths empty when the runner set none of them", async () => {
    await runSandboxedCommand(options({ env: {} }), deps);

    expect(mocks.buildOciConfig.mock.calls[0][1].writable).toStrictEqual({
      workdir: undefined,
      home: undefined,
      runnerTemp: undefined,
      tmp: "/tmp",
      writablePaths: [],
    });
  });

  it("hands the config the writable paths as they really resolve", async () => {
    mocks.realpath.mockImplementation((p: string) => p.replace(/^\/home\//, "/var/home/"));

    await runSandboxedCommand(
      options({
        env: {
          GITHUB_WORKSPACE: "/home/runner/work/repo/repo",
          HOME: "/home/runner",
          RUNNER_TEMP: "/home/runner/work/_temp",
        },
      }),
      deps,
    );

    expect(mocks.buildOciConfig.mock.calls[0][1].writable).toStrictEqual({
      workdir: "/var/home/runner/work/repo/repo",
      home: "/var/home/runner",
      runnerTemp: "/var/home/runner/work/_temp",
      tmp: "/tmp",
      writablePaths: [],
    });
  });

  it("keeps the docker CLI's config directory read-only, creating it first", async () => {
    await runSandboxedCommand(options(), deps);

    // On CI the checkout is under /home/runner and adds its own entry.
    expect(mocks.buildOciConfig.mock.calls[0][1].readonlyHostPaths).toContain(
      "/home/runner/.docker",
    );
    expect(mocks.mkdir).toHaveBeenCalledWith("/home/runner/.docker", {
      mode: 0o700,
      recursive: true,
    });
  });

  it("guards the writable dirs above a read-only dir so they cannot be renamed", async () => {
    await runSandboxedCommand(
      options({ env: { HOME: "/home/runner", DOCKER_CONFIG: "/home/runner/a/b/cfg" } }),
      deps,
    );

    // On CI the checkout is under /home/runner and adds its own guards.
    expect(mocks.buildOciConfig.mock.calls[0][1].renameGuardDirs).toEqual(
      expect.arrayContaining(["/home/runner/a", "/home/runner/a/b"]),
    );
  });

  it("leaves it writable in ephemeral mode, where no write_through reaches it", async () => {
    await runSandboxedCommand(
      options({ filesystemMode: "ephemeral", overlayRoots: ["/home/runner"] }),
      deps,
    );

    expect(mocks.buildOciConfig.mock.calls[0][1].readonlyHostPaths).toStrictEqual([]);
    expect(mocks.mkdir).not.toHaveBeenCalledWith("/home/runner/.docker", expect.anything());
  });

  describe("the runner's file commands", () => {
    const COMMANDS = "/home/runner/work/_temp/_runner_file_commands";
    const env = {
      HOME: "/home/runner",
      RUNNER_TEMP: "/home/runner/work/_temp",
      GITHUB_ENV: `${COMMANDS}/set_env_1`,
      GITHUB_PATH: `${COMMANDS}/add_path_1`,
      GITHUB_STATE: `${COMMANDS}/save_state_1`,
    };

    it("keeps them read-only and their directory unrenamable, making any that is missing", async () => {
      await runSandboxedCommand(options({ env }), deps);

      const config = mocks.buildOciConfig.mock.calls[0][1];
      expect(config.readonlyHostPaths).toEqual(
        expect.arrayContaining([env.GITHUB_ENV, env.GITHUB_PATH, env.GITHUB_STATE]),
      );
      expect(config.renameGuardDirs).toContain(COMMANDS);
      expect(mocks.touch.mock.calls.map(([path]) => path)).toStrictEqual([
        env.GITHUB_ENV,
        env.GITHUB_PATH,
        env.GITHUB_STATE,
      ]);
    });

    it("keeps them read-only in ephemeral mode too, unless write_through names one", async () => {
      await runSandboxedCommand(
        options({
          env,
          filesystemMode: "ephemeral",
          overlayRoots: ["/home/runner"],
          writeThroughPaths: [env.GITHUB_ENV],
        }),
        deps,
      );

      expect(mocks.buildOciConfig.mock.calls[0][1].readonlyHostPaths).toStrictEqual([
        env.GITHUB_PATH,
        env.GITHUB_STATE,
      ]);
    });
  });

  it("says so when the runner's primary group forced a GID substitution", async () => {
    mocks.resolveSandboxGid.mockReturnValue({ gid: 65534, substitutedFrom: 118 });

    await runSandboxedCommand(options(), deps);

    expect(mocks.info).toHaveBeenCalledWith(
      expect.stringContaining("(118 -> 65534) -- the runner's primary group grants"),
    );
    expect(mocks.buildOciConfig.mock.calls[0][1].identity.gid).toBe(65534);
  });

  it("warns when NSS could not answer the primary group check", async () => {
    mocks.resolveSandboxGid.mockReturnValue({
      gid: 65534,
      substitutedFrom: 1001,
      nssError: "timed out",
    });

    await runSandboxedCommand(options(), deps);

    expect(mocks.warn).toHaveBeenCalledWith(expect.stringContaining("NSS (timed out)"));
    expect(mocks.warn).toHaveBeenCalledWith(expect.stringContaining("treated as privileged"));
    expect(mocks.info).toHaveBeenCalledWith(
      expect.stringContaining("(1001 -> 65534) -- the runner's primary group couldn't be verified"),
    );
  });

  async function failureFrom(
    overrides: Partial<RunSandboxedCommandOptions> = {},
  ): Promise<SandboxError | undefined> {
    try {
      await runSandboxedCommand(options(overrides), deps);
    } catch (e) {
      return e as SandboxError;
    }
  }

  it.each([
    ["extractRuncBootstrap", () => mocks.extractRuncBootstrap, "RUNC_EXTRACT_FAILED", {}],
    ["extractCaCert", () => mocks.extractCaCert, "CA_EXTRACT_FAILED", { proxyEngine: "inspect" }],
    ["buildOciConfig", () => mocks.buildOciConfig, "OCI_CONFIG_BUILD_FAILED", {}],
  ])("turns a %s failure into its own SandboxError", async (_name, target, code, overrides) => {
    target().mockImplementation(() => {
      throw new Error("boom");
    });

    const error = await failureFrom(overrides as Partial<RunSandboxedCommandOptions>);

    expect(error).toBeInstanceOf(SandboxError);
    expect(error!.code).toBe(code);
    expect(error!.message).toContain("boom");
  });

  it.each([
    ["extractRuncBootstrap", () => mocks.extractRuncBootstrap, {}],
    ["extractCaCert", () => mocks.extractCaCert, { proxyEngine: "inspect" }],
    ["resolveSandboxGid", () => mocks.resolveSandboxGid, {}],
  ])("lets a SandboxError from %s through untouched", async (_name, target, overrides) => {
    const thrown = new SandboxError("the primary group is privileged", "UNSAFE_PRIMARY_GID");
    target().mockImplementation(() => {
      throw thrown;
    });

    expect(await failureFrom(overrides as Partial<RunSandboxedCommandOptions>)).toBe(thrown);
  });

  // Same misconfiguration, same code whichever check catches it first: the
  // early one in resolveFilesystemPlan, or buildOciConfig's authoritative one.
  it("reports a writable-path conflict as FILESYSTEM_INPUT_CONFLICT", async () => {
    mocks.buildOciConfig.mockImplementation(() => {
      throw new WritablePathConflictError('writable path "/proc" is inside "/proc"');
    });

    const error = await failureFrom();

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

    expect(mocks.writeResolvConf).toHaveBeenCalledWith("198.19.255.1", SCRATCH);
  });

  it("hands back the CA trust files the inspect engine needs, for the caller to pass on", () => {
    const bundle = assembleBundle(SCRATCH, options({ proxyEngine: "inspect" }), deps);

    expect(bundle.caTrust).toStrictEqual({
      ownCaPath: `${SCRATCH}/buildcage-ca.pem`,
      stores: [],
      nssDb: undefined,
    });
  });
});

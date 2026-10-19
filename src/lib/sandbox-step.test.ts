import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";

import { InvalidInputError } from "#core/lib/actions/inputs.ts";
import type { SummaryBlock } from "#core/lib/report/render/fit-step-summary.ts";

import { SandboxError } from "./errors.ts";
import type { RecordArtifact } from "./filesystem-audit/render.ts";
import type { ReadStepFilesystemAudit } from "./filesystem-audit/report.ts";
import {
  finalizeStep,
  preflight,
  readStepInputs,
  runSandboxStep,
  WRITE_THROUGH_ALL_WARNING,
  type SandboxStepDeps,
} from "./sandbox-step.ts";
import { filesystemAuditPaths } from "./sandbox/filesystem-audit-paths.ts";
import { SANDBOX_SCRATCH_BASE } from "./sandbox/scratch-dir.ts";

// Assembled at runtime: a literal shaped like an AWS access key ID trips
// secret scanning on push.
const ASIA = ["A", "S", "I", "A"].join("");

// What is left to check here is the order they run in, what each one is
// handed, and which of them still run when an earlier step fails.
const annotation = { notice: vi.fn(), warning: vi.fn(), error: vi.fn() };

const mocks = {
  applyConfigFile: vi.fn(),
  readRunCommand: vi.fn(),
  readProxyInputs: vi.fn(),
  readFilesystemInputs: vi.fn(),
  readFilesystemAuditInput: vi.fn(),
  readFilesystemAuditArtifactInputs: vi.fn(),
  readRuleInputs: vi.fn(),
  readFailOnCaResidue: vi.fn(),
  readFailOnBlocked: vi.fn(),
  readAwsKeyInputs: vi.fn(),
  readTrafficArtifactInputs: vi.fn(),
  saveWriteThroughForPost: vi.fn(),
  validateFilesystemInputs: vi.fn(),
  checkScratchBaseParent: vi.fn(),
  checkPasswordlessSudo: vi.fn(),
  checkOverlayfsSupport: vi.fn(),
  checkFilesystemAuditHost: vi.fn(),
  createAnnotation: vi.fn(),
  resolveFilesystemPlan: vi.fn(),
  pinHostCommands: vi.fn(),
  realPathOf: vi.fn(),
  getuid: vi.fn(),
  readLocalImageOverride: vi.fn(),
  verifyImageDigestOrThrow: vi.fn(),
  checkUrlAndTlsRuleSupport: vi.fn(),
  checkKnownBlockedUrlRuleSupport: vi.fn(),
  logRules: vi.fn(),
  withLogGroup: vi.fn(),
  generateContainerName: vi.fn(),
  getContainerNetns: vi.fn(),
  startSandboxProxy: vi.fn(),
  stopSandboxProxy: vi.fn(),
  runSandboxedCommand: vi.fn(),
  reportStepTraffic: vi.fn(),
  readStepFilesystemAudit: vi.fn(),
  mediateRunnerOutputFiles: vi.fn(),
  readBackingFile: vi.fn(),
  removeBackingDir: vi.fn(),
  writeBackOutputFile: vi.fn(),
  writeRunnerFile: vi.fn(),
  setTrafficArtifactOutput: vi.fn(),
  setFilesystemAuditOutput: vi.fn(),
  onCancel: vi.fn(),
  saveState: vi.fn(),
  info: vi.fn(),
  log: vi.fn(),
  notice: vi.fn(),
  warn: vi.fn(),
};

// Every step is replaced, so the cast only says what the shape already is.
const deps = mocks as unknown as SandboxStepDeps;

// What onCancel hands back.
const stopListening = vi.fn();

const DIGEST = "sha256:" + "a".repeat(64);

/** A read recording, its upload and blocks spied on. */
function readAudit<T extends Partial<ReadStepFilesystemAudit>>(over: T = {} as T) {
  return {
    expected: "not-requested" as RecordArtifact,
    upload: vi.fn(async (): Promise<RecordArtifact> => "not-requested"),
    blocks: vi.fn((): SummaryBlock[] => []),
    ...over,
  };
}

const RUNNER_FILES = ["GITHUB_OUTPUT", "GITHUB_STEP_SUMMARY"] as const;

const ENV = {
  GITHUB_WORKSPACE: "/home/runner/work/repo/repo",
  HOME: "/home/runner",
  GITHUB_STEP_SUMMARY: "/home/runner/work/_temp/summary",
  GITHUB_STATE: "/home/runner/work/_temp/state",
  GITHUB_OUTPUT: "/home/runner/work/_temp/output",
  GITHUB_ACTION_REF: "v1.2.3",
  GITHUB_ACTION_REPOSITORY: "buildcage/isolated-run",
};

// A failure the step reports by process.exitCode must not fail the test run.
const exitCode = process.exitCode;
afterEach(() => {
  process.exitCode = exitCode;
});

beforeEach(() => {
  vi.resetAllMocks();
  // Keeps pinningPaths from resolving the fixture's paths on this machine.
  mocks.realPathOf.mockImplementation((path: string) => path);
  mocks.getuid.mockReturnValue(1001);
  mocks.readRunCommand.mockReturnValue("echo hello");
  mocks.readProxyInputs.mockReturnValue({ proxyEngine: "universal", proxyMode: "restrict" });
  mocks.readFilesystemInputs.mockReturnValue({
    filesystemMode: "persistent",
    writeThroughInput: "",
  });
  mocks.readFilesystemAuditInput.mockReturnValue("off");
  mocks.readFilesystemAuditArtifactInputs.mockReturnValue({ upload: false });
  mocks.readRuleInputs.mockReturnValue({
    httpsRules: ["example.com:443"],
    httpRules: [],
    ipRules: [],
    urlRules: [],
    tlsRules: [],
    knownBlockedRules: [],
  });
  mocks.readFailOnCaResidue.mockReturnValue(true);
  mocks.readFailOnBlocked.mockReturnValue(true);
  mocks.readAwsKeyInputs.mockReturnValue({ key: "", roleAccounts: [] });
  mocks.readTrafficArtifactInputs.mockReturnValue({ upload: false });
  mocks.createAnnotation.mockReturnValue(annotation);
  mocks.resolveFilesystemPlan.mockReturnValue({
    overlayRoots: [],
    writeThroughPaths: [],
    mediatedVariables: RUNNER_FILES,
  });
  mocks.readLocalImageOverride.mockResolvedValue(null);
  mocks.verifyImageDigestOrThrow.mockResolvedValue(DIGEST);
  // The real one runs the callback; a test that cares asserts on logRules.
  mocks.withLogGroup.mockImplementation((_title: string, fn: () => void) => fn());
  mocks.generateContainerName.mockReturnValue("buildcage-proxy-deadbeef");
  mocks.getContainerNetns.mockReturnValue("/var/run/docker/netns/abc123");
  mocks.startSandboxProxy.mockResolvedValue(undefined);
  mocks.stopSandboxProxy.mockResolvedValue(undefined);
  mocks.runSandboxedCommand.mockResolvedValue(0);
  mocks.reportStepTraffic.mockResolvedValue(undefined);
  mocks.readStepFilesystemAudit.mockReturnValue(readAudit());
  mocks.onCancel.mockReturnValue(stopListening);
  // Mirrors the real mediation: a backing file per variable the step has.
  mocks.mediateRunnerOutputFiles.mockImplementation(
    (env: NodeJS.ProcessEnv, variables: typeof RUNNER_FILES, backingDir: string) => {
      const files = variables
        .filter((v) => env[v])
        .map((variable) => ({
          variable,
          realPath: env[variable]!,
          backingPath: `${backingDir}/${variable}`,
        }));
      return files.length === 0
        ? undefined
        : { envOverrides: {}, mounts: [], maskedPaths: [], files };
    },
  );
  // The command wrote nothing by default; a test that cares overrides this.
  mocks.readBackingFile.mockReturnValue({ empty: true });
  mocks.writeBackOutputFile.mockReturnValue({});
});

/** Call order of a step that ran, for comparing two steps against each other. */
function orderOf(mock: { mock: { invocationCallOrder: number[] } }): number {
  const [first] = mock.mock.invocationCallOrder;
  expect(first).toBeDefined();
  return first!;
}

describe("runSandboxStep", () => {
  it("applies config_file to the step's env before reading any input, and logs it", async () => {
    mocks.applyConfigFile.mockReturnValue({
      path: "/home/runner/work/repo/repo/c.yml",
      summary: ["Ignored from config_file c.yml, set by the workflow: proxy_mode"],
    });

    await runSandboxStep(ENV, deps);

    expect(mocks.applyConfigFile).toHaveBeenCalledWith(
      ENV,
      expect.objectContaining({ known: expect.arrayContaining(["proxy_mode"]) }),
    );
    expect(orderOf(mocks.applyConfigFile)).toBeLessThan(orderOf(mocks.readRunCommand));
    expect(mocks.log).toHaveBeenCalledWith(
      "Ignored from config_file c.yml, set by the workflow: proxy_mode",
    );
  });

  it("saves the merged write_through for the post step when config_file was read", async () => {
    mocks.applyConfigFile.mockReturnValue({ path: "/w/c.yml", summary: [] });
    mocks.readFilesystemInputs.mockReturnValue({
      filesystemMode: "persistent",
      writeThroughInput: "/opt/cache",
    });

    await runSandboxStep(ENV, deps);

    expect(mocks.saveWriteThroughForPost).toHaveBeenCalledWith(ENV, "/opt/cache");
    expect(orderOf(mocks.saveWriteThroughForPost)).toBeLessThan(orderOf(mocks.runSandboxedCommand));
  });

  it("saves nothing without config_file, leaving post the workflow's own input", async () => {
    await runSandboxStep(ENV, deps);

    expect(mocks.saveWriteThroughForPost).not.toHaveBeenCalled();
  });

  it("returns the isolated command's own exit code", async () => {
    mocks.runSandboxedCommand.mockResolvedValue(42);

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
      mediatedVariables: RUNNER_FILES,
    });
    mocks.readFailOnCaResidue.mockReturnValue(false);

    await runSandboxStep(ENV, deps);

    expect(mocks.runSandboxedCommand.mock.calls[0][0]).toMatchObject({
      runInput: "echo hello",
      proxyNetns: "/var/run/docker/netns/abc123",
      containerName: "buildcage-proxy-deadbeef",
      filesystemMode: "ephemeral",
      overlayRoots: ["/home/runner"],
      writeThroughPaths: ["/home/runner/work/repo/repo/dist"],
      failOnCaResidue: false,
    });
  });

  it("passes the audit output paths to the command under filesystem_audit: record", async () => {
    mocks.readFilesystemAuditInput.mockReturnValue("record");

    await runSandboxStep(ENV, deps);

    expect(mocks.runSandboxedCommand.mock.calls[0][0].filesystemAudit).toStrictEqual(
      filesystemAuditPaths("buildcage-proxy-deadbeef", SANDBOX_SCRATCH_BASE),
    );
  });

  it("uploads the audit first and writes its summary with the traffic report", async () => {
    const read = readAudit({ upload: vi.fn(async () => ({ name: "uploaded" })) });
    mocks.readStepFilesystemAudit.mockReturnValue(read);
    mocks.readFilesystemAuditInput.mockReturnValue("record");

    await runSandboxStep(ENV, deps);

    expect(mocks.readStepFilesystemAudit.mock.calls[0][0].cancelled).toBe(false);
    const report = mocks.reportStepTraffic.mock.calls[0][0];
    report.moreBlocks(1_700_000_000, "build");
    expect(read.blocks).toHaveBeenCalledWith(1_700_000_000, { name: "uploaded" }, "build");
    expect(read.upload).toHaveBeenCalledTimes(1);
    expect(orderOf(read.upload)).toBeLessThan(orderOf(mocks.reportStepTraffic));
  });

  it("tells the report whether the tracer attached", async () => {
    mocks.readFilesystemAuditInput.mockReturnValue("record");
    await runSandboxStep(ENV, deps);
    expect(mocks.readStepFilesystemAudit.mock.calls[0][0].attached).toBe(false);

    mocks.runSandboxedCommand.mockImplementation(async ({ onAuditAttached }) => {
      onAuditAttached?.();
      throw new Error("the command failed to run");
    });
    await expect(runSandboxStep(ENV, deps)).rejects.toThrow("the command failed to run");
    expect(mocks.readStepFilesystemAudit.mock.calls[1][0].attached).toBe(true);

    mocks.runSandboxedCommand.mockImplementation(async ({ onAuditAttached }) => {
      onAuditAttached?.();
      return 0;
    });
    await runSandboxStep(ENV, deps);
    expect(mocks.readStepFilesystemAudit.mock.calls[2][0].attached).toBe(true);
  });

  it("leaves the audit off by default", async () => {
    await runSandboxStep(ENV, deps);

    expect(mocks.runSandboxedCommand.mock.calls[0][0].filesystemAudit).toBeUndefined();
  });

  it("hands the report the inputs read up front", async () => {
    mocks.readFailOnBlocked.mockReturnValue(false);
    mocks.readTrafficArtifactInputs.mockReturnValue({ upload: true, retentionDays: 7 });

    await runSandboxStep(ENV, deps);

    expect(mocks.reportStepTraffic.mock.calls[0][0]).toMatchObject({
      failOnBlocked: false,
      trafficArtifact: { upload: true, retentionDays: 7 },
    });
  });

  it.each([
    "readFailOnCaResidue",
    "readFailOnBlocked",
    "readTrafficArtifactInputs",
    "readRuleInputs",
    "readAwsKeyInputs",
  ] as const)("fails on a bad value from %s before any setup", async (reader) => {
    mocks[reader].mockImplementation(() => {
      throw new InvalidInputError("Invalid input", "INVALID_BOOLEAN_INPUT");
    });

    await expect(runSandboxStep(ENV, deps)).rejects.toThrow("Invalid input");
    expect(mocks.checkPasswordlessSudo).not.toHaveBeenCalled();
    expect(mocks.readLocalImageOverride).not.toHaveBeenCalled();
    expect(mocks.verifyImageDigestOrThrow).not.toHaveBeenCalled();
    expect(mocks.startSandboxProxy).not.toHaveBeenCalled();
  });

  it.each(["checkUrlAndTlsRuleSupport", "checkKnownBlockedUrlRuleSupport"] as const)(
    "fails on a rule %s rejects before any setup",
    async (check) => {
      mocks[check].mockImplementation(() => {
        throw new InvalidInputError("url rules need the inspect engine", "INVALID_PROXY_ENGINE");
      });

      await expect(runSandboxStep(ENV, deps)).rejects.toThrow("url rules need the inspect engine");
      expect(mocks.pinHostCommands).not.toHaveBeenCalled();
      expect(mocks.checkPasswordlessSudo).not.toHaveBeenCalled();
      expect(mocks.resolveFilesystemPlan).not.toHaveBeenCalled();
      expect(mocks.verifyImageDigestOrThrow).not.toHaveBeenCalled();
      expect(mocks.startSandboxProxy).not.toHaveBeenCalled();
    },
  );

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

  it("refuses a symlinked /var/tmp before writing anything under it", async () => {
    mocks.applyConfigFile.mockReturnValue({ path: "/w/c.yml", summary: [] });
    mocks.checkScratchBaseParent.mockImplementation(() => {
      throw new SandboxError("/var/tmp resolves to /tmp", "SCRATCH_BASE_SYMLINKED");
    });

    await expect(runSandboxStep(ENV, deps)).rejects.toMatchObject({
      code: "SCRATCH_BASE_SYMLINKED",
    });
    expect(mocks.saveWriteThroughForPost).not.toHaveBeenCalled();
    expect(mocks.checkPasswordlessSudo).not.toHaveBeenCalled();
    expect(mocks.startSandboxProxy).not.toHaveBeenCalled();
  });

  it("validates the write_through lines, resolved without touching the host", async () => {
    mocks.readFilesystemInputs.mockReturnValue({
      filesystemMode: "ephemeral",
      writeThroughInput: " /opt/cache \n\n./dist\n/\n",
    });

    await runSandboxStep(ENV, deps);

    expect(mocks.validateFilesystemInputs).toHaveBeenCalledWith("ephemeral", [
      "/opt/cache",
      "/home/runner/work/repo/repo/dist",
      "/",
    ]);
  });

  it("warns that write_through: / gives up the outbound restriction too", async () => {
    mocks.readFilesystemInputs.mockReturnValue({
      filesystemMode: "persistent",
      writeThroughInput: "/opt/cache\n/",
    });

    await runSandboxStep(ENV, deps);

    expect(annotation.warning).toHaveBeenCalledExactlyOnceWith(WRITE_THROUGH_ALL_WARNING);
  });

  it("does not warn when write_through names only narrower paths", async () => {
    mocks.readFilesystemInputs.mockReturnValue({
      filesystemMode: "persistent",
      writeThroughInput: "/opt/cache",
    });

    await runSandboxStep(ENV, deps);

    expect(annotation.warning).not.toHaveBeenCalled();
  });

  it("fails on a write_through entry that does not parse before any setup", async () => {
    mocks.readFilesystemInputs.mockReturnValue({
      filesystemMode: "persistent",
      writeThroughInput: "$UNSET_DIR/cache",
    });

    await expect(runSandboxStep(ENV, deps)).rejects.toMatchObject({
      code: "INVALID_WRITE_THROUGH_PATH",
    });
    expect(mocks.validateFilesystemInputs).not.toHaveBeenCalled();
    expect(mocks.pinHostCommands).not.toHaveBeenCalled();
    expect(mocks.checkPasswordlessSudo).not.toHaveBeenCalled();
    expect(mocks.resolveFilesystemPlan).not.toHaveBeenCalled();
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

  it("checks the host for the filesystem audit only under record, before the proxy starts", async () => {
    await runSandboxStep(ENV, deps);
    expect(mocks.checkFilesystemAuditHost).not.toHaveBeenCalled();

    mocks.readFilesystemAuditInput.mockReturnValue("record");
    mocks.checkFilesystemAuditHost.mockImplementation(() => {
      throw new SandboxError("no cgroup v2", "FILESYSTEM_AUDIT_UNAVAILABLE");
    });
    mocks.startSandboxProxy.mockClear();
    await expect(runSandboxStep(ENV, deps)).rejects.toThrow("no cgroup v2");
    expect(mocks.startSandboxProxy).not.toHaveBeenCalled();
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
      mediatedVariables: ["GITHUB_OUTPUT"],
    });
    await runSandboxStep(ENV, deps);

    expect(mocks.info.mock.calls.map(([line]) => line)).toStrictEqual([
      "Filesystem mode: ephemeral",
      "Ephemeral (writes discarded at step end): /home/runner",
      "Writable (persisted):                    /opt/cache",
      "Written back after the step:             $GITHUB_OUTPUT",
    ]);
  });

  it("hands the starting key and the role accounts to the proxy, and logs no key", async () => {
    mocks.readAwsKeyInputs.mockReturnValue({
      key: `${ASIA}AAAAAAAAAAAAAAAA`,
      roleAccounts: ["111111111111"],
    });
    const log = mocks.log;

    await runSandboxStep(ENV, deps);

    expect(mocks.readAwsKeyInputs).toHaveBeenCalledWith({ proxyEngine: "universal" }, ENV);
    expect(mocks.startSandboxProxy.mock.calls[0][0].composeEnv).toMatchObject({
      ALLOWED_AWS_KEY: `${ASIA}AAAAAAAAAAAAAAAA`,
      ALLOWED_AWS_ROLE_ACCOUNTS: "111111111111",
    });
    expect(mocks.reportStepTraffic.mock.calls[0][0].extraInputs({ timeline: [] })).toStrictEqual([
      "aws_key_check: true",
      'allowed_aws_role_accounts: "111111111111"',
    ]);
    expect(log).toHaveBeenCalledWith("AWS access key check: on");
    expect(log).toHaveBeenCalledWith("AWS role accounts: 111111111111");
    expect(log.mock.calls.flat().join("\n").includes(`${ASIA}AAAAAAAAAAAAAAAA`)).toBe(false);
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

  // A local-path `uses: ./` names no ref: verification takes it empty (and
  // hard-fails on that), the report takes the v2 fallback for a valid `uses:`.
  it("verifies against an empty ref but reports with the v2 fallback for a local-path invocation", async () => {
    await runSandboxStep(
      { ...ENV, GITHUB_ACTION_REF: undefined, GITHUB_ACTION_REPOSITORY: undefined },
      deps,
    );

    expect(mocks.verifyImageDigestOrThrow.mock.calls[0][0]).toMatchObject({
      actionRef: "",
      actionRepo: "buildcage/isolated-run",
    });
    expect(mocks.reportStepTraffic.mock.calls[0][0]).toMatchObject({
      actionRef: "v2",
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
    expect(mocks.resolveFilesystemPlan.mock.calls[0][3]).toStrictEqual({ warn: mocks.warn });
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
    expect(annotation.warning).toHaveBeenCalledOnce();
    expect(annotation.warning).toHaveBeenCalledWith("url rules need the inspect engine");
  });

  it("checks known_blocked_rules URL lines against the engine, host lines excluded", async () => {
    mocks.readRuleInputs.mockReturnValue({
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

  describe("the state post.ts cleans up from", () => {
    it("records the container name, and the overlay roots in ephemeral mode", async () => {
      mocks.readFilesystemInputs.mockReturnValue({
        filesystemMode: "ephemeral",
        writeThroughInput: "",
      });
      mocks.resolveFilesystemPlan.mockReturnValue({
        overlayRoots: ["/home/runner", "/tmp"],
        writeThroughPaths: [],
        mediatedVariables: RUNNER_FILES,
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
      expect(mocks.writeRunnerFile).toHaveBeenCalled();
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

    it("stops the proxy that failed to start, without reporting or running anything", async () => {
      mocks.startSandboxProxy.mockRejectedValue(
        new SandboxError("sandbox proxy is unhealthy", "PROXY_NOT_READY"),
      );

      await expect(runSandboxStep(ENV, deps)).rejects.toThrow("sandbox proxy is unhealthy");
      expect(mocks.stopSandboxProxy).toHaveBeenCalledTimes(1);
      expect(orderOf(mocks.startSandboxProxy)).toBeLessThan(orderOf(mocks.stopSandboxProxy));
      expect(mocks.reportStepTraffic).not.toHaveBeenCalled();
      expect(mocks.runSandboxedCommand).not.toHaveBeenCalled();
    });

    it("stops the proxy and stops listening when a report throws", async () => {
      mocks.reportStepTraffic.mockRejectedValue(new Error("render failed"));

      await expect(runSandboxStep(ENV, deps)).rejects.toThrow("render failed");
      expect(mocks.stopSandboxProxy).toHaveBeenCalledTimes(1);
      expect(stopListening).toHaveBeenCalledTimes(1);
      expect(orderOf(mocks.stopSandboxProxy)).toBeLessThan(orderOf(stopListening));
    });

    it("does not catch a cancel while the proxy is still starting", async () => {
      mocks.startSandboxProxy.mockRejectedValue(new Error("compose up failed"));

      await expect(runSandboxStep(ENV, deps)).rejects.toThrow("compose up failed");
      expect(mocks.onCancel).not.toHaveBeenCalled();
    });

    // The command wrote a backing copy; the real file is written from it after
    // the command stops, before the report appends its own outputs.
    it("writes $GITHUB_OUTPUT back once the command has stopped, before the report", async () => {
      await runSandboxStep(ENV, deps);

      expect(mocks.writeBackOutputFile).toHaveBeenCalledExactlyOnceWith(
        expect.stringMatching(/GITHUB_OUTPUT$/),
        ENV.GITHUB_OUTPUT,
      );
      const writeBack = orderOf(mocks.writeBackOutputFile);
      expect(orderOf(mocks.runSandboxedCommand)).toBeLessThan(writeBack);
      expect(writeBack).toBeLessThan(orderOf(mocks.readStepFilesystemAudit));
      expect(writeBack).toBeLessThan(orderOf(mocks.reportStepTraffic));
      expect(annotation.error).not.toHaveBeenCalled();
    });

    // The runner applies the file after ::set-output commands, and its last
    // entry for a name, so an empty value there overrides any the command set.
    it("then sets both names empty, before the report sets them", async () => {
      await runSandboxStep(ENV, deps);

      expect(mocks.setTrafficArtifactOutput.mock.calls).toStrictEqual([[""]]);
      expect(mocks.setFilesystemAuditOutput.mock.calls).toStrictEqual([[""]]);
      expect(orderOf(mocks.writeBackOutputFile)).toBeLessThan(
        orderOf(mocks.setTrafficArtifactOutput),
      );
      expect(orderOf(mocks.setFilesystemAuditOutput)).toBeLessThan(
        orderOf(mocks.readStepFilesystemAudit),
      );
    });

    it("still sets the other name empty and reports when one cannot be set", async () => {
      mocks.setTrafficArtifactOutput.mockImplementation(() => {
        throw new Error("EACCES");
      });

      await expect(runSandboxStep(ENV, deps)).resolves.toBe(0);
      expect(mocks.setFilesystemAuditOutput).toHaveBeenCalledWith("");
      expect(mocks.reportStepTraffic).toHaveBeenCalledTimes(1);
    });

    it("writes nothing back and still reports where the runner gave neither file", async () => {
      await runSandboxStep({ ...ENV, GITHUB_OUTPUT: "", GITHUB_STEP_SUMMARY: "" }, deps);
      expect(mocks.writeBackOutputFile).not.toHaveBeenCalled();
      expect(mocks.writeRunnerFile).not.toHaveBeenCalled();
      expect(mocks.reportStepTraffic).toHaveBeenCalledTimes(1);
    });

    it("fails the step but still reports when $GITHUB_OUTPUT held what the runner cannot read", async () => {
      mocks.writeBackOutputFile.mockReturnValue({
        error: 'line 2, output "x", never reaches its delimiter "NEVER"',
      });

      await expect(runSandboxStep(ENV, deps)).resolves.toBe(0);
      expect(annotation.error).toHaveBeenCalledWith(
        '$GITHUB_OUTPUT was written without what the runner could not read: line 2, output "x", never reaches its delimiter "NEVER"; failing the step',
      );
      expect(process.exitCode).toBe(1);
      expect(mocks.reportStepTraffic).toHaveBeenCalledTimes(1);
      expect(mocks.stopSandboxProxy).toHaveBeenCalledTimes(1);
    });

    it("fails the step but still reports when $GITHUB_OUTPUT's real file cannot be written", async () => {
      mocks.writeBackOutputFile.mockImplementation(() => {
        throw new Error("EACCES");
      });

      await expect(runSandboxStep(ENV, deps)).resolves.toBe(0);
      expect(annotation.error).toHaveBeenCalledWith(
        "$GITHUB_OUTPUT could not be written: EACCES; failing the step",
      );
      expect(process.exitCode).toBe(1);
      expect(mocks.reportStepTraffic).toHaveBeenCalledTimes(1);
    });

    // Written before the report so a cancelled step keeps it; the report step
    // moves it after its own part.
    it("writes $GITHUB_STEP_SUMMARY back as it is before the report, and says how much", async () => {
      mocks.readBackingFile.mockImplementation((path: string) =>
        path.endsWith("GITHUB_STEP_SUMMARY") ? { bytes: Buffer.from("```\nlog") } : { empty: true },
      );

      await runSandboxStep(ENV, deps);

      expect(mocks.writeRunnerFile).toHaveBeenCalledWith(
        ENV.GITHUB_STEP_SUMMARY,
        Buffer.from("```\nlog"),
      );
      expect(orderOf(mocks.writeRunnerFile)).toBeLessThan(orderOf(mocks.reportStepTraffic));
      expect(mocks.reportStepTraffic.mock.calls[0][0].commandSummaryBytes).toBe(7);
      expect(annotation.error).not.toHaveBeenCalled();
    });

    it("reads $GITHUB_STEP_SUMMARY back up to GitHub's 1 MiB limit", async () => {
      await runSandboxStep(ENV, deps);

      expect(mocks.readBackingFile).toHaveBeenCalledExactlyOnceWith(
        expect.stringMatching(/GITHUB_STEP_SUMMARY$/),
        1024 * 1024,
      );
    });

    // GitHub drops a summary over its limit whole without failing the step.
    it("writes a note in place of a $GITHUB_STEP_SUMMARY over the limit, without failing", async () => {
      mocks.readBackingFile.mockImplementation((path: string) =>
        path.endsWith("GITHUB_STEP_SUMMARY") ? { oversize: 1024 * 1024 + 1 } : { empty: true },
      );

      await expect(runSandboxStep(ENV, deps)).resolves.toBe(0);

      // Rounded up: a byte over the limit does not read as 1024 KiB.
      const message =
        "This step's own Job Summary was dropped: at 1025 KiB it was over GitHub's 1 MiB limit.";
      const note = Buffer.from(`> ⚠️ ${message}\n`);
      expect(mocks.writeRunnerFile).toHaveBeenCalledWith(ENV.GITHUB_STEP_SUMMARY, note);
      expect(annotation.warning).toHaveBeenCalledWith(message);
      expect(mocks.reportStepTraffic.mock.calls[0][0].commandSummaryBytes).toBe(note.length);
      expect(annotation.error).not.toHaveBeenCalled();
      expect(process.exitCode).toBeUndefined();
    });

    it("fails the step but still reports when the $GITHUB_OUTPUT backing was not a regular file", async () => {
      mocks.writeBackOutputFile.mockReturnValue({ reason: "it was not a regular file" });

      await expect(runSandboxStep(ENV, deps)).resolves.toBe(0);
      expect(annotation.error).toHaveBeenCalledWith(
        "$GITHUB_OUTPUT it was not a regular file; failing the step",
      );
      expect(process.exitCode).toBe(1);
      expect(mocks.reportStepTraffic).toHaveBeenCalledTimes(1);
    });

    it("counts nothing of a $GITHUB_STEP_SUMMARY it could not write", async () => {
      mocks.readBackingFile.mockImplementation((path: string) =>
        path.endsWith("GITHUB_STEP_SUMMARY") ? { bytes: Buffer.from("mine\n") } : { empty: true },
      );
      mocks.writeRunnerFile.mockImplementation((path: string) => {
        if (path === ENV.GITHUB_STEP_SUMMARY) throw new Error("EACCES");
      });

      await runSandboxStep(ENV, deps);

      expect(mocks.reportStepTraffic.mock.calls[0][0].commandSummaryBytes).toBe(0);
      expect(annotation.error).toHaveBeenCalledWith(
        "$GITHUB_STEP_SUMMARY could not be written: EACCES; failing the step",
      );
    });

    it("fails the step but still reports when the $GITHUB_STEP_SUMMARY backing was not a regular file", async () => {
      mocks.readBackingFile.mockImplementation((path: string) =>
        path.endsWith("GITHUB_STEP_SUMMARY")
          ? { reason: "it was not a regular file" }
          : { empty: true },
      );

      await expect(runSandboxStep(ENV, deps)).resolves.toBe(0);
      expect(mocks.writeRunnerFile).toHaveBeenCalledWith(ENV.GITHUB_STEP_SUMMARY, Buffer.alloc(0));
      expect(annotation.error).toHaveBeenCalledWith(
        "$GITHUB_STEP_SUMMARY it was not a regular file; failing the step",
      );
      expect(process.exitCode).toBe(1);
      expect(mocks.reportStepTraffic).toHaveBeenCalledTimes(1);
    });

    it("writes back none of the runner files the plan leaves under the overlay", async () => {
      mocks.resolveFilesystemPlan.mockReturnValue({
        overlayRoots: ["/home/runner"],
        writeThroughPaths: [],
        mediatedVariables: [],
      });
      await runSandboxStep(ENV, deps);

      expect(mocks.mediateRunnerOutputFiles.mock.calls[0][1]).toStrictEqual([]);
      expect(mocks.writeBackOutputFile).not.toHaveBeenCalled();
      expect(mocks.writeRunnerFile).not.toHaveBeenCalled();
      expect(mocks.removeBackingDir).not.toHaveBeenCalled();
      expect(mocks.readStepFilesystemAudit.mock.calls[0][0].mediated).toStrictEqual([]);
    });

    it("tells the audit report which runner files were mediated", async () => {
      mocks.resolveFilesystemPlan.mockReturnValue({
        overlayRoots: ["/home/runner"],
        writeThroughPaths: [],
        mediatedVariables: ["GITHUB_OUTPUT"],
      });
      await runSandboxStep(ENV, deps);

      expect(mocks.readStepFilesystemAudit.mock.calls[0][0].mediated).toStrictEqual([
        "GITHUB_OUTPUT",
      ]);
    });

    // The sandbox sees the backing directory only through its bind, and the
    // post step finds it by the container name.
    it("keeps the backing directory beside the scratch dir, and removes it after the write-back", async () => {
      await runSandboxStep(ENV, deps);

      const backingDir = `${SANDBOX_SCRATCH_BASE}/runner-files-deadbeef`;
      expect(mocks.mediateRunnerOutputFiles.mock.calls[0][2]).toBe(backingDir);
      expect(mocks.removeBackingDir).toHaveBeenCalledExactlyOnceWith(backingDir);
      expect(orderOf(mocks.writeRunnerFile)).toBeLessThan(orderOf(mocks.removeBackingDir));
    });

    // The command can leave a subdirectory it made unreadable there.
    it("warns but still reports when the backing directory cannot be removed", async () => {
      mocks.removeBackingDir.mockImplementation(() => {
        throw new Error("EACCES");
      });

      await expect(runSandboxStep(ENV, deps)).resolves.toBe(0);
      expect(mocks.warn).toHaveBeenCalledWith(
        expect.stringMatching(/^Could not remove .*: EACCES$/),
      );
      expect(mocks.reportStepTraffic).toHaveBeenCalledTimes(1);
      expect(mocks.stopSandboxProxy).toHaveBeenCalledTimes(1);
    });

    it("writes nothing back where the runner gave no $GITHUB_STEP_SUMMARY", async () => {
      await runSandboxStep({ ...ENV, GITHUB_STEP_SUMMARY: "" }, deps);
      expect(mocks.writeRunnerFile).not.toHaveBeenCalled();
      expect(mocks.writeBackOutputFile.mock.calls[0][1]).toBe(ENV.GITHUB_OUTPUT);
    });

    it("writes nothing back where the runner gave no $GITHUB_OUTPUT", async () => {
      await runSandboxStep({ ...ENV, GITHUB_OUTPUT: "" }, deps);
      expect(mocks.writeBackOutputFile).not.toHaveBeenCalled();
      const written = mocks.writeRunnerFile.mock.calls.map((c: unknown[]) => c[0]);
      expect(written).toStrictEqual([ENV.GITHUB_STEP_SUMMARY]);
      expect(mocks.setTrafficArtifactOutput).toHaveBeenCalledWith("");
    });

    it("creates nothing when docker or sudo cannot be pinned", async () => {
      mocks.pinHostCommands.mockImplementation(() => {
        throw new SandboxError("no docker", "HOST_COMMAND_UNPINNABLE");
      });

      await expect(runSandboxStep(ENV, deps)).rejects.toThrow("no docker");
      expect(mocks.checkPasswordlessSudo).not.toHaveBeenCalled();
      expect(mocks.resolveFilesystemPlan).not.toHaveBeenCalled();
    });
  });

  describe("cancellation", () => {
    /** The listener the step handed onCancel. */
    function cancelListener(): () => void {
      return mocks.onCancel.mock.calls[0][0] as () => void;
    }

    it("listens from after the proxy starts until after it is stopped", async () => {
      await runSandboxStep(ENV, deps);

      expect(orderOf(mocks.startSandboxProxy)).toBeLessThan(orderOf(mocks.onCancel));
      expect(orderOf(mocks.onCancel)).toBeLessThan(orderOf(mocks.runSandboxedCommand));
      expect(orderOf(mocks.stopSandboxProxy)).toBeLessThan(orderOf(stopListening));
    });

    it("stops listening when the command fails", async () => {
      mocks.runSandboxedCommand.mockRejectedValue(new Error("runc: exec failed"));

      await expect(runSandboxStep(ENV, deps)).rejects.toThrow("runc: exec failed");
      expect(stopListening).toHaveBeenCalledTimes(1);
    });

    it("aborts the sandbox's cancel signal, says so once, and still reports", async () => {
      let cancel: AbortSignal | undefined;
      mocks.runSandboxedCommand.mockImplementation(async (options: { cancel: AbortSignal }) => {
        cancel = options.cancel;
        expect(cancel.aborted).toBe(false);
        cancelListener()();
        cancelListener()();
        return 143;
      });

      await expect(runSandboxStep(ENV, deps)).resolves.toBe(143);
      expect(cancel?.aborted).toBe(true);
      expect(
        mocks.info.mock.calls.filter(([message]) => String(message).includes("cancelled")),
      ).toStrictEqual([["buildcage: the step was cancelled; stopping the sandbox"]]);
      expect(mocks.reportStepTraffic).toHaveBeenCalledTimes(1);
      expect(mocks.stopSandboxProxy).toHaveBeenCalledTimes(1);
    });

    // The upload is what takes long, so the summary goes out before it.
    it("writes the whole summary before the upload once cancelled, naming the artifact to come", async () => {
      const read = readAudit({ expected: { name: "to-come" } });
      mocks.readStepFilesystemAudit.mockReturnValue(read);
      mocks.readFilesystemAuditInput.mockReturnValue("record");
      mocks.runSandboxedCommand.mockImplementation(async () => {
        cancelListener()();
        return 143;
      });

      await runSandboxStep(ENV, deps);

      expect(mocks.readStepFilesystemAudit.mock.calls[0][0].cancelled).toBe(true);
      const report = mocks.reportStepTraffic.mock.calls[0][0];
      report.moreBlocks(1_700_000_000, "build");
      expect(read.blocks).toHaveBeenCalledWith(1_700_000_000, { name: "to-come" }, "build");
      expect(read.upload).toHaveBeenCalledTimes(1);
      expect(orderOf(mocks.readStepFilesystemAudit)).toBeLessThan(orderOf(mocks.reportStepTraffic));
      expect(orderOf(mocks.reportStepTraffic)).toBeLessThan(orderOf(read.upload));
      expect(orderOf(read.upload)).toBeLessThan(orderOf(mocks.stopSandboxProxy));
    });
  });
});

describe("readStepInputs", () => {
  it("reads every input and checks the rules, before any privileged check", () => {
    const inputs = readStepInputs(ENV, deps);

    expect(inputs).toMatchObject({
      actionRef: "v1.2.3",
      runInput: "echo hello",
      proxyEngine: "universal",
      filesystemMode: "persistent",
      rules: { httpsRules: ["example.com:443"] },
      annotation,
    });
    expect(mocks.checkUrlAndTlsRuleSupport).toHaveBeenCalled();
    expect(mocks.readAwsKeyInputs).toHaveBeenCalled();
    expect(mocks.pinHostCommands).not.toHaveBeenCalled();
    expect(mocks.checkPasswordlessSudo).not.toHaveBeenCalled();
  });
});

describe("preflight", () => {
  it("returns the resolved plan, and starts no proxy", () => {
    mocks.resolveFilesystemPlan.mockReturnValue({
      overlayRoots: ["/home/runner"],
      writeThroughPaths: ["/opt/out"],
      mediatedVariables: RUNNER_FILES,
    });

    const plan = preflight(readStepInputs(ENV, deps), ENV, deps);

    expect(plan).toStrictEqual({
      overlayRoots: ["/home/runner"],
      writeThroughPaths: ["/opt/out"],
      mediatedVariables: RUNNER_FILES,
    });
    expect(mocks.readLocalImageOverride).not.toHaveBeenCalled();
    expect(mocks.startSandboxProxy).not.toHaveBeenCalled();
  });

  it("refuses root before checking anything else", () => {
    mocks.getuid.mockReturnValue(0);

    expect(() => preflight(readStepInputs(ENV, deps), ENV, deps)).toThrow(SandboxError);
    expect(mocks.validateFilesystemInputs).not.toHaveBeenCalled();
    expect(mocks.pinHostCommands).not.toHaveBeenCalled();
  });
});

describe("finalizeStep", () => {
  const run = (over: Partial<Parameters<typeof finalizeStep>[0]> = {}) => ({
    inputs: readStepInputs(ENV, deps),
    env: ENV,
    containerName: "buildcage-proxy-deadbeef",
    audit: undefined,
    auditAttached: () => false,
    mediation: undefined,
    runnerFilesBackingDir: "/var/tmp/buildcage-runner-files",
    cancelled: false,
    ...over,
  });

  it("reports, with nothing to write back", async () => {
    expect(await finalizeStep(run(), deps)).toBe(false);

    expect(mocks.readBackingFile).not.toHaveBeenCalled();
    expect(mocks.setTrafficArtifactOutput).toHaveBeenCalledWith("");
  });

  it("says a runner file it could not write back failed the step, and still reports", async () => {
    mocks.writeBackOutputFile.mockImplementation(() => {
      throw new Error("EACCES");
    });
    const mediation = {
      envOverrides: {},
      mounts: [],
      maskedPaths: [],
      files: [
        {
          variable: "GITHUB_OUTPUT" as const,
          realPath: ENV.GITHUB_OUTPUT,
          backingPath: "/b/GITHUB_OUTPUT",
        },
      ],
    };

    const failed = await finalizeStep(run({ mediation }), deps);

    expect(annotation.error).toHaveBeenCalledWith(
      "$GITHUB_OUTPUT could not be written: EACCES; failing the step",
    );
    expect(failed).toBe(true);
    expect(mocks.reportStepTraffic).toHaveBeenCalled();
  });
});

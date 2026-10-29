import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";

import { InvalidInputError } from "#core/lib/actions/inputs.ts";
import type { SummaryBlock } from "#core/lib/report/render/fit-step-summary.ts";

import { SandboxError } from "./errors.ts";
import type { RecordArtifact } from "./filesystem-audit/render.ts";
import type { ReadStepFilesystemAudit } from "./filesystem-audit/report.ts";
import { parseExpectedRules } from "./filesystem-audit/rules.ts";
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

const annotation = { notice: vi.fn(), warning: vi.fn(), error: vi.fn() };

// Each dependency is tested in its own file; what is left to check here is the
// order they run in, what each one is handed, and which of them still run when
// an earlier one fails.
const mocks = {
  applyConfigFile: vi.fn(),
  readRunCommand: vi.fn(),
  readProxyInputs: vi.fn(),
  readFilesystemInputs: vi.fn(),
  readFilesystemAuditInput: vi.fn(),
  readFilesystemAuditArtifactInputs: vi.fn(),
  readExpectedFilesystemRules: vi.fn(),
  readFailOnUnexpectedFileAccess: vi.fn(),
  readRuleInputs: vi.fn(),
  readFailOnCaResidue: vi.fn(),
  readFailOnBlocked: vi.fn(),
  readAwsKeyInputs: vi.fn(),
  readTrafficArtifactInputs: vi.fn(),
  readStepLabel: vi.fn(),
  readWorkingDirectory: vi.fn(),
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
  mocks.readExpectedFilesystemRules.mockReturnValue(undefined);
  mocks.readFailOnUnexpectedFileAccess.mockReturnValue(false);
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

// expected-filesystem-rules as readExpectedFilesystemRules gives them.
function givenRules(text: string, origin: "input" | "config" = "input") {
  const parsed = parseExpectedRules([{ text, origin, firstLine: 1 }]);
  return { expected: parsed.rules.length ? parsed : undefined };
}

describe("runSandboxStep", () => {
  it("applies config-file to the step's env before reading any input, and warns of what it ignored", async () => {
    mocks.applyConfigFile.mockReturnValue({
      path: "/home/runner/work/repo/repo/c.yml",
      warning: "Ignored from config-file c.yml, set by the workflow: proxy-mode",
      origins: new Map(),
    });

    await runSandboxStep(ENV, deps);

    expect(mocks.applyConfigFile).toHaveBeenCalledWith(
      ENV,
      expect.objectContaining({ known: expect.arrayContaining(["proxy-mode"]) }),
      ENV.GITHUB_WORKSPACE,
    );
    expect(orderOf(mocks.applyConfigFile)).toBeLessThan(orderOf(mocks.readRunCommand));
    expect(mocks.warn).toHaveBeenCalledWith(
      "Ignored from config-file c.yml, set by the workflow: proxy-mode",
    );
  });

  it("reads an input's underscore spelling, before config-file, and warns of one it ignored", async () => {
    const env = {
      ...ENV,
      INPUT_CONFIG_FILE: "c.yml",
      INPUT_PROXY_MODE: "audit",
      "INPUT_PROXY-MODE": "restrict",
    };
    mocks.applyConfigFile.mockImplementation((seen: NodeJS.ProcessEnv) => {
      expect(seen).toMatchObject({ "INPUT_CONFIG-FILE": "c.yml", "INPUT_PROXY-MODE": "restrict" });
      expect(seen).not.toHaveProperty("INPUT_PROXY_MODE");
    });

    await runSandboxStep(env, deps);

    expect(mocks.warn).toHaveBeenCalledWith("Ignored proxy_mode, as proxy-mode is also set.");
  });

  it("joins a list input's two spellings", async () => {
    const env = { ...ENV, INPUT_WRITE_THROUGH: "./a", "INPUT_WRITE-THROUGH": "./b" };
    mocks.applyConfigFile.mockImplementation((seen: NodeJS.ProcessEnv) => {
      expect(seen["INPUT_WRITE-THROUGH"]).toBe("./b\n./a");
    });

    await runSandboxStep(env, deps);

    expect(mocks.applyConfigFile).toHaveBeenCalled();
    expect(mocks.warn).not.toHaveBeenCalled();
  });

  it("drops an input's underscore spelling from env too", async () => {
    const env = { ...ENV, INPUT_FAIL_ON_BLOCKED: "false" };

    await runSandboxStep(env, deps);

    expect(env).not.toHaveProperty("INPUT_FAIL_ON_BLOCKED");
    expect(env).not.toHaveProperty("INPUT_FAIL-ON-BLOCKED");
  });

  it("saves the merged write-through for the post step when config-file was read", async () => {
    mocks.applyConfigFile.mockReturnValue({ path: "/w/c.yml", origins: new Map() });
    mocks.readFilesystemInputs.mockReturnValue({
      filesystemMode: "persistent",
      writeThroughInput: "/opt/cache",
    });

    await runSandboxStep(ENV, deps);

    expect(mocks.saveWriteThroughForPost).toHaveBeenCalledWith(ENV, "/opt/cache");
    expect(orderOf(mocks.saveWriteThroughForPost)).toBeLessThan(orderOf(mocks.runSandboxedCommand));
  });

  it("saves nothing without config-file, leaving post the workflow's own input", async () => {
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

  it("passes the audit output paths to the command under filesystem-audit: record", async () => {
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

  it("drops this action's inputs from env once every one is read", async () => {
    const env = {
      ...ENV,
      INPUT_RUN: "echo hello",
      "INPUT_EXPECTED-FILESYSTEM-RULES": "* R ./a\n".repeat(20_000),
      INPUT_DIR: "the workflow's own",
    };
    let lastRead: string | undefined;
    mocks.readAwsKeyInputs.mockImplementation((_: unknown, e: NodeJS.ProcessEnv) => {
      lastRead = e.INPUT_RUN;
      return { key: "", roleAccounts: [] };
    });

    await runSandboxStep(env, deps);

    expect(lastRead).toBe("echo hello");
    expect(env).toStrictEqual({ ...ENV, INPUT_DIR: "the workflow's own" });
  });

  it("hands the report the inputs read up front", async () => {
    mocks.readFailOnBlocked.mockReturnValue(false);
    mocks.readTrafficArtifactInputs.mockReturnValue({ upload: true, retentionDays: 7 });
    mocks.readStepLabel.mockReturnValue("build");

    await runSandboxStep(ENV, deps);

    expect(mocks.reportStepTraffic.mock.calls[0][0]).toMatchObject({
      failOnBlocked: false,
      trafficArtifact: { upload: true, retentionDays: 7 },
      stepLabel: "build",
    });
  });

  it("reads expected-filesystem-rules once config-file joined its own, with where they start", async () => {
    const origin = { offset: 1, line: 3 };
    mocks.applyConfigFile.mockImplementation((env: NodeJS.ProcessEnv) => {
      env["INPUT_EXPECTED-FILESYSTEM-RULES"] = "* R ./a\n* R ./b";
      return { path: "/w/c.yml", origins: new Map([["expected-filesystem-rules", origin]]) };
    });
    mocks.readFilesystemAuditInput.mockReturnValue("record");

    await runSandboxStep({ ...ENV, "INPUT_EXPECTED-FILESYSTEM-RULES": "* R ./a" }, deps);

    expect(mocks.readExpectedFilesystemRules).toHaveBeenCalledWith(
      "* R ./a\n* R ./b",
      origin,
      "record",
    );
  });

  it("refuses fail-on-unexpected-file-access without filesystem-audit: record, before any setup", async () => {
    mocks.readFailOnUnexpectedFileAccess.mockReturnValue(true);

    await expect(runSandboxStep(ENV, deps)).rejects.toThrow(
      "fail-on-unexpected-file-access needs filesystem-audit: record",
    );
    expect(mocks.checkScratchBaseParent).not.toHaveBeenCalled();
  });

  it("runs as if rules all commented out were unset, and warns of them once, fail-on-unexpected-file-access's effect included", async () => {
    mocks.readFilesystemAuditInput.mockReturnValue("record");
    mocks.readFailOnUnexpectedFileAccess.mockReturnValue(true);
    mocks.readExpectedFilesystemRules.mockReturnValue(givenRules("# node R ./a"));

    await runSandboxStep(ENV, deps);

    expect(mocks.readStepFilesystemAudit.mock.calls[0][0]).toMatchObject({ rules: undefined });
    // Once, for the one cause.
    expect(annotation.warning).toHaveBeenCalledWith(
      "expected-filesystem-rules holds only comments and blank lines, so the step runs as if it were not set, " +
        "and fail-on-unexpected-file-access fails it on every file access.",
    );
    expect(annotation.warning).toHaveBeenCalledTimes(2);
  });

  it("warns of rules all commented out without fail-on-unexpected-file-access", async () => {
    mocks.readFilesystemAuditInput.mockReturnValue("record");
    mocks.readExpectedFilesystemRules.mockReturnValue(givenRules("# node R ./a"));

    await runSandboxStep(ENV, deps);

    expect(annotation.warning).toHaveBeenCalledWith(
      "expected-filesystem-rules holds only comments and blank lines, so the step runs as if it were not set.",
    );
  });

  it("reads no inline expected-filesystem-rules when the workflow set none", async () => {
    await runSandboxStep(ENV, deps);

    expect(mocks.readExpectedFilesystemRules).toHaveBeenCalledWith("", undefined, "off");
  });

  it("fails before any setup on an allowed rule list too long for the proxy's environment", async () => {
    mocks.readRuleInputs.mockReturnValue({
      httpsRules: Array.from({ length: 12_000 }, () => "a.example.com:443"),
      httpRules: [],
      ipRules: [],
      urlRules: [],
      tlsRules: [],
      knownBlockedRules: [],
    });

    await expect(runSandboxStep(ENV, deps)).rejects.toThrow("allowed-https-rules is");
    expect(mocks.checkUrlAndTlsRuleSupport).toHaveBeenCalled();
    expect(mocks.checkPasswordlessSudo).not.toHaveBeenCalled();
    expect(mocks.startSandboxProxy).not.toHaveBeenCalled();
  });

  it.each([
    "readExpectedFilesystemRules",
    "readFailOnUnexpectedFileAccess",
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
  it("pins against persistent mode's paths plus write-through in ephemeral mode too", async () => {
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
    mocks.applyConfigFile.mockReturnValue({ path: "/w/c.yml", origins: new Map() });
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

  it("validates the write-through lines, resolved without touching the host", async () => {
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

  it("warns that write-through: / gives up the outbound restriction too", async () => {
    mocks.readFilesystemInputs.mockReturnValue({
      filesystemMode: "persistent",
      writeThroughInput: "/opt/cache\n/",
    });

    await runSandboxStep(ENV, deps);

    expect(annotation.warning).toHaveBeenCalledExactlyOnceWith(WRITE_THROUGH_ALL_WARNING);
  });

  it("does not warn when write-through names only narrower paths", async () => {
    mocks.readFilesystemInputs.mockReturnValue({
      filesystemMode: "persistent",
      writeThroughInput: "/opt/cache",
    });

    await runSandboxStep(ENV, deps);

    expect(annotation.warning).not.toHaveBeenCalled();
  });

  it("fails on a write-through entry that does not parse before any setup", async () => {
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
      "aws-key-check: true",
      'allowed-aws-role-accounts: "111111111111"',
    ]);
    expect(log).toHaveBeenCalledWith("AWS access key check: on");
    expect(log).toHaveBeenCalledWith("AWS role accounts: 111111111111");
    expect(log.mock.calls.flat().join("\n").includes(`${ASIA}AAAAAAAAAAAAAAAA`)).toBe(false);
  });

  it("carries the filesystem inputs into the restrict example after the AWS ones", async () => {
    mocks.readAwsKeyInputs.mockReturnValue({ key: `${ASIA}AAAAAAAAAAAAAAAA`, roleAccounts: [] });
    mocks.readFilesystemAuditInput.mockReturnValue("record");

    await runSandboxStep(ENV, deps);

    expect(mocks.reportStepTraffic.mock.calls[0][0].extraInputs({ timeline: [] })).toStrictEqual([
      "aws-key-check: true",
      "filesystem-audit: record",
    ]);
  });

  it("leaves the step's expected rules out of the restrict example, pointing to the guide", async () => {
    mocks.readFilesystemAuditInput.mockReturnValue("record");
    mocks.readExpectedFilesystemRules.mockReturnValue(givenRules("node R ./a", "config"));

    await runSandboxStep(ENV, deps);

    const inputs: string[] = mocks.reportStepTraffic.mock.calls[0][0].extraInputs({ timeline: [] });
    expect(inputs.join("\n")).not.toContain("node R ./a");
    expect(inputs).toContainEqual(
      expect.stringMatching(
        /^# See https:\/\/github\.com\/buildcage\/isolated-run\/blob\/.+\/docs\/filesystem-audit\.md#expected-accesses$/,
      ),
    );
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
      composeFiles: [expect.stringContaining("compose.action.yaml")],
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

  it("skips provenance verification and layers a local override's compose file on the shipped one", async () => {
    mocks.readLocalImageOverride.mockResolvedValue({
      imageRef: "local:dev",
      pullPolicy: "never",
      composeOverlay: "/repo/docker/compose.action.test-inspect.yaml",
    });

    await runSandboxStep(ENV, deps);

    expect(mocks.verifyImageDigestOrThrow).not.toHaveBeenCalled();
    expect(mocks.startSandboxProxy.mock.calls[0][0]).toMatchObject({
      pullPolicy: "never",
      composeFiles: [
        expect.stringMatching(/\/compose\.action\.yaml$/),
        "/repo/docker/compose.action.test-inspect.yaml",
      ],
    });
  });

  // A renamed input still works, so its migration notice is the only hint the
  // run gets; suppressing it with the rest of the annotations would leave a
  // workflow on the old spelling with nothing to go on.
  it("sends a renamed input's notice to the emitter the annotation gate cannot suppress", async () => {
    await runSandboxStep({ ...ENV, GITHUB_STEP_SUMMARY: "" }, deps);

    expect(mocks.readFilesystemInputs.mock.calls[0][0]).toBe(mocks.notice);
    expect(mocks.readFilesystemInputs.mock.calls[0][0]).not.toBe(annotation.notice);
  });

  it("gives the sandbox the emitter the annotation gate cannot suppress", async () => {
    await runSandboxStep({ ...ENV, GITHUB_STEP_SUMMARY: "" }, deps);

    expect(mocks.runSandboxedCommand.mock.calls[0][0].warn).toBe(mocks.warn);
    expect(mocks.runSandboxedCommand.mock.calls[0][0].warn).not.toBe(annotation.warning);
    expect(mocks.resolveFilesystemPlan.mock.calls[0][3]).toStrictEqual({
      baseDir: ENV.GITHUB_WORKSPACE,
      warn: mocks.warn,
    });
  });

  it("starts the command in working-directory and joins relative paths to it", async () => {
    const workingDirectory = {
      input: "app",
      dir: `${ENV.GITHUB_WORKSPACE}/app`,
      real: `${ENV.GITHUB_WORKSPACE}/packages/app`,
      isWorkspace: false,
    };
    mocks.readWorkingDirectory.mockReturnValue(workingDirectory);
    mocks.applyConfigFile.mockReturnValue(undefined);
    mocks.readFilesystemInputs.mockReturnValue({
      filesystemMode: "persistent",
      writeThroughInput: "bin",
    });

    await runSandboxStep({ ...ENV }, deps);

    expect(orderOf(mocks.readWorkingDirectory)).toBeLessThan(orderOf(mocks.applyConfigFile));
    expect(mocks.applyConfigFile.mock.calls[0][2]).toBe(workingDirectory.dir);
    expect(mocks.resolveFilesystemPlan.mock.calls[0][3].baseDir).toBe(workingDirectory.dir);
    expect(mocks.pinHostCommands.mock.calls[0][0]).toContain(`${workingDirectory.dir}/bin`);
    expect(mocks.runSandboxedCommand.mock.calls[0][0]).toMatchObject({
      workingDirectory,
      envOverrides: { PWD: workingDirectory.dir },
    });
    expect(mocks.readStepFilesystemAudit.mock.calls[0][0].workingDirectory).toBe(
      workingDirectory.dir,
    );
  });

  it("sets PWD to the workspace without working-directory", async () => {
    await runSandboxStep({ ...ENV }, deps);

    expect(mocks.runSandboxedCommand.mock.calls[0][0].envOverrides).toStrictEqual({
      PWD: ENV.GITHUB_WORKSPACE,
    });
  });

  it("refuses a bad working-directory before reading config-file", async () => {
    mocks.readWorkingDirectory.mockImplementation(() => {
      throw new SandboxError("no such directory", "INVALID_WORKING_DIRECTORY");
    });

    await expect(runSandboxStep({ ...ENV }, deps)).rejects.toThrow("no such directory");
    expect(mocks.applyConfigFile).not.toHaveBeenCalled();
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

  it("checks known-blocked-rules URL lines against the engine, host lines excluded", async () => {
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

    it("fails the step, still reporting and stopping the proxy, when a runner file fails", async () => {
      mocks.writeBackOutputFile.mockImplementation(() => {
        throw new Error("EACCES");
      });

      await expect(runSandboxStep(ENV, deps)).resolves.toBe(0);
      expect(process.exitCode).toBe(1);
      expect(mocks.reportStepTraffic).toHaveBeenCalledTimes(1);
      expect(mocks.stopSandboxProxy).toHaveBeenCalledTimes(1);
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

    // The sandbox sees the backing directory only through its bind, and the
    // post step finds it by the container name.
    it("keeps the backing directory beside the scratch dir, and removes it after the write-back", async () => {
      await runSandboxStep(ENV, deps);

      const backingDir = `${SANDBOX_SCRATCH_BASE}/runner-files-deadbeef`;
      expect(mocks.mediateRunnerOutputFiles.mock.calls[0][2]).toBe(backingDir);
      expect(mocks.removeBackingDir).toHaveBeenCalledExactlyOnceWith(backingDir);
      expect(orderOf(mocks.writeRunnerFile)).toBeLessThan(orderOf(mocks.removeBackingDir));
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
    mocks.readStepLabel.mockReturnValue("build");
    const inputs = readStepInputs(ENV, deps);

    expect(inputs).toMatchObject({
      actionRef: "v1.2.3",
      runInput: "echo hello",
      proxyEngine: "universal",
      filesystemMode: "persistent",
      rules: { httpsRules: ["example.com:443"] },
      stepLabel: "build",
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

  /** The mediation of `variables`, each backed under /b. */
  const mediating = (...variables: (typeof RUNNER_FILES)[number][]) => ({
    envOverrides: {},
    mounts: [],
    maskedPaths: [],
    files: variables.map((variable) => ({
      variable,
      realPath: ENV[variable],
      backingPath: `/b/${variable}`,
    })),
  });
  const both = mediating(...RUNNER_FILES);

  /** The step summary's backing copy reads as `read`, the output's as empty. */
  function summaryReads(read: unknown) {
    mocks.readBackingFile.mockImplementation((path: string) =>
      path.endsWith("GITHUB_STEP_SUMMARY") ? read : { empty: true },
    );
  }

  it("reports, with nothing to write back", async () => {
    expect(await finalizeStep(run(), deps)).toBe(false);

    expect(mocks.readBackingFile).not.toHaveBeenCalled();
    expect(mocks.setTrafficArtifactOutput).toHaveBeenCalledWith("");
  });

  it("writes back only the runner files it mediated", async () => {
    await finalizeStep(run({ mediation: mediating("GITHUB_STEP_SUMMARY") }), deps);
    expect(mocks.writeBackOutputFile).not.toHaveBeenCalled();
    expect(mocks.writeRunnerFile.mock.calls.map((c: unknown[]) => c[0])).toStrictEqual([
      ENV.GITHUB_STEP_SUMMARY,
    ]);

    vi.clearAllMocks();
    await finalizeStep(run({ mediation: mediating("GITHUB_OUTPUT") }), deps);
    expect(mocks.writeBackOutputFile).toHaveBeenCalledExactlyOnceWith(
      "/b/GITHUB_OUTPUT",
      ENV.GITHUB_OUTPUT,
    );
    expect(mocks.writeRunnerFile).not.toHaveBeenCalled();
  });

  it("tells the audit report which runner files were mediated", async () => {
    await finalizeStep(run({ mediation: mediating("GITHUB_OUTPUT") }), deps);

    expect(mocks.readStepFilesystemAudit.mock.calls[0][0].mediated).toStrictEqual([
      "GITHUB_OUTPUT",
    ]);
  });

  it("still sets the other name empty and reports when one cannot be set", async () => {
    mocks.setTrafficArtifactOutput.mockImplementation(() => {
      throw new Error("EACCES");
    });

    expect(await finalizeStep(run(), deps)).toBe(false);
    expect(mocks.setFilesystemAuditOutput).toHaveBeenCalledWith("");
    expect(mocks.reportStepTraffic).toHaveBeenCalledTimes(1);
  });

  it.each([
    [
      "its real file cannot be written",
      () => {
        throw new Error("EACCES");
      },
      "$GITHUB_OUTPUT could not be written: EACCES; failing the step",
    ],
    [
      "it held what the runner cannot read",
      () => ({ error: 'line 2, output "x", never reaches its delimiter "NEVER"' }),
      '$GITHUB_OUTPUT was written without what the runner could not read: line 2, output "x", never reaches its delimiter "NEVER"; failing the step',
    ],
    [
      "its backing was not a regular file",
      () => ({ reason: "it was not a regular file" }),
      "$GITHUB_OUTPUT it was not a regular file; failing the step",
    ],
  ])("fails the step but still reports when $GITHUB_OUTPUT %s", async (_, writeBack, error) => {
    mocks.writeBackOutputFile.mockImplementation(writeBack);

    expect(await finalizeStep(run({ mediation: both }), deps)).toBe(true);
    expect(annotation.error).toHaveBeenCalledWith(error);
    expect(mocks.reportStepTraffic).toHaveBeenCalledTimes(1);
  });

  // Written before the report so a cancelled step keeps it; the report step
  // moves it after its own part.
  it("writes $GITHUB_STEP_SUMMARY back as it is before the report, and says how much", async () => {
    summaryReads({ bytes: Buffer.from("```\nlog") });

    expect(await finalizeStep(run({ mediation: both }), deps)).toBe(false);

    expect(mocks.writeRunnerFile).toHaveBeenCalledWith(
      ENV.GITHUB_STEP_SUMMARY,
      Buffer.from("```\nlog"),
    );
    expect(orderOf(mocks.writeRunnerFile)).toBeLessThan(orderOf(mocks.reportStepTraffic));
    expect(mocks.reportStepTraffic.mock.calls[0][0].commandSummaryBytes).toBe(7);
    expect(annotation.error).not.toHaveBeenCalled();
  });

  it("reads $GITHUB_STEP_SUMMARY back up to GitHub's 1 MiB limit", async () => {
    await finalizeStep(run({ mediation: both }), deps);

    expect(mocks.readBackingFile).toHaveBeenCalledExactlyOnceWith(
      "/b/GITHUB_STEP_SUMMARY",
      1024 * 1024,
    );
  });

  // GitHub drops a summary over its limit whole without failing the step.
  it("writes a note in place of a $GITHUB_STEP_SUMMARY over the limit, without failing", async () => {
    summaryReads({ oversize: 1024 * 1024 + 1 });

    expect(await finalizeStep(run({ mediation: both }), deps)).toBe(false);

    // Rounded up: a byte over the limit does not read as 1024 KiB.
    const message =
      "This step's own Job Summary was dropped: at 1025 KiB it was over GitHub's 1 MiB limit.";
    const note = Buffer.from(`> ⚠️ ${message}\n`);
    expect(mocks.writeRunnerFile).toHaveBeenCalledWith(ENV.GITHUB_STEP_SUMMARY, note);
    expect(annotation.warning).toHaveBeenCalledWith(message);
    expect(mocks.reportStepTraffic.mock.calls[0][0].commandSummaryBytes).toBe(note.length);
    expect(annotation.error).not.toHaveBeenCalled();
  });

  it("counts nothing of a $GITHUB_STEP_SUMMARY it could not write", async () => {
    summaryReads({ bytes: Buffer.from("mine\n") });
    mocks.writeRunnerFile.mockImplementation((path: string) => {
      if (path === ENV.GITHUB_STEP_SUMMARY) throw new Error("EACCES");
    });

    expect(await finalizeStep(run({ mediation: both }), deps)).toBe(true);

    expect(mocks.reportStepTraffic.mock.calls[0][0].commandSummaryBytes).toBe(0);
    expect(annotation.error).toHaveBeenCalledWith(
      "$GITHUB_STEP_SUMMARY could not be written: EACCES; failing the step",
    );
  });

  it("fails the step but still reports when the $GITHUB_STEP_SUMMARY backing was not a regular file", async () => {
    summaryReads({ reason: "it was not a regular file" });

    expect(await finalizeStep(run({ mediation: both }), deps)).toBe(true);
    expect(mocks.writeRunnerFile).toHaveBeenCalledWith(ENV.GITHUB_STEP_SUMMARY, Buffer.alloc(0));
    expect(annotation.error).toHaveBeenCalledWith(
      "$GITHUB_STEP_SUMMARY it was not a regular file; failing the step",
    );
    expect(mocks.reportStepTraffic).toHaveBeenCalledTimes(1);
  });

  // The command can leave a subdirectory it made unreadable there.
  it("warns but still reports when the backing directory cannot be removed", async () => {
    mocks.removeBackingDir.mockImplementation(() => {
      throw new Error("EACCES");
    });

    const step = run({ mediation: both });

    expect(await finalizeStep(step, deps)).toBe(false);
    expect(mocks.warn).toHaveBeenCalledWith(
      `Could not remove ${step.runnerFilesBackingDir}: EACCES`,
    );
    expect(mocks.reportStepTraffic).toHaveBeenCalledTimes(1);
  });
});

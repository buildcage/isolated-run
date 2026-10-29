import { mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { describe, it, expect, vi } from "vitest";
import { parse } from "yaml";

import { applyConfigFile } from "#core/lib/actions/config-file.ts";
import { InvalidInputError } from "#core/lib/actions/inputs.ts";
import type { TrafficEvent } from "#core/lib/log/traffic-event.ts";

import { parseAwsAccounts } from "../proxy/aws-keys.ts";
import { SandboxError } from "./errors.ts";
import {
  CONFIG_FILE_INPUTS,
  awsExampleInputs,
  readAwsKeyInputs,
  readProxyInputs,
  readFailOnBlocked,
  readFailOnCaResidue,
  readFailOnUnexpectedFileAccess,
  readFilesystemAuditInput,
  readFilesystemAuditArtifactInputs,
  readFilesystemInputs,
  readRunCommand,
  readStepLabel,
  resolveWriteThroughInput,
} from "./inputs.ts";

// Assembled at runtime: a literal shaped like an AWS access key ID trips
// secret scanning on push.
const ASIA = ["A", "S", "I", "A"].join("");

const silent = () => {};

describe("CONFIG_FILE_INPUTS", () => {
  it("names every action.yml input but run, writable, config-file itself and working-directory", () => {
    const actionYml = parse(readFileSync("action.yml", "utf8")) as { inputs: object };
    const inputs = Object.keys(actionYml.inputs).filter(
      (n) =>
        !["run", "writable", "config-file", "working-directory"].includes(n) && !n.includes("_"),
    );
    expect([...CONFIG_FILE_INPUTS.known].sort()).toEqual(inputs.sort());
  });

  it("merges only inputs it knows", () => {
    expect(CONFIG_FILE_INPUTS.known).toEqual(expect.arrayContaining([...CONFIG_FILE_INPUTS.lists]));
  });

  it("lets the workflow's allowed-aws-role-accounts replace the file's, and adds rule lines", () => {
    const workspace = mkdtempSync(join(tmpdir(), "config-file-"));
    writeFileSync(
      join(workspace, "buildcage.yml"),
      'allowed-aws-role-accounts: "222222222222"\nallowed-url-rules: GET https://b.example.com/**\n',
    );
    const env = (inline: NodeJS.ProcessEnv): NodeJS.ProcessEnv => ({
      GITHUB_WORKSPACE: workspace,
      GITHUB_EVENT_NAME: "push",
      "INPUT_CONFIG-FILE": "buildcage.yml",
      ...inline,
    });
    const set = env({
      "INPUT_ALLOWED-AWS-ROLE-ACCOUNTS": "111111111111",
      "INPUT_ALLOWED-URL-RULES": "GET https://a.example.com/**",
    });
    applyConfigFile(set, CONFIG_FILE_INPUTS);
    expect(set["INPUT_ALLOWED-AWS-ROLE-ACCOUNTS"]).toBe("111111111111");
    expect(set["INPUT_ALLOWED-URL-RULES"]).toBe(
      "GET https://a.example.com/**\nGET https://b.example.com/**",
    );
    const unset = env({});
    applyConfigFile(unset, CONFIG_FILE_INPUTS);
    expect(unset["INPUT_ALLOWED-AWS-ROLE-ACCOUNTS"]).toBe("222222222222");
  });
});

describe("resolveWriteThroughInput", () => {
  const inputs = (over: Partial<Parameters<typeof resolveWriteThroughInput>[0]> = {}) => ({
    writeThrough: "",
    writable: "",
    allowWrite: "",
    ...over,
  });

  it("returns write-through: as given", () => {
    expect(resolveWriteThroughInput(inputs({ writeThrough: "/opt/cache" }), silent)).toBe(
      "/opt/cache",
    );
  });

  it("accepts writable: as the pre-rename spelling, pointing at the new name", () => {
    const notice = vi.fn();

    expect(resolveWriteThroughInput(inputs({ writable: "/opt/cache" }), notice)).toBe("/opt/cache");
    expect(notice).toHaveBeenCalledWith(
      expect.stringContaining("writable: is now called write-through:"),
    );
  });

  // write-through may hold config-file's lines, which the workflow cannot see.
  it("joins writable:'s lines to write-through:'s when both are set", () => {
    const notice = vi.fn();

    expect(
      resolveWriteThroughInput(inputs({ writeThrough: "/opt/a", writable: "/opt/b" }), notice),
    ).toBe("/opt/a\n/opt/b");
    expect(notice).toHaveBeenCalledOnce();
  });

  it("rejects the removed allow_write: input rather than ignoring it", () => {
    expect.assertions(2);
    try {
      resolveWriteThroughInput(inputs({ allowWrite: "./dist" }), silent);
    } catch (err) {
      expect(err).toBeInstanceOf(SandboxError);
      expect((err as SandboxError).code).toBe("ALLOW_WRITE_REMOVED");
    }
  });

  it("returns an empty string when nothing is set", () => {
    expect(resolveWriteThroughInput(inputs(), silent)).toBe("");
  });
});

// ---------------------------------------------------------------------------
// The input reads themselves
// ---------------------------------------------------------------------------

/** Stands in for core.getInput, which returns "" for anything unset. */
function inputs(values: Record<string, string> = {}): (name: string) => string {
  return (name) => values[name] ?? "";
}

describe("readRunCommand", () => {
  it("returns the run script as given", () => {
    expect(readRunCommand(inputs({ run: "npm ci" }))).toBe("npm ci");
  });

  // Read untrimmed, so a heredoc or an indented block survives intact.
  it("keeps leading and trailing whitespace", () => {
    expect(readRunCommand(inputs({ run: "  npm ci\n" }))).toBe("  npm ci\n");
  });

  it("rejects an absent run input", () => {
    expect(() => readRunCommand(inputs())).toThrow(/'run' is required/);
  });

  it("rejects a run input that is only whitespace", () => {
    expect(() => readRunCommand(inputs({ run: "  \n\t" }))).toThrow(/'run' is required/);
  });
});

describe("readProxyInputs", () => {
  it("defaults to inspect and restrict when unset", () => {
    expect(readProxyInputs(inputs())).toStrictEqual({
      proxyEngine: "inspect",
      proxyMode: "restrict",
    });
  });

  it("reads both inputs", () => {
    expect(
      readProxyInputs(inputs({ "proxy-engine": "universal", "proxy-mode": "audit" })),
    ).toStrictEqual({ proxyEngine: "universal", proxyMode: "audit" });
  });

  it("rejects an unknown engine before an unknown mode", () => {
    expect(() =>
      readProxyInputs(inputs({ "proxy-engine": "nope", "proxy-mode": "Audit" })),
    ).toThrow(/Invalid proxy-engine/);
  });

  it("rejects an unknown mode", () => {
    expect(() => readProxyInputs(inputs({ "proxy-mode": "Audit" }))).toThrow(/Invalid proxy-mode/);
  });
});

describe("readFilesystemInputs", () => {
  it("defaults to persistent with no write-through entries", () => {
    expect(readFilesystemInputs(silent, inputs())).toStrictEqual({
      filesystemMode: "persistent",
      writeThroughInput: "",
    });
  });

  it("reads both inputs together", () => {
    expect(
      readFilesystemInputs(
        silent,
        inputs({ "filesystem-mode": "ephemeral", "write-through": "/tmp/out" }),
      ),
    ).toStrictEqual({ filesystemMode: "ephemeral", writeThroughInput: "/tmp/out" });
  });

  // resolveWriteThroughInput decides what these mean; what is left here is
  // that each of the three reaches it under its own name.
  it("hands writable: and allow_write: to resolveWriteThroughInput too", () => {
    expect(
      readFilesystemInputs(silent, inputs({ "write-through": "/a", writable: "/b" }))
        .writeThroughInput,
    ).toBe("/a\n/b");
    expect(() => readFilesystemInputs(silent, inputs({ allow_write: "/tmp/out" }))).toThrow(
      /allow_write: has been replaced/,
    );
  });

  it("passes its notice callback on, for the writable: rename notice", () => {
    const notice = vi.fn();

    readFilesystemInputs(notice, inputs({ writable: "/b" }));

    expect(notice).toHaveBeenCalledWith(expect.stringContaining("writable:"));
  });
});

describe("readFilesystemAuditInput", () => {
  it("defaults to off", () => {
    expect(readFilesystemAuditInput(inputs())).toBe("off");
  });

  it("reads record", () => {
    expect(readFilesystemAuditInput(inputs({ "filesystem-audit": "record" }))).toBe("record");
  });

  it("rejects an invalid value", () => {
    expect(() => readFilesystemAuditInput(inputs({ "filesystem-audit": "on" }))).toThrow(
      /Invalid filesystem-audit/,
    );
  });
});

describe("readFilesystemAuditArtifactInputs", () => {
  it("uploads nothing and leaves the retention to the repository when unset", () => {
    expect(readFilesystemAuditArtifactInputs(inputs())).toStrictEqual({
      upload: false,
      retentionDays: undefined,
    });
  });

  it("reads the upload switch and a whole number of days", () => {
    expect(
      readFilesystemAuditArtifactInputs(
        inputs({
          "upload-filesystem-audit-artifact": "true",
          "filesystem-audit-retention-days": "7",
        }),
      ),
    ).toStrictEqual({ upload: true, retentionDays: 7 });
  });

  it("rejects a value that is not true or false", () => {
    expect(() =>
      readFilesystemAuditArtifactInputs(inputs({ "upload-filesystem-audit-artifact": "yes" })),
    ).toThrow('Invalid upload-filesystem-audit-artifact: "yes". Must be true or false.');
  });

  it("rejects a non-positive or non-numeric retention even with nothing to upload", () => {
    expect(() =>
      readFilesystemAuditArtifactInputs(inputs({ "filesystem-audit-retention-days": "0" })),
    ).toThrow(/Invalid filesystem-audit-retention-days/);
  });
});

describe("readStepLabel", () => {
  it("returns the label when set", () => {
    expect(readStepLabel(inputs({ label: "install" }))).toBe("install");
  });

  it("returns undefined rather than an empty string when unset", () => {
    expect(readStepLabel(inputs())).toBeUndefined();
  });
});

describe.each([
  { name: "fail-on-ca-residue", read: readFailOnCaResidue, unset: true },
  { name: "fail-on-blocked", read: readFailOnBlocked, unset: true },
  { name: "fail-on-unexpected-file-access", read: readFailOnUnexpectedFileAccess, unset: false },
])("$name", ({ name, read, unset }) => {
  it("reads its own input", () => {
    expect(read(inputs({ [name]: String(!unset) }))).toBe(!unset);
  });

  it("takes the default when unset", () => {
    expect(read(inputs())).toBe(unset);
  });

  it("names the input when it refuses a value", () => {
    expect(() => read(inputs({ [name]: "yes" }))).toThrow(
      `Invalid ${name}: "yes". Must be true or false.`,
    );
  });
});

describe("readAwsKeyInputs", () => {
  const KEY = `${ASIA}AAAAAAAAAAAAAAAA`;
  const inspect = { proxyEngine: "inspect" } as const;
  const accounts = (value: string) =>
    inputs({ "aws-key-check": "true", "allowed-aws-role-accounts": value });
  const OFF = { key: "", roleAccounts: [] };

  it("leaves the check off when unset, whatever the environment holds", () => {
    expect(readAwsKeyInputs(inspect, { AWS_ACCESS_KEY_ID: KEY }, inputs())).toStrictEqual(OFF);
    expect(
      readAwsKeyInputs(inspect, { AWS_ACCESS_KEY_ID: KEY }, inputs({ "aws-key-check": "false" })),
    ).toStrictEqual(OFF);
  });

  it("pins the step's key with aws-key-check alone, learning no role's key", () => {
    expect(
      readAwsKeyInputs(inspect, { AWS_ACCESS_KEY_ID: KEY }, inputs({ "aws-key-check": "true" })),
    ).toStrictEqual({ key: KEY, roleAccounts: [] });
  });

  // Ahead of the engine and key checks.
  it.each([
    ["unset", "inspect", {}],
    ["false", "inspect", { "aws-key-check": "false" }],
    ["unset", "universal", {}],
  ] as const)("refuses role accounts with aws-key-check %s on %s", (_, proxyEngine, check) => {
    expect(() =>
      readAwsKeyInputs(
        { proxyEngine },
        {},
        inputs({ ...check, "allowed-aws-role-accounts": "111111111111" }),
      ),
    ).toThrow(expect.objectContaining({ code: "AWS_KEY_CHECK_NOT_SET" }));
  });

  it("refuses a config-file's accounts when the workflow sets aws-key-check: false", () => {
    const workspace = mkdtempSync(join(tmpdir(), "config-file-"));
    writeFileSync(join(workspace, "buildcage.yml"), "allowed-aws-role-accounts: '111111111111'\n");
    const env: NodeJS.ProcessEnv = {
      GITHUB_WORKSPACE: workspace,
      GITHUB_EVENT_NAME: "push",
      "INPUT_CONFIG-FILE": "buildcage.yml",
      "INPUT_AWS-KEY-CHECK": "false",
    };
    applyConfigFile(env, CONFIG_FILE_INPUTS);
    expect(() =>
      readAwsKeyInputs(inspect, { AWS_ACCESS_KEY_ID: KEY }, (name) =>
        (env[`INPUT_${name.toUpperCase()}`] ?? "").trim(),
      ),
    ).toThrow(/use a file without them/);
  });

  it("reads the role accounts, deduplicated, and pins the step's key", () => {
    expect(
      readAwsKeyInputs(
        inspect,
        { AWS_ACCESS_KEY_ID: ` ${KEY}\n` },
        accounts("111111111111 222222222222\n111111111111 # prod"),
      ),
    ).toStrictEqual({ key: KEY, roleAccounts: ["111111111111", "222222222222"] });
  });

  it("names every entry that is not an account ID", () => {
    const read = () =>
      readAwsKeyInputs(inspect, { AWS_ACCESS_KEY_ID: KEY }, accounts("12345 111111111111 abc"));
    expect(read).toThrow(SandboxError);
    expect(read).toThrow('invalid AWS account ID: "12345", "abc"');
  });

  it("asks for quotes when a config file read an ID that begins with 0 as a number", () => {
    const workspace = mkdtempSync(join(tmpdir(), "config-file-"));
    writeFileSync(
      join(workspace, "buildcage.yml"),
      "aws-key-check: true\nallowed-aws-role-accounts: 012345678901\n",
    );
    const env: NodeJS.ProcessEnv = {
      GITHUB_WORKSPACE: workspace,
      GITHUB_EVENT_NAME: "push",
      "INPUT_CONFIG-FILE": "buildcage.yml",
    };
    applyConfigFile(env, CONFIG_FILE_INPUTS);
    expect(() =>
      readAwsKeyInputs(inspect, { AWS_ACCESS_KEY_ID: KEY }, (name) =>
        (env[`INPUT_${name.toUpperCase()}`] ?? "").trim(),
      ),
    ).toThrow(/"12345678901".*Quote an ID that begins with 0/);
    for (const typo of ["abc", "12345"]) {
      const read = () => readAwsKeyInputs(inspect, { AWS_ACCESS_KEY_ID: KEY }, accounts(typo));
      expect(read).toThrow(SandboxError);
      expect(read).not.toThrow(/Quote/);
    }
  });

  it.each([
    ["unset", {}],
    ["empty", { AWS_ACCESS_KEY_ID: "" }],
    ["not a key ID", { AWS_ACCESS_KEY_ID: "asia-not-a-key" }],
  ])("refuses a step whose AWS_ACCESS_KEY_ID is %s", (_, env) => {
    expect(() => readAwsKeyInputs(inspect, env, accounts("111111111111"))).toThrow(
      expect.objectContaining({
        code: "AWS_ACCESS_KEY_MISSING",
        message: expect.stringContaining("run the AWS commands in a step without the check"),
      }),
    );
  });

  it("does not echo the key it refuses", () => {
    expect(() =>
      readAwsKeyInputs(inspect, { AWS_ACCESS_KEY_ID: "SECRET-LOOKING" }, accounts("111111111111")),
    ).toThrow(expect.objectContaining({ message: expect.not.stringContaining("SECRET-LOOKING") }));
  });

  it("refuses universal, where the check would silently not run", () => {
    expect(() =>
      readAwsKeyInputs(
        { proxyEngine: "universal" },
        { AWS_ACCESS_KEY_ID: KEY },
        accounts("111111111111"),
      ),
    ).toThrow(InvalidInputError);
  });
});

describe("awsExampleInputs", () => {
  const KEY = `${ASIA}AAAAAAAAAAAAAAAA`;

  it("writes nothing when the check was off for the run", () => {
    expect(awsExampleInputs({ key: "", roleAccounts: [] })).toStrictEqual([]);
  });

  it("turns the check on, and names the accounts given", () => {
    expect(awsExampleInputs({ key: KEY, roleAccounts: [] })).toStrictEqual(["aws-key-check: true"]);
    const lines = awsExampleInputs({ key: KEY, roleAccounts: ["111111111111"] });
    expect(lines).toStrictEqual([
      "aws-key-check: true",
      'allowed-aws-role-accounts: "111111111111"',
    ]);
    expect(lines.join("\n").includes(KEY)).toBe(false);
  });

  it("adds each account the run assumed a role in, commented out for a look", () => {
    const event = (assumedAccount: string) => ({
      time: 0,
      action: "allow",
      protocol: "https",
      host: "sts.amazonaws.com",
      extensions: { aws: { key: "env", assumedAccount } },
    });
    const timeline = [
      event("222222222222"),
      event("012345678901"),
      event("222222222222"),
      event("111111111111"),
      event('1" injected'),
      { time: 0, action: "allow", protocol: "https", host: "example.com" },
    ] as TrafficEvent[];
    const block = awsExampleInputs({ key: KEY, roleAccounts: ["111111111111"] }, timeline);
    expect(block).toStrictEqual([
      "aws-key-check: true",
      "allowed-aws-role-accounts: |",
      "  # 012345678901 # assumed in this run, check it is yours",
      "  111111111111",
      "  # 222222222222 # assumed in this run, check it is yours",
    ]);
    // The block reads back as the accounts given alone.
    expect(parseAwsAccounts(block.slice(2).join("\n"))).toStrictEqual(["111111111111"]);
    expect(awsExampleInputs({ key: KEY, roleAccounts: [] }, timeline.slice(0, 1))).toStrictEqual([
      "aws-key-check: true",
      '# allowed-aws-role-accounts: "222222222222" # assumed in this run, check it is yours',
    ]);
  });

  it("names the blocked keys that naming the account alone lets through", () => {
    const sts = (aws: Record<string, string>, wouldBlock?: string): TrafficEvent => ({
      time: 0,
      action: wouldBlock ? "audit" : "allow",
      protocol: "https",
      host: "sts.amazonaws.com",
      port: 443,
      ...(wouldBlock ? { wouldBlock } : {}),
      extensions: { aws },
    });
    const signed = (keyRef: string): TrafficEvent => ({
      time: 1,
      action: "audit",
      protocol: "https",
      host: "s3.amazonaws.com",
      port: 443,
      wouldBlock: "aws-key-not-allowed",
      extensions: { aws: { keyRef } },
    });
    const issued = (assumedAccount: string, issuedKeyRef: string) =>
      sts({ key: "env", assumedAccount, issuedKeyRef });
    const timeline = [
      issued("222222222222", "aaaa1111"),
      issued("333333333333", "cccc3333"),
      signed("aaaa1111"),
      signed("bbbb2222"),
      issued("222222222222", "dddd4444"),
      signed("dddd4444"),
      // A chain: the call that issued it is signed with key 1, whose account
      // is not named either, so 444444444444 alone would not let it through.
      sts(
        { keyRef: "aaaa1111", assumedAccount: "444444444444", issuedKeyRef: "eeee5555" },
        "aws-key-not-allowed",
      ),
      signed("eeee5555"),
    ];
    expect(awsExampleInputs({ key: KEY, roleAccounts: [] }, timeline).slice(1)).toStrictEqual([
      "# allowed-aws-role-accounts: |",
      "#   222222222222 # lets key 1 and key 4 through; assumed in this run, check it is yours",
      "#   333333333333 # assumed in this run, check it is yours",
      "#   444444444444 # assumed in this run, check it is yours",
    ]);
    // With an account given, the input stays on and only the added lines are commented out.
    expect(
      awsExampleInputs({ key: KEY, roleAccounts: ["111111111111"] }, timeline.slice(0, 3)).slice(1),
    ).toStrictEqual([
      "allowed-aws-role-accounts: |",
      "  111111111111",
      "  # 222222222222 # lets key 1 through; assumed in this run, check it is yours",
      "  # 333333333333 # assumed in this run, check it is yours",
    ]);
  });

  describe("what naming an account alone lets through", () => {
    const event = (
      host: string,
      aws: Record<string, string>,
      wouldBlock?: string,
    ): TrafficEvent => ({
      time: 0,
      action: wouldBlock ? "audit" : "allow",
      protocol: "https",
      host,
      port: 443,
      ...(wouldBlock ? { wouldBlock } : {}),
      extensions: { aws },
    });
    const signed = (keyRef: string, host = "s3.amazonaws.com") =>
      event(host, { keyRef }, "aws-key-not-allowed");
    const comments = (timeline: TrafficEvent[]) =>
      awsExampleInputs({ key: KEY, roleAccounts: ["111111111111"] }, timeline).slice(3);

    it("names an AssumeRoleWithWebIdentity call judged by its account, and the key it issued", () => {
      const webIdentity = (wouldBlock: string, account: string, roleAccount?: string) =>
        event(
          "sts.amazonaws.com",
          {
            assumedAccount: account,
            issuedKeyRef: `${account}-key`,
            ...(roleAccount ? { roleAccount } : {}),
          },
          wouldBlock,
        );
      expect(
        comments([
          webIdentity("aws-role-not-allowed", "222222222222", "222222222222"),
          // No account named, so judged as unsigned; the proxy still names the account.
          webIdentity("aws-no-credential", "333333333333", "333333333333"),
          // A form the proxy does not judge by account, so naming it changes nothing.
          webIdentity("aws-no-credential", "444444444444"),
          signed("222222222222-key"),
          signed("333333333333-key"),
          signed("444444444444-key"),
          // Signed, so its key decides, not the account of its role.
          event(
            "sts.amazonaws.com",
            { keyRef: "ffff6666", assumedAccount: "555555555555", roleAccount: "555555555555" },
            "aws-role-not-allowed",
          ),
        ]),
      ).toStrictEqual([
        "  # 222222222222 # lets key 1 and its AssumeRoleWithWebIdentity call through; assumed in this run, check it is yours",
        "  # 333333333333 # lets key 2 and its AssumeRoleWithWebIdentity call through; assumed in this run, check it is yours",
        "  # 444444444444 # assumed in this run, check it is yours",
        "  # 555555555555 # assumed in this run, check it is yours",
      ]);
    });

    it("names a key ECR issued for a registry request signed with a key the account lets through", () => {
      const registry = "222222222222.dkr.ecr.us-east-1.amazonaws.com";
      expect(
        comments([
          event("sts.amazonaws.com", {
            key: "env",
            assumedAccount: "222222222222",
            issuedKeyRef: "aaaa1111",
          }),
          event(registry, { keyRef: "aaaa1111", issuedKeyRef: "bbbb2222" }, "aws-key-not-allowed"),
          signed("bbbb2222"),
          // ECR hands the same key out again, to a request no account lets through.
          event(registry, { keyRef: "zzzz9999", issuedKeyRef: "bbbb2222" }, "aws-key-not-allowed"),
          // Audit already learned this key, so naming an account changes nothing for it.
          event(registry, { key: "env", issuedKeyRef: "gggg7777" }),
          signed("gggg7777", "sqs.amazonaws.com"),
          // An STS answer that named no account teaches nothing, whatever signed it.
          event("sts.amazonaws.com", { key: "env", issuedKeyRef: "cccc3333" }),
          signed("cccc3333"),
          // A key that would lead back to itself.
          event(registry, { keyRef: "dddd4444", issuedKeyRef: "dddd4444" }, "aws-key-not-allowed"),
          // Another reason stays whatever account is named.
          event(
            registry,
            { keyRef: "aaaa1111", issuedKeyRef: "eeee5555" },
            "aws-ambiguous-credential",
          ),
          signed("eeee5555"),
        ]),
      ).toStrictEqual([
        "  # 222222222222 # lets key 1 and key 2 through; assumed in this run, check it is yours",
      ]);
    });
  });
});

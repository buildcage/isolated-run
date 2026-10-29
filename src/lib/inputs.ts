/**
 * Every `core.getInput` this action makes, and the resolvers that turn those
 * strings into validated values, in one place, so what the action reads is
 * answerable from one file rather than by grepping the entry point.
 *
 * The step calls every reader before any privileged setup or network
 * round-trip, so a typo fails first; the order of those calls decides which
 * error a run with more than one problem reports.
 *
 * Nothing here imports `sandbox/`. What a value may be is a question about the
 * sandbox's own mounts, so it belongs to the module that makes them, and a
 * unit test of any reader here would otherwise run `sandbox/scratch-dir.ts`'s
 * uid-dependent top-level setup on the way in.
 */
import * as core from "@actions/core";

import type { ConfigFileInputs } from "#core/lib/actions/config-file.ts";
import {
  InvalidInputError,
  readBooleanInput,
  resolveProxyEngine,
  resolveProxyMode,
  type ProxyEngine,
  type ProxyMode,
} from "#core/lib/actions/inputs.ts";
import type { TrafficEvent } from "#core/lib/log/traffic-event.ts";

import { isAwsAccessKeyId, isAwsAccountId, parseAwsAccounts } from "../proxy/aws-keys.ts";
import { awsFieldsOf, type AwsBlockedReason } from "../proxy/aws-log.ts";
import { awsKeys, isEcrRegistry, KEY_NOT_ALLOWED, type AwsKey } from "./aws-keys.ts";
import { SandboxError } from "./errors.ts";
import { resolveFilesystemAudit, type FilesystemAudit } from "./filesystem-audit/mode.ts";
import { resolveFilesystemMode, type FilesystemMode } from "./filesystem-mode.ts";
import { blockedKeys } from "./would-block.ts";

const LIST_INPUTS = [
  "allowed-https-rules",
  "allowed-http-rules",
  "allowed-ip-rules",
  "allowed-url-rules",
  "allowed-tls-rules",
  "known-blocked-rules",
  "write-through",
  "expected-filesystem-rules",
];

/** Every input action.yml declares. config-file takes these less
 *  NOT_IN_CONFIG_FILE, and its error lists them in this order. */
export const ACTION_INPUTS = [
  "run",
  "config-file",
  "proxy-mode",
  "proxy-engine",
  ...LIST_INPUTS,
  "writable",
  "aws-key-check",
  // Not merged from config-file: the workflow's accounts replace the file's.
  "allowed-aws-role-accounts",
  "upload-traffic-artifact",
  "traffic-artifact-retention-days",
  "fail-on-blocked",
  "fail-on-ca-residue",
  "filesystem-mode",
  "filesystem-audit",
  "upload-filesystem-audit-artifact",
  "filesystem-audit-retention-days",
  "fail-on-unexpected-file-access",
  "label",
  "working-directory",
];

// The step itself, the file itself, the deprecated spelling of write-through,
// and the directory the file's own path is relative to.
const NOT_IN_CONFIG_FILE = ["run", "config-file", "writable", "working-directory"];

export const CONFIG_FILE_INPUTS: ConfigFileInputs = {
  // Marked pure so post.cjs, which uses other parts of this module, leaves it out.
  known: /* @__PURE__ */ ACTION_INPUTS.filter((input) => !NOT_IN_CONFIG_FILE.includes(input)),
  lists: LIST_INPUTS,
};

/** Narrowed to what this module needs, so a test can pass a plain lookup. */
export type GetInput = (name: string, options?: { trimWhitespace?: boolean }) => string;

/** Where a renamed input's migration message goes; the entry point supplies it. */
export type Notice = (message: string) => void;

export interface WriteThroughInputs {
  writeThrough: string;
  /** Pre-rename spelling of write-through, still accepted. */
  writable: string;
  /** Removed input, only read so it can be rejected with a migration hint. */
  allowWrite: string;
}

/**
 * The effective write-through: input. `writable:` is its old name and still
 * works; its lines join write-through's, as config-file's do. `allow_write:`
 * (the ephemeral-only input this replaced) is rejected rather than ignored,
 * since ignoring it would silently discard writes the step asked to keep.
 */
export function resolveWriteThroughInput(
  { writeThrough, writable, allowWrite }: WriteThroughInputs,
  notice: Notice,
): string {
  if (allowWrite.trim()) {
    throw new SandboxError(
      "allow_write: has been replaced by write-through:, which covers both filesystem modes. " +
        "Rename the input; the path syntax is unchanged.",
      "ALLOW_WRITE_REMOVED",
    );
  }
  if (!writable.trim()) return writeThrough;
  notice(
    "writable: is now called write-through:; writable: still works, but consider updating to write-through:.",
  );
  return writeThrough.trim() ? `${writeThrough}\n${writable}` : writable;
}

/** The `run:` script. Read untrimmed: leading indentation is part of it. */
export function readRunCommand(getInput: GetInput = core.getInput): string {
  const runInput = getInput("run", { trimWhitespace: false });
  if (!runInput.trim()) {
    throw new SandboxError("Input 'run' is required.", "MISSING_RUN");
  }
  return runInput;
}

export interface ProxyInputs {
  proxyEngine: ProxyEngine;
  proxyMode: ProxyMode;
}

export function readProxyInputs(getInput: GetInput = core.getInput): ProxyInputs {
  return {
    proxyEngine: resolveProxyEngine(getInput("proxy-engine")),
    proxyMode: resolveProxyMode(getInput("proxy-mode")),
  };
}

export interface FilesystemInputs {
  filesystemMode: FilesystemMode;
  /** The effective write-through: text, one entry per line, unresolved. */
  writeThroughInput: string;
}

export function readFilesystemInputs(
  notice: Notice,
  getInput: GetInput = core.getInput,
): FilesystemInputs {
  return {
    filesystemMode: resolveFilesystemMode(getInput("filesystem-mode")),
    writeThroughInput: resolveWriteThroughInput(
      {
        writeThrough: getInput("write-through"),
        writable: getInput("writable"),
        allowWrite: getInput("allow_write"),
      },
      notice,
    ),
  };
}

export function readFilesystemAuditInput(getInput: GetInput = core.getInput): FilesystemAudit {
  return resolveFilesystemAudit(getInput("filesystem-audit"));
}

export interface FilesystemAuditArtifactInputs {
  upload: boolean;
  /** Undefined leaves the retention to the repository's own default. */
  retentionDays?: number;
}

/**
 * Whether to upload the record, off unless asked for as the traffic artifact
 * is, and how long to keep it. The retention is checked even when nothing is
 * uploaded, as the traffic one is.
 */
export function readFilesystemAuditArtifactInputs(
  getInput: GetInput = core.getInput,
): FilesystemAuditArtifactInputs {
  const days = getInput("filesystem-audit-retention-days");
  if (days !== "" && !/^[1-9]\d*$/.test(days)) {
    throw new SandboxError(
      `Invalid filesystem-audit-retention-days: ${JSON.stringify(days)}. ` +
        "Must be a whole number of days above zero.",
      "INVALID_FILESYSTEM_AUDIT_RETENTION_DAYS",
    );
  }
  return {
    upload: readBooleanInput("upload-filesystem-audit-artifact", false, getInput),
    retentionDays: days === "" ? undefined : Number(days),
  };
}

/** The optional `label:`, which only titles the report heading. */
export function readStepLabel(getInput: GetInput = core.getInput): string | undefined {
  return getInput("label") || undefined;
}

export function readFailOnCaResidue(getInput: GetInput = core.getInput): boolean {
  return readBooleanInput("fail-on-ca-residue", true, getInput);
}

export function readFailOnBlocked(getInput: GetInput = core.getInput): boolean {
  return readBooleanInput("fail-on-blocked", true, getInput);
}

export function readFailOnUnexpectedFileAccess(getInput: GetInput = core.getInput): boolean {
  return readBooleanInput("fail-on-unexpected-file-access", false, getInput);
}

export interface AwsKeyInputs {
  /** The key the step starts with, its own AWS_ACCESS_KEY_ID; empty leaves the check off. */
  key: string;
  /** Accounts whose roles the step may assume; empty learns no key. */
  roleAccounts: string[];
}

const AWS_KEY_CHECK_OFF: AwsKeyInputs = { key: "", roleAccounts: [] };

const STARTING_KEY_HELP =
  "The check starts from that variable alone, never from a profile, a credentials file or any " +
  "other credential source. Put the key to check there in an earlier step, for example with " +
  "aws-actions/configure-aws-credentials, or run the AWS commands in a step without the check.";

/**
 * The AWS access key check pins the step to its own AWS_ACCESS_KEY_ID; role
 * accounts also let through the keys STS issues for their roles, and need the
 * check set on explicitly. A check that cannot run fails audit too, where
 * turning it off would let the run read as checked.
 */
export function readAwsKeyInputs(
  { proxyEngine }: Pick<ProxyInputs, "proxyEngine">,
  env: NodeJS.ProcessEnv,
  getInput: GetInput = core.getInput,
): AwsKeyInputs {
  let roleAccounts: string[];
  try {
    roleAccounts = parseAwsAccounts(getInput("allowed-aws-role-accounts"));
  } catch (e) {
    const { message } = e as Error;
    // YAML reads an unquoted 012345678901 as a number, 11 digits long.
    const hint = /"\d{11}"/.test(message)
      ? " Quote an ID that begins with 0, which YAML otherwise reads as a number."
      : "";
    throw new SandboxError(
      `allowed-aws-role-accounts: ${message}. Each entry must be a 12-digit AWS account ID.${hint}`,
      "INVALID_AWS_ACCOUNTS",
    );
  }
  const check = readBooleanInput("aws-key-check", false, getInput);
  // Required rather than implied by the accounts, so a config-file the workflow
  // does not show can never be what turns the check off.
  if (roleAccounts.length > 0 && !check) {
    throw new SandboxError(
      "allowed-aws-role-accounts needs aws-key-check: true. Set it, or remove the accounts. " +
        "A workflow cannot clear accounts its config-file names: use a file without them.",
      "AWS_KEY_CHECK_NOT_SET",
    );
  }
  if (!check) return AWS_KEY_CHECK_OFF;

  if (proxyEngine !== "inspect") {
    throw new InvalidInputError(
      `The AWS access key check has no effect with proxy-engine: ${proxyEngine}, which never ` +
        "sees a request's headers. Switch to proxy-engine: inspect, or remove aws-key-check " +
        "and allowed-aws-role-accounts.",
      "INVALID_PROXY_ENGINE",
    );
  }

  // Not echoed back: configure-aws-credentials masks it.
  const key = env.AWS_ACCESS_KEY_ID?.trim() ?? "";
  if (!isAwsAccessKeyId(key)) {
    throw new SandboxError(
      `The AWS access key check is on, but AWS_ACCESS_KEY_ID is unset or is not an access key ID. ${STARTING_KEY_HELP}`,
      "AWS_ACCESS_KEY_MISSING",
    );
  }
  return { key, roleAccounts };
}

/** Closes the comment on an account the run assumed a role in but was not given. */
const ASSUMED_ACCOUNT_MARK = "assumed in this run, check it is yours";
const NO_CREDENTIAL = "aws-no-credential" satisfies AwsBlockedReason;
const ROLE_NOT_ALLOWED = "aws-role-not-allowed" satisfies AwsBlockedReason;

/**
 * The check's inputs for the report's restrict example, only when it was on
 * for this run: the accounts given, and every account the run assumed a role
 * in. A build's own AssumeRole names an account too, so each one not given is
 * left commented out for a look, with what naming it alone would let through.
 * One account is quoted, since YAML reads an ID that begins with 0 as a number;
 * more are a block, one to a line, which needs no quotes and lets each carry
 * its own comment.
 */
export function awsExampleInputs(
  { key, roleAccounts }: AwsKeyInputs,
  timeline: TrafficEvent[] = [],
): string[] {
  if (!key) return [];
  const lines = ["aws-key-check: true"];
  // The log is the proxy's, but only an ID goes into the YAML.
  const assumed = timeline
    .flatMap((e) => awsFieldsOf(e).assumedAccount ?? [])
    .filter(isAwsAccountId);
  const added = new Set(assumed.filter((a) => !roleAccounts.includes(a)));
  const accounts = [...roleAccounts, ...added].sort();
  const known = awsKeys(timeline);
  // Whether naming `account` alone lets a request through. An answer teaches
  // its key only when restrict lets the call through: an AssumeRole's for a
  // role in the account, and an ECR registry's only for a request audit would
  // block, as audit already learned the rest. A chain through another unnamed
  // account does not pass.
  const passes = (e: TrafficEvent, account: string, seen: Set<AwsKey>): boolean => {
    const { keyRef, roleAccount } = awsFieldsOf(e);
    switch (e.wouldBlock) {
      case undefined:
        return true;
      case NO_CREDENTIAL:
      case ROLE_NOT_ALLOWED:
        // A signed call is judged by its key, whatever its role.
        return !keyRef && roleAccount === account;
      case KEY_NOT_ALLOWED: {
        const key = keyRef && known.get(keyRef);
        return !!key && learned(key, account, seen);
      }
      default:
        return false;
    }
  };
  const teaches = (issuer: TrafficEvent, account: string, seen: Set<AwsKey>): boolean => {
    const { assumedAccount } = awsFieldsOf(issuer);
    const learnable = assumedAccount
      ? assumedAccount === account
      : isEcrRegistry(issuer.host) && issuer.wouldBlock !== undefined;
    return learnable && passes(issuer, account, seen);
  };
  const learned = (key: AwsKey, account: string, seen: Set<AwsKey>): boolean => {
    if (seen.has(key)) return false;
    const next = new Set(seen).add(key);
    return key.issuers.some((issuer) => teaches(issuer, account, next));
  };
  const keys = [...blockedKeys(timeline, known).values()];
  const mark = (a: string) => {
    const names = keys.filter(({ key }) => learned(key, a, new Set())).map(({ key }) => key.name);
    const webIdentity = timeline.some(
      (e) =>
        (e.wouldBlock === NO_CREDENTIAL || e.wouldBlock === ROLE_NOT_ALLOWED) &&
        passes(e, a, new Set()),
    );
    if (webIdentity) names.push("its AssumeRoleWithWebIdentity call");
    const last = names.pop();
    const list = names.length > 0 ? `${names.join(", ")} and ${last}` : last;
    return ` # ${list ? `lets ${list} through; ` : ""}${ASSUMED_ACCOUNT_MARK}`;
  };
  const line = (a: string, text: string) => (added.has(a) ? `# ${text}${mark(a)}` : text);
  if (accounts.length === 1) {
    lines.push(line(accounts[0], `allowed-aws-role-accounts: "${accounts[0]}"`));
  } else if (accounts.length > 1 && roleAccounts.length === 0) {
    // With every line commented out, the input's own line is too, so the
    // example sets nothing until one is uncommented along with it.
    lines.push("# allowed-aws-role-accounts: |", ...accounts.map((a) => `#   ${a}${mark(a)}`));
  } else if (accounts.length > 1) {
    lines.push("allowed-aws-role-accounts: |", ...accounts.map((a) => `  ${line(a, a)}`));
  }
  return lines;
}

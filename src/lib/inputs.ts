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

import { isAwsAccessKeyId, parseAwsAccounts } from "../proxy/aws-keys.ts";
import { SandboxError } from "./errors.ts";
import { resolveFilesystemAudit, type FilesystemAudit } from "./filesystem-audit-mode.ts";
import { resolveFilesystemMode, type FilesystemMode } from "./filesystem-mode.ts";

const LIST_INPUTS = [
  "allowed_https_rules",
  "allowed_http_rules",
  "allowed_ip_rules",
  "allowed_url_rules",
  "allowed_tls_rules",
  "known_blocked_rules",
  "write_through",
];

/** Every input but `run`, the step itself, and the deprecated `writable`. */
export const CONFIG_FILE_INPUTS: ConfigFileInputs = {
  known: [
    "proxy_mode",
    "proxy_engine",
    ...LIST_INPUTS,
    "aws_key_check",
    // Not merged: the workflow's accounts replace the file's.
    "allowed_aws_role_accounts",
    "upload_traffic_artifact",
    "traffic_artifact_retention_days",
    "fail_on_blocked",
    "fail_on_ca_residue",
    "filesystem_mode",
    "filesystem_audit",
    "filesystem_audit_retention_days",
    "label",
  ],
  lists: LIST_INPUTS,
};

/** Narrowed to what this module needs, so a test can pass a plain lookup. */
export type GetInput = (name: string, options?: { trimWhitespace?: boolean }) => string;

/** Where a renamed input's migration message goes; the entry point supplies it. */
export type Notice = (message: string) => void;

export interface WriteThroughInputs {
  writeThrough: string;
  /** Pre-rename spelling of write_through, still accepted. */
  writable: string;
  /** Removed input, only read so it can be rejected with a migration hint. */
  allowWrite: string;
}

/**
 * The effective write_through: input. `writable:` is its old name and still
 * works; its lines join write_through's, as config_file's do. `allow_write:`
 * (the ephemeral-only input this replaced) is rejected rather than ignored,
 * since ignoring it would silently discard writes the step asked to keep.
 */
export function resolveWriteThroughInput(
  { writeThrough, writable, allowWrite }: WriteThroughInputs,
  notice: Notice,
): string {
  if (allowWrite.trim()) {
    throw new SandboxError(
      "allow_write: has been replaced by write_through:, which covers both filesystem modes. " +
        "Rename the input; the path syntax is unchanged.",
      "ALLOW_WRITE_REMOVED",
    );
  }
  if (!writable.trim()) return writeThrough;
  notice(
    "writable: is now called write_through:; writable: still works, but consider updating to write_through:.",
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
    proxyEngine: resolveProxyEngine(getInput("proxy_engine")),
    proxyMode: resolveProxyMode(getInput("proxy_mode")),
  };
}

export interface FilesystemInputs {
  filesystemMode: FilesystemMode;
  /** The effective write_through: text, one entry per line, unresolved. */
  writeThroughInput: string;
}

export function readFilesystemInputs(
  notice: Notice,
  getInput: GetInput = core.getInput,
): FilesystemInputs {
  return {
    filesystemMode: resolveFilesystemMode(getInput("filesystem_mode")),
    writeThroughInput: resolveWriteThroughInput(
      {
        writeThrough: getInput("write_through"),
        writable: getInput("writable"),
        allowWrite: getInput("allow_write"),
      },
      notice,
    ),
  };
}

export function readFilesystemAuditInput(getInput: GetInput = core.getInput): FilesystemAudit {
  return resolveFilesystemAudit(getInput("filesystem_audit"));
}

/** Undefined when unset, which leaves the retention to the repository default. */
export function readFilesystemAuditRetentionDays(
  getInput: GetInput = core.getInput,
): number | undefined {
  const days = getInput("filesystem_audit_retention_days");
  if (days === "") return undefined;
  if (!/^[1-9]\d*$/.test(days)) {
    throw new SandboxError(
      `Invalid filesystem_audit_retention_days: ${JSON.stringify(days)}. ` +
        "Must be a whole number of days above zero.",
      "INVALID_FILESYSTEM_AUDIT_RETENTION_DAYS",
    );
  }
  return Number(days);
}

/** The optional `label:`, which only titles the report heading. */
export function readStepLabel(getInput: GetInput = core.getInput): string | undefined {
  return getInput("label") || undefined;
}

export function readFailOnCaResidue(getInput: GetInput = core.getInput): boolean {
  return readBooleanInput("fail_on_ca_residue", true, getInput);
}

export function readFailOnBlocked(getInput: GetInput = core.getInput): boolean {
  return readBooleanInput("fail_on_blocked", true, getInput);
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
    roleAccounts = parseAwsAccounts(getInput("allowed_aws_role_accounts"));
  } catch (e) {
    const { message } = e as Error;
    // YAML reads an unquoted 012345678901 as a number, 11 digits long.
    const hint = /"\d{11}"/.test(message)
      ? " Quote an ID that begins with 0, which YAML otherwise reads as a number."
      : "";
    throw new SandboxError(
      `allowed_aws_role_accounts: ${message}. Each entry must be a 12-digit AWS account ID.${hint}`,
      "INVALID_AWS_ACCOUNTS",
    );
  }
  const check = readBooleanInput("aws_key_check", false, getInput);
  // Required rather than implied by the accounts, so a config_file the workflow
  // does not show can never be what turns the check off.
  if (roleAccounts.length > 0 && !check) {
    throw new SandboxError(
      "allowed_aws_role_accounts needs aws_key_check: true. Set it, or remove the accounts. " +
        "A workflow cannot clear accounts its config_file names: use a file without them.",
      "AWS_KEY_CHECK_NOT_SET",
    );
  }
  if (!check) return AWS_KEY_CHECK_OFF;

  if (proxyEngine !== "inspect") {
    throw new InvalidInputError(
      `The AWS access key check has no effect with proxy_engine: ${proxyEngine}, which never ` +
        "sees a request's headers. Switch to proxy_engine: inspect, or remove aws_key_check " +
        "and allowed_aws_role_accounts.",
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

/** Ends the restrict example's line for an account the run assumed a role in but was not given. */
export const ASSUMED_ACCOUNT_MARK = " # assumed in this run, check it is yours";

/**
 * The check's inputs for the report's restrict example, only when it was on
 * for this run: the accounts given, and every account the run assumed a role
 * in. A build's own AssumeRole names an account too, so each one not given is
 * marked for a look. One account is quoted, since YAML reads an ID that begins
 * with 0 as a number; more are a block, one to a line, which needs no quotes
 * and lets each carry its own comment.
 */
export function awsExampleInputs(
  { key, roleAccounts }: AwsKeyInputs,
  timeline: TrafficEvent[] = [],
): string[] {
  if (!key) return [];
  const lines = ["aws_key_check: true"];
  // The log is the proxy's, but only an ID goes into the YAML.
  const assumed = timeline
    .flatMap((e) => e.extensions?.aws?.assumedAccount ?? [])
    .filter((a) => /^\d{12}$/.test(a));
  const added = new Set(assumed.filter((a) => !roleAccounts.includes(a)));
  const accounts = [...roleAccounts, ...added].sort();
  const mark = (a: string) => (added.has(a) ? ASSUMED_ACCOUNT_MARK : "");
  if (accounts.length === 1) {
    lines.push(`allowed_aws_role_accounts: "${accounts[0]}"${mark(accounts[0])}`);
  } else if (accounts.length > 1) {
    lines.push("allowed_aws_role_accounts: |", ...accounts.map((a) => `  ${a}${mark(a)}`));
  }
  return lines;
}

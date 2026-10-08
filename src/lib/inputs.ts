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

import { isAwsAccessKeyId, parseAwsAccounts } from "../proxy/aws-keys.ts";
import { SandboxError } from "./errors.ts";
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
    // Replaced, but read so a file that still sets it is told what replaces it.
    "allowed_aws_accounts",
    "upload_traffic_artifact",
    "traffic_artifact_retention_days",
    "fail_on_blocked",
    "fail_on_ca_residue",
    "filesystem_mode",
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

/**
 * The AWS access key check pins the step to its own AWS_ACCESS_KEY_ID; role
 * accounts also let through the keys STS issues for their roles, and turn the
 * check on. universal never sees a request's headers, so it fails in restrict
 * and is warned about in audit.
 */
export function readAwsKeyInputs(
  { proxyEngine, proxyMode }: ProxyInputs,
  env: NodeJS.ProcessEnv,
  warn: Notice,
  getInput: GetInput = core.getInput,
): AwsKeyInputs {
  // A value naming no account left the old check off, so it still passes.
  let replacedNamesAccounts = true;
  try {
    replacedNamesAccounts = parseAwsAccounts(getInput("allowed_aws_accounts")).length > 0;
  } catch {}
  if (replacedNamesAccounts) {
    throw new SandboxError(
      "allowed_aws_accounts has been replaced. Set aws_key_check: true to accept only the step's " +
        "own AWS_ACCESS_KEY_ID, and list in allowed_aws_role_accounts the accounts whose roles the " +
        "step may assume.",
      "AWS_ACCOUNTS_REMOVED",
    );
  }
  let roleAccounts: string[];
  try {
    roleAccounts = parseAwsAccounts(getInput("allowed_aws_role_accounts"));
  } catch (e) {
    throw new SandboxError(
      `allowed_aws_role_accounts: ${(e as Error).message}. Each entry must be a 12-digit AWS account ID.`,
      "INVALID_AWS_ACCOUNTS",
    );
  }
  // An explicit false wins, so a step can opt out of accounts a shared
  // config_file names.
  if (!readBooleanInput("aws_key_check", roleAccounts.length > 0, getInput)) {
    if (roleAccounts.length > 0) {
      warn("aws_key_check is false, so allowed_aws_role_accounts is ignored for this run.");
    }
    return AWS_KEY_CHECK_OFF;
  }

  if (proxyEngine !== "inspect") {
    const reason =
      `The AWS access key check has no effect with proxy_engine: ${proxyEngine}, which never ` +
      "sees a request's headers.";
    if (proxyMode === "audit") {
      warn(`${reason} It is ignored for this run.`);
      return AWS_KEY_CHECK_OFF;
    }
    throw new InvalidInputError(
      `${reason} Switch to proxy_engine: inspect, or remove aws_key_check and ` +
        "allowed_aws_role_accounts.",
      "INVALID_PROXY_ENGINE",
    );
  }

  // Not echoed back: configure-aws-credentials masks it.
  const key = env.AWS_ACCESS_KEY_ID?.trim() ?? "";
  if (!isAwsAccessKeyId(key)) {
    if (proxyMode === "audit") {
      warn(
        "The AWS access key check is on, but AWS_ACCESS_KEY_ID is unset or is not an access " +
          "key ID, so the check is off for this run.",
      );
      return AWS_KEY_CHECK_OFF;
    }
    throw new SandboxError(
      "The AWS access key check is on, but AWS_ACCESS_KEY_ID is unset or is not an access key ID. " +
        "Set up the credentials in an earlier step, for example with " +
        "aws-actions/configure-aws-credentials.",
      "AWS_ACCESS_KEY_MISSING",
    );
  }
  return { key, roleAccounts };
}

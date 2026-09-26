/**
 * Every `core.getInput` this action makes, and the resolvers that turn those
 * strings into validated values, in one place, so what the action reads is
 * answerable from one file rather than by grepping the entry point.
 *
 * Read in several calls rather than one because the step needs them at
 * different points: the engine before it resolves the image, the filesystem
 * inputs before the privileged preflight checks, the rules only after the
 * image is verified. Folding them together would reorder validation against
 * those steps and change which error a run with more than one problem reports.
 *
 * Nothing here imports `sandbox/`. What a value may be is a question about the
 * sandbox's own mounts, so it belongs to the module that makes them, and a
 * unit test of any reader here would otherwise run `sandbox/scratch-dir.ts`'s
 * uid-dependent top-level setup on the way in.
 */
import * as core from "@actions/core";

import {
  buildACLRules,
  buildUrlRulesOrThrow,
  checkRulesCompileOrThrow,
  parseKnownBlockedRulesOrThrow,
  parseRulesOrThrow,
} from "#core/lib/acl/rules.ts";
import { SandboxError } from "./errors.ts";
import { resolveProxyEngine, type ProxyEngine } from "./engine.ts";
import { resolveFilesystemMode, type FilesystemMode } from "./filesystem-mode.ts";

/** Narrowed to what this module needs, so a test can pass a plain lookup. */
export type GetInput = (name: string, options?: { trimWhitespace?: boolean }) => string;
export type GetBooleanInput = (name: string) => boolean;

/** Where a renamed input's migration message goes; the entry point supplies it. */
export type Notice = (message: string) => void;

function readKnownBlockedRules(input: string | undefined): string[] {
  return parseKnownBlockedRulesOrThrow(input);
}

export interface WriteThroughInputs {
  writeThrough: string;
  /** Pre-rename spelling of write_through, still accepted. */
  writable: string;
  /** Removed input, only read so it can be rejected with a migration hint. */
  allowWrite: string;
}

/**
 * Pick the effective write_through: input. `writable:` is the same input under
 * its old name and still works; `allow_write:` (the ephemeral-only input this
 * replaced) is rejected rather than ignored, since ignoring it would silently
 * discard writes the step asked to keep.
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
  if (writeThrough.trim() && writable.trim()) {
    throw new SandboxError(
      "write_through: and writable: are the same input under two names. Set only write_through:.",
      "FILESYSTEM_INPUT_CONFLICT",
    );
  }
  if (!writeThrough.trim() && writable.trim()) {
    notice(
      "writable: is now called write_through:; writable: still works, but consider updating to write_through:.",
    );
    return writable;
  }
  return writeThrough;
}

/** The `run:` script. Read untrimmed: leading indentation is part of it. */
export function readRunCommand(getInput: GetInput = core.getInput): string {
  const runInput = getInput("run", { trimWhitespace: false });
  if (!runInput.trim()) {
    throw new SandboxError("Input 'run' is required.", "MISSING_RUN");
  }
  return runInput;
}

export interface EngineInputs {
  proxyEngine: ProxyEngine;
}

export function readEngineInputs(getInput: GetInput = core.getInput): EngineInputs {
  return { proxyEngine: resolveProxyEngine(getInput("proxy_engine")) };
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

const PROXY_MODES = ["audit", "restrict"] as const;
export type ProxyMode = (typeof PROXY_MODES)[number];

/**
 * Anything but the two modes is refused rather than read as `restrict`, which
 * would enforce a run its author meant only to record.
 */
export function resolveProxyMode(input: string | undefined): ProxyMode {
  const trimmed = input?.trim() || "restrict";
  if (!(PROXY_MODES as readonly string[]).includes(trimmed)) {
    throw new SandboxError(
      `Invalid proxy_mode: ${JSON.stringify(input)}. Must be one of ${PROXY_MODES.join(", ")}.`,
      "INVALID_PROXY_MODE",
    );
  }
  return trimmed as ProxyMode;
}

export interface ParsedRuleInputs {
  proxyMode: ProxyMode;
  httpsRules: string[];
  httpRules: string[];
  ipRules: string[];
  /** The raw text of each compiled URL rule, not the compiled form: only the
   *  proxy re-compiles them, and only inspect enforces them. */
  urlRules: string[];
  tlsRules: string[];
  knownBlockedRules: string[];
}

/**
 * Parse and validate every rule input.
 *
 * URL and TLS rules are compiled here even on the engine that ignores them,
 * purely so a typo fails at startup rather than silently inside the sandbox.
 * Everything is then compiled once more the way the proxy does it, so a rule
 * this parser accepts but the proxy refuses fails here too.
 *
 * The statement order is the order a malformed-rule error surfaces in, so it
 * is deliberate rather than incidental.
 *
 * @throws {SandboxError} if proxy_mode is neither mode
 * @throws {InvalidRulesError} if any rule is malformed
 */
export function readRuleInputs(getInput: GetInput = core.getInput): ParsedRuleInputs {
  const proxyMode = resolveProxyMode(getInput("proxy_mode"));
  const rules = buildACLRules({
    httpsRulesInput: getInput("allowed_https_rules"),
    httpRulesInput: getInput("allowed_http_rules"),
    ipRulesInput: getInput("allowed_ip_rules"),
  });
  const knownBlockedRules = readKnownBlockedRules(getInput("known_blocked_rules"));
  const urlRulesInput = getInput("allowed_url_rules");
  const tlsRules = parseRulesOrThrow(getInput("allowed_tls_rules"));
  const compiledUrlRules = buildUrlRulesOrThrow(urlRulesInput);
  checkRulesCompileOrThrow({ ...rules, tlsRules, urlRules: compiledUrlRules });
  const urlRules = compiledUrlRules.map((r) => r.raw);

  return {
    proxyMode,
    httpsRules: rules.httpsRules,
    httpRules: rules.httpRules,
    ipRules: rules.ipRules,
    urlRules,
    tlsRules,
    knownBlockedRules,
  };
}

/** The optional `label:`, which only titles the report heading. */
export function readStepLabel(getInput: GetInput = core.getInput): string | undefined {
  return getInput("label") || undefined;
}

/**
 * Read the same way as fail_on_blocked below, for the same reason, and to the
 * same safe side: unset or unreadable is true.
 */
export function readFailOnCaResidue(
  getBooleanInput: GetBooleanInput = core.getBooleanInput,
): boolean {
  try {
    return getBooleanInput("fail_on_ca_residue");
  } catch {
    return true;
  }
}

/**
 * Several integration scripts invoke this action directly without setting
 * fail_on_blocked, unlike a real workflow where action.yml's own default
 * always supplies it. Fall back to that same default.
 */
export function readFailOnBlocked(
  getBooleanInput: GetBooleanInput = core.getBooleanInput,
): boolean {
  try {
    return getBooleanInput("fail_on_blocked");
  } catch {
    return true;
  }
}

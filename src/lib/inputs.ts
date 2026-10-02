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

import {
  readBooleanInput,
  readRetentionDays,
  resolveProxyEngine,
  type ProxyEngine,
} from "#core/lib/actions/inputs.ts";

import { SandboxError } from "./errors.ts";
import { resolveFilesystemMode, type FilesystemMode } from "./filesystem-mode.ts";

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

export interface TrafficArtifactInputs {
  upload: boolean;
  /** Undefined takes the repository's own default. */
  retentionDays?: number;
}

/** The retention is checked even when nothing is uploaded: a bad value is a
 *  mistake either way. */
export function readTrafficArtifactInputs(
  getInput: GetInput = core.getInput,
): TrafficArtifactInputs {
  return {
    upload: readBooleanInput("upload_traffic_artifact", false, getInput),
    retentionDays: readRetentionDays(getInput),
  };
}

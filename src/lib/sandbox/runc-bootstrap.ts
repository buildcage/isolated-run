import { execFileSync } from "node:child_process";
import { readFileSync, chmodSync, rmSync } from "node:fs";
import { join } from "node:path";
import { buildDockerCpArgs } from "#core/lib/docker/args.ts";
import type { OciSpec } from "./types.ts";
import { hostCommand } from "./pinned-commands.ts";

/**
 * Generate runc's own default OCI bundle config via `runc spec` (run in
 * `bundleDir`, which is where it writes `config.json`). Used as the
 * starting point for buildOciConfig rather than hand-writing the full
 * spec from scratch, so the baseline mounts/masked-paths/rlimits stay
 * exactly what runc itself considers a sane default for its own version,
 * and buildOciConfig only needs to override/extend the handful of fields
 * this sandbox actually cares about.
 */
export function generateBaseOciSpec(
  runcPath: string,
  bundleDir: string,
  { execIn = defaultExecIn, readFile = defaultReadFile }: RuncBootstrapDeps = {},
): OciSpec {
  execIn(runcPath, ["spec"], bundleDir);
  return JSON.parse(readFile(join(bundleDir, "config.json")));
}

export interface ExtractRuncBootstrapOptions {
  containerName: string;
  destDir: string;
}

export interface RuncBootstrapDeps {
  exec?: (command: string, args: string[]) => string;
  execIn?: (command: string, args: string[], cwd: string) => void;
  readFile?: (path: string) => string;
  chmod?: (path: string, mode: number) => void;
  remove?: (path: string) => void;
}

// Untested by design: the defaults behind this module's seams, which only hand
// node:fs and node:child_process what the tested caller decided.
/* v8 ignore start */
function defaultExec(command: string, args: string[]): string {
  return execFileSync(hostCommand(command), args, { encoding: "utf8" });
}

function defaultExecIn(command: string, args: string[], cwd: string): void {
  execFileSync(hostCommand(command), args, { cwd });
}

function defaultReadFile(path: string): string {
  return readFileSync(path, "utf8");
}
/* v8 ignore stop */

export interface RuncBootstrap {
  runcPath: string;
  seccompProfile: unknown;
  baseSpec: OciSpec;
}

/**
 * Extract runc and gen-seccomp-profile from the proxy image into this run's
 * own `destDir` (its per-step scratch dir), then resolve the base OCI spec
 * and the seccomp profile from them. Run once per `run:` step; each
 * invocation is independent, and everything written here is torn down with
 * the scratch dir (see withScratchDir / cleanupScratchDir).
 *
 * Both binaries ship inside the proxy image and are pulled onto the host via
 * `docker cp`, then run natively there (not `docker exec`) since the seccomp
 * profile's content depends on the real host kernel/arch; see
 * gen-seccomp-profile/main.go. gen-seccomp-profile is only needed transiently
 * to resolve the profile, so it's removed once read; runc stays for `runc run`.
 */
export function extractRuncBootstrap(
  { containerName, destDir }: ExtractRuncBootstrapOptions,
  deps: RuncBootstrapDeps = {},
): RuncBootstrap {
  const { exec = defaultExec, chmod = chmodSync, remove = rmSync } = deps;
  const runcPath = join(destDir, "runc");
  const genSeccompProfilePath = join(destDir, "gen-seccomp-profile");
  exec(
    "docker",
    buildDockerCpArgs({
      containerName,
      containerPath: "/opt/buildcage/bin/runc",
      hostPath: runcPath,
    }),
  );
  exec(
    "docker",
    buildDockerCpArgs({
      containerName,
      containerPath: "/opt/buildcage/bin/gen-seccomp-profile",
      hostPath: genSeccompProfilePath,
    }),
  );
  chmod(runcPath, 0o755);
  chmod(genSeccompProfilePath, 0o755);
  const seccompProfile = JSON.parse(exec(genSeccompProfilePath, []));
  const baseSpec = generateBaseOciSpec(runcPath, destDir, deps); // writes config.json into destDir (overwritten later by writeOciConfig)
  remove(genSeccompProfilePath); // only needed to resolve seccompProfile above

  return { runcPath, seccompProfile, baseSpec };
}

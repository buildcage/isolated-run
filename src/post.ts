import { execFileSync } from "node:child_process";
import { realpathSync } from "node:fs";
import { fileURLToPath } from "node:url";

import * as core from "@actions/core";

import { annotate } from "#core/lib/actions/annotation.ts";
import { buildComposeDownArgs } from "#core/lib/docker/args.ts";

import { readLocalImageOverride, resolveComposeFile } from "./lib/compose-file.ts";
import { readFilesystemInputs } from "./lib/inputs.ts";
import { planPostCleanup } from "./lib/post-cleanup.ts";
import type { PostCleanupTargets } from "./lib/post-state.ts";
import { takeWriteThroughForPost } from "./lib/post-write-through.ts";
import { pinHostCommands, pinningPaths } from "./lib/sandbox/host-commands.ts";
import { hostCommand, hostCommandEnv } from "./lib/sandbox/pinned-commands.ts";

// Untested by design, down to the end of the file: planPostCleanup decides
// what may be torn down, and tearing it down is one `docker compose down`.
/* v8 ignore start */
// The override is read here too, not just in main.ts: if main.ts started the
// proxy via BUILDCAGE_TEST_COMPOSE_FILE (this repo's own inspect-engine fixture
// tests) and the process was then killed before its own finally block ran, this
// fallback must tear down the same compose file that started it, not the
// shipped default it never used.
async function stopProxyContainer({ containerName, projectName }: PostCleanupTargets) {
  const composeFile = resolveComposeFile(await readLocalImageOverride(process.env));

  execFileSync(hostCommand("docker"), buildComposeDownArgs({ composeFile, projectName }), {
    stdio: "inherit",
    env: hostCommandEnv("docker", { ...process.env, PROXY_CONTAINER_NAME: containerName }),
  });
}

// Fallback-only cleanup: main.ts already stops the proxy container in its
// own finally block on every normal exit path. This only matters if the
// process was killed outright before reaching that finally (e.g. a cancel
// while the proxy was still starting). State saved by main.ts's core.saveState surfaces
// here via core.getState; see
// https://docs.github.com/en/actions/reference/workflows-and-actions/workflow-commands#sending-values-to-the-pre-and-post-actions.
function main(): void {
  // The write_through the main step saved when it read config_file, which
  // this step must not read again; the workflow's own input otherwise.
  const savedWriteThrough = takeWriteThroughForPost(process.env);
  // Before planPostCleanup, which already runs docker and sudo. The main step
  // already reported any renamed input, hence the no-op notice.
  pinHostCommands(
    pinningPaths(
      () => savedWriteThrough ?? readFilesystemInputs(() => {}).writeThroughInput,
      process.env,
    ),
    process.env,
  );
  const targets = planPostCleanup(
    {
      containerName: core.getState("container_name"),
      ephemeralRoots: core.getState("ephemeral_overlay_roots"),
    },
    process.env,
    // Always on: the post step has no report to suppress annotations for, and
    // what it has to say is about cleanup that either happened or didn't.
    annotate,
  );
  // No catch: a failure here should crash this script with an uncaught error
  // and a non-zero exit, which is Node's default unhandled-rejection behavior.
  if (targets) void stopProxyContainer(targets);
}

// Node resolves symlinks in import.meta.url but not in argv, and the runner
// may reach the checkout through one.
if (process.argv[1] && realpathSync(process.argv[1]) === fileURLToPath(import.meta.url)) {
  main();
}
/* v8 ignore stop */

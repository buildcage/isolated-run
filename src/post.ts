import { execFileSync } from "node:child_process";
import { existsSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import * as core from "@actions/core";

import { buildComposeDownArgs } from "#core/lib/docker/args.ts";
import { ownerToken, readContainerOwner } from "./lib/container.ts";
import { cleanupScratchDir, scratchDirFor } from "./lib/sandbox/scratch-dir.ts";
import { resolvePostState } from "./lib/post-state.ts";
import { errorMessage } from "#core/lib/errors.ts";

const __dirname = dirname(fileURLToPath(import.meta.url));
const defaultComposeFile = join(__dirname, "../docker/compose.action.yaml");

// Same gate as main.ts's own LOCAL_IMAGE_OVERRIDE_ENABLED — see its comment
// there. Needed here too: if main.ts started the proxy via
// BUILDCAGE_TEST_COMPOSE_FILE (this repo's own inspect-engine fixture tests)
// and the process was then killed before its own finally block ran, this
// fallback must tear down the same compose file that started it, not the
// shipped default it never used.
const LOCAL_IMAGE_OVERRIDE_ENABLED = process.env.BUILDCAGE_BUILD_TEST_HOOKS === "1";

// Fallback-only cleanup: main.ts already stops the proxy container in its
// own finally block on every normal exit path. This only matters if the
// process was killed outright before reaching that finally (e.g. the
// runner cancels the step). State saved by main.ts's core.saveState surfaces
// here via core.getState — see
// https://docs.github.com/en/actions/creating-actions/dockerfile-support-for-github-actions#saving-state.
const { targets, problems } = resolvePostState({
  containerName: core.getState("container_name"),
  ephemeralRoots: core.getState("ephemeral_overlay_roots"),
});
for (const problem of problems) {
  console.log(`::error::run post-cleanup: ${problem}`);
}

/**
 * A name this action could have generated isn't proof that this step
 * generated it: the isolated command can name a concurrent Buildcage step's
 * container just as easily as a malformed one. What the container itself
 * records about the step that started it is what decides.
 *
 * No container behind the name leaves nothing to protect -- main.ts starts
 * the proxy before the scratch dir and stops it after, so a live sandbox
 * always has one, and anything left under that name is a dead run's
 * leftovers. Reclaiming those is what this fallback exists for.
 *
 * Deliberately not caught: if docker can't answer, ownership can't be
 * established and nothing should be torn down.
 */
function startedByThisStep(containerName: string): boolean {
  const owner = readContainerOwner(containerName);
  return owner === null || owner === ownerToken(process.env);
}

let owned = true;
if (targets) {
  owned = startedByThisStep(targets.containerName);
  if (!owned) {
    console.log(
      `::error::run post-cleanup: the proxy container named in GITHUB_STATE was started by a ` +
        `different step. Skipping all post-step cleanup: tearing it down would stop that step's ` +
        `proxy and delete its sandbox scratch directory.`,
    );
  }
}

// Reclaim this step's sandbox scratch dir if a hard kill bypassed main.ts's
// own withScratchDir finally. Its path is derived deterministically from
// containerName (scratchDirFor), so no separately recorded path is needed.
// cleanupScratchDir force-detaches the rootfs bind-mount before deleting, so
// this can't walk into the host filesystem even if a mount somehow survived.
// Independent of the container teardown below, so a failure in one still
// leaves the other to run.
if (targets && owned) {
  try {
    const scratchDir = scratchDirFor(targets.containerName);
    if (existsSync(scratchDir)) {
      cleanupScratchDir(scratchDir, targets.ephemeralRoots);
    }
  } catch (e) {
    console.log(
      `::warning::run post-cleanup: failed to remove sandbox scratch dir: ${errorMessage(e)}`,
    );
  }
}

async function stopProxyContainer(): Promise<void> {
  if (!targets || !owned) return;
  const { containerName, projectName } = targets;

  const localOverride = LOCAL_IMAGE_OVERRIDE_ENABLED
    ? (await import("./core/lib/provenance/local-image-override.ts")).readLocalImageOverride(
        process.env,
      )
    : null;
  const composeFile = localOverride?.composeFile ?? defaultComposeFile;

  execFileSync("docker", buildComposeDownArgs({ composeFile, projectName }), {
    stdio: "inherit",
    env: { ...process.env, PROXY_CONTAINER_NAME: containerName },
  });
}

// No catch: a failure here should crash this script the same way the
// original synchronous execFileSync call did (an uncaught error, non-zero
// exit) -- Node's default unhandled-rejection behavior matches that.
void stopProxyContainer();

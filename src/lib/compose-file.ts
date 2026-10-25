/**
 * Which compose files start (and tear down) the proxy container, for both
 * entry points. main.ts and post.ts have to agree on this: post.ts's fallback
 * cleanup only reaches the right containers if it runs against the same files
 * main.ts started them from.
 */
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";

import type { LocalImageOverride } from "../core/lib/provenance/local-image-override.ts";

// Resolved from the bundle's own location: dist/main.cjs and dist/post.cjs
// both sit in dist/, a sibling of docker/.
const __dirname = dirname(fileURLToPath(import.meta.url));
export const DEFAULT_COMPOSE_FILE = join(__dirname, "../docker/compose.action.yaml");

/**
 * The local-image override, or null in a normal build.
 *
 * Gates a local-image override used only by this repo's own CI/dev testing
 * (the test_sandbox_* jobs in .github/workflows/test-e2e.yml, test_sandbox in
 * test-integration.yml, and verify-image in docker-publish.yml, where the image
 * is not signed yet), never by a consumer of a published action. rolldown's
 * replacePlugin substitutes BUILDCAGE_BUILD_TEST_HOOKS with the *build's* env,
 * so without that flag the condition is constant-false and the dynamic import
 * below is tree-shaken out of dist entirely; see rolldown.config.js.
 */
export async function readLocalImageOverride(
  env: NodeJS.ProcessEnv,
  log: (message: string) => void = console.log,
): Promise<LocalImageOverride | null> {
  if (process.env.BUILDCAGE_BUILD_TEST_HOOKS !== "1") return null;
  const override = (
    await import("../core/lib/provenance/local-image-override.ts")
  ).readLocalImageOverride(env);
  // Said here rather than by the caller so every entry point that takes the
  // bypass announces it, and so a normal build carries neither the message
  // nor the module it describes.
  if (override) {
    log(
      `BUILDCAGE_LOCAL_IMAGE_REF is set (${JSON.stringify(override.imageRef)}): ` +
        `skipping image provenance verification entirely. This bypass exists only for ` +
        `buildcage's own CI self-tests and local development.`,
    );
  }
  return override;
}

/** The shipped compose file, with the override's overlay on top if it names one. */
export function resolveComposeFiles(override: LocalImageOverride | null): string[] {
  return override?.composeOverlay
    ? [DEFAULT_COMPOSE_FILE, override.composeOverlay]
    : [DEFAULT_COMPOSE_FILE];
}

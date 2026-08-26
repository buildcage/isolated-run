export interface LocalImageOverride {
  imageRef: string;
  pullPolicy: "never";
  /**
   * BUILDCAGE_TEST_COMPOSE_FILE, when set: a compose file to start the proxy
   * from in place of docker/compose.action.yaml. Used only by this repo's own
   * fixture-network integration tests (see test/compose.test-inspect.yaml),
   * which need the proxy container to join a test-only Docker network the
   * shipped compose.action.yaml has no reason to know about.
   */
  composeFile: string | undefined;
}

/**
 * Reads BUILDCAGE_LOCAL_IMAGE_REF (and BUILDCAGE_TEST_COMPOSE_FILE) from the
 * given env. Kept in its own module so a normal build can exclude it
 * entirely — see LOCAL_IMAGE_OVERRIDE_ENABLED in main.ts.
 */
export function readLocalImageOverride(env: NodeJS.ProcessEnv): LocalImageOverride | null {
  const ref = env.BUILDCAGE_LOCAL_IMAGE_REF;
  if (!ref) return null;
  return { imageRef: ref, pullPolicy: "never", composeFile: env.BUILDCAGE_TEST_COMPOSE_FILE };
}

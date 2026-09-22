/** The engine a tag falls back to when none is given. */
const DEFAULT_ENGINE = "inspect";

export function engineTagSuffix(proxyEngine: string): string {
  return `-${proxyEngine}`;
}

/**
 * Convert an action ref into the Docker image tag to resolve (e.g.
 * `<version>-inspect`, `<version>-universal`, `sha-<sha>-inspect`).
 *
 * Every engine's tag carries its own `-<engine>` suffix. The suffix is not part
 * of the Sigstore identity; engine-label.ts is what binds the resolved image to
 * the requested engine.
 */
export function imageTagFromRef(
  actionRef: string | undefined,
  proxyEngine: string = DEFAULT_ENGINE,
): string {
  if (!actionRef) return "";
  let base;
  if (/^[0-9a-f]{40}$/i.test(actionRef)) {
    base = `sha-${actionRef.toLowerCase()}`;
  } else if (actionRef.startsWith("v")) {
    base = actionRef.slice(1);
  } else {
    base = actionRef;
  }
  return `${base}${engineTagSuffix(proxyEngine)}`;
}

/**
 * Convert an action ref into the base Docker image tag, then append the
 * proxy engine suffix for a non-default engine. The `transparent` engine
 * (default) publishes the plain version tag (e.g. `1.0.0`), matching the
 * pre-multi-engine tagging scheme; `inspect` publishes under its own
 * suffix (e.g. `1.0.0-inspect`). Both share the same Sigstore verification
 * identity (same workflow, same git ref) — only the published Docker tag
 * differs, so this does not affect verify-policy.ts's buildVerifyOptions.
 */
export function imageTagFromRef(
  actionRef: string | undefined,
  proxyEngine: string = "transparent",
): string {
  let base;
  if (!actionRef) {
    base = "";
  } else if (/^[0-9a-f]{40}$/i.test(actionRef)) {
    base = `sha-${actionRef.toLowerCase()}`;
  } else if (actionRef.startsWith("v")) {
    base = actionRef.slice(1);
  } else {
    base = actionRef;
  }

  if (proxyEngine !== "transparent" && proxyEngine !== "") return `${base}-${proxyEngine}`;
  return base;
}

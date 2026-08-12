/**
 * Convert an action ref into the Docker image tag. Unlike buildcage/docker
 * (which publishes transparent/explicit/proxy engines as suffixed tags under
 * one shared image repository), isolated-run publishes a single image, so
 * the tag is always the plain version (e.g. `1.0.0`) — no engine suffix.
 */
export function imageTagFromRef(actionRef: string | undefined): string {
  if (!actionRef) return "";
  if (/^[0-9a-f]{40}$/i.test(actionRef)) {
    return `sha-${actionRef.toLowerCase()}`;
  }
  if (actionRef.startsWith("v")) {
    return actionRef.slice(1);
  }
  return actionRef;
}

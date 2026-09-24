import { VerifyImageError } from "./errors.ts";
import { engineTagSuffix } from "./image-tag.ts";

/** Holds the published Docker tag, engine suffix included. */
export const IMAGE_VERSION_LABEL = "org.opencontainers.image.version";

/**
 * A release version as docker-publish.yml writes it, before any engine suffix.
 * The prerelease grammar is the one release.yml and docker-publish.yml accept
 * for a tag, which admits no `-` inside it.
 */
const RELEASE_VERSION = /^\d+\.\d+\.\d+(-[0-9A-Za-z]+(\.[0-9A-Za-z]+)*)?$/;

export interface EngineLabelCheck {
  labels: Record<string, string>;
  proxyEngine: string;
  imageTag: string;
}

/**
 * Fail unless the verified image was published for the requested engine.
 *
 * Every engine of a release verifies under the same signing identity, which
 * covers the git tag and never the Docker tag, so the tag alone would decide
 * which engine runs.
 *
 * The label has to be this engine's suffix on a bare release version. Reading
 * the engine off the label instead would fail open for any suffix the action
 * does not recognize, such as an engine it has since stopped offering but whose
 * images are still published and still signed.
 */
export function checkImageEngine({ labels, proxyEngine, imageTag }: EngineLabelCheck): void {
  const label = labels[IMAGE_VERSION_LABEL];
  if (!label) {
    throw new VerifyImageError(
      `Image ${imageTag} carries no ${IMAGE_VERSION_LABEL} label, so the proxy engine it was ` +
        `published for cannot be confirmed.`,
      "VERIFY_FAILED",
    );
  }

  const suffix = engineTagSuffix(proxyEngine);
  if (
    label.endsWith(suffix) &&
    RELEASE_VERSION.test(label.slice(0, label.length - suffix.length))
  ) {
    return;
  }

  throw new VerifyImageError(
    `Image ${imageTag} was not published for proxy engine ${proxyEngine} ` +
      `(${IMAGE_VERSION_LABEL}: ${label}), so the rules this run was given would not be enforced.`,
    "VERIFY_FAILED",
  );
}

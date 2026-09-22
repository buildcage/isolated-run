import { SandboxError } from "./errors.ts";

/**
 * Each accepted value maps to a separately published, separately tagged
 * Docker image (see provenance/image-tag.ts's imageTagFromRef).
 *
 * Lives here rather than beside the input reads because lib/ modules need
 * the type: defining it with the reads would make compose-env.ts and
 * engine-rule-support.ts import back out of them.
 */
const ENGINES = ["universal", "inspect"] as const;
export type ProxyEngine = (typeof ENGINES)[number];

export function resolveProxyEngine(input: string | undefined): ProxyEngine {
  const trimmed = input?.trim() || "inspect";
  if (!(ENGINES as readonly string[]).includes(trimmed)) {
    throw new SandboxError(
      `Invalid proxy_engine: ${JSON.stringify(input)}. Must be one of ${ENGINES.join(", ")}.`,
      "INVALID_PROXY_ENGINE",
    );
  }
  return trimmed as ProxyEngine;
}

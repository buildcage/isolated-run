import { ownerToken } from "./container.ts";
import type { ProxyEngine } from "./engine.ts";
import { listHostIpv4Addresses } from "./host-addresses.ts";

export interface ComposeEnvOptions {
  containerName: string;
  proxyMode: string;
  proxyEngine: ProxyEngine;
  imageRef: string;
  httpsRules: string[];
  httpRules: string[];
  ipRules: string[];
  urlRules: string[];
  tlsRules: string[];
}

/**
 * The environment `docker compose up` starts this step's proxy container
 * with. Every value the engine reads is set here rather than inherited, so
 * nothing an earlier workflow step left in the job environment can reach it.
 *
 * `hostAddresses` is an injectable seam for testing without reading the
 * runner's own interfaces, not a caller-facing precondition.
 */
export function buildComposeEnv(
  {
    containerName,
    proxyMode,
    proxyEngine,
    imageRef,
    httpsRules,
    httpRules,
    ipRules,
    urlRules,
    tlsRules,
  }: ComposeEnvOptions,
  env: NodeJS.ProcessEnv,
  hostAddresses: () => string[] = listHostIpv4Addresses,
): NodeJS.ProcessEnv {
  return {
    ...env,
    PROXY_CONTAINER_NAME: containerName,
    BUILDCAGE_OWNER: ownerToken(env),
    PROXY_MODE: proxyMode,
    PROXY_ENGINE: proxyEngine,
    ALLOWED_HTTPS_RULES: httpsRules.join("\n"),
    ALLOWED_HTTP_RULES: httpRules.join("\n"),
    ALLOWED_IP_RULES: ipRules.join("\n"),
    ALLOWED_URL_RULES: urlRules.join("\n"),
    ALLOWED_TLS_RULES: tlsRules.join("\n"),
    BUILDCAGE_PROXY_IMAGE_REF: imageRef,
    // Pinned rather than inherited: in persistent mode an isolated command can
    // write $GITHUB_ENV, so a resolver left to the step environment would be a
    // previous step's choice, not the action's.
    EXTERNAL_RESOLVER: "",
    // The compose network's gateway is added engine-side; see
    // lib/host-addresses.ts.
    HOST_ADDRESSES: hostAddresses().join(" "),
  };
}

import { describe, it, expect } from "vitest";

import { buildComposeEnv, type ComposeEnvOptions } from "./compose-env.ts";

const CONTAINER = "buildcage-proxy-deadbeef";
const HOST_ADDRESSES = () => ["10.0.0.4", "172.17.0.1"];

/** Set by the runner per step; ownerToken joins the four into one token. */
const STEP_ENV = {
  GITHUB_RUN_ID: "1",
  GITHUB_RUN_ATTEMPT: "1",
  GITHUB_JOB: "build",
  GITHUB_ACTION: "buildcage",
};

function options(overrides: Partial<ComposeEnvOptions> = {}): ComposeEnvOptions {
  return {
    containerName: CONTAINER,
    proxyMode: "restrict",
    proxyEngine: "universal",
    imageRef: "ghcr.io/buildcage/isolated-run@sha256:feedface",
    httpsRules: [],
    httpRules: [],
    ipRules: [],
    urlRules: [],
    tlsRules: [],
    ...overrides,
  };
}

describe("buildComposeEnv", () => {
  it("carries every resolved input the engine reads", () => {
    const env = buildComposeEnv(
      options({
        proxyMode: "audit",
        proxyEngine: "inspect",
        httpsRules: ["registry.npmjs.org:443", "*.githubusercontent.com:443"],
        httpRules: ["deb.debian.org:80"],
        ipRules: ["10.0.0.0/8"],
        urlRules: ["GET https://api.github.com/repos/*"],
        tlsRules: ["*.example.com:443"],
      }),
      {},
      HOST_ADDRESSES,
    );

    expect(env).toStrictEqual({
      PROXY_CONTAINER_NAME: CONTAINER,
      BUILDCAGE_OWNER: "",
      PROXY_MODE: "audit",
      PROXY_ENGINE: "inspect",
      ALLOWED_HTTPS_RULES: "registry.npmjs.org:443\n*.githubusercontent.com:443",
      ALLOWED_HTTP_RULES: "deb.debian.org:80",
      ALLOWED_IP_RULES: "10.0.0.0/8",
      ALLOWED_URL_RULES: "GET https://api.github.com/repos/*",
      ALLOWED_TLS_RULES: "*.example.com:443",
      BUILDCAGE_PROXY_IMAGE_REF: "ghcr.io/buildcage/isolated-run@sha256:feedface",
      HOST_ADDRESSES: "10.0.0.4 172.17.0.1",
    });
  });

  // The label is what post.ts checks before tearing a container down.
  it("labels the container with the step that started it", () => {
    const env = buildComposeEnv(options(), STEP_ENV, () => []);

    expect(env.BUILDCAGE_OWNER).toBe("1/1/build/buildcage");
  });

  it("passes the job environment through, so docker compose keeps working", () => {
    const env = buildComposeEnv(options(), { PATH: "/usr/bin" }, () => []);

    expect(env.PATH).toBe("/usr/bin");
  });

  // A URL rule contains a space, unlike the others, so no rule list can be
  // space separated.
  it("separates every rule list by newline", () => {
    const env = buildComposeEnv(
      options({
        httpsRules: ["a:443", "b:443"],
        urlRules: ["GET https://a/x", "POST https://b/y"],
      }),
      {},
      () => [],
    );

    expect(env.ALLOWED_HTTPS_RULES).toBe("a:443\nb:443");
    expect(env.ALLOWED_URL_RULES).toBe("GET https://a/x\nPOST https://b/y");
  });
});

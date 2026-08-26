import { describe, it, expect } from "vitest";
import { readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";

import {
  writeCaTrustFiles,
  caTrustAdditions,
  OWN_CA_DESTINATION,
  SYSTEM_CA_DESTINATION,
} from "./ca-trust.ts";
import { withScratchDir } from "./scratch-dir.ts";

const FAKE_CA = "-----BEGIN CERTIFICATE-----\nfake\n-----END CERTIFICATE-----";

describe("writeCaTrustFiles", () => {
  it("writes the CA into its own file, trailing whitespace trimmed to one newline", () => {
    withScratchDir((dir) => {
      const caCertPath = join(dir, "input-ca.pem");
      writeFileSync(caCertPath, `${FAKE_CA}\n\n\n`);
      const { ownCaPath } = writeCaTrustFiles(caCertPath, dir);
      expect(readFileSync(ownCaPath, "utf8")).toBe(`${FAKE_CA}\n`);
    });
  });
});

// caTrustAdditions never touches the filesystem itself -- it only reasons
// about the CaTrustFiles paths it's given -- so these don't need
// withScratchDir; only writeCaTrustFiles above does real file I/O.
describe("caTrustAdditions", () => {
  it("mounts the CA-only file and points the additive variables at it, when unset", () => {
    const { mounts, env } = caTrustAdditions(
      { ownCaPath: "/scratch/buildcage-ca.pem", systemCaPath: undefined },
      {},
    );
    expect(mounts).toEqual([
      {
        destination: OWN_CA_DESTINATION,
        type: "none",
        source: "/scratch/buildcage-ca.pem",
        options: ["rbind", "ro"],
      },
    ]);
    expect(env.NODE_EXTRA_CA_CERTS).toBe(OWN_CA_DESTINATION);
    expect(env.DENO_CERT).toBe(OWN_CA_DESTINATION);
  });

  it("does not override a variable the step already set", () => {
    const { env } = caTrustAdditions(
      { ownCaPath: "/scratch/buildcage-ca.pem", systemCaPath: undefined },
      { NODE_EXTRA_CA_CERTS: "/my/own/bundle.pem" },
    );
    expect(env.NODE_EXTRA_CA_CERTS).toBeUndefined();
    expect(env.DENO_CERT).toBe(OWN_CA_DESTINATION);
  });

  it("adds the system-store mount and points the replacing variables at it, only when a system store was found", () => {
    const { mounts, env } = caTrustAdditions(
      { ownCaPath: "/scratch/buildcage-ca.pem", systemCaPath: "/scratch/system-ca-bundle.pem" },
      {},
    );
    expect(mounts).toContainEqual({
      destination: SYSTEM_CA_DESTINATION,
      type: "none",
      source: "/scratch/system-ca-bundle.pem",
      options: ["rbind", "ro"],
    });
    expect(env.REQUESTS_CA_BUNDLE).toBe(SYSTEM_CA_DESTINATION);
    expect(env.PIP_CERT).toBe(SYSTEM_CA_DESTINATION);
    expect(env.SSL_CERT_FILE).toBe(SYSTEM_CA_DESTINATION);
  });

  it("leaves CURL_CA_BUNDLE alone either way, since curl already reads the system store", () => {
    const { env } = caTrustAdditions(
      { ownCaPath: "/scratch/buildcage-ca.pem", systemCaPath: "/scratch/system-ca-bundle.pem" },
      {},
    );
    expect(env.CURL_CA_BUNDLE).toBeUndefined();
  });

  it("omits the system-store mount entirely when no system store was found", () => {
    const { mounts, env } = caTrustAdditions(
      { ownCaPath: "/scratch/buildcage-ca.pem", systemCaPath: undefined },
      {},
    );
    expect(mounts.some((m) => m.destination === SYSTEM_CA_DESTINATION)).toBe(false);
    expect(env.REQUESTS_CA_BUNDLE).toBeUndefined();
    expect(env.PIP_CERT).toBeUndefined();
    expect(env.SSL_CERT_FILE).toBeUndefined();
  });
});

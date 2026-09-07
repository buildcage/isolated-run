import { describe, it, expect } from "vitest";

import {
  generateContainerName,
  getContainerNetns,
  isContainerNotFoundError,
  isValidContainerName,
  CONTAINER_NAME_PATTERN,
} from "./container.ts";
import { deriveProjectName } from "#core/lib/docker/compose-project-name.ts";
import { SandboxError } from "./errors.ts";

describe("generateContainerName", () => {
  it("always starts with the buildcage-proxy- prefix", () => {
    expect(generateContainerName()).toMatch(/^buildcage-proxy-[0-9a-f]{8}$/);
  });

  it("produces distinct names across calls", () => {
    const names = new Set(Array.from({ length: 20 }, () => generateContainerName()));
    expect(names.size).toBe(20);
  });

  it("always matches CONTAINER_NAME_PATTERN (drift detection between generation and validation)", () => {
    for (let i = 0; i < 100; i++) {
      expect(generateContainerName()).toMatch(CONTAINER_NAME_PATTERN);
    }
  });
});

describe("isValidContainerName", () => {
  it("accepts a genuine generated name", () => {
    expect(isValidContainerName(generateContainerName())).toBe(true);
  });

  it("rejects a path traversal payload", () => {
    expect(isValidContainerName("buildcage-proxy-x/../../../..")).toBe(false);
  });

  it("rejects an uppercase-hex payload", () => {
    expect(isValidContainerName("buildcage-proxy-ABCD1234")).toBe(false);
  });

  it("rejects a too-long suffix", () => {
    expect(isValidContainerName("buildcage-proxy-abcd12345")).toBe(false);
  });
});

describe("getContainerNetns", () => {
  it("returns null for a container that doesn't exist (no real docker needed)", () => {
    const fakeExec = () => {
      throw { stderr: "error: no such object: buildcage-proxy-xyz" };
    };
    expect(getContainerNetns("buildcage-proxy-xyz", { exec: fakeExec })).toBe(null);
  });

  it("parses the SandboxKey from a successful docker inspect", () => {
    const fakeExec = () => "/var/run/docker/netns/1a2b3c4d5e6f\n";
    expect(getContainerNetns("buildcage-proxy-abc", { exec: fakeExec })).toBe(
      "/var/run/docker/netns/1a2b3c4d5e6f",
    );
  });

  it("returns null when docker inspect prints an empty SandboxKey (container exists but stopped)", () => {
    const fakeExec = () => "\n";
    expect(getContainerNetns("buildcage-proxy-abc", { exec: fakeExec })).toBe(null);
  });

  it("throws SandboxError with DOCKER_UNAVAILABLE when docker is unreachable", () => {
    const fakeExec = () => {
      throw { stderr: "Cannot connect to the Docker daemon at unix:///var/run/docker.sock" };
    };
    expect.assertions(2);
    try {
      getContainerNetns("buildcage-proxy-abc", { exec: fakeExec });
    } catch (err) {
      expect(err).toBeInstanceOf(SandboxError);
      expect((err as SandboxError).code).toBe("DOCKER_UNAVAILABLE");
    }
  });
});

describe("isContainerNotFoundError", () => {
  it("recognizes docker's 'no such object' wording", () => {
    expect(isContainerNotFoundError({ stderr: "error: no such object: buildcage-proxy-xyz" })).toBe(
      true,
    );
  });

  it("recognizes docker's 'no such container' wording", () => {
    expect(
      isContainerNotFoundError({ stderr: "Error: No such container: buildcage-proxy-xyz" }),
    ).toBe(true);
  });

  it("does not misclassify a daemon-unreachable failure", () => {
    expect(
      isContainerNotFoundError({
        stderr: "Cannot connect to the Docker daemon at unix:///var/run/docker.sock",
      }),
    ).toBe(false);
  });

  it("does not misclassify an ENOENT (docker not on PATH)", () => {
    expect(isContainerNotFoundError({ code: "ENOENT" })).toBe(false);
  });
});

// General deriveProjectName tests live in core/lib/docker/container.test.ts;
// this one is specific to run's own container-name format.
describe("deriveProjectName", () => {
  it("matches docker compose's project-name character constraints for any generated container name", () => {
    for (let i = 0; i < 20; i++) {
      const projectName = deriveProjectName(generateContainerName());
      expect(projectName).toMatch(/^[a-z0-9][a-z0-9_-]*$/);
    }
  });
});

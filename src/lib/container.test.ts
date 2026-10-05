import { describe, it, expect } from "vitest";

import { deriveProjectName } from "#core/lib/docker/compose-project-name.ts";

import {
  generateContainerName,
  getContainerNetns,
  isContainerNotFoundError,
  isValidContainerName,
  netnsNameFor,
  ownerToken,
  readContainerOwner,
  scratchDirNameFor,
  CONTAINER_NAME_PATTERN,
} from "./container.ts";
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

describe("the names derived from a container's own", () => {
  it("swaps the prefix, keeping the part that identifies the step", () => {
    expect(netnsNameFor("buildcage-proxy-deadbeef")).toBe("buildcage-sandbox-deadbeef");
    expect(scratchDirNameFor("buildcage-proxy-deadbeef")).toBe("sandbox-deadbeef");
  });

  // Sharing a spelling between the three would make `docker ps` output
  // ambiguous.
  it("gives a generated name three distinct spellings", () => {
    const containerName = generateContainerName();
    const names = [containerName, netnsNameFor(containerName), scratchDirNameFor(containerName)];

    expect(new Set(names).size).toBe(3);
  });

  it("leaves a name that does not carry the prefix alone", () => {
    expect(netnsNameFor("something-else")).toBe("something-else");
    expect(scratchDirNameFor("something-else")).toBe("something-else");
  });

  // scratchDirFor validates before deriving, and assertUnderScratchBase
  // re-checks the shape on the way back in; see scratch-dir.ts.
  it("produces a scratch dir name of the shape cleanup will accept", () => {
    expect(scratchDirNameFor(generateContainerName())).toMatch(/^sandbox-[0-9a-f]{8}$/);
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

describe("ownerToken", () => {
  const ACTIONS_ENV = {
    GITHUB_RUN_ID: "17",
    GITHUB_RUN_ATTEMPT: "2",
    GITHUB_JOB: "build",
    GITHUB_ACTION: "buildcage_2",
    RUNNER_NAME: "runner-1",
  };

  it("is built from the variables the runner sets for the step", () => {
    expect(ownerToken(ACTIONS_ENV)).toBe("17/2/build/buildcage_2/runner-1");
  });

  it("separates two uses of the action in one job, which GITHUB_ACTION numbers", () => {
    expect(ownerToken({ ...ACTIONS_ENV, GITHUB_ACTION: "buildcage_3" })).not.toBe(
      ownerToken(ACTIONS_ENV),
    );
  });

  it("separates two jobs sharing a host", () => {
    expect(ownerToken({ ...ACTIONS_ENV, GITHUB_RUN_ID: "18" })).not.toBe(ownerToken(ACTIONS_ENV));
    expect(ownerToken({ ...ACTIONS_ENV, GITHUB_JOB: "test" })).not.toBe(ownerToken(ACTIONS_ENV));
  });

  it("separates matrix legs sharing a host, which differ only in RUNNER_NAME", () => {
    expect(ownerToken({ ...ACTIONS_ENV, RUNNER_NAME: "runner-2" })).not.toBe(
      ownerToken(ACTIONS_ENV),
    );
  });

  it("is empty outside a real Actions step, rather than a partial token", () => {
    for (const name of Object.keys(ACTIONS_ENV)) {
      expect(ownerToken({ ...ACTIONS_ENV, [name]: undefined })).toBe("");
    }
    expect(ownerToken({})).toBe("");
  });
});

describe("readContainerOwner", () => {
  it("returns null for a container that doesn't exist", () => {
    const fakeExec = () => {
      throw { stderr: "error: no such object: buildcage-proxy-xyz" };
    };
    expect(readContainerOwner("buildcage-proxy-xyz", { exec: fakeExec })).toBe(null);
  });

  it("reads the label back", () => {
    const fakeExec = () => "17/2/build/buildcage_2\n";
    expect(readContainerOwner("buildcage-proxy-abc", { exec: fakeExec })).toBe(
      "17/2/build/buildcage_2",
    );
  });

  it("reads a container carrying no labels at all as unowned, not as the literal template output", () => {
    const fakeExec = () => "<no value>\n";
    expect(readContainerOwner("buildcage-proxy-abc", { exec: fakeExec })).toBe("");
  });

  it("throws SandboxError with DOCKER_UNAVAILABLE when docker is unreachable", () => {
    const fakeExec = () => {
      throw { stderr: "Cannot connect to the Docker daemon at unix:///var/run/docker.sock" };
    };
    expect.assertions(2);
    try {
      readContainerOwner("buildcage-proxy-abc", { exec: fakeExec });
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

// General deriveProjectName tests live in
// core/lib/docker/compose-project-name.test.ts; this one is specific to the
// run action's own container-name format.
describe("deriveProjectName", () => {
  it("matches docker compose's project-name character constraints for any generated container name", () => {
    for (let i = 0; i < 20; i++) {
      const projectName = deriveProjectName(generateContainerName());
      expect(projectName).toMatch(/^[a-z0-9][a-z0-9_-]*$/);
    }
  });
});

describe("isContainerNotFoundError on a value that is not an object", () => {
  it("reads it as some other failure rather than a missing container", () => {
    expect(isContainerNotFoundError("Error: No such object: buildcage")).toBe(false);
  });
});

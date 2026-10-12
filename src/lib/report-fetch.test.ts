import { describe, it, expect, beforeEach, vi } from "vitest";

import type { Docker } from "#core/lib/docker/client.ts";

import { readActionVersion } from "./report-fetch.ts";

// Label parsing is tested in action-version.test.ts.
const readLabels = vi.fn();
const docker = { readLabels } as unknown as Docker;

describe("readActionVersion", () => {
  const containerName = "buildcage-proxy-abcd1234";

  beforeEach(() => {
    readLabels.mockReset();
  });

  it("turns the image's bare version label back into its git tag", () => {
    readLabels.mockReturnValueOnce({
      "org.opencontainers.image.version": "3.1.4",
    });
    expect(readActionVersion(containerName, "universal", docker)).toBe("v3.1.4");
  });

  it("strips the engine suffix a non-universal image carries", () => {
    readLabels.mockReturnValueOnce({
      "org.opencontainers.image.version": "3.1.4-inspect",
    });
    expect(readActionVersion(containerName, "inspect", docker)).toBe("v3.1.4");
  });
});

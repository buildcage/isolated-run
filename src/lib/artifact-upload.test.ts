import { describe, it, expect } from "vitest";

import { artifactName } from "./artifact-upload.ts";

describe("artifactName", () => {
  it("puts the container's own random suffix after the prefix, so concurrent steps don't collide", () => {
    expect(artifactName("buildcage-traffic", "buildcage-proxy-deadbeef")).toBe(
      "buildcage-traffic-deadbeef",
    );
    expect(artifactName("buildcage-filesystem-audit", "buildcage-proxy-0badcafe")).toBe(
      "buildcage-filesystem-audit-0badcafe",
    );
  });
});

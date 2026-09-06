import { describe, it, expect } from "vitest";

import { resolvePostState } from "./post-state.ts";
import { deriveProjectName } from "#core/lib/docker/compose-project-name.ts";

describe("resolvePostState", () => {
  it("returns null targets and no problems when container_name is unset (the ordinary case)", () => {
    const result = resolvePostState({ containerName: "", ephemeralRoots: "" });
    expect(result).toStrictEqual({ targets: null, problems: [] });
  });

  it("rejects a path-traversal container_name and reports it", () => {
    const result = resolvePostState({
      containerName: "buildcage-proxy-x/../../../..",
      ephemeralRoots: "",
    });
    expect(result.targets).toBeNull();
    expect(result.problems).toHaveLength(1);
    expect(result.problems[0]).toMatch(/not a name this action generates/);
  });

  it("rejects a traversal aimed at a specific host path", () => {
    const result = resolvePostState({
      containerName: "buildcage-proxy-x/../../../../home/runner",
      ephemeralRoots: "",
    });
    expect(result.targets).toBeNull();
    expect(result.problems).toHaveLength(1);
  });

  it("rejects an uppercase-hex container_name", () => {
    const result = resolvePostState({
      containerName: "buildcage-proxy-ABCD1234",
      ephemeralRoots: "",
    });
    expect(result.targets).toBeNull();
    expect(result.problems).toHaveLength(1);
  });

  it("rejects a 9-digit suffix", () => {
    const result = resolvePostState({
      containerName: "buildcage-proxy-abcd12345",
      ephemeralRoots: "",
    });
    expect(result.targets).toBeNull();
    expect(result.problems).toHaveLength(1);
  });

  it("derives projectName from container_name for a genuine name, without taking it as input", () => {
    const containerName = "buildcage-proxy-abcd1234";
    const result = resolvePostState({ containerName, ephemeralRoots: "" });
    expect(result.targets).not.toBeNull();
    expect(result.targets?.projectName).toBe(deriveProjectName(containerName));
    expect(result.problems).toStrictEqual([]);
  });

  it.each(["not json", '{"a":1}', '["relative/path"]', '["/home/runner\\n::error::forged"]'])(
    "treats malformed ephemeral_overlay_roots (%s) as absent",
    (ephemeralRoots) => {
      const result = resolvePostState({
        containerName: "buildcage-proxy-abcd1234",
        ephemeralRoots,
      });
      expect(result.targets?.ephemeralRoots).toBeUndefined();
      expect(result.problems).toHaveLength(1);
    },
  );

  it("passes through a well-formed ephemeral_overlay_roots value", () => {
    const result = resolvePostState({
      containerName: "buildcage-proxy-abcd1234",
      ephemeralRoots: '["/home/runner"]',
    });
    expect(result.targets?.ephemeralRoots).toStrictEqual(["/home/runner"]);
    expect(result.problems).toStrictEqual([]);
  });
});

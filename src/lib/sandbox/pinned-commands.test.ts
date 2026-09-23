import { describe, it, expect } from "vitest";

import { hostCommandEnv } from "./pinned-commands.ts";

describe("hostCommandEnv", () => {
  const env = { PATH: "/home/runner/.local/bin:/usr/bin", HOME: "/home/runner" };

  it("gives sudo the system dirs only, keeping the rest of the environment", () => {
    expect(hostCommandEnv("sudo", env)).toStrictEqual({
      PATH: "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
      HOME: "/home/runner",
    });
  });

  it("leaves any other command's environment as is", () => {
    expect(hostCommandEnv("docker", env)).toBe(env);
  });
});

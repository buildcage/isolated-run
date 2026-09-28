import { describe, it, expect } from "vitest";

import { hostCommandEnv, pinCommandPathEnv } from "./pinned-commands.ts";

describe("hostCommandEnv", () => {
  const env = { PATH: "/home/runner/.local/bin:/usr/bin", HOME: "/home/runner" };

  it("gives docker and sudo the system dirs only until their PATH is pinned", () => {
    for (const command of ["docker", "sudo"]) {
      expect(hostCommandEnv(command, env)).toStrictEqual({
        PATH: "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
        HOME: "/home/runner",
      });
    }
  });

  it("gives docker and sudo each their pinned PATH, keeping the rest of the environment", () => {
    pinCommandPathEnv("docker", "/opt/hostedtoolcache/bin:/usr/bin");
    pinCommandPathEnv("sudo", "/usr/sbin:/usr/bin");

    expect(hostCommandEnv("docker", env)).toStrictEqual({
      PATH: "/opt/hostedtoolcache/bin:/usr/bin",
      HOME: "/home/runner",
    });
    expect(hostCommandEnv("sudo", env)).toStrictEqual({
      PATH: "/usr/sbin:/usr/bin",
      HOME: "/home/runner",
    });
  });

  it("leaves any other command's environment as is", () => {
    expect(hostCommandEnv("/usr/bin/keytool", env)).toBe(env);
  });
});

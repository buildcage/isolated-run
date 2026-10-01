import { describe, it, expect } from "vitest";

import { rootlessRuntimeSocketPaths } from "./runtime-sockets.ts";

describe("rootlessRuntimeSocketPaths", () => {
  it("names the rootless Docker and Podman sockets under $XDG_RUNTIME_DIR", () => {
    expect(rootlessRuntimeSocketPaths({ XDG_RUNTIME_DIR: "/run/user/1000" })).toStrictEqual([
      "/run/user/1000/docker.sock",
      "/run/user/1000/podman/podman.sock",
    ]);
  });

  it("is empty when $XDG_RUNTIME_DIR is unset", () => {
    expect(rootlessRuntimeSocketPaths({})).toStrictEqual([]);
  });
});

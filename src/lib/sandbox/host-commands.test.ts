import { describe, it, expect } from "vitest";

import {
  dockerConfigDir,
  findPinnableCommand,
  persistingWritablePaths,
  pinHostCommands,
  pinningPaths,
  renameGuardDirs,
  sandboxReadonlyHostDirs,
  type FindCommandDeps,
} from "./host-commands.ts";
import { hostCommand } from "./pinned-commands.ts";
import { SandboxError } from "../errors.ts";

const HOME = "/home/runner";
const WORKSPACE = "/home/runner/work/repo/repo";
const PERSISTENT = [WORKSPACE, HOME, "/tmp", "/home/runner/work/_temp"];

/**
 * A host where `files` are the executables, and `links` map a symlink to its
 * immediate target (a chain is spelled out one hop per entry). A path in
 * `links` is executable too, so only its final target need be listed in `files`.
 * `dirLinks` map a directory to where it really is.
 */
function host(
  files: string[],
  links: Record<string, string> = {},
  dirLinks: Record<string, string> = {},
): FindCommandDeps {
  return {
    isExecutable: (p) => files.includes(p) || p in links,
    readlink: (p) => links[p] ?? null,
    realpathDir: (d) => dirLinks[d] ?? d,
  };
}

describe("persistingWritablePaths", () => {
  const env = { GITHUB_WORKSPACE: WORKSPACE, HOME, RUNNER_TEMP: "/home/runner/work/_temp" };

  it("is every directory persistent mode binds back read-write", () => {
    expect(persistingWritablePaths("persistent", ["/opt/out"], env)).toStrictEqual([
      ...PERSISTENT,
      "/opt/out",
    ]);
  });

  it("is only the write_through paths in ephemeral mode, whose overlays are discarded", () => {
    expect(persistingWritablePaths("ephemeral", [`${WORKSPACE}/dist`], env)).toStrictEqual([
      `${WORKSPACE}/dist`,
    ]);
  });
});

describe("findPinnableCommand", () => {
  it("skips a match inside a persisting path for the next one on PATH", () => {
    const deps = host([`${HOME}/.local/bin/docker`, "/usr/bin/docker"]);
    const path = `${HOME}/.local/bin:/usr/bin`;

    expect(findPinnableCommand("docker", path, PERSISTENT, deps)).toBe("/usr/bin/docker");
  });

  it("skips a candidate whose symlink chain passes through a persisting path", () => {
    // /usr/local/bin/docker -> ~/bin/docker (writable hop) -> /usr/bin/docker
    const deps = host(["/usr/bin/docker"], {
      "/usr/local/bin/docker": `${HOME}/bin/docker`,
      [`${HOME}/bin/docker`]: "/usr/bin/docker",
    });

    expect(findPinnableCommand("docker", "/usr/local/bin:/usr/bin", PERSISTENT, deps)).toBe(
      "/usr/bin/docker",
    );
  });

  it("returns the PATH entry, not the resolved target, so name-based tools still work", () => {
    // snap's docker: /snap/bin/docker -> /usr/bin/snap, both outside.
    const deps = host(["/usr/bin/snap"], { "/snap/bin/docker": "/usr/bin/snap" });

    expect(findPinnableCommand("docker", "/snap/bin:/usr/bin", PERSISTENT, deps)).toBe(
      "/snap/bin/docker",
    );
  });

  it("judges a PATH directory by where it really is, not how it is spelled", () => {
    // A self-hosted /opt/tools -> ~/tools: /opt/tools/bin/docker is writable
    // through $HOME even though its spelling is outside it.
    const deps = host(
      ["/opt/tools/bin/docker", "/usr/bin/docker"],
      {},
      { "/opt/tools/bin": `${HOME}/tools/bin` },
    );

    expect(findPinnableCommand("docker", "/opt/tools/bin:/usr/bin", PERSISTENT, deps)).toBe(
      "/usr/bin/docker",
    );
  });

  it("judges a symlink hop's directory the same way", () => {
    // /usr/local/bin/docker -> /opt/tools/bin/docker, whose directory is ~/tools/bin.
    const deps = host(
      ["/opt/tools/bin/docker", "/usr/bin/docker"],
      { "/usr/local/bin/docker": "/opt/tools/bin/docker" },
      { "/opt/tools/bin": `${HOME}/tools/bin` },
    );

    expect(findPinnableCommand("docker", "/usr/local/bin:/usr/bin", PERSISTENT, deps)).toBe(
      "/usr/bin/docker",
    );
  });

  it("gives up on a symlink cycle rather than looping", () => {
    const deps = host([], { "/usr/bin/docker": "/usr/local/bin/docker" });
    deps.readlink = (p) =>
      ({
        "/usr/bin/docker": "/usr/local/bin/docker",
        "/usr/local/bin/docker": "/usr/bin/docker",
      })[p] ?? null;
    deps.isExecutable = (p) => p === "/usr/bin/docker";

    // A cycle stays entirely outside the persisting paths here, so the guard
    // must stop it by hop count, not by finding a writable hop.
    expect(findPinnableCommand("docker", "/usr/bin", PERSISTENT, deps)).toBe("/usr/bin/docker");
  });

  it("skips relative and empty PATH entries, which resolve against the workspace", () => {
    const deps = host(["bin/docker", "docker", "/usr/bin/docker"]);

    expect(findPinnableCommand("docker", "bin::/usr/bin", PERSISTENT, deps)).toBe(
      "/usr/bin/docker",
    );
  });

  it("finds nothing when every match is inside a persisting path", () => {
    const deps = host([`${HOME}/.local/bin/docker`]);

    expect(findPinnableCommand("docker", `${HOME}/.local/bin`, PERSISTENT, deps)).toBeUndefined();
    expect(findPinnableCommand("docker", undefined, PERSISTENT, deps)).toBeUndefined();
  });

  it("takes the first match under write_through: /, the full opt-out", () => {
    const deps = host([`${HOME}/.local/bin/docker`, "/usr/bin/docker"]);

    expect(findPinnableCommand("docker", `${HOME}/.local/bin:/usr/bin`, ["/"], deps)).toBe(
      `${HOME}/.local/bin/docker`,
    );
  });
});

describe("pinHostCommands", () => {
  it("makes hostCommand answer with the pinned path of docker and sudo only", () => {
    pinHostCommands(
      PERSISTENT,
      { PATH: `${HOME}/.local/bin:/usr/bin` },
      host([`${HOME}/.local/bin/docker`, "/usr/bin/docker", "/usr/bin/sudo"]),
    );

    expect(hostCommand("docker")).toBe("/usr/bin/docker");
    expect(hostCommand("sudo")).toBe("/usr/bin/sudo");
    expect(hostCommand("keytool")).toBe("keytool");
  });

  it("fails the step when one can only be found where the command can write", () => {
    const error = (() => {
      try {
        pinHostCommands(
          PERSISTENT,
          { PATH: `${HOME}/.local/bin:/usr/bin` },
          host([`${HOME}/.local/bin/docker`, "/usr/bin/sudo"]),
        );
      } catch (e) {
        return e;
      }
    })();

    expect(error).toBeInstanceOf(SandboxError);
    expect((error as SandboxError).code).toBe("HOST_COMMAND_UNPINNABLE");
    expect((error as SandboxError).message).toContain("'docker'");
  });
  it("does not fail over a command missing from PATH, leaving it to the caller's own check", () => {
    expect(() =>
      pinHostCommands(PERSISTENT, { PATH: "/usr/bin" }, host(["/usr/bin/docker"])),
    ).not.toThrow();
  });
});

describe("pinningPaths", () => {
  const env = { GITHUB_WORKSPACE: WORKSPACE, HOME, RUNNER_TEMP: "/home/runner/work/_temp" };

  it("is persistent mode's set plus write_through, whatever mode the step runs in", () => {
    expect(pinningPaths(() => "/opt/out", env)).toStrictEqual([...PERSISTENT, "/opt/out"]);
  });

  it("falls back to persistent mode's set when the input does not parse", () => {
    expect(
      pinningPaths(() => {
        throw new Error("allow_write was removed");
      }, env),
    ).toStrictEqual(PERSISTENT);
  });
});

describe("dockerConfigDir", () => {
  it("is DOCKER_CONFIG when set, made absolute", () => {
    expect(dockerConfigDir({ DOCKER_CONFIG: "/etc/docker-cli", HOME })).toBe("/etc/docker-cli");
  });

  it("is ~/.docker otherwise, and nothing without a HOME", () => {
    expect(dockerConfigDir({ HOME })).toBe(`${HOME}/.docker`);
    expect(dockerConfigDir({})).toBeUndefined();
  });
});

describe("sandboxReadonlyHostDirs", () => {
  const ACTION = "/home/runner/work/_actions/buildcage/isolated-run/v1";

  it("is the action and docker config directories when a persisting path holds them", () => {
    expect(sandboxReadonlyHostDirs(PERSISTENT, { HOME }, ACTION)).toStrictEqual([
      ACTION,
      `${HOME}/.docker`,
    ]);
  });

  it("leaves out a directory no persisting path holds", () => {
    expect(sandboxReadonlyHostDirs([`${WORKSPACE}/dist`], { HOME }, ACTION)).toStrictEqual([]);
  });

  it("covers both under write_through: /", () => {
    expect(sandboxReadonlyHostDirs(["/"], { HOME }, ACTION)).toStrictEqual([
      ACTION,
      `${HOME}/.docker`,
    ]);
  });

  it("leaves out one that contains a persisting path, as uses: ./ puts the action in the workspace", () => {
    expect(sandboxReadonlyHostDirs(PERSISTENT, { HOME }, WORKSPACE)).toStrictEqual([
      `${HOME}/.docker`,
    ]);
  });

  it("leaves out one a write_through entry names outright", () => {
    expect(
      sandboxReadonlyHostDirs([...PERSISTENT, `${HOME}/.docker`], { HOME }, ACTION),
    ).toStrictEqual([ACTION]);
  });
});

describe("renameGuardDirs", () => {
  const ACTION = "/home/runner/work/_actions/buildcage/isolated-run/v1";

  it("pins every directory between the writable root and the read-only dir", () => {
    expect(renameGuardDirs([ACTION], PERSISTENT)).toStrictEqual([
      "/home/runner/work",
      "/home/runner/work/_actions",
      "/home/runner/work/_actions/buildcage",
      "/home/runner/work/_actions/buildcage/isolated-run",
    ]);
  });

  it("pins nothing for a dir sitting directly under the root, its parent already a mount point", () => {
    expect(renameGuardDirs([`${HOME}/.docker`], PERSISTENT)).toStrictEqual([]);
  });

  it("uses the deepest containing root, so it never pins a path outside the writable area", () => {
    // WORKSPACE is under HOME; the guards must stop at WORKSPACE, not walk up to HOME.
    expect(renameGuardDirs([`${WORKSPACE}/a/b`], PERSISTENT)).toStrictEqual([`${WORKSPACE}/a`]);
  });

  it("dedupes shared ancestors across several read-only dirs", () => {
    expect(
      renameGuardDirs(
        ["/home/runner/work/_actions/x/a/v1", "/home/runner/work/_actions/y/b/v1"],
        PERSISTENT,
      ),
    ).toStrictEqual([
      "/home/runner/work",
      "/home/runner/work/_actions",
      "/home/runner/work/_actions/x",
      "/home/runner/work/_actions/y",
      "/home/runner/work/_actions/x/a",
      "/home/runner/work/_actions/y/b",
    ]);
  });

  it("pins nothing under write_through: /, the full opt-out", () => {
    expect(renameGuardDirs([ACTION], ["/"])).toStrictEqual([]);
  });
});

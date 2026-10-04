import { describe, it, expect } from "vitest";

import { SandboxError } from "../errors.ts";
import {
  dockerConfigDir,
  findPinnableCommand,
  jvmTools,
  pathOutside,
  persistingWritablePaths,
  resolveDefaultWritableDirs,
  pinHostCommands,
  pinningPaths,
  renameGuardDirs,
  sandboxReadonlyFileCommands,
  sandboxReadonlyHostDirs,
  withRealPaths,
  type FindCommandDeps,
} from "./host-commands.ts";
import { hostCommand, hostCommandEnv } from "./pinned-commands.ts";
import { resolveHostPath } from "./symlinks.ts";

const HOME = "/home/runner";
const WORKSPACE = "/home/runner/work/repo/repo";
const PERSISTENT = [WORKSPACE, HOME, "/tmp", "/home/runner/work/_temp"];

/** A filesystem whose only symlinks are `links`, each to its stored target. */
function withLinks(links: Record<string, string>) {
  const fs = {
    lstat: (path: string) => ({ uid: 1001, isSymbolicLink: () => path in links }),
    readlink: (path: string) => links[path]!,
  };
  const realpathDir = (path: string): string => {
    const resolved = resolveHostPath(path, fs);
    return "real" in resolved ? resolved.real : path;
  };
  return { ...fs, realpathDir };
}
const NO_LINKS = withLinks({});

/**
 * A host where `files` are the executables, and `links` map each symlink, to a
 * file or a directory, to its immediate target, one hop per entry. A path in
 * `links` is executable too, so only its final target need be listed in `files`.
 */
function host(files: string[], links: Record<string, string> = {}): FindCommandDeps {
  return { ...withLinks(links), isExecutable: (p) => files.includes(p) || p in links };
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
    // A self-hosted /opt/tools -> ~/tools.
    const deps = host(["/opt/tools/bin/docker", "/usr/bin/docker"], {
      "/opt/tools/bin": `${HOME}/tools/bin`,
    });

    expect(findPinnableCommand("docker", "/opt/tools/bin:/usr/bin", PERSISTENT, deps)).toBe(
      "/usr/bin/docker",
    );
  });

  it("judges a symlink hop's directory the same way", () => {
    // /usr/local/bin/docker -> /opt/tools/bin/docker, whose directory is ~/tools/bin.
    const deps = host(["/opt/tools/bin/docker", "/usr/bin/docker"], {
      "/usr/local/bin/docker": "/opt/tools/bin/docker",
      "/opt/tools/bin": `${HOME}/tools/bin`,
    });

    expect(findPinnableCommand("docker", "/usr/local/bin:/usr/bin", PERSISTENT, deps)).toBe(
      "/usr/bin/docker",
    );
  });

  it("skips a candidate that passes through a symlink in a persisting path, wherever it resolves", () => {
    // /usr/local/bin/docker -> /opt/tools/docker, where /opt/tools -> ~/tools -> /usr/lib/tools.
    const deps = host(["/usr/lib/tools/docker", "/usr/bin/docker"], {
      "/usr/local/bin/docker": "/opt/tools/docker",
      "/opt/tools": `${HOME}/tools`,
      [`${HOME}/tools`]: "/usr/lib/tools",
    });

    expect(findPinnableCommand("docker", "/usr/local/bin:/usr/bin", PERSISTENT, deps)).toBe(
      "/usr/bin/docker",
    );
  });

  it("recognizes a persisting path by its real spelling too", () => {
    // $HOME=/home/runner is a symlink to /data/runner.
    const deps = host(["/data/runner/.local/bin/docker", "/usr/bin/docker"], {
      [HOME]: "/data/runner",
    });

    expect(
      findPinnableCommand("docker", "/data/runner/.local/bin:/usr/bin", PERSISTENT, deps),
    ).toBe("/usr/bin/docker");
  });

  it("passes over a symlink cycle rather than looping", () => {
    const deps = host([], {
      "/usr/bin/docker": "/usr/local/bin/docker",
      "/usr/local/bin/docker": "/usr/bin/docker",
    });

    expect(findPinnableCommand("docker", "/usr/bin", PERSISTENT, deps)).toBeUndefined();
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

describe("resolveDefaultWritableDirs", () => {
  it("follows a symlinked $HOME to the directory it names", () => {
    const real = (p: string) => p.replace(/^\/home\//, "/var/home/");

    expect(resolveDefaultWritableDirs({ HOME, GITHUB_WORKSPACE: WORKSPACE }, real)).toStrictEqual({
      workdir: "/var/home/runner/work/repo/repo",
      home: "/var/home/runner",
      runnerTemp: undefined,
      tmp: "/tmp",
    });
  });

  it("drops a trailing slash even when the path doesn't exist to resolve", () => {
    expect(
      resolveDefaultWritableDirs({ HOME: "/home/runner/", RUNNER_TEMP: "/opt/temp//" }, (p) => p),
    ).toMatchObject({ home: "/home/runner", runnerTemp: "/opt/temp" });
  });

  it("leaves / as it is", () => {
    expect(resolveDefaultWritableDirs({ HOME: "/" }, (p) => p).home).toBe("/");
  });
});

describe("withRealPaths", () => {
  it("adds each path's real spelling, without duplicates", () => {
    const real = (p: string) => (p === HOME ? "/data/runner" : p);

    expect(withRealPaths([HOME, "/tmp"], real)).toStrictEqual([HOME, "/tmp", "/data/runner"]);
  });
});

describe("jvmTools", () => {
  const JDK = "/usr/lib/jvm/temurin-21-jdk-amd64";

  it("takes JAVA_HOME's keytool and the first java on PATH", () => {
    const env = { JAVA_HOME: JDK, PATH: "/opt/other/bin:/usr/bin" };
    expect(
      jvmTools(
        env,
        PERSISTENT,
        host([`${JDK}/bin/keytool`, "/opt/other/bin/java", "/usr/bin/java", "/usr/bin/keytool"]),
      ),
    ).toStrictEqual({ java: "/opt/other/bin/java", keytool: `${JDK}/bin/keytool` });
  });

  // java is only located, so a JDK under $HOME (sdkman, say) still counts.
  it("takes a java under a persisting path, but never such a keytool", () => {
    const sdk = `${HOME}/.sdkman/candidates/java/current`;
    expect(
      jvmTools(
        { JAVA_HOME: sdk, PATH: `${HOME}/.local/bin:${sdk}/bin` },
        PERSISTENT,
        host([`${HOME}/.local/bin/java`, `${HOME}/.local/bin/keytool`, `${sdk}/bin/keytool`]),
      ),
    ).toStrictEqual({ java: `${HOME}/.local/bin/java`, keytool: undefined });
  });

  it("falls back to PATH's keytool when JAVA_HOME's is unpinnable or JAVA_HOME is unset", () => {
    const path = `${HOME}/.local/bin:/usr/bin`;
    const deps = host([
      `${HOME}/jdk/bin/keytool`,
      `${HOME}/.local/bin/keytool`,
      "/usr/bin/keytool",
    ]);
    expect(jvmTools({ JAVA_HOME: `${HOME}/jdk`, PATH: path }, PERSISTENT, deps).keytool).toBe(
      "/usr/bin/keytool",
    );
    expect(jvmTools({ PATH: path }, PERSISTENT, deps).keytool).toBe("/usr/bin/keytool");
  });

  it("finds neither on a runner without a JDK", () => {
    expect(jvmTools({ PATH: "/usr/bin" }, PERSISTENT, host([]))).toStrictEqual({
      java: undefined,
      keytool: undefined,
    });
  });
});

describe("pathOutside", () => {
  it("drops the persisting paths a hosted runner puts on PATH", () => {
    const path = `${HOME}/.local/bin:/opt/pipx_bin:${HOME}/.cargo/bin:/usr/local/bin:/usr/bin:/snap/bin`;

    expect(pathOutside(path, PERSISTENT, (d) => d)).toBe(
      "/opt/pipx_bin:/usr/local/bin:/usr/bin:/snap/bin",
    );
  });

  it("drops an entry whose real directory is inside a persisting path", () => {
    const realpath = (d: string) => (d === "/opt/tools" ? `${HOME}/tools` : d);

    expect(pathOutside("/opt/tools:/usr/bin", PERSISTENT, realpath)).toBe("/usr/bin");
  });

  it("drops relative and empty entries, which resolve against the workspace", () => {
    expect(pathOutside("bin::/usr/bin:./node_modules/.bin:", PERSISTENT, (d) => d)).toBe(
      "/usr/bin",
    );
  });

  it("drops a write_through path outside the persistent set", () => {
    expect(pathOutside("/usr/local/bin:/usr/bin", ["/usr/local/bin"], (d) => d)).toBe("/usr/bin");
  });

  it("is empty for an unset PATH", () => {
    expect(pathOutside(undefined, PERSISTENT, (d) => d)).toBe("");
  });

  it("keeps PATH as is under write_through: /, the full opt-out", () => {
    const path = `${HOME}/.local/bin:bin:/usr/bin`;

    expect(pathOutside(path, [...PERSISTENT, "/"], (d) => d)).toBe(path);
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

  it("pins the PATH docker and sudo run with, without the persisting paths", () => {
    pinHostCommands(
      [...PERSISTENT, "/usr/local/bin"],
      { PATH: `${HOME}/.local/bin:/opt/hostedtoolcache/node/bin:/usr/local/bin:/usr/bin` },
      host(["/usr/bin/docker", "/usr/bin/sudo"]),
    );

    expect(hostCommandEnv("docker", {}).PATH).toBe("/opt/hostedtoolcache/node/bin:/usr/bin");
    expect(hostCommandEnv("sudo", {}).PATH).toBe("/usr/local/sbin:/usr/sbin:/usr/bin:/sbin:/bin");
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
    expect(sandboxReadonlyHostDirs(PERSISTENT, { HOME }, ACTION, NO_LINKS)).toStrictEqual([
      ACTION,
      `${HOME}/.docker`,
    ]);
  });

  it("leaves out a directory no persisting path holds", () => {
    expect(
      sandboxReadonlyHostDirs([`${WORKSPACE}/dist`], { HOME }, ACTION, NO_LINKS),
    ).toStrictEqual([]);
  });

  it("covers both under write_through: /", () => {
    expect(sandboxReadonlyHostDirs(["/"], { HOME }, ACTION, NO_LINKS)).toStrictEqual([
      ACTION,
      `${HOME}/.docker`,
    ]);
  });

  it("leaves out one that contains a persisting path, as uses: ./ puts the action in the workspace", () => {
    expect(sandboxReadonlyHostDirs(PERSISTENT, { HOME }, WORKSPACE, NO_LINKS)).toStrictEqual([
      `${HOME}/.docker`,
    ]);
  });

  it("keeps one read-only when a persisting path only sits inside it", () => {
    expect(
      sandboxReadonlyHostDirs(
        [...PERSISTENT, `${HOME}/.docker/buildx`],
        { HOME },
        ACTION,
        NO_LINKS,
      ),
    ).toStrictEqual([ACTION, `${HOME}/.docker`]);
  });

  it("leaves out one a write_through entry names outright", () => {
    expect(
      sandboxReadonlyHostDirs([...PERSISTENT, `${HOME}/.docker`], { HOME }, ACTION, NO_LINKS),
    ).toStrictEqual([ACTION]);
  });
  it("refuses a docker config directory that is itself a symlink in a persisting path", () => {
    expect(() =>
      sandboxReadonlyHostDirs(
        PERSISTENT,
        { HOME },
        ACTION,
        withLinks({ [`${HOME}/.docker`]: "/mnt/shared/docker" }),
      ),
    ).toThrow(
      expect.objectContaining({
        code: "HOST_DIR_UNPROTECTABLE",
        message: expect.stringContaining(
          'Set DOCKER_CONFIG to its real path, "/mnt/shared/docker"',
        ),
      }),
    );
  });

  it("refuses a checkout reached through a symlinked runner work directory in a persisting path", () => {
    const checkout = `${HOME}/actions-runner/_work/_actions/buildcage/isolated-run/v1`;

    expect(() =>
      sandboxReadonlyHostDirs(
        PERSISTENT,
        { HOME },
        checkout,
        withLinks({ [`${HOME}/actions-runner/_work`]: "/mnt/data/_work" }),
      ),
    ).toThrow(
      expect.objectContaining({
        code: "HOST_DIR_UNPROTECTABLE",
        message: expect.stringMatching(
          new RegExp(
            `goes through "${HOME}/actions-runner/_work".*work directory by its real path`,
          ),
        ),
      }),
    );
  });

  it("follows a symlink outside every persisting path and protects its target", () => {
    expect(
      sandboxReadonlyHostDirs(
        PERSISTENT,
        { HOME, DOCKER_CONFIG: "/opt/cfg" },
        ACTION,
        withLinks({ "/opt/cfg": `${HOME}/.cfg` }),
      ),
    ).toStrictEqual([ACTION, `${HOME}/.cfg`]);
  });

  it("refuses nothing under write_through: /, where every symlink is replaceable", () => {
    expect(
      sandboxReadonlyHostDirs(
        ["/"],
        { HOME },
        ACTION,
        withLinks({ [`${HOME}/.docker`]: "/mnt/shared/docker" }),
      ),
    ).toStrictEqual([ACTION, "/mnt/shared/docker"]);
  });

  it("refuses nothing when the symlink sits where writes are discarded, as in ephemeral mode", () => {
    expect(
      sandboxReadonlyHostDirs(
        [`${WORKSPACE}/dist`],
        { HOME },
        ACTION,
        withLinks({ [`${HOME}/.docker`]: "/mnt/shared/docker" }),
      ),
    ).toStrictEqual([]);
  });

  it("still refuses a replaceable symlink whose target loops, naming no other path", () => {
    const links: Record<string, string> = {
      [`${HOME}/.docker`]: "/opt/a",
      "/opt/a": "/opt/b",
      "/opt/b": "/opt/a",
    };

    expect(() => sandboxReadonlyHostDirs(PERSISTENT, { HOME }, ACTION, withLinks(links))).toThrow(
      expect.objectContaining({
        message: expect.stringContaining(`its real path, "${HOME}/.docker"`),
      }),
    );
  });

  it("refuses nothing for a directory write_through names, even through a symlink", () => {
    expect(
      sandboxReadonlyHostDirs(
        [...PERSISTENT, `${HOME}/.docker`],
        { HOME },
        ACTION,
        withLinks({ [`${HOME}/.docker`]: "/mnt/shared/docker" }),
      ),
    ).toStrictEqual([ACTION]);
  });

  it("refuses a symlink loop", () => {
    expect(() =>
      sandboxReadonlyHostDirs(
        PERSISTENT,
        { HOME, DOCKER_CONFIG: "/opt/a" },
        ACTION,
        withLinks({ "/opt/a": "/opt/b", "/opt/b": "/opt/a" }),
      ),
    ).toThrow(
      expect.objectContaining({
        code: "HOST_DIR_UNPROTECTABLE",
        message: expect.stringContaining("too many symlinks"),
      }),
    );
  });
});

describe("sandboxReadonlyFileCommands", () => {
  const COMMANDS = "/home/runner/work/_temp/_runner_file_commands";
  const ENV = {
    GITHUB_ENV: `${COMMANDS}/set_env_1`,
    GITHUB_PATH: `${COMMANDS}/add_path_1`,
    GITHUB_STATE: `${COMMANDS}/save_state_1`,
    GITHUB_OUTPUT: `${COMMANDS}/set_output_1`,
  };
  const files = (
    writeThrough: string[],
    env: NodeJS.ProcessEnv = ENV,
    deps: Parameters<typeof sandboxReadonlyFileCommands>[3] = NO_LINKS,
  ) => sandboxReadonlyFileCommands(writeThrough, [...PERSISTENT, ...writeThrough], env, deps);

  it("is this step's GITHUB_ENV, GITHUB_PATH and GITHUB_STATE, and not GITHUB_OUTPUT", () => {
    expect(files([])).toStrictEqual([ENV.GITHUB_ENV, ENV.GITHUB_PATH, ENV.GITHUB_STATE]);
  });

  it("leaves out GITHUB_ENV or GITHUB_PATH when write_through names it", () => {
    expect(files([ENV.GITHUB_ENV])).toStrictEqual([ENV.GITHUB_PATH, ENV.GITHUB_STATE]);
  });

  it("keeps GITHUB_STATE even when write_through names its path", () => {
    expect(files([ENV.GITHUB_STATE])).toStrictEqual([
      ENV.GITHUB_ENV,
      ENV.GITHUB_PATH,
      ENV.GITHUB_STATE,
    ]);
  });

  it("matches a write_through entry through a symlink, and names each by its real path", () => {
    const deps = withLinks({ "/home": "/var/home" });
    const real = (p: string) => p.replace(/^\/home\//, "/var/home/");

    expect(
      sandboxReadonlyFileCommands([real(ENV.GITHUB_PATH)], [real(ENV.GITHUB_PATH)], ENV, deps),
    ).toStrictEqual([real(ENV.GITHUB_ENV), real(ENV.GITHUB_STATE)]);
  });

  it("skips one that is not set", () => {
    expect(files([], { GITHUB_ENV: ENV.GITHUB_ENV })).toStrictEqual([ENV.GITHUB_ENV]);
  });

  it("refuses one reached through a symlink loop", () => {
    const links: Record<string, string> = { "/opt/a": "/opt/b", "/opt/b": "/opt/a" };

    expect(() => files([], { GITHUB_ENV: "/opt/a/set_env_1" }, withLinks(links))).toThrow(
      expect.objectContaining({ message: expect.stringContaining("too many symlinks") }),
    );
  });

  it("refuses one reached through a symlink in a persisting path", () => {
    expect(() => files([], ENV, withLinks({ "/home/runner/work": "/mnt/data/work" }))).toThrow(
      expect.objectContaining({
        code: "HOST_DIR_UNPROTECTABLE",
        message: expect.stringContaining(
          `The runner's GITHUB_ENV file "${ENV.GITHUB_ENV}" goes through "/home/runner/work"`,
        ),
      }),
    );
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

  it("uses the outermost containing root, pinning a writable root nested in it", () => {
    expect(renameGuardDirs([`${WORKSPACE}/a/b`], PERSISTENT)).toStrictEqual([
      "/home/runner/work",
      "/home/runner/work/repo",
      WORKSPACE,
      `${WORKSPACE}/a`,
    ]);
  });

  it("never pins a path outside the writable area", () => {
    expect(renameGuardDirs(["/etc/x/y"], PERSISTENT)).toStrictEqual([]);
  });

  it("does not take the read-only path itself as its root", () => {
    expect(renameGuardDirs([`${WORKSPACE}/a/b`], [`${WORKSPACE}/a/b`, WORKSPACE])).toStrictEqual([
      `${WORKSPACE}/a`,
    ]);
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

  // Nothing is a mount point then, so every directory above the dir is pinned.
  it("pins up to / under write_through: /", () => {
    expect(renameGuardDirs([ACTION], ["/", HOME])).toStrictEqual([
      "/home",
      "/home/runner",
      "/home/runner/work",
      "/home/runner/work/_actions",
      "/home/runner/work/_actions/buildcage",
      "/home/runner/work/_actions/buildcage/isolated-run",
    ]);
  });
});

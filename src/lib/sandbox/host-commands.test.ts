import { afterAll, describe, it, expect, vi } from "vitest";

import { SandboxError } from "../errors.ts";
import {
  HOME,
  NO_LINKS,
  PERSISTENT,
  RUNNER_DIRS_ENV,
  WORKSPACE,
  withLinks,
} from "../test/runner-host.ts";
import {
  findPinnableCommand,
  jvmTools,
  pathOutside,
  persistingWritablePaths,
  resolveDefaultWritableDirs,
  pinHostCommands,
  pinningPaths,
  type FindCommandDeps,
} from "./host-commands.ts";
import { hostCommand, hostCommandEnv } from "./pinned-commands.ts";
import { realPathOf } from "./symlinks.ts";

const asWritten = (path: string) => path;

/**
 * A host where `files` are the executables, and `links` map each symlink, to a
 * file or a directory, to its immediate target, one hop per entry. A path in
 * `links` is executable too, so only its final target need be listed in `files`.
 */
function host(files: string[], links: Record<string, string> = {}): FindCommandDeps {
  return { ...withLinks(links), isExecutable: (p) => files.includes(p) || p in links };
}

describe("persistingWritablePaths", () => {
  const env = RUNNER_DIRS_ENV;

  it("is every directory persistent mode binds back read-write", () => {
    expect(
      persistingWritablePaths(
        "persistent",
        ["/opt/out"],
        resolveDefaultWritableDirs(env, asWritten),
      ),
    ).toStrictEqual([...PERSISTENT, "/opt/out"]);
  });

  it("is only the write-through paths in ephemeral mode, whose overlays are discarded", () => {
    expect(
      persistingWritablePaths(
        "ephemeral",
        [`${WORKSPACE}/dist`],
        resolveDefaultWritableDirs(env, asWritten),
      ),
    ).toStrictEqual([`${WORKSPACE}/dist`]);
  });

  it("spells the runner's directories as they really resolve, and write-through as written", () => {
    const real = (p: string) => realPathOf(p, withLinks({ [HOME]: "/data/runner" }));

    expect(
      persistingWritablePaths("persistent", ["/opt/out"], resolveDefaultWritableDirs(env, real)),
    ).toStrictEqual([
      "/data/runner/work/repo/repo",
      "/data/runner",
      "/tmp",
      "/data/runner/work/_temp",
      "/opt/out",
    ]);
  });
});

describe("findPinnableCommand", () => {
  it("skips a match inside a persisting path for the next one on PATH", () => {
    const deps = host([`${HOME}/.local/bin/docker`, "/usr/bin/docker"]);
    const path = `${HOME}/.local/bin:/usr/bin`;

    expect(findPinnableCommand("docker", path, PERSISTENT, deps)).toBe("/usr/bin/docker");
  });

  it("skips a candidate whose symlink chain passes through a persisting path to another name", () => {
    // /usr/local/bin/docker -> ~/bin/docker (writable hop) -> /usr/bin/podman
    const deps = host(["/usr/bin/podman", "/usr/bin/docker"], {
      "/usr/local/bin/docker": `${HOME}/bin/docker`,
      [`${HOME}/bin/docker`]: "/usr/bin/podman",
    });

    expect(findPinnableCommand("docker", "/usr/local/bin:/usr/bin", PERSISTENT, deps)).toBe(
      "/usr/bin/docker",
    );
  });

  it("takes the file such a chain leads to when it bears the command's name", () => {
    // Ubuntu 26.04's sudo-rs, under write-through: /etc.
    const deps = host(["/usr/lib/cargo/bin/sudo"], {
      "/usr/bin/sudo": "/etc/alternatives/sudo",
      "/etc/alternatives/sudo": "/usr/lib/cargo/bin/sudo",
    });

    expect(findPinnableCommand("sudo", "/usr/bin", [...PERSISTENT, "/etc"], deps)).toBe(
      "/usr/lib/cargo/bin/sudo",
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

  it("skips a symlink in a persisting PATH directory even to a file of the command's name", () => {
    const deps = host(["/opt/old/bin/docker", "/usr/bin/docker"], {
      [`${HOME}/.local/bin/docker`]: "/opt/old/bin/docker",
    });

    expect(findPinnableCommand("docker", `${HOME}/.local/bin:/usr/bin`, PERSISTENT, deps)).toBe(
      "/usr/bin/docker",
    );
  });

  it("takes the file a directory symlink in a persisting path leads to", () => {
    // /usr/local/bin/docker -> /opt/tools/docker, where /opt/tools -> ~/tools -> /usr/lib/tools.
    const deps = host(["/usr/lib/tools/docker", "/usr/bin/docker"], {
      "/usr/local/bin/docker": "/opt/tools/docker",
      "/opt/tools": `${HOME}/tools`,
      [`${HOME}/tools`]: "/usr/lib/tools",
    });

    expect(findPinnableCommand("docker", "/usr/local/bin:/usr/bin", PERSISTENT, deps)).toBe(
      "/usr/lib/tools/docker",
    );
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

  it("takes the first match under write-through: /, the full opt-out", () => {
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

  it("takes the JDK's keytool behind /etc/alternatives under write-through: /etc", () => {
    const deps = host([`${JDK}/bin/keytool`], {
      "/usr/bin/keytool": "/etc/alternatives/keytool",
      "/etc/alternatives/keytool": `${JDK}/bin/keytool`,
    });
    expect(jvmTools({ PATH: "/usr/bin" }, [...PERSISTENT, "/etc"], deps).keytool).toBe(
      `${JDK}/bin/keytool`,
    );
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

    expect(pathOutside(path, PERSISTENT, NO_LINKS)).toBe(
      "/opt/pipx_bin:/usr/local/bin:/usr/bin:/snap/bin",
    );
  });

  it("drops an entry whose real directory is inside a persisting path", () => {
    const deps = withLinks({ "/opt/tools": `${HOME}/tools` });

    expect(pathOutside("/opt/tools:/usr/bin", PERSISTENT, deps)).toBe("/usr/bin");
  });

  it("drops an entry not there yet that a symlink leads into a persisting path", () => {
    const deps = withLinks({ [HOME]: "/data/runner" });

    expect(pathOutside(`${HOME}/.local/bin:/usr/bin`, ["/data/runner"], deps)).toBe("/usr/bin");
  });

  it("drops an entry that passes through a symlink in a persisting path, wherever it resolves", () => {
    // ~/bin -> /opt/tools/bin: the command could repoint ~/bin itself.
    const deps = withLinks({ [`${HOME}/bin`]: "/opt/tools/bin" });

    expect(pathOutside(`${HOME}/bin:/usr/bin`, PERSISTENT, deps)).toBe("/usr/bin");
  });

  it("drops an entry whose symlinks loop", () => {
    const deps = withLinks({ "/opt/a": "/opt/b", "/opt/b": "/opt/a" });

    expect(pathOutside("/opt/a/bin:/usr/bin", PERSISTENT, deps)).toBe("/usr/bin");
  });

  it("drops relative and empty entries, which resolve against the workspace", () => {
    expect(pathOutside("bin::/usr/bin:./node_modules/.bin:", PERSISTENT, NO_LINKS)).toBe(
      "/usr/bin",
    );
  });

  it("drops a write-through path outside the persistent set", () => {
    expect(pathOutside("/usr/local/bin:/usr/bin", ["/usr/local/bin"], NO_LINKS)).toBe("/usr/bin");
  });

  it("is empty for an unset PATH", () => {
    expect(pathOutside(undefined, PERSISTENT, NO_LINKS)).toBe("");
  });

  it("keeps PATH as is under write-through: /, the full opt-out", () => {
    const path = `${HOME}/.local/bin:bin:/usr/bin`;

    expect(pathOutside(path, [...PERSISTENT, "/"], NO_LINKS)).toBe(path);
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
    expect((error as SandboxError).message).toMatch(
      /^'docker' is on PATH only in directories a sandboxed command can write to or reach /,
    );
  });

  const unpinnable = (
    persisting: string[],
    deps: FindCommandDeps,
    PATH = "/usr/local/bin:/usr/bin",
  ) => {
    try {
      pinHostCommands(persisting, { PATH }, deps);
    } catch (e) {
      return (e as SandboxError).message;
    }
    return undefined;
  };

  it("names the symlink and the file it leads to when that file bears another name", () => {
    const deps = host(["/usr/bin/docker", `${HOME}/bin/sudo`, "/usr/bin/sudo.ws"], {
      "/usr/bin/sudo": "/etc/alternatives/sudo",
      "/etc/alternatives/sudo": "/usr/bin/sudo.ws",
    });

    expect(unpinnable([...PERSISTENT, "/etc"], deps, `${HOME}/bin:/usr/bin`)).toBe(
      "'sudo' on PATH, /usr/bin/sudo, leads to /usr/bin/sudo.ws through /etc/alternatives/sudo, " +
        "under /etc, which a sandboxed command can write to. This action runs it outside the " +
        "sandbox, so through such a symlink it pins only a file named 'sudo'.",
    );
  });

  it("names the file a symlink leads to when that file is where the command can write", () => {
    const deps = host(["/usr/bin/sudo", `${HOME}/bin/docker`], {
      "/usr/bin/docker": "/usr/bin/docker",
      "/usr/local/bin/docker": `${HOME}/bin/docker`,
    });

    // The loop ahead of it is passed over.
    expect(unpinnable(PERSISTENT, deps, "/usr/bin:/usr/local/bin")).toBe(
      `'docker' on PATH, /usr/local/bin/docker, leads to ${HOME}/bin/docker, under ${HOME}, ` +
        "which a sandboxed command can write to. This action runs it outside the sandbox, so " +
        "it has to be a file no sandboxed command can replace.",
    );
  });

  it("says a command is itself where the command can write when it is no symlink", () => {
    const deps = host(["/usr/bin/sudo", "/usr/local/bin/docker"]);

    expect(unpinnable([...PERSISTENT, "/usr/local/bin/docker"], deps, "/usr/local/bin")).toBe(
      "'docker' on PATH, /usr/local/bin/docker, is under /usr/local/bin/docker, which a " +
        "sandboxed command can write to. This action runs it outside the sandbox, so it has " +
        "to be a file no sandboxed command can replace.",
    );
  });

  it("does not fail over a command missing from PATH, leaving it to the caller's own check", () => {
    expect(() =>
      pinHostCommands(PERSISTENT, { PATH: "/usr/bin" }, host(["/usr/bin/docker"])),
    ).not.toThrow();
  });
});

describe("hostCommandEnv", () => {
  const env = { PATH: "/home/runner/.local/bin:/usr/bin", HOME: "/home/runner" };

  // The pins are module state, so each case starts from a fresh module.
  async function freshPins() {
    vi.resetModules();
    return import("./pinned-commands.ts");
  }

  afterAll(() => vi.resetModules());

  it("gives docker and sudo the system dirs only until their PATH is pinned", async () => {
    const { hostCommandEnv } = await freshPins();

    for (const command of ["docker", "sudo"]) {
      expect(hostCommandEnv(command, env)).toStrictEqual({
        PATH: "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
        HOME: "/home/runner",
      });
    }
  });

  it("gives docker and sudo each their pinned PATH, keeping the rest of the environment", async () => {
    const { hostCommandEnv, pinCommandPathEnv } = await freshPins();
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

  it("leaves any other command's environment as is", async () => {
    const { hostCommandEnv } = await freshPins();

    expect(hostCommandEnv("/usr/bin/keytool", env)).toBe(env);
  });
});

describe("pinningPaths", () => {
  const env = RUNNER_DIRS_ENV;

  it("is persistent mode's set plus write-through, whatever mode the step runs in", () => {
    expect(pinningPaths(() => "/opt/out", env, asWritten)).toStrictEqual([
      ...PERSISTENT,
      "/opt/out",
    ]);
  });

  it("falls back to persistent mode's set when the input does not parse", () => {
    expect(
      pinningPaths(
        () => {
          throw new Error("allow_write was removed");
        },
        env,
        asWritten,
      ),
    ).toStrictEqual(PERSISTENT);
  });
});

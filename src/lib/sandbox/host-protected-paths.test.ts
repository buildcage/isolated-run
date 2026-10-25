import { describe, it, expect } from "vitest";

import { HOME, NO_LINKS, PERSISTENT, WORKSPACE, withLinks } from "../test/runner-host.ts";
import {
  dockerConfigDir,
  renameGuardDirs,
  runnerInstallRoot,
  sandboxReadonlyFileCommands,
  sandboxReadonlyHostDirs,
} from "./host-protected-paths.ts";
import type { MountinfoEntry } from "./types.ts";

/** A bind mount of `root` on the host's one filesystem at `mountPoint`. */
function mount(root: string, mountPoint: string): MountinfoEntry {
  return { mountPoint, fsType: "ext4", device: "8:1", root };
}

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
    expect(
      sandboxReadonlyHostDirs(PERSISTENT, { HOME }, { actionRoot: ACTION }, NO_LINKS),
    ).toStrictEqual([ACTION, `${HOME}/.docker`]);
  });

  it("leaves out a directory no persisting path holds", () => {
    expect(
      sandboxReadonlyHostDirs([`${WORKSPACE}/dist`], { HOME }, { actionRoot: ACTION }, NO_LINKS),
    ).toStrictEqual([]);
  });

  it("covers both under write_through: /", () => {
    expect(
      sandboxReadonlyHostDirs(["/"], { HOME }, { actionRoot: ACTION }, NO_LINKS),
    ).toStrictEqual([ACTION, `${HOME}/.docker`]);
  });

  it("leaves out one that contains a persisting path, as uses: ./ puts the action in the workspace", () => {
    expect(
      sandboxReadonlyHostDirs(PERSISTENT, { HOME }, { actionRoot: WORKSPACE }, NO_LINKS),
    ).toStrictEqual([`${HOME}/.docker`]);
  });

  it("keeps one read-only when a persisting path only sits inside it", () => {
    expect(
      sandboxReadonlyHostDirs(
        [...PERSISTENT, `${HOME}/.docker/buildx`],
        { HOME },
        { actionRoot: ACTION },
        NO_LINKS,
      ),
    ).toStrictEqual([ACTION, `${HOME}/.docker`]);
  });

  it("leaves out one a write_through entry names outright", () => {
    expect(
      sandboxReadonlyHostDirs(
        [...PERSISTENT, `${HOME}/.docker`],
        { HOME },
        { actionRoot: ACTION },
        NO_LINKS,
      ),
    ).toStrictEqual([ACTION]);
  });
  it("refuses a docker config directory that is itself a symlink in a persisting path", () => {
    expect(() =>
      sandboxReadonlyHostDirs(
        PERSISTENT,
        { HOME },
        { actionRoot: ACTION },
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
        { actionRoot: checkout },
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
        { actionRoot: ACTION },
        withLinks({ "/opt/cfg": `${HOME}/.cfg` }),
      ),
    ).toStrictEqual([ACTION, `${HOME}/.cfg`]);
  });

  it("refuses nothing under write_through: /, where every symlink is replaceable", () => {
    expect(
      sandboxReadonlyHostDirs(
        ["/"],
        { HOME },
        { actionRoot: ACTION },
        withLinks({ [`${HOME}/.docker`]: "/mnt/shared/docker" }),
      ),
    ).toStrictEqual([ACTION, "/mnt/shared/docker"]);
  });

  it("refuses nothing when the symlink sits where writes are discarded, as in ephemeral mode", () => {
    expect(
      sandboxReadonlyHostDirs(
        [`${WORKSPACE}/dist`],
        { HOME },
        { actionRoot: ACTION },
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

    expect(() =>
      sandboxReadonlyHostDirs(PERSISTENT, { HOME }, { actionRoot: ACTION }, withLinks(links)),
    ).toThrow(
      expect.objectContaining({
        message: expect.stringContaining(`its real path, "${HOME}/.docker"`),
      }),
    );
  });

  it("refuses nothing for a directory write_through names, even through a symlink", () => {
    expect(
      sandboxReadonlyHostDirs(
        [...PERSISTENT, "/mnt/shared/docker"],
        { HOME },
        { actionRoot: ACTION },
        withLinks({ [`${HOME}/.docker`]: "/mnt/shared/docker" }),
      ),
    ).toStrictEqual([ACTION]);
  });

  it("refuses a symlink loop", () => {
    expect(() =>
      sandboxReadonlyHostDirs(
        PERSISTENT,
        { HOME, DOCKER_CONFIG: "/opt/a" },
        { actionRoot: ACTION },
        withLinks({ "/opt/a": "/opt/b", "/opt/b": "/opt/a" }),
      ),
    ).toThrow(
      expect.objectContaining({
        code: "HOST_DIR_UNPROTECTABLE",
        message: expect.stringContaining("too many symlinks"),
      }),
    );
  });

  describe("the runner's own directories", () => {
    const RUNNER_WORKSPACE = "/home/runner/work/repo";
    const INSTALL = "/home/runner/actions-runner/cached";

    it("covers the action checkouts and the install directory in place of this checkout", () => {
      expect(
        sandboxReadonlyHostDirs(
          PERSISTENT,
          { HOME, RUNNER_WORKSPACE },
          { actionRoot: ACTION, installRoot: INSTALL },
          NO_LINKS,
        ),
      ).toStrictEqual(["/home/runner/work/_actions", INSTALL, `${HOME}/.docker`]);
    });

    it("leaves a work directory inside the install directory to it, as on a self-hosted runner", () => {
      const root = `${HOME}/actions-runner`;

      expect(
        sandboxReadonlyHostDirs(
          PERSISTENT,
          { HOME, RUNNER_WORKSPACE: `${root}/_work/repo` },
          { actionRoot: `${root}/_work/_actions/buildcage/isolated-run/v1`, installRoot: root },
          NO_LINKS,
        ),
      ).toStrictEqual([root, `${HOME}/.docker`]);
    });

    it("keeps one inside the install directory that a persisting path between them would reopen", () => {
      const root = `${HOME}/actions-runner`;
      const temp = `${root}/_work/_temp`;

      expect(
        sandboxReadonlyHostDirs(
          [...PERSISTENT, temp],
          { HOME, RUNNER_WORKSPACE: `${root}/_work/repo`, DOCKER_CONFIG: `${temp}/docker` },
          { actionRoot: `${root}/_work/_actions/buildcage/isolated-run/v1`, installRoot: root },
          NO_LINKS,
        ),
      ).toStrictEqual([root, `${temp}/docker`]);
    });

    it("refuses an action checkouts directory reached through a symlink in a persisting path", () => {
      expect(() =>
        sandboxReadonlyHostDirs(
          PERSISTENT,
          { HOME, RUNNER_WORKSPACE },
          { actionRoot: WORKSPACE },
          withLinks({ "/home/runner/work/_actions": "/mnt/actions" }),
        ),
      ).toThrow(
        expect.objectContaining({
          code: "HOST_DIR_UNPROTECTABLE",
          message: expect.stringContaining("later steps' actions"),
        }),
      );
    });

    it("refuses an install directory reached through a symlink in a persisting path", () => {
      expect(() =>
        sandboxReadonlyHostDirs(
          PERSISTENT,
          { HOME },
          { actionRoot: ACTION, installRoot: INSTALL },
          withLinks({ [INSTALL]: "/mnt/runner" }),
        ),
      ).toThrow(
        expect.objectContaining({
          code: "HOST_DIR_UNPROTECTABLE",
          message: expect.stringContaining("Install the runner by its real path"),
        }),
      );
    });
  });

  describe("at the other paths a bind mount shows it", () => {
    const MOUNTS = [mount("/", "/"), mount("/home", "/data/home"), mount("/etc", "/data/etc")];
    const ALIAS = "/data/home/runner";

    it("covers each alias in a persisting path too", () => {
      expect(
        sandboxReadonlyHostDirs(
          [...PERSISTENT, "/data/home"],
          { HOME },
          { actionRoot: ACTION },
          NO_LINKS,
          MOUNTS,
        ),
      ).toStrictEqual([
        ACTION,
        `${ALIAS}/work/_actions/buildcage/isolated-run/v1`,
        `${HOME}/.docker`,
        `${ALIAS}/.docker`,
      ]);
    });

    it("leaves out an alias no persisting path holds, as the rest of the host is read-only", () => {
      expect(
        sandboxReadonlyHostDirs(PERSISTENT, { HOME }, { actionRoot: ACTION }, NO_LINKS, MOUNTS),
      ).toStrictEqual([ACTION, `${HOME}/.docker`]);
    });

    it("leaves out an alias a write_through entry names outright", () => {
      expect(
        sandboxReadonlyHostDirs(
          [...PERSISTENT, `${ALIAS}/.docker`],
          { HOME },
          { actionRoot: ACTION },
          NO_LINKS,
          MOUNTS,
        ),
      ).toStrictEqual([ACTION, `${HOME}/.docker`]);
    });

    it("covers the alias of a directory no persisting path holds itself", () => {
      expect(
        sandboxReadonlyHostDirs(
          [...PERSISTENT, "/data/etc"],
          { HOME, DOCKER_CONFIG: "/etc/docker-cli" },
          { actionRoot: ACTION },
          NO_LINKS,
          MOUNTS,
        ),
      ).toStrictEqual([ACTION, "/data/etc/docker-cli"]);
    });
  });
});

describe("runnerInstallRoot", () => {
  it("is the directory holding externals/, from the node the runner runs actions with", () => {
    expect(runnerInstallRoot("/home/runner/actions-runner/externals/node24/bin/node")).toBe(
      "/home/runner/actions-runner",
    );
  });

  it("is nothing for a node the runner did not ship", () => {
    expect(runnerInstallRoot("/usr/local/bin/node")).toBeUndefined();
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
    mounts: MountinfoEntry[] = [],
  ) =>
    sandboxReadonlyFileCommands(writeThrough, [...PERSISTENT, ...writeThrough], env, deps, mounts);

  it("is this step's GITHUB_ENV, GITHUB_PATH and GITHUB_STATE, and not GITHUB_OUTPUT", () => {
    expect(files([])).toStrictEqual([ENV.GITHUB_ENV, ENV.GITHUB_PATH, ENV.GITHUB_STATE]);
  });

  describe("at the other paths a bind mount shows it", () => {
    const MOUNTS = [mount("/", "/"), mount("/home", "/data/home")];
    const ALIASED = "/data/home/runner/work/_temp/_runner_file_commands";

    it("covers each alias in a persisting path too", () => {
      expect(files(["/data/home"], ENV, NO_LINKS, MOUNTS)).toStrictEqual([
        ENV.GITHUB_ENV,
        `${ALIASED}/set_env_1`,
        ENV.GITHUB_PATH,
        `${ALIASED}/add_path_1`,
        ENV.GITHUB_STATE,
        `${ALIASED}/save_state_1`,
      ]);
    });

    it("leaves out an alias no persisting path holds", () => {
      expect(files([], ENV, NO_LINKS, MOUNTS)).toStrictEqual([
        ENV.GITHUB_ENV,
        ENV.GITHUB_PATH,
        ENV.GITHUB_STATE,
      ]);
    });

    it("opens a GITHUB_ENV alias write_through names, but never one of GITHUB_STATE", () => {
      expect(
        files([`${ALIASED}/set_env_1`, `${ALIASED}/save_state_1`], ENV, NO_LINKS, MOUNTS),
      ).toStrictEqual([
        ENV.GITHUB_ENV,
        ENV.GITHUB_PATH,
        ENV.GITHUB_STATE,
        `${ALIASED}/save_state_1`,
      ]);
    });
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

  it("pins nothing inside another read-only dir, only what a persisting path nested there holds", () => {
    const root = `${HOME}/actions-runner`;
    const commands = `${root}/_work/_temp/_runner_file_commands`;

    expect(
      renameGuardDirs([root, `${commands}/set_env_1`], [HOME, `${root}/_work/_temp`]),
    ).toStrictEqual([`${root}/_work/_temp`, commands]);
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

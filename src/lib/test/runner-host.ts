// A GitHub-hosted Linux runner's layout, shared by the tests that resolve paths on it.

export const HOME = "/home/runner";
export const WORKSPACE = `${HOME}/work/repo/repo`;
export const RUNNER_TEMP = `${HOME}/work/_temp`;

/** What persistent mode binds back read-write. */
export const PERSISTENT = [WORKSPACE, HOME, "/tmp", RUNNER_TEMP];

/** The runner's directories, without its generated files. */
export const RUNNER_DIRS_ENV = { HOME, GITHUB_WORKSPACE: WORKSPACE, RUNNER_TEMP };

const COMMANDS = `${RUNNER_TEMP}/_runner_file_commands`;

/** The runner's directories and the files it generates for a step. */
export const RUNNER_ENV = {
  ...RUNNER_DIRS_ENV,
  GITHUB_OUTPUT: `${COMMANDS}/set_output_abc`,
  GITHUB_ENV: `${COMMANDS}/set_env_abc`,
  GITHUB_PATH: `${COMMANDS}/add_path_abc`,
  GITHUB_STEP_SUMMARY: `${COMMANDS}/step_summary_abc`,
};

/** A real Actions step's environment, which ownerToken joins into a token. */
export const STEP_OWNER_ENV = {
  GITHUB_RUN_ID: "1",
  GITHUB_RUN_ATTEMPT: "1",
  GITHUB_JOB: "build",
  GITHUB_ACTION: "buildcage",
  RUNNER_TEMP,
};

/** A filesystem where every path exists and only `links` are symlinks, each to its stored target. */
export function withLinks(links: Record<string, string> = {}) {
  return {
    lstat: (path: string) => ({ isSymbolicLink: () => path in links }),
    readlink: (path: string) => links[path]!,
  };
}

export const NO_LINKS = withLinks();

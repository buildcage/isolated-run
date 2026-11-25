/** The container's random suffix keeps the name unique among concurrent steps in one job. */
export function artifactName(prefix: string, containerName: string): string {
  return `${prefix}-${containerName.split("-").at(-1)}`;
}

export type UploadArtifact = (
  name: string,
  files: string[],
  rootDirectory: string,
  options: { retentionDays?: number },
) => Promise<unknown>;

/** Rejects while the run's artifact list does not show `name` yet. */
export type FindArtifact = (name: string) => Promise<unknown>;

export interface WaitUntilListedOptions {
  timeoutMs?: number;
  intervalMs?: number;
  now?: () => number;
  sleep?: (ms: number) => Promise<void>;
}

/**
 * Wait until `find` sees the artifact, or `timeoutMs` passes. GitHub lists a
 * finalized artifact some time later, and download-artifact looks it up in
 * that list, so a download right after the step could otherwise miss it.
 * Returns whether it was listed.
 */
export async function waitUntilListed(
  name: string,
  find: FindArtifact,
  {
    timeoutMs = 30_000,
    intervalMs = 1_000,
    now = Date.now,
    sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms)),
  }: WaitUntilListedOptions = {},
): Promise<boolean> {
  const deadline = now() + timeoutMs;
  for (;;) {
    try {
      await find(name);
      return true;
    } catch {
      if (now() >= deadline) return false;
    }
    await sleep(intervalMs);
  }
}

/** Imported lazily so a run that uploads nothing never loads @actions/artifact.
 *  Untested by design: it only passes on what the tested callers decided. */
/* v8 ignore start */
export const uploadViaActionsArtifact: UploadArtifact = async (
  name,
  files,
  rootDirectory,
  options,
) => {
  const { DefaultArtifactClient } = await import("@actions/artifact");
  const client = new DefaultArtifactClient();
  const uploaded = await client.uploadArtifact(name, files, rootDirectory, options);
  if (!(await waitUntilListed(name, (n) => client.getArtifact(n)))) {
    console.log(`GitHub does not list ${name} yet; downloading it in this job may fail`);
  }
  return uploaded;
};
/* v8 ignore stop */

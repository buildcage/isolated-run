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
  return new DefaultArtifactClient().uploadArtifact(name, files, rootDirectory, options);
};
/* v8 ignore stop */

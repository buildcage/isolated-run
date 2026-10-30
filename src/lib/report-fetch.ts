import { execFileSync, spawn } from "node:child_process";

import type { ProxyEngine } from "#core/lib/actions/inputs.ts";
import { createDocker, type Docker } from "#core/lib/docker/client.ts";
import { readProxyDroppedLogs } from "#core/lib/docker/proxy-dropped-logs.ts";
import { readResolverAnswered } from "#core/lib/docker/resolver-health.ts";
import { readRotatedLog } from "#core/lib/docker/rotated-log.ts";
import { readActionVersion as readImageActionVersion } from "#core/lib/report/action-version.ts";
import { buildInspectReportData } from "#core/lib/report/build/inspect.ts";
import { buildUniversalReportData } from "#core/lib/report/build/universal.ts";
import type { GenReportParameters, ReportData, ServiceHealth } from "#core/lib/report/types.ts";

import { hostCommand, hostCommandEnv } from "./sandbox/pinned-commands.ts";

const HAPROXY_LOG_DIR = "/var/log/haproxy";
/** The only trace of a name that was looked up but never connected to. */
const COREDNS_LOG_DIR = "/var/log/coredns";

// Untested by design: the log reader and the builders are tested directly.
/* v8 ignore start */
function createHostDocker(): Docker {
  return createDocker(
    (args) =>
      execFileSync(hostCommand("docker"), args, {
        encoding: "utf8",
        stdio: ["ignore", "pipe", "pipe"],
        maxBuffer: 64 * 1024 * 1024,
        env: hostCommandEnv("docker"),
      }),
    (args) =>
      spawn(hostCommand("docker"), args, {
        stdio: ["ignore", "pipe", "pipe"],
        env: hostCommandEnv("docker"),
      }),
  );
}

/** Built in-process: this action runs one pinned version end to end. */
export function fetchReport(
  containerName: string,
  parameters: GenReportParameters,
  proxyEngine: ProxyEngine,
): Promise<ReportData> {
  const docker = createHostDocker();
  const health: ServiceHealth = {
    droppedLogs: readProxyDroppedLogs(docker, containerName),
    resolverAnswered: readResolverAnswered(docker, containerName),
  };
  if (proxyEngine === "inspect") {
    return buildInspectReportData(
      readRotatedLog(docker, containerName, HAPROXY_LOG_DIR),
      readRotatedLog(docker, containerName, COREDNS_LOG_DIR),
      parameters,
      health,
    );
  }
  return buildUniversalReportData(
    readRotatedLog(docker, containerName, HAPROXY_LOG_DIR),
    readRotatedLog(docker, containerName, COREDNS_LOG_DIR),
    parameters,
    health,
  );
}
/* v8 ignore stop */

export function readActionVersion(
  containerName: string,
  proxyEngine: ProxyEngine,
  docker?: Docker,
): string | undefined {
  // Untested by design: the default client behind the seam.
  /* v8 ignore next */
  const client = docker ?? createHostDocker();
  return readImageActionVersion(client, containerName, proxyEngine);
}

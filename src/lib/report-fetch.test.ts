import { describe, it, expect, beforeEach, vi } from "vitest";

import type { Docker } from "#core/lib/docker/client.ts";
import { reportParams } from "#core/lib/test/report-data.node.ts";

import { ProxyStoppedError, readActionVersion, readReport } from "./report-fetch.ts";

// Label parsing is tested in action-version.test.ts.
const readLabels = vi.fn();
const docker = { readLabels } as unknown as Docker;

describe("readActionVersion", () => {
  const containerName = "buildcage-proxy-abcd1234";

  beforeEach(() => {
    readLabels.mockReset();
  });

  it("turns the image's bare version label back into its git tag", () => {
    readLabels.mockReturnValueOnce({
      "org.opencontainers.image.version": "3.1.4",
    });
    expect(readActionVersion(containerName, "universal", docker)).toBe("v3.1.4");
  });

  it("strips the engine suffix a non-universal image carries", () => {
    readLabels.mockReturnValueOnce({
      "org.opencontainers.image.version": "3.1.4-inspect",
    });
    expect(readActionVersion(containerName, "inspect", docker)).toBe("v3.1.4");
  });
});

describe("readReport", () => {
  const containerName = "buildcage-proxy-abcd1234";
  const gone = () => {
    throw new Error("container is not running");
  };

  it.each(["inspect", "universal"] as const)(
    "names a stopped container when neither the logs nor the services answer (%s)",
    async (engine) => {
      const stopped = { exec: vi.fn(gone) } as unknown as Docker;

      const result = readReport(stopped, containerName, reportParams(), engine);

      await expect(result).rejects.toThrow(ProxyStoppedError);
      await expect(result).rejects.toThrow(
        "the proxy or the DNS resolver did not answer and the logs could not be read: container is not running",
      );
    },
  );

  it("names a stopped container when only the resolver did not answer", async () => {
    const exec = vi.fn((_id: string, args: string[]) => {
      if (args.includes("--unix-socket")) return "haproxy_process_dropped_logs_total 0\n";
      return gone();
    });

    await expect(
      readReport({ exec } as unknown as Docker, containerName, reportParams(), "inspect"),
    ).rejects.toThrow(ProxyStoppedError);
  });

  it("passes the read error on as it is while both services answer", async () => {
    const exec = vi.fn((_id: string, args: string[]) => {
      if (args[0] === "curl") return "haproxy_process_dropped_logs_total 0\n";
      throw new Error("ls failed");
    });

    const result = readReport(
      { exec } as unknown as Docker,
      containerName,
      reportParams(),
      "inspect",
    );

    await expect(result).rejects.toThrow("ls failed");
    await expect(result).rejects.not.toThrow(ProxyStoppedError);
  });
});

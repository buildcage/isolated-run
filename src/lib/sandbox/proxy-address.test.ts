import { readFileSync } from "node:fs";

import { describe, it, expect } from "vitest";

import { PROXY_ADDRESS, PROXY_SUBNET } from "#core/lib/log/proxy-address.ts";

describe("PROXY_ADDRESS", () => {
  it("is the gateway the sandbox's veth link hands the command", () => {
    const sandbox = readFileSync(new URL("./sandboxed-command.ts", import.meta.url), "utf8");
    expect(sandbox).toContain('import { PROXY_ADDRESS } from "#core/lib/log/proxy-address.ts";');
    expect(sandbox).toContain("gateway: PROXY_ADDRESS");
  });
});

describe("PROXY_SUBNET", () => {
  it("is the network the sandbox's veth link puts both ends on", () => {
    // The internal-address guard refuses PROXY_SUBNET; a link outside it
    // would leave the sandbox's own address reachable by name.
    const script = readFileSync(
      new URL("../../../scripts/run-isolated.sh", import.meta.url),
      "utf8",
    );
    expect(script.match(/ip addr add "\$2\/24"/g)).toHaveLength(2);
    const sandbox = readFileSync(new URL("./sandboxed-command.ts", import.meta.url), "utf8");
    const sandboxIp = /const SANDBOX_IP = "([\d.]+)";/.exec(sandbox)![1];
    const prefix = PROXY_SUBNET.replace(/0\/24$/, "");
    for (const ip of [PROXY_ADDRESS, sandboxIp]) expect(ip.startsWith(prefix)).toBe(true);
  });
});

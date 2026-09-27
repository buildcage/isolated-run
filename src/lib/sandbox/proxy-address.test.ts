import { readFileSync } from "node:fs";
import { describe, it, expect } from "vitest";

describe("PROXY_ADDRESS", () => {
  it("is the gateway the sandbox's veth link hands the command", () => {
    const sandbox = readFileSync(new URL("./sandboxed-command.ts", import.meta.url), "utf8");
    expect(sandbox).toContain('import { PROXY_ADDRESS } from "#core/lib/log/proxy-address.ts";');
    expect(sandbox).toContain("gateway: PROXY_ADDRESS");
  });
});

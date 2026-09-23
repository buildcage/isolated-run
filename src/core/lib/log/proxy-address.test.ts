import { readFileSync } from "node:fs";
import { describe, it, expect } from "vitest";
import { PROXY_ADDRESS } from "./proxy-address.ts";

describe("PROXY_ADDRESS", () => {
  it("matches the gateway the inspect image's config generator echoes", () => {
    // init-inspect-cfg cannot import this, and a change there without one here
    // would make the parser name every name-based connection by the wrong
    // address. The sandbox's own gateway takes this constant directly (see
    // sandboxed-command.ts), so it needs no guard of its own.
    const script = readFileSync(
      new URL("../../../../docker/inspect/files/s6-scripts/init-inspect-cfg", import.meta.url),
      "utf8",
    );
    expect(script).toContain(`\nGATEWAY=${PROXY_ADDRESS}\n`);
  });

  it("is the gateway the sandbox's veth link hands the command", () => {
    // The definer, so this cannot drift: it imports the same constant.
    const sandbox = readFileSync(
      new URL("../../../lib/sandbox/sandboxed-command.ts", import.meta.url),
      "utf8",
    );
    expect(sandbox).toContain('import { PROXY_ADDRESS } from "#core/lib/log/proxy-address.ts";');
    expect(sandbox).toContain("gateway: PROXY_ADDRESS");
  });
});

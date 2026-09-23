import { readFileSync } from "node:fs";
import { describe, it, expect } from "vitest";
import { PROXY_ADDRESS } from "./proxy-address.ts";

describe("PROXY_ADDRESS", () => {
  it("is the gateway the inspect engine's resolver answers every name with", () => {
    // The shell script cannot import this; a change on one side alone would
    // name every name-based connection by the proxy's own address.
    const script = readFileSync(
      new URL("../../../../docker/inspect/files/s6-scripts/init-inspect-cfg", import.meta.url),
      "utf8",
    );
    expect(script.includes(`\nGATEWAY=${PROXY_ADDRESS}\n`)).toBe(true);
  });
});

import { describe, it, expect } from "vitest";
import { readFileSync, statSync } from "node:fs";

import { writeRunScript, writeResolvConf, writeOciConfig } from "./oci-files.ts";
import { withScratchDir } from "./scratch-dir.ts";

describe("writeRunScript", () => {
  it("wraps plain commands in a #!/bin/bash + set -e preamble", () => {
    withScratchDir((dir) => {
      const path = writeRunScript("echo hello", dir);
      const content = readFileSync(path, "utf8");
      expect(content).toBe("#!/bin/bash\nset -e\necho hello\n");
    });
  });

  it("leaves an input that already starts with a shebang untouched", () => {
    withScratchDir((dir) => {
      const script = "#!/usr/bin/env bash\necho custom-shebang\n";
      const path = writeRunScript(script, dir);
      expect(readFileSync(path, "utf8")).toBe(script);
    });
  });

  it("writes the script as executable", () => {
    withScratchDir((dir) => {
      const path = writeRunScript("echo hi", dir);
      const mode = statSync(path).mode & 0o777;
      expect(mode).toBe(0o700);
    });
  });
});

describe("writeResolvConf", () => {
  it("writes a single nameserver line", () => {
    withScratchDir((dir) => {
      const path = writeResolvConf("198.19.255.1", dir);
      expect(readFileSync(path, "utf8")).toBe("nameserver 198.19.255.1\n");
    });
  });
});

describe("writeOciConfig", () => {
  it("writes valid JSON matching the given config", () => {
    withScratchDir((dir) => {
      const config = { ociVersion: "1.0.2", process: { args: ["/bin/true"] } };
      const path = writeOciConfig(config, dir);
      expect(JSON.parse(readFileSync(path, "utf8"))).toStrictEqual(config);
    });
  });

  it("writes config.json 0600 (nothing but runc has any business reading it)", () => {
    withScratchDir((dir) => {
      const path = writeOciConfig({ process: { env: ["SECRET=s3cr3t"] } }, dir);
      const mode = statSync(path).mode & 0o777;
      expect(mode).toBe(0o600);
    });
  });
});

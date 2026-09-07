import { describe, it, expect } from "vitest";
import { readFileSync, statSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { spawnSync } from "node:child_process";

import { encodeEnvBlob, writeEnvLoader } from "./env-loader.ts";
import { withScratchDir } from "./scratch-dir.ts";

describe("encodeEnvBlob", () => {
  it("joins KEY=VALUE entries with a trailing NUL each", () => {
    const blob = encodeEnvBlob([
      ["FOO", "bar"],
      ["BAZ", "qux"],
    ]);
    expect(blob.toString("utf8")).toBe("FOO=bar\0BAZ=qux\0");
  });

  it("survives a value containing newlines (e.g. a multi-line secret)", () => {
    const value = "-----BEGIN KEY-----\nline1\nline2\n-----END KEY-----";
    const blob = encodeEnvBlob([["PRIVATE_KEY", value]]);
    const [record] = blob.toString("utf8").split("\0").filter(Boolean);
    expect(record).toBe(`PRIVATE_KEY=${value}`);
  });

  it("survives a value containing '=' (splitting only on the first one)", () => {
    const blob = encodeEnvBlob([["QUERY", "a=1&b=2"]]);
    const [record] = blob.toString("utf8").split("\0").filter(Boolean);
    expect(record).toBe("QUERY=a=1&b=2");
  });

  it("returns an empty buffer for no entries", () => {
    expect(encodeEnvBlob([]).length).toBe(0);
  });
});

describe("writeEnvLoader", () => {
  it("writes a #!/bin/bash script (not /bin/sh -- dash lacks `read -d ''`)", () => {
    withScratchDir((dir) => {
      const path = writeEnvLoader(dir);
      expect(readFileSync(path, "utf8")).toMatch(/^#!\/bin\/bash\n/);
    });
  });

  it("never uses eval", () => {
    withScratchDir((dir) => {
      const path = writeEnvLoader(dir);
      expect(readFileSync(path, "utf8")).not.toMatch(/\beval\b/);
    });
  });

  it("base64-decodes its own stdin and execs into $1 after the read loop", () => {
    withScratchDir((dir) => {
      const path = writeEnvLoader(dir);
      const content = readFileSync(path, "utf8");
      expect(content).toMatch(/base64 -d/);
      expect(content).toMatch(/exec "\$1"/);
    });
  });

  it("writes the script as executable", () => {
    withScratchDir((dir) => {
      const path = writeEnvLoader(dir);
      const mode = statSync(path).mode & 0o777;
      expect(mode).toBe(0o700);
    });
  });

  // End-to-end: actually run the loader under bash, feeding it a real
  // encodeEnvBlob buffer, base64-encoded, over stdin -- exactly how
  // run.ts's runIsolated invokes it -- and check what the exec'd script
  // sees.
  it("exports every valid KEY=VALUE pair from base64-encoded stdin and hands off to the target script", () => {
    withScratchDir((dir) => {
      const loaderPath = writeEnvLoader(dir);
      const targetPath = join(dir, "target.sh");
      writeFileSync(targetPath, `#!/bin/bash\necho "FOO=$FOO"\necho "MULTILINE=$MULTILINE"\n`, {
        mode: 0o700,
      });
      const blob = encodeEnvBlob([
        ["FOO", "bar"],
        ["MULTILINE", "line1\nline2"],
      ]);
      const result = spawnSync("bash", [loaderPath, targetPath], {
        input: blob.toString("base64"),
      });
      expect(result.stdout.toString("utf8")).toBe("FOO=bar\nMULTILINE=line1\nline2\n");
    });
  });

  it("silently drops a record whose key isn't a valid shell identifier", () => {
    withScratchDir((dir) => {
      const loaderPath = writeEnvLoader(dir);
      const targetPath = join(dir, "target.sh");
      writeFileSync(targetPath, `#!/bin/bash\nenv | grep -c '^1BAD=' || true\n`, { mode: 0o700 });
      const result = spawnSync("bash", [loaderPath, targetPath], {
        input: encodeEnvBlob([["1BAD", "nope"]]).toString("base64"),
      });
      expect(result.stdout.toString("utf8").trim()).toBe("0");
    });
  });

  // This doesn't exercise a real pty (spawnSync's `input` is a plain pipe
  // here, not a tty) -- it can't reproduce the actual `sudo`/`use_pty`
  // corruption this design avoids. What it does confirm: the base64
  // encode/decode round-trip itself is byte-exact for values containing
  // bytes a canonical-mode tty's line discipline would otherwise intercept
  // as signals (Ctrl-C/INTR) or flow control (Ctrl-S/Ctrl-Q, XON/XOFF),
  // not just NUL.
  it("round-trips a value containing tty-special control bytes (Ctrl-C, Ctrl-S, Ctrl-Q)", () => {
    withScratchDir((dir) => {
      const loaderPath = writeEnvLoader(dir);
      const targetPath = join(dir, "target.sh");
      writeFileSync(targetPath, `#!/bin/bash\nprintf '%s' "$WEIRD" | base64\n`, { mode: 0o700 });
      const value = "a\x03b\x13c\x11d";
      const blob = encodeEnvBlob([["WEIRD", value]]);
      const result = spawnSync("bash", [loaderPath, targetPath], {
        input: blob.toString("base64"),
      });
      expect(Buffer.from(result.stdout.toString("utf8").trim(), "base64").toString("utf8")).toBe(
        value,
      );
    });
  });
});

import { describe, it, expect } from "vitest";

import {
  assertWriteThroughClearOfCaTrust,
  extractCaCert,
  writeCaTrustFiles,
  caTrustAdditions,
  presetCaVariables,
  discoverJvmKeystores,
  writeJvmKeystoreFiles,
  OWN_CA_DESTINATION,
  type CaTrustDeps,
} from "./ca-trust.ts";
import { NSS_CA_DB_DESTINATION } from "./nss-db.ts";

const FAKE_CA = "-----BEGIN CERTIFICATE-----\nfake\n-----END CERTIFICATE-----";

/** The candidate a Debian/Ubuntu runner actually has. */
const DEBIAN_STORE = "/etc/ssl/certs/ca-certificates.crt";
/** What a self-hosted RHEL runner is reached by instead. */
const RHEL_STORE = "/etc/pki/tls/certs/ca-bundle.crt";
const FAKE_SYSTEM_BUNDLE = "-----BEGIN CERTIFICATE-----\nsystem\n-----END CERTIFICATE-----";

/**
 * A host whose files are exactly `files`. Nothing here touches a real
 * filesystem: left real, this suite would read whatever CA bundle the machine
 * running it happens to have: a different answer on a macOS dev machine than
 * in CI.
 */
function fakeHost(files: Record<string, string>, dirs: string[] = []) {
  const written: Record<string, { contents: string; mode: number }> = {};
  const copied: [string, string][] = [];
  const exec: [string, string[]][] = [];
  const chmod: [string, number][] = [];
  const deps: CaTrustDeps = {
    exec: (command, args) => {
      exec.push([command, args]);
    },
    chmod: (path, mode) => {
      chmod.push([path, mode]);
    },
    exists: (path) => path in files,
    realpath: (path) => path,
    isDirectory: (path) => dirs.includes(path),
    copyDir: (source, destination) => {
      copied.push([source, destination]);
    },
    readFile: (path) => {
      const contents = files[path] ?? written[path]?.contents;
      if (contents === undefined) throw new Error(`ENOENT: ${path}`);
      return contents;
    },
    writeFile: (path, contents, mode) => {
      written[path] = { contents, mode };
    },
  };
  return { deps, written, exec, chmod, copied };
}

describe("writeCaTrustFiles", () => {
  const CA_INPUT = "/scratch/input-ca.pem";

  it("writes the CA into its own file, trailing whitespace trimmed to one newline", () => {
    const { deps, written } = fakeHost({ [CA_INPUT]: `${FAKE_CA}\n\n\n` });
    const { ownCaPath } = writeCaTrustFiles(CA_INPUT, "/scratch", deps);

    expect(ownCaPath).toBe("/scratch/buildcage-ca.pem");
    expect(written[ownCaPath].contents).toBe(`${FAKE_CA}\n`);
    expect(written[ownCaPath].mode).toBe(0o644);
  });

  it("appends the CA to the host's system store when the runner has one", () => {
    const { deps, written } = fakeHost({
      [CA_INPUT]: `${FAKE_CA}\n`,
      [DEBIAN_STORE]: `${FAKE_SYSTEM_BUNDLE}\n`,
    });
    const { systemCa } = writeCaTrustFiles(CA_INPUT, "/scratch", deps);

    expect(systemCa).toEqual({ path: "/scratch/system-ca-bundle.pem", destination: DEBIAN_STORE });
    expect(written[systemCa!.path].contents).toBe(`${FAKE_SYSTEM_BUNDLE}\n${FAKE_CA}\n`);
  });

  // The augmented copy has to go back over the path it was read from. Mounted
  // anywhere else, a tool going by its own compiled-in path reads the runner's
  // untouched store and never sees the proxy's CA.
  it("reports the candidate it read, not the first one in the list", () => {
    const { deps } = fakeHost({
      [CA_INPUT]: `${FAKE_CA}\n`,
      [RHEL_STORE]: `${FAKE_SYSTEM_BUNDLE}\n`,
    });
    const { systemCa } = writeCaTrustFiles(CA_INPUT, "/scratch", deps);

    expect(systemCa?.destination).toBe(RHEL_STORE);
  });

  // A tool pointed at a replacing variable would otherwise end up trusting the
  // proxy CA and nothing else, so no system file means no system bundle.
  it("leaves systemCaPath undefined when no candidate store exists", () => {
    const { deps, written } = fakeHost({ [CA_INPUT]: `${FAKE_CA}\n` });
    const { systemCa } = writeCaTrustFiles(CA_INPUT, "/scratch", deps);

    expect(systemCa).toBeUndefined();
    expect(written["/scratch/system-ca-bundle.pem"]).toBeUndefined();
  });

  it("takes the first candidate that exists, in the documented order", () => {
    const { deps, written } = fakeHost({
      [CA_INPUT]: `${FAKE_CA}\n`,
      "/etc/ssl/ca-bundle.pem": `${FAKE_SYSTEM_BUNDLE}\n`,
      "/etc/ssl/cert.pem": "-----BEGIN CERTIFICATE-----\nlater\n-----END CERTIFICATE-----\n",
    });
    const { systemCa } = writeCaTrustFiles(CA_INPUT, "/scratch", deps);

    expect(written[systemCa!.path].contents).toContain(FAKE_SYSTEM_BUNDLE);
    expect(written[systemCa!.path].contents).not.toContain("later");
  });
});

describe("writeCaTrustFiles with CA directories", () => {
  const CA_INPUT = "/scratch/input-ca.pem";
  const RHEL_ANCHORS = "/etc/pki/ca-trust/source/anchors";
  const SUSE_ANCHORS = "/etc/pki/trust/anchors";
  const SUSE_GNUTLS = "/var/lib/ca-certificates/pem";

  for (const dirs of [[], [RHEL_ANCHORS], [SUSE_ANCHORS, SUSE_GNUTLS]]) {
    it(`copies each of ${dirs.length} CA directories and adds the CA to the copy`, () => {
      const { deps, written, copied } = fakeHost({ [CA_INPUT]: `${FAKE_CA}\n` }, dirs);
      const { caDirs } = writeCaTrustFiles(CA_INPUT, "/scratch", deps);

      const want = dirs.map((destination, i) => ({ path: `/scratch/ca-dir${i}`, destination }));
      expect(caDirs).toEqual(want);
      expect(copied).toEqual(want.map((a) => [a.destination, a.path]));
      for (const { path } of want) {
        expect(written[`${path}/buildcage-proxy-ca.pem`]).toEqual({
          contents: `${FAKE_CA}\n`,
          mode: 0o644,
        });
      }
    });
  }

  it("warns and leaves out a directory it cannot copy, keeping the rest", () => {
    const { deps, written } = fakeHost({ [CA_INPUT]: `${FAKE_CA}\n` }, [SUSE_ANCHORS, SUSE_GNUTLS]);
    deps.copyDir = (source) => {
      if (source === SUSE_ANCHORS) throw new Error(`EACCES: permission denied, ${source}/private`);
    };
    const warnings: string[] = [];
    deps.warn = (message) => warnings.push(message);

    const { caDirs } = writeCaTrustFiles(CA_INPUT, "/scratch", deps);

    expect(caDirs).toEqual([{ path: "/scratch/ca-dir1", destination: SUSE_GNUTLS }]);
    expect(written["/scratch/ca-dir0/buildcage-proxy-ca.pem"]).toBeUndefined();
    expect(warnings).toEqual([
      `could not add the proxy CA to the CA directory ${SUSE_ANCHORS} ` +
        `(EACCES: permission denied, ${SUSE_ANCHORS}/private); a tool that reads it through ` +
        "GnuTLS or p11-kit (such as wget on RHEL or SUSE) will not trust the proxy. Check that " +
        "the runner user can read it, or use proxy_engine: universal.",
    ]);
  });

  it("leaves out a directory whose copy the CA cannot be written into", () => {
    const { deps } = fakeHost({ [CA_INPUT]: `${FAKE_CA}\n` }, [RHEL_ANCHORS]);
    deps.writeFile = (path) => {
      if (path.startsWith("/scratch/ca-dir0/")) throw new Error("EACCES");
    };

    expect(writeCaTrustFiles(CA_INPUT, "/scratch", deps).caDirs).toEqual([]);
  });
});

describe("caTrustAdditions", () => {
  it("mounts Chromium's NSS database after everything else", () => {
    const { mounts } = caTrustAdditions(
      {
        ownCaPath: "/scratch/buildcage-ca.pem",
        systemCa: undefined,
        jvmKeystores: [],
        caDirs: [],
        nssDb: {
          path: "/scratch/nssdb",
          destination: "/home/runner/.pki/nssdb",
          slot: { caDb: "/scratch/nssdb-ca", appended: "", hadPkcs11: false, snapshot: new Map() },
        },
      },
      {},
    );

    expect(mounts.slice(-2).map((m) => m.destination)).toStrictEqual([
      "/home/runner/.pki/nssdb",
      NSS_CA_DB_DESTINATION,
    ]);
  });

  it("mounts the CA-only file and points the additive variables at it, when unset", () => {
    const { mounts, env } = caTrustAdditions(
      {
        ownCaPath: "/scratch/buildcage-ca.pem",
        systemCa: undefined,
        jvmKeystores: [],
        caDirs: [],
      },
      {},
    );
    expect(mounts).toEqual([
      {
        destination: OWN_CA_DESTINATION,
        type: "none",
        source: "/scratch/buildcage-ca.pem",
        options: ["rbind", "ro", "nosuid", "nodev", "noexec"],
      },
    ]);
    expect(env.NODE_EXTRA_CA_CERTS).toBe(OWN_CA_DESTINATION);
    expect(env.DENO_CERT).toBe(OWN_CA_DESTINATION);
  });

  it("does not override a variable the step already set", () => {
    const { env } = caTrustAdditions(
      {
        ownCaPath: "/scratch/buildcage-ca.pem",
        systemCa: undefined,
        jvmKeystores: [],
        caDirs: [],
      },
      { NODE_EXTRA_CA_CERTS: "/my/own/bundle.pem" },
    );
    expect(env.NODE_EXTRA_CA_CERTS).toBeUndefined();
    expect(env.DENO_CERT).toBe(OWN_CA_DESTINATION);
  });

  it("adds the system-store mount and points the replacing variables at it, only when a system store was found", () => {
    const { mounts, env } = caTrustAdditions(
      {
        ownCaPath: "/scratch/buildcage-ca.pem",
        systemCa: { path: "/scratch/system-ca-bundle.pem", destination: RHEL_STORE },
        jvmKeystores: [],
        caDirs: [],
      },
      {},
    );
    expect(mounts).toContainEqual({
      destination: RHEL_STORE,
      type: "none",
      source: "/scratch/system-ca-bundle.pem",
      options: ["rbind", "ro"],
    });
    expect(env.REQUESTS_CA_BUNDLE).toBe(RHEL_STORE);
    expect(env.PIP_CERT).toBe(RHEL_STORE);
    expect(env.SSL_CERT_FILE).toBe(RHEL_STORE);
  });

  it("leaves CURL_CA_BUNDLE alone either way, since curl already reads the system store", () => {
    const { env } = caTrustAdditions(
      {
        ownCaPath: "/scratch/buildcage-ca.pem",
        systemCa: { path: "/scratch/system-ca-bundle.pem", destination: RHEL_STORE },
        jvmKeystores: [],
        caDirs: [],
      },
      {},
    );
    expect(env.CURL_CA_BUNDLE).toBeUndefined();
  });

  it("does not override a replacing variable the step already set", () => {
    const { env } = caTrustAdditions(
      {
        ownCaPath: "/scratch/buildcage-ca.pem",
        systemCa: { path: "/scratch/system-ca-bundle.pem", destination: RHEL_STORE },
        jvmKeystores: [],
        caDirs: [],
      },
      { REQUESTS_CA_BUNDLE: "/my/own/bundle.pem" },
    );
    expect(env.REQUESTS_CA_BUNDLE).toBeUndefined();
    expect(env.PIP_CERT).toBe(RHEL_STORE);
  });

  it("omits the system-store mount entirely when no system store was found", () => {
    const { mounts, env } = caTrustAdditions(
      {
        ownCaPath: "/scratch/buildcage-ca.pem",
        systemCa: undefined,
        jvmKeystores: [],
        caDirs: [],
      },
      {},
    );
    expect(mounts.some((m) => m.destination === RHEL_STORE)).toBe(false);
    expect(env.REQUESTS_CA_BUNDLE).toBeUndefined();
    expect(env.PIP_CERT).toBeUndefined();
    expect(env.SSL_CERT_FILE).toBeUndefined();
  });
});

describe("extractCaCert", () => {
  const containerName = "buildcage-proxy-abcd1234";
  const destDir = "/var/tmp/buildcage-0/sandbox-abcd1234";

  it("copies the proxy's own CA out of the running container", () => {
    const { deps, exec } = fakeHost({});
    const path = extractCaCert(containerName, destDir, deps);

    expect(path).toBe(`${destDir}/proxy-ca.pem`);
    expect(exec).toStrictEqual([
      ["docker", ["cp", `${containerName}:/opt/buildcage/ca.pem`, `${destDir}/proxy-ca.pem`]],
    ]);
  });

  // The sandboxed process runs as the unprivileged runner user and has to be
  // able to read it.
  it("leaves the copy world-readable", () => {
    const { deps, chmod } = fakeHost({});
    extractCaCert(containerName, destDir, deps);

    expect(chmod).toStrictEqual([[`${destDir}/proxy-ca.pem`, 0o644]]);
  });
});

describe("discoverJvmKeystores", () => {
  const at = (paths: string[], links: Record<string, string> = {}): CaTrustDeps => ({
    exists: (p) => paths.includes(p),
    realpath: (p) => links[p] ?? p,
  });

  it("finds cacerts under JAVA_HOME", () => {
    expect(
      discoverJvmKeystores(
        { JAVA_HOME: "/opt/java" },
        undefined,
        at(["/opt/java/lib/security/cacerts"]),
      ),
    ).toEqual(["/opt/java/lib/security/cacerts"]);
  });

  it("finds a JDK 8's jre/lib/security cacerts", () => {
    expect(
      discoverJvmKeystores(
        { JAVA_HOME: "/opt/jdk8" },
        undefined,
        at(["/opt/jdk8/jre/lib/security/cacerts"]),
      ),
    ).toEqual(["/opt/jdk8/jre/lib/security/cacerts"]);
  });

  // jssecacerts overrides cacerts, so both are found.
  it("finds jssecacerts alongside cacerts", () => {
    const dir = "/opt/java/lib/security";
    expect(
      discoverJvmKeystores(
        { JAVA_HOME: "/opt/java" },
        undefined,
        at([`${dir}/cacerts`, `${dir}/jssecacerts`]),
      ),
    ).toEqual([`${dir}/jssecacerts`, `${dir}/cacerts`]);
  });

  it("falls back to the known fixed directories when JAVA_HOME is unset", () => {
    expect(discoverJvmKeystores({}, undefined, at(["/etc/pki/java/cacerts"]))).toEqual([
      "/etc/pki/java/cacerts",
    ]);
  });

  // The java PATH resolves need not be the one JAVA_HOME names.
  it("finds the keystore of the java on PATH through its symlinks, ahead of JAVA_HOME's", () => {
    const jdk = "/usr/lib/jvm/temurin-21-jdk-amd64";
    expect(
      discoverJvmKeystores(
        { JAVA_HOME: "/opt/java" },
        "/usr/bin/java",
        at([`${jdk}/lib/security/cacerts`, "/opt/java/lib/security/cacerts"], {
          "/usr/bin/java": `${jdk}/bin/java`,
        }),
      ),
    ).toEqual([`${jdk}/lib/security/cacerts`, "/opt/java/lib/security/cacerts"]);
  });

  // A JDK 8's bin/java sits above the jre/ its java.home names.
  it("finds a JDK 8's keystore from the java on PATH", () => {
    expect(
      discoverJvmKeystores({}, "/opt/jdk8/bin/java", at(["/opt/jdk8/jre/lib/security/cacerts"])),
    ).toEqual(["/opt/jdk8/jre/lib/security/cacerts"]);
  });

  // JAVA_HOME's cacerts symlinked to a fixed path is one keystore, not two.
  it("resolves and deduplicates a keystore reachable by two paths", () => {
    const real = "/etc/pki/ca-trust/extracted/java/cacerts";
    expect(
      discoverJvmKeystores(
        { JAVA_HOME: "/opt/java" },
        undefined,
        at(["/opt/java/lib/security/cacerts", real], { "/opt/java/lib/security/cacerts": real }),
      ),
    ).toEqual([real]);
  });

  // setup-java puts only its last JDK on JAVA_HOME; a toolchain or the script
  // can switch to the others.
  describe("JAVA_HOME_<major>_<arch>", () => {
    const jdk17 = "/opt/hostedtoolcache/Java_Zulu_jdk/17.0.12-7/x64";
    const jdk21 = "/opt/hostedtoolcache/Java_Zulu_jdk/21.0.4-7/x64";

    it("finds the keystore of each JDK, in variable name order, after JAVA_HOME's", () => {
      expect(
        discoverJvmKeystores(
          { JAVA_HOME_21_X64: jdk21, JAVA_HOME: "/opt/java", JAVA_HOME_17_X64: jdk17 },
          undefined,
          at([
            `${jdk21}/lib/security/cacerts`,
            `${jdk17}/lib/security/cacerts`,
            "/opt/java/lib/security/cacerts",
            "/etc/pki/java/cacerts",
          ]),
        ),
      ).toEqual([
        "/opt/java/lib/security/cacerts",
        `${jdk17}/lib/security/cacerts`,
        `${jdk21}/lib/security/cacerts`,
        "/etc/pki/java/cacerts",
      ]);
    });

    // The hosted images' preinstalled JDKs all link to one shared cacerts.
    it("finds a keystore two JDKs share once", () => {
      const shared = "/etc/ssl/certs/adoptium/cacerts";
      expect(
        discoverJvmKeystores(
          { JAVA_HOME_17_X64: jdk17, JAVA_HOME_21_X64: jdk21 },
          undefined,
          at([`${jdk17}/lib/security/cacerts`, `${jdk21}/lib/security/cacerts`], {
            [`${jdk17}/lib/security/cacerts`]: shared,
            [`${jdk21}/lib/security/cacerts`]: shared,
          }),
        ),
      ).toEqual([shared]);
    });

    it("finds a JDK 8's jre/lib/security cacerts", () => {
      expect(
        discoverJvmKeystores(
          { JAVA_HOME_8_X64: "/opt/jdk8" },
          undefined,
          at(["/opt/jdk8/jre/lib/security/cacerts"]),
        ),
      ).toEqual(["/opt/jdk8/jre/lib/security/cacerts"]);
    });

    // An empty one would otherwise name the relative lib/security.
    it("ignores an empty variable", () => {
      expect(
        discoverJvmKeystores({ JAVA_HOME_17_X64: "" }, undefined, at(["lib/security/cacerts"])),
      ).toEqual([]);
    });

    it("ignores a variable not of that form", () => {
      expect(
        discoverJvmKeystores(
          { JAVA_HOME_FOO: "/opt/foo", JAVA_HOME_21: "/opt/bar", JAVA_HOME_21_x64: "/opt/baz" },
          undefined,
          at([
            "/opt/foo/lib/security/cacerts",
            "/opt/bar/lib/security/cacerts",
            "/opt/baz/lib/security/cacerts",
          ]),
        ),
      ).toEqual([]);
    });
  });

  it("finds nothing when there is no keystore", () => {
    expect(discoverJvmKeystores({ JAVA_HOME: "/opt/java" }, undefined, at([]))).toEqual([]);
  });
});

describe("writeJvmKeystoreFiles", () => {
  const CA = "/scratch/proxy-ca.pem";
  const KEYTOOL = "/opt/java/bin/keytool";

  function harness(keystores: string[], failKeytool = false) {
    const copies: [string, string][] = [];
    const exec: [string, string[], NodeJS.ProcessEnv | undefined][] = [];
    const warnings: string[] = [];
    const deps: CaTrustDeps = {
      exists: (p) => keystores.includes(p),
      realpath: (p) => p,
      copyFile: (source, destination) => copies.push([source, destination]),
      chmod: () => {},
      exec: (command, args, env) => {
        exec.push([command, args, env]);
        if (failKeytool) throw new Error("keytool failed");
      },
      warn: (message) => warnings.push(message),
    };
    return { deps, copies, exec, warnings };
  }

  it("copies each keystore and imports the CA with the pinned keytool, returning the mounts", () => {
    const ks = "/opt/java/lib/security/cacerts";
    const { deps, copies, exec } = harness([ks]);

    const result = writeJvmKeystoreFiles(
      CA,
      "/scratch",
      { JAVA_HOME: "/opt/java" },
      { java: undefined, keytool: KEYTOOL },
      deps,
    );

    expect(copies).toEqual([[ks, "/scratch/jvm-keystore-0"]]);
    expect(exec).toEqual([
      [
        KEYTOOL,
        [
          "-importcert",
          "-noprompt",
          "-alias",
          "buildcage-proxy-ca",
          "-file",
          CA,
          "-keystore",
          "/scratch/jvm-keystore-0",
          "-storepass",
          "changeit",
        ],
        {},
      ],
    ]);
    expect(result).toEqual([{ path: "/scratch/jvm-keystore-0", destination: ks }]);
  });

  it("runs keytool once for each distinct keystore", () => {
    const ks17 = "/opt/jdk17/lib/security/cacerts";
    const ks21 = "/opt/jdk21/lib/security/cacerts";
    const { deps, exec } = harness([ks17, ks21]);

    const result = writeJvmKeystoreFiles(
      CA,
      "/scratch",
      { JAVA_HOME: "/opt/jdk21", JAVA_HOME_17_X64: "/opt/jdk17", JAVA_HOME_21_X64: "/opt/jdk21" },
      { java: undefined, keytool: KEYTOOL },
      deps,
    );

    expect(exec.map(([, args]) => args[args.indexOf("-keystore") + 1])).toEqual([
      "/scratch/jvm-keystore-0",
      "/scratch/jvm-keystore-1",
    ]);
    expect(result).toEqual([
      { path: "/scratch/jvm-keystore-0", destination: ks21 },
      { path: "/scratch/jvm-keystore-1", destination: ks17 },
    ]);
  });

  // JAVA_TOOL_OPTIONS=-javaagent:... would otherwise run outside the sandbox.
  it("runs keytool without the step's environment", () => {
    const { deps, exec } = harness(["/opt/java/lib/security/cacerts"]);
    writeJvmKeystoreFiles(
      CA,
      "/scratch",
      { JAVA_HOME: "/opt/java", JAVA_TOOL_OPTIONS: "-javaagent:/home/runner/a.jar" },
      { java: undefined, keytool: KEYTOOL },
      deps,
    );
    expect(exec[0][2]).toEqual({});
  });

  it("skips a keystore keytool cannot rewrite, warns, and leaves it out of the mounts", () => {
    const { deps, warnings } = harness(["/opt/java/lib/security/cacerts"], true);
    expect(
      writeJvmKeystoreFiles(
        CA,
        "/scratch",
        { JAVA_HOME: "/opt/java" },
        { java: undefined, keytool: KEYTOOL },
        deps,
      ),
    ).toEqual([]);
    expect(warnings).toHaveLength(1);
    expect(warnings[0]).toContain("/opt/java/lib/security/cacerts");
    expect(warnings[0]).toContain("proxy_engine: universal");
  });

  it("skips every keystore and warns once when there is no pinnable keytool", () => {
    const keystores = ["/opt/java/lib/security/cacerts", "/etc/pki/java/cacerts"];
    const { deps, exec, copies, warnings } = harness(keystores);
    expect(
      writeJvmKeystoreFiles(
        CA,
        "/scratch",
        { JAVA_HOME: "/opt/java" },
        { java: undefined, keytool: undefined },
        deps,
      ),
    ).toEqual([]);
    expect(exec).toEqual([]);
    expect(copies).toEqual([]);
    expect(warnings).toHaveLength(1);
    expect(warnings[0]).toContain(keystores.join(", "));
    expect(warnings[0]).toContain("Install a JDK outside those paths");
    expect(warnings[0]).toContain("proxy_engine: universal");
  });

  it("returns nothing, and does not warn, when the runner has no JVM keystore", () => {
    for (const keytool of [KEYTOOL, undefined]) {
      const { deps, warnings } = harness([]);
      expect(
        writeJvmKeystoreFiles(
          CA,
          "/scratch",
          { JAVA_HOME: "/opt/java" },
          { java: undefined, keytool },
          deps,
        ),
      ).toEqual([]);
      expect(warnings).toEqual([]);
    }
  });
});

describe("writeCaTrustFiles with a CA directory that is a symlink", () => {
  it("copies the directory it resolves to, not the link", () => {
    const anchors = "/etc/pki/ca-trust/source/anchors";
    const { deps, copied } = fakeHost({ "/scratch/input-ca.pem": `${FAKE_CA}\n` }, [anchors]);
    deps.realpath = (path) => (path === anchors ? "/usr/share/pki/anchors" : path);

    const { caDirs } = writeCaTrustFiles("/scratch/input-ca.pem", "/scratch", deps);

    expect(copied).toEqual([["/usr/share/pki/anchors", "/scratch/ca-dir0"]]);
    expect(caDirs).toEqual([{ path: "/scratch/ca-dir0", destination: anchors }]);
  });
});

describe("caTrustAdditions with CA directories", () => {
  it("mounts each copy read-only over the directory it came from, adding no env", () => {
    const { mounts, env } = caTrustAdditions(
      {
        ownCaPath: "/scratch/buildcage-ca.pem",
        systemCa: undefined,
        jvmKeystores: [],
        caDirs: [{ path: "/scratch/ca-dir0", destination: "/etc/pki/ca-trust/source/anchors" }],
      },
      { NODE_EXTRA_CA_CERTS: "/set", DENO_CERT: "/set" },
    );
    expect(mounts).toContainEqual({
      destination: "/etc/pki/ca-trust/source/anchors",
      type: "none",
      source: "/scratch/ca-dir0",
      options: ["rbind", "ro"],
    });
    expect(env).toEqual({});
  });
});

describe("caTrustAdditions with JVM keystores", () => {
  it("mounts each injected keystore over the keystore it stands in for, adding no env", () => {
    const { mounts, env } = caTrustAdditions(
      {
        ownCaPath: "/scratch/buildcage-ca.pem",
        systemCa: undefined,
        jvmKeystores: [
          { path: "/scratch/jvm-keystore-0", destination: "/opt/java/lib/security/cacerts" },
          { path: "/scratch/jvm-keystore-1", destination: "/opt/java/lib/security/jssecacerts" },
        ],
        caDirs: [],
      },
      {},
    );
    expect(mounts).toContainEqual({
      destination: "/opt/java/lib/security/cacerts",
      type: "none",
      source: "/scratch/jvm-keystore-0",
      options: ["rbind", "ro"],
    });
    expect(mounts).toContainEqual({
      destination: "/opt/java/lib/security/jssecacerts",
      type: "none",
      source: "/scratch/jvm-keystore-1",
      options: ["rbind", "ro"],
    });
    // The JVM reads no variable.
    expect(Object.keys(env)).toEqual(["NODE_EXTRA_CA_CERTS", "DENO_CERT"]);
  });
});

describe("assertWriteThroughClearOfCaTrust", () => {
  const KEYSTORE = "/usr/lib/jvm/temurin-21-jdk-amd64/lib/security/cacerts";
  const NSS_DB = "/home/runner/.pki/nssdb";
  const ANCHORS = "/etc/pki/ca-trust/source/anchors";
  const files = {
    ownCaPath: "/scratch/buildcage-ca.pem",
    systemCa: undefined,
    jvmKeystores: [{ path: "/scratch/jvm-0/cacerts", destination: KEYSTORE }],
    caDirs: [{ path: "/scratch/ca-dir0", destination: ANCHORS }],
    nssDb: {
      path: "/scratch/nssdb",
      destination: NSS_DB,
      slot: { caDb: "/scratch/nssdb-ca", appended: "", hadPkcs11: false, snapshot: new Map() },
    },
  };

  it.each([
    [KEYSTORE, /is a JVM keystore/],
    [`${NSS_DB}/cert9.db`, /is inside the NSS database/],
    [ANCHORS, /is in the CA directory/],
    [`${ANCHORS}/corp.pem`, /is in the CA directory/],
  ])("refuses %s, which a CA mount would shadow", (path, message) => {
    expect(() => assertWriteThroughClearOfCaTrust(files, [path])).toThrow(message);
  });

  it.each([
    ["the directory holding a keystore", "/usr/lib/jvm/temurin-21-jdk-amd64/lib/security"],
    ["the NSS database itself, which is written back", NSS_DB],
    ["the directory holding the anchors", "/etc/pki/ca-trust/source"],
    ["an unrelated path", "/opt/cache"],
  ])("allows %s", (_, path) => {
    expect(() => assertWriteThroughClearOfCaTrust(files, [path])).not.toThrow();
  });

  it("allows anything when there is no NSS database to cover", () => {
    expect(() =>
      assertWriteThroughClearOfCaTrust({ ...files, nssDb: undefined }, [`${NSS_DB}/cert9.db`]),
    ).not.toThrow();
  });
});

describe("presetCaVariables", () => {
  const files = {
    ownCaPath: "/scratch/buildcage-ca.pem",
    systemCa: { path: "/scratch/system-ca-bundle.pem", destination: RHEL_STORE },
    jvmKeystores: [],
    caDirs: [],
  };
  // /usr/lib/ssl/cert.pem stands for a symlink to the store.
  const realpath = (path: string) => (path === "/usr/lib/ssl/cert.pem" ? RHEL_STORE : path);

  it("names a variable set to a file other than the store or the CA-only file", () => {
    expect(
      presetCaVariables(
        files,
        {
          NODE_EXTRA_CA_CERTS: "/opt/corp-ca.pem",
          GIT_SSL_CAINFO: "/opt/corp-ca.pem",
          Npm_Config_Cafile: "/opt/corp-ca.pem",
          SSL_CERT_FILE: "/not/there.pem",
        },
        realpath,
      ),
    ).toEqual(["NODE_EXTRA_CA_CERTS", "GIT_SSL_CAINFO", "Npm_Config_Cafile", "SSL_CERT_FILE"]);
  });

  it("leaves out one that carries the proxy CA, or is unset or empty", () => {
    expect(
      presetCaVariables(
        files,
        {
          REQUESTS_CA_BUNDLE: RHEL_STORE,
          PIP_CERT: "/usr/lib/ssl/cert.pem",
          DENO_CERT: OWN_CA_DESTINATION,
          CURL_CA_BUNDLE: "",
          PATH: "/usr/bin",
        },
        realpath,
      ),
    ).toEqual([]);
  });

  it("names one set to the store's path when the runner has no store", () => {
    expect(
      presetCaVariables({ ...files, systemCa: undefined }, { SSL_CERT_FILE: RHEL_STORE }, realpath),
    ).toEqual(["SSL_CERT_FILE"]);
  });
});

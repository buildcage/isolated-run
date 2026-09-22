import { execFileSync } from "node:child_process";
import {
  readFileSync,
  writeFileSync,
  existsSync,
  chmodSync,
  copyFileSync,
  realpathSync,
} from "node:fs";
import { join } from "node:path";
import { buildDockerCpArgs } from "#core/lib/docker/args.ts";
import type { MountEntry } from "./types.ts";

/**
 * CA trust for the inspect engine, adapted for this sandbox's rootfs being
 * the live host `/` (via `mount --rbind /`), not a throwaway image layer.
 *
 * Writing the CA into the rootfs and deleting it again once the step's
 * process exits is the obvious approach, and the right one when that rootfs
 * is a disposable image layer, one torn down (or diffed and discarded) after
 * the step. It does not work here: this sandbox's rootfs is a bind-mount of
 * the live host `/`, so both the write and the delete land on the host
 * filesystem itself.
 *
 * Instead, the two files below are written into this run's own scratch
 * directory and mounted over the sandbox's own view of the relevant
 * paths (see caTrustAdditions / buildOciConfig), a mount-namespace-scoped
 * overlay, not a host write. The mount needs nothing undone
 * afterward: run-isolated.sh's `umount -R` (and the scratch dir's own
 * cleanup) removes it, along with the rest of the rootfs bind-mount, when
 * the step ends, and the real host store is never touched (the augmented copy
 * goes back over the path it was read from, so there is always a file there).
 *
 * OWN_CA_DESTINATION is the one exception: nothing exists at that path
 * ahead of time, so runc creates an empty placeholder file to mount onto,
 * which on this rootfs is a real write to the host filesystem. It is
 * removed by run-isolated.sh's cleanup(), whose comment gives the ordering
 * and the guard it removes it under.
 */
export interface CaTrustFiles {
  /** A CA-only file, mounted at OWN_CA_DESTINATION, for variables that add
   *  to a tool's built-in trust set (NODE_EXTRA_CA_CERTS, DENO_CERT). */
  ownCaPath: string;
  /** The runner's own system CA store with this CA appended, and the path it
   *  was read from, which is where the copy is mounted; it is no use anywhere
   *  else, so the two are one value. Undefined if the runner has no system
   *  store at any of the well-known candidate paths. For the variables that
   *  replace a tool's trust bundle outright (REQUESTS_CA_BUNDLE, PIP_CERT,
   *  SSL_CERT_FILE), and for every other tool (curl, ...) that already reads
   *  the system store by default. SYSTEM_CA_CANDIDATES[0] is the only
   *  candidate a GitHub-hosted (passwordless-sudo) Linux runner has; the rest
   *  are what a self-hosted RHEL or SUSE runner is reached by.
   */
  systemCa: { path: string; destination: string } | undefined;
  /** Injected copies of the JVM's own keystores (see writeJvmKeystoreFiles),
   *  each mounted over the keystore it was copied from. A JVM already on the
   *  runner reads only these, not the system store or the variables above, so
   *  `mvn`/`gradle`/`java` under the inspect engine trust the CA only once it
   *  is in here. Empty when the runner has no JVM keystore this found. */
  jvmKeystores: { path: string; destination: string }[];
}

export const SYSTEM_CA_CANDIDATES = [
  "/etc/ssl/certs/ca-certificates.crt", // Debian/Ubuntu
  "/etc/pki/tls/certs/ca-bundle.crt", // RHEL/Fedora
  "/etc/ssl/ca-bundle.pem", // openSUSE
  "/etc/pki/tls/cacert.pem", // OpenELEC
  "/etc/ssl/cert.pem", // Alpine
];

/** Where the two files above are mounted inside the sandbox. Changing this
 *  value must stay in sync with run-isolated.sh's own BUILDCAGE_CA_PLACEHOLDER
 *  (its cleanup() targets this exact path; see the module doc comment). */
export const OWN_CA_DESTINATION = "/etc/buildcage-ca.pem";

export interface CaTrustDeps {
  exec?: (command: string, args: string[]) => void;
  readFile?: (path: string) => string;
  writeFile?: (path: string, contents: string, mode: number) => void;
  exists?: (path: string) => boolean;
  chmod?: (path: string, mode: number) => void;
  copyFile?: (source: string, destination: string) => void;
  realpath?: (path: string) => string;
}

// Untested by design: the defaults behind this module's seams, which only hand
// node:fs and node:child_process what the tested caller decided.
/* v8 ignore start */
function defaultExec(command: string, args: string[]): void {
  execFileSync(command, args);
}

function defaultReadFile(path: string): string {
  return readFileSync(path, "utf8");
}

function defaultWriteFile(path: string, contents: string, mode: number): void {
  writeFileSync(path, contents, { mode });
}
/* v8 ignore stop */

/**
 * Pull the proxy's own CA (generated once per container by
 * init-inspect-cfg) out of the inspect proxy image, the same way
 * extractRuncBootstrap pulls runc and gen-seccomp-profile: `docker cp`, run
 * once per `run:` step, into this run's own scratch dir.
 */
export function extractCaCert(
  containerName: string,
  destDir: string,
  { exec = defaultExec, chmod = chmodSync }: CaTrustDeps = {},
): string {
  const caCertPath = join(destDir, "proxy-ca.pem");
  exec(
    "docker",
    buildDockerCpArgs({
      containerName,
      containerPath: "/opt/buildcage/ca.pem",
      hostPath: caCertPath,
    }),
  );
  chmod(caCertPath, 0o644);
  return caCertPath;
}

/**
 * Write the CA trust files a step's env vars will point at, into `dir`
 * (this run's own scratch directory). `caCertPath` is the proxy's own CA,
 * already `docker cp`'d onto the host; see extractCaCert.
 */
export function writeCaTrustFiles(
  caCertPath: string,
  dir: string,
  {
    readFile = defaultReadFile,
    writeFile = defaultWriteFile,
    exists = existsSync,
  }: CaTrustDeps = {},
): Omit<CaTrustFiles, "jvmKeystores"> {
  const ca = readFile(caCertPath).trimEnd();

  const ownCaPath = join(dir, "buildcage-ca.pem");
  writeFile(ownCaPath, `${ca}\n`, 0o644);

  const destination = SYSTEM_CA_CANDIDATES.find((p) => exists(p));
  let systemCa: CaTrustFiles["systemCa"];
  if (destination) {
    const existing = readFile(destination).trimEnd();
    const path = join(dir, "system-ca-bundle.pem");
    writeFile(path, `${existing}\n${ca}\n`, 0o644);
    systemCa = { path, destination };
  }

  return { ownCaPath, systemCa };
}

// The keystore file names a JVM's default trust manager reads: jssecacerts
// overrides cacerts when present, so both get the CA.
const JVM_KEYSTORE_NAMES = ["jssecacerts", "cacerts"];

// Keystore directories tried when JAVA_HOME is unset, for a JVM at a fixed
// location without it: Debian's ca-certificates-java output and RHEL's, each a
// symlink realpath resolves to the real file.
const KNOWN_JVM_KEYSTORE_DIRS = [
  "/etc/ssl/certs/java",
  "/etc/pki/java",
  "/etc/pki/ca-trust/extracted/java",
];

// The alias the injected trusted certificate carries; only has to not collide
// with one the keystore already uses.
const JVM_KEYSTORE_ALIAS = "buildcage-proxy-ca";

/**
 * Find the JVM keystores on the runner, from JAVA_HOME (the JDK 9+ lib/security
 * and a JDK 8's jre/lib/security) and then the known fixed directories, each
 * resolved and deduplicated so a symlinked one is not injected into twice.
 */
export function discoverJvmKeystores(
  env: NodeJS.ProcessEnv,
  { exists = existsSync, realpath = realpathSync }: CaTrustDeps = {},
): string[] {
  const dirs: string[] = [];
  if (env.JAVA_HOME) {
    dirs.push(
      join(env.JAVA_HOME, "lib", "security"),
      join(env.JAVA_HOME, "jre", "lib", "security"),
    );
  }
  dirs.push(...KNOWN_JVM_KEYSTORE_DIRS);

  const found: string[] = [];
  const seen = new Set<string>();
  for (const dir of dirs) {
    for (const name of JVM_KEYSTORE_NAMES) {
      const candidate = join(dir, name);
      if (!exists(candidate)) continue;
      const real = realpath(candidate);
      if (seen.has(real)) continue;
      seen.add(real);
      found.push(real);
    }
  }
  return found;
}

/**
 * Inject the proxy CA into a copy of each JVM keystore, in `dir` (this run's own
 * scratch directory), and return each copy with the keystore it stands in for,
 * for caTrustAdditions to mount over. The copy is made and rewritten with the
 * runner's own keytool, so its output is one that JVM will trust as its cacerts;
 * the real keystore is only read, never written. A keystore keytool cannot
 * rewrite (an unusual password, say) is skipped, so the step's JVM does not
 * trust the CA rather than the step failing.
 */
export function writeJvmKeystoreFiles(
  caCertPath: string,
  dir: string,
  env: NodeJS.ProcessEnv,
  {
    exec = defaultExec,
    exists = existsSync,
    realpath = realpathSync,
    copyFile = copyFileSync,
    chmod = chmodSync,
  }: CaTrustDeps = {},
): CaTrustFiles["jvmKeystores"] {
  const keytool = env.JAVA_HOME ? join(env.JAVA_HOME, "bin", "keytool") : "keytool";
  const injected: CaTrustFiles["jvmKeystores"] = [];

  discoverJvmKeystores(env, { exists, realpath }).forEach((keystore, i) => {
    const copy = join(dir, `jvm-keystore-${i}`);
    try {
      copyFile(keystore, copy);
      chmod(copy, 0o644);
      exec(keytool, [
        "-importcert",
        "-noprompt",
        "-alias",
        JVM_KEYSTORE_ALIAS,
        "-file",
        caCertPath,
        "-keystore",
        copy,
        "-storepass",
        "changeit",
      ]);
    } catch {
      return; // keytool or the copy failed: leave this keystore untrusted.
    }
    injected.push({ path: copy, destination: keystore });
  });

  return injected;
}

// Mirrors buildcage/docker's inspect-engine CA-injection policy table (see
// docs/security.md): NODE_EXTRA_CA_CERTS/DENO_CERT add to a built-in trust
// set, so they're pointed at a CA-only file; REQUESTS_CA_BUNDLE/PIP_CERT/
// SSL_CERT_FILE replace a tool's bundle outright, so they're pointed at the
// (augmented) system store instead, never a CA-only file: doing so would
// leave the tool trusting nothing else. CURL_CA_BUNDLE is left unset: curl
// already reads the system store by default, which is also how GnuTLS-linked
// tools (Debian's wget and git) reach it, since they read none of these.
//
// Only applied when a variable is unset. A step that already points one of
// these somewhere keeps doing so unmodified: safely appending to an
// arbitrary already-set path would need host-escape-safe symlink
// resolution.
const POINT_AT_OWN_CA = ["NODE_EXTRA_CA_CERTS", "DENO_CERT"];
const POINT_AT_SYSTEM_STORE = ["REQUESTS_CA_BUNDLE", "PIP_CERT", "SSL_CERT_FILE"];

export interface CaTrustAdditions {
  mounts: MountEntry[];
  env: Record<string, string>;
}

/**
 * The extra mounts and env vars buildOciConfig should add on top of the
 * step's own, so the sandboxed process trusts the proxy's CA; see the
 * module doc comment for why these are mounts, not host writes.
 */
export function caTrustAdditions(files: CaTrustFiles, env: NodeJS.ProcessEnv): CaTrustAdditions {
  const mounts: MountEntry[] = [
    {
      destination: OWN_CA_DESTINATION,
      type: "none",
      source: files.ownCaPath,
      options: ["rbind", "ro"],
    },
  ];
  const extraEnv: Record<string, string> = {};
  for (const name of POINT_AT_OWN_CA) {
    if (!env[name]) extraEnv[name] = OWN_CA_DESTINATION;
  }

  if (files.systemCa) {
    mounts.push({
      destination: files.systemCa.destination,
      type: "none",
      source: files.systemCa.path,
      options: ["rbind", "ro"],
    });
    for (const name of POINT_AT_SYSTEM_STORE) {
      if (!env[name]) extraEnv[name] = files.systemCa.destination;
    }
  }

  // The JVM reads no variable, only its own keystore, so these add no env, just
  // the injected copy mounted over each keystore it stands in for.
  for (const keystore of files.jvmKeystores) {
    mounts.push({
      destination: keystore.destination,
      type: "none",
      source: keystore.path,
      options: ["rbind", "ro"],
    });
  }

  return { mounts, env: extraEnv };
}

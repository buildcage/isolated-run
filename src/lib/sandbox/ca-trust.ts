import { execFileSync } from "node:child_process";
import {
  readFileSync,
  writeFileSync,
  existsSync,
  chmodSync,
  copyFileSync,
  cpSync,
  realpathSync,
  statSync,
} from "node:fs";
import { dirname, join } from "node:path";

import { buildDockerCpArgs } from "#core/lib/docker/args.ts";
import { errorMessage } from "#core/lib/errors.ts";

import { nssDbMounts, type NssDbFiles } from "./nss-db.ts";
import { isAtOrUnder, WritablePathConflictError } from "./paths.ts";
import { hostCommand, hostCommandEnv } from "./pinned-commands.ts";
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
 * Instead, the files below are written into this run's own scratch
 * directory and mounted over the sandbox's own view of the relevant
 * paths (see caTrustAdditions / buildOciConfig), a mount-namespace-scoped
 * overlay, not a host write. The mount needs nothing undone
 * afterward: run-isolated.sh's `umount -R` (and the scratch dir's own
 * cleanup) removes it, along with the rest of the rootfs bind-mount, when
 * the step ends, and the real host store is never touched (the augmented copy
 * goes back over the path it was read from, so there is always a file there).
 *
 * OWN_CA_DESTINATION is the one path with nothing there ahead of time. runc
 * creates its mount point in the container's own /dev tmpfs, not on the host.
 */
export interface CaTrustFiles {
  /** A CA-only file, mounted at OWN_CA_DESTINATION, for variables that add
   *  to a tool's built-in trust set (NODE_EXTRA_CA_CERTS, DENO_CERT). */
  ownCaPath: string;
  /** The runner's CA stores this covers, in CA_STORES order. */
  stores: CaStoreCopy[];
  /** Undefined when there was nowhere to mount it. */
  nssDb?: NssDbFiles;
}

/** A copy of one of the runner's CA stores with the CA added, mounted over the
 *  store it was copied from. */
export interface CaStoreCopy {
  kind: CaStoreKind;
  path: string;
  destination: string;
}

export const SYSTEM_CA_CANDIDATES = [
  "/etc/ssl/certs/ca-certificates.crt", // Debian/Ubuntu
  "/etc/pki/tls/certs/ca-bundle.crt", // RHEL/Fedora
  "/etc/ssl/ca-bundle.pem", // openSUSE
  "/etc/pki/tls/cacert.pem", // OpenELEC
  "/etc/ssl/cert.pem", // Alpine
];

/** Certificate directories some tools read in place of the system bundle. */
export const CA_DIR_CANDIDATES = [
  // p11-kit's anchors on RHEL/Fedora, which GnuTLS (wget) reads through p11-kit.
  "/etc/pki/ca-trust/source/anchors",
  // p11-kit's anchors on SUSE, for what reads p11-kit directly.
  "/etc/pki/trust/anchors",
  // SUSE's GnuTLS reads this directory, not p11-kit.
  "/var/lib/ca-certificates/pem",
];

/** Not under /run: `write_through` can put the host's /run back, and the mount
 *  point would then be created on the host. */
export const OWN_CA_DESTINATION = "/dev/buildcage-ca.pem";

export interface CaTrustDeps {
  exec?: (command: string, args: string[], env?: NodeJS.ProcessEnv) => void;
  readFile?: (path: string) => string;
  writeFile?: (path: string, contents: string, mode: number) => void;
  exists?: (path: string) => boolean;
  chmod?: (path: string, mode: number) => void;
  copyFile?: (source: string, destination: string) => void;
  realpath?: (path: string) => string;
  isDirectory?: (path: string) => boolean;
  copyDir?: (source: string, destination: string) => void;
  warn?: (message: string) => void;
}

// Untested by design: the defaults behind this module's seams, which only hand
// node:fs and node:child_process what the tested caller decided.
/* v8 ignore start */
function defaultExec(command: string, args: string[], env?: NodeJS.ProcessEnv): void {
  execFileSync(hostCommand(command), args, { env: hostCommandEnv(command, env) });
}

function defaultReadFile(path: string): string {
  return readFileSync(path, "utf8");
}

function defaultWriteFile(path: string, contents: string, mode: number): void {
  writeFileSync(path, contents, { mode });
}

function defaultIsDirectory(path: string): boolean {
  return statSync(path, { throwIfNoEntry: false })?.isDirectory() === true;
}

// A symlink in the directory is copied as the link it is, so the mirror never
// reads through one to somewhere else.
function defaultCopyDir(source: string, destination: string): void {
  cpSync(source, destination, { recursive: true, verbatimSymlinks: true });
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

// The keystore file names a JVM's default trust manager reads: jssecacerts
// overrides cacerts when present, so both get the CA.
const JVM_KEYSTORE_NAMES = ["jssecacerts", "cacerts"];

// The alias the injected trusted certificate carries; only has to not collide
// with one the keystore already uses.
const JVM_KEYSTORE_ALIAS = "buildcage-proxy-ca";

/** The host binaries the JVM keystore injection uses; see jvmTools. */
export interface JvmTools {
  java: string | undefined;
  keytool: string | undefined;
}

// The JDK 9+ lib/security and a JDK 8's jre/lib/security.
function keystoreDirsOf(home: string): string[] {
  return [join(home, "lib", "security"), join(home, "jre", "lib", "security")];
}

/**
 * Find the JVM keystores on the runner: the keystore of the java PATH actually
 * resolves (which mvn/gradle/java read and which need not be the one JAVA_HOME
 * names), then JAVA_HOME's (for a tool that goes by JAVA_HOME instead). Each
 * is resolved and deduplicated so a keystore reachable by more than one path is
 * injected into once.
 *
 * The java's home is read off its symlinks rather than asked of the java,
 * which may be a binary an earlier sandboxed step planted. A wrapper script
 * (an asdf or jenv shim) resolves to the wrong place, leaving JAVA_HOME.
 */
export function discoverJvmKeystores(
  env: NodeJS.ProcessEnv,
  java: string | undefined,
  { exists = existsSync, realpath = realpathSync }: CaTrustDeps = {},
): string[] {
  const dirs: string[] = [];
  if (java) dirs.push(...keystoreDirsOf(dirname(dirname(realpath(java)))));
  if (env.JAVA_HOME) dirs.push(...keystoreDirsOf(env.JAVA_HOME));

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

// Mirrors buildcage/docker's inspect-engine CA-injection policy table (see
// docs/security.md): NODE_EXTRA_CA_CERTS/DENO_CERT add to a built-in trust
// set, so they're pointed at a CA-only file; REQUESTS_CA_BUNDLE/PIP_CERT/
// SSL_CERT_FILE replace a tool's bundle outright, so they're pointed at the
// (augmented) system store instead, never a CA-only file: doing so would
// leave the tool trusting nothing else. CURL_CA_BUNDLE is left unset: curl
// already reads the system store by default, which is also how Debian's
// GnuTLS-linked tools (wget, git) reach it, since they read none of these.
// RHEL's and SUSE's read a directory instead; see CA_DIR_CANDIDATES.
//
// Only applied when a variable is unset. A step that already points one of
// these somewhere keeps doing so unmodified: safely appending to an
// arbitrary already-set path would need host-escape-safe symlink
// resolution.
const POINT_AT_OWN_CA = ["NODE_EXTRA_CA_CERTS", "DENO_CERT"];
const POINT_AT_SYSTEM_STORE = ["REQUESTS_CA_BUNDLE", "PIP_CERT", "SSL_CERT_FILE"];

interface CaStoreContext {
  /** The proxy CA, PEM, trailing whitespace trimmed. */
  ca: string;
  caCertPath: string;
  env: NodeJS.ProcessEnv;
  tools: JvmTools;
  deps: Required<Omit<CaTrustDeps, "warn">> & Pick<CaTrustDeps, "warn">;
}

/** Which write_through entries a store's mount refuses, since it is mounted
 *  after every write_through entry and would silently shadow them. */
type CaStoreReservation =
  /** Every candidate, and where each resolves, in every engine, whether or
   *  not the runner has it: which one the mount lands on depends on the
   *  runner, so an input is refused on every machine or on none. */
  | { candidates: readonly string[] }
  /** Only the store this step covers under inspect: which exist depends on
   *  what is installed. */
  | {
      refuses: (entry: string, destination: string) => boolean;
      refusal: (destination: string) => string;
    };

/** A kind of CA store on the runner, covered with a copy carrying the proxy CA. */
interface CaStore {
  find: (context: CaStoreContext) => string[];
  copyName: (i: number) => string;
  inject: (context: CaStoreContext, destination: string, path: string) => void;
  /** Warns and leaves the store uncovered; without it, a failure fails the step. */
  notAdded?: (destination: string, error: unknown) => string;
  mountOptions: string[];
  /** Pointed at the store when the step left them unset. */
  variables?: string[];
  reserve: CaStoreReservation;
}

export type CaStoreKind = "systemStore" | "caDir" | "jvmKeystore";

const READ_ONLY = ["rbind", "ro"];

/** The CA stores the inspect engine covers, in mount order. A new store is a new row. */
export const CA_STORES: Record<CaStoreKind, CaStore> = {
  // The runner's own system CA store with the CA appended. The replacing
  // variables point here, and every other tool (curl, ...) already reads it
  // by default. Only the first candidate the runner has: the copy goes back
  // over the path it was read from, and is no use anywhere else.
  // SYSTEM_CA_CANDIDATES[0] is the only candidate a GitHub-hosted
  // (passwordless-sudo) Linux runner has; the rest are what a self-hosted RHEL
  // or SUSE runner is reached by.
  systemStore: {
    find: ({ deps }) => {
      const found = SYSTEM_CA_CANDIDATES.find((p) => deps.exists(p));
      return found ? [found] : [];
    },
    copyName: () => "system-ca-bundle.pem",
    inject: ({ ca, deps }, destination, path) => {
      const existing = deps.readFile(destination).trimEnd();
      deps.writeFile(path, `${existing}\n${ca}\n`, 0o644);
    },
    mountOptions: READ_ONLY,
    variables: POINT_AT_SYSTEM_STORE,
    reserve: { candidates: SYSTEM_CA_CANDIDATES },
  },

  // Only a directory the runner already has: one is never created.
  caDir: {
    find: ({ deps }) => CA_DIR_CANDIDATES.filter((d) => deps.isDirectory(d)),
    copyName: (i) => `ca-dir${i}`,
    inject: ({ ca, deps }, destination, path) => {
      // Copied from where it resolves: a symlinked directory copied verbatim
      // would make the copy a link back to it, and the CA would land in the
      // runner's own store.
      deps.copyDir(deps.realpath(destination), path);
      deps.writeFile(join(path, "buildcage-proxy-ca.pem"), `${ca}\n`, 0o644);
    },
    // The copy runs as the runner user, so an entry only root can read fails it.
    notAdded: (destination, e) =>
      `could not add the proxy CA to the CA directory ${destination} (${errorMessage(e)}); ` +
      "a tool that reads it through GnuTLS or p11-kit (such as wget on RHEL or SUSE) will " +
      "not trust the proxy. Check that the runner user can read it, or use " +
      "proxy_engine: universal.",
    mountOptions: READ_ONLY,
    reserve: {
      refuses: (entry, destination) => isAtOrUnder(entry, destination),
      refusal: (destination) =>
        `is in the CA directory ${JSON.stringify(destination)}, which the inspect engine ` +
        "covers with a read-only copy carrying the proxy CA for the step. Name a containing " +
        "directory instead to persist writes around it.",
    },
  },

  // A JVM already on the runner reads only its own keystores, not the system
  // store or any variable, so `mvn`/`gradle`/`java` trust the CA only once it
  // is in there. The copy is rewritten with the runner's own keytool, so its
  // output is one that JVM will trust as its cacerts; the real keystore is
  // only read. keytool gets an empty environment, so the step's
  // JAVA_TOOL_OPTIONS or LD_PRELOAD stays inside the sandbox.
  jvmKeystore: {
    find: ({ env, tools, deps }) => {
      const keystores = discoverJvmKeystores(env, tools.java, deps);
      if (!tools.keytool && keystores.length > 0) {
        deps.warn?.(
          `could not add the proxy CA to the JVM keystores (${keystores.join(", ")}): found no ` +
            "keytool outside the paths a sandboxed command can write to ($HOME, $GITHUB_WORKSPACE, " +
            "/tmp, $RUNNER_TEMP, write_through:). A Java step will not trust the proxy. Install a " +
            "JDK outside those paths (a system package, or RUNNER_TOOL_CACHE outside $HOME), or " +
            "use proxy_engine: universal.",
        );
        return [];
      }
      return keystores;
    },
    copyName: (i) => `jvm-keystore-${i}`,
    inject: ({ caCertPath, tools, deps }, destination, path) => {
      deps.copyFile(destination, path);
      deps.chmod(path, 0o644);
      deps.exec(
        tools.keytool!,
        [
          "-importcert",
          "-noprompt",
          "-alias",
          JVM_KEYSTORE_ALIAS,
          "-file",
          caCertPath,
          "-keystore",
          path,
          "-storepass",
          "changeit",
        ],
        {},
      );
    },
    // A non-default store password otherwise shows only as an opaque TLS error.
    notAdded: (destination) =>
      `could not add the proxy CA to the JVM keystore ${destination}; a Java step ` +
      `will not trust it. Use proxy_engine: universal for a JVM build whose ` +
      `keystore cannot be rewritten.`,
    mountOptions: READ_ONLY,
    reserve: {
      refuses: (entry, destination) => entry === destination,
      refusal: () =>
        "is a JVM keystore the inspect engine covers with a read-only copy carrying the " +
        "proxy CA for the step. Name a containing directory instead to persist writes around it.",
    },
  },
};

/** The paths write_through: refuses in every engine; see CaStoreReservation. */
export function reservedCaStorePaths(): string[] {
  return Object.values(CA_STORES).flatMap(({ reserve }) =>
    "candidates" in reserve ? reserve.candidates : [],
  );
}

// Not in CA_STORES: the NSS database is claimed, written back and released (see prepareNssDb).
const NSS_DB_RESERVATION = {
  refuses: (entry: string, destination: string) =>
    entry !== destination && isAtOrUnder(entry, destination),
  refusal: (destination: string) =>
    `is inside the NSS database at ${JSON.stringify(destination)}, which the inspect engine ` +
    `covers for the step. Name ${JSON.stringify(destination)} itself to have the command's ` +
    "changes written back.",
};

/**
 * Write the CA trust files a step's env vars will point at, into `dir`
 * (this run's own scratch directory), and a copy of each store in CA_STORES
 * with the CA added. `caCertPath` is the proxy's own CA, already `docker cp`'d
 * onto the host; see extractCaCert.
 */
export function writeCaTrustFiles(
  caCertPath: string,
  dir: string,
  env: NodeJS.ProcessEnv,
  tools: JvmTools,
  {
    exec = defaultExec,
    readFile = defaultReadFile,
    writeFile = defaultWriteFile,
    exists = existsSync,
    chmod = chmodSync,
    copyFile = copyFileSync,
    realpath = realpathSync,
    isDirectory = defaultIsDirectory,
    copyDir = defaultCopyDir,
    warn,
  }: CaTrustDeps = {},
): Omit<CaTrustFiles, "nssDb"> {
  const deps = {
    exec,
    readFile,
    writeFile,
    exists,
    chmod,
    copyFile,
    realpath,
    isDirectory,
    copyDir,
    warn,
  };
  const ca = readFile(caCertPath).trimEnd();

  const ownCaPath = join(dir, "buildcage-ca.pem");
  writeFile(ownCaPath, `${ca}\n`, 0o644);

  const context: CaStoreContext = { ca, caCertPath, env, tools, deps };
  const stores: CaStoreCopy[] = [];
  for (const [kind, store] of Object.entries(CA_STORES) as [CaStoreKind, CaStore][]) {
    store.find(context).forEach((destination, i) => {
      const path = join(dir, store.copyName(i));
      try {
        store.inject(context, destination, path);
      } catch (e) {
        if (!store.notAdded) throw e;
        warn?.(store.notAdded(destination, e));
        return;
      }
      stores.push({ kind, path, destination });
    });
  }

  return { ownCaPath, stores };
}

// Variables this never sets, each replacing its tool's bundle when the step
// does. npm reads npm_config_* in any case.
const REPLACING_WHEN_SET = [
  "CURL_CA_BUNDLE",
  "GIT_SSL_CAINFO",
  "AWS_CA_BUNDLE",
  "CARGO_HTTP_CAINFO",
  "BUNDLE_SSL_CA_CERT",
];
const REPLACING_WHEN_SET_ANY_CASE = ["npm_config_cafile"];

/**
 * The CA variables the step set to a file other than a store they would point
 * at or OWN_CA_DESTINATION. They stay as set, so a tool reading one does not
 * trust the proxy CA.
 */
export function presetCaVariables(
  files: CaTrustFiles,
  env: NodeJS.ProcessEnv,
  realpath: (path: string) => string,
): string[] {
  const stores = files.stores
    .filter((s) => CA_STORES[s.kind].variables)
    .map((s) => realpath(s.destination));
  const exact = [...POINT_AT_OWN_CA, ...POINT_AT_SYSTEM_STORE, ...REPLACING_WHEN_SET];
  return Object.keys(env).filter((name) => {
    const value = env[name];
    if (!value || value === OWN_CA_DESTINATION || stores.includes(realpath(value))) return false;
    return (
      exact.includes(name) ||
      REPLACING_WHEN_SET_ANY_CASE.some((v) => v.toLowerCase() === name.toLowerCase())
    );
  });
}

/** Refuse a write_through entry a CA mount would shadow. An ancestor stays allowed. */
export function assertWriteThroughClearOfCaTrust(
  files: CaTrustFiles,
  writeThroughPaths: string[],
): void {
  const covered = files.stores.map(({ kind, destination }) => ({
    reserve: CA_STORES[kind].reserve,
    destination,
  }));
  if (files.nssDb) {
    covered.push({ reserve: NSS_DB_RESERVATION, destination: files.nssDb.destination });
  }
  for (const path of writeThroughPaths) {
    for (const { reserve, destination } of covered) {
      if ("refuses" in reserve && reserve.refuses(path, destination)) {
        throw new WritablePathConflictError(
          `write_through entry ${JSON.stringify(path)} ${reserve.refusal(destination)}`,
        );
      }
    }
  }
}

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
      options: ["rbind", "ro", "nosuid", "nodev", "noexec"],
    },
  ];
  const extraEnv: Record<string, string> = {};
  for (const name of POINT_AT_OWN_CA) {
    if (!env[name]) extraEnv[name] = OWN_CA_DESTINATION;
  }

  for (const { kind, path, destination } of files.stores) {
    const { mountOptions, variables = [] } = CA_STORES[kind];
    mounts.push({ destination, type: "none", source: path, options: [...mountOptions] });
    for (const name of variables) {
      if (!env[name]) extraEnv[name] = destination;
    }
  }

  // Chromium reads no variable, only the NSS database in $HOME.
  if (files.nssDb) mounts.push(...nssDbMounts(files.nssDb));

  return { mounts, env: extraEnv };
}

import { execFileSync } from "node:child_process";
import { readFileSync, writeFileSync, existsSync, chmodSync } from "node:fs";
import { join } from "node:path";
import { buildDockerCpArgs } from "#core/lib/docker/args.ts";
import type { MountEntry } from "./types.ts";

/**
 * CA trust for the inspect engine, adapted for this sandbox's rootfs being
 * the live host `/` (via `mount --rbind /`), not a throwaway image layer.
 *
 * buildcage/docker's inspect engine has a runc wrapper (buildkit-runc)
 * write the CA into the BuildKit worker's own disposable rootfs layer, then
 * delete it again once the step's process exits, before the layer is
 * committed as a snapshot. That design leans on the rootfs being torn down
 * (or in BuildKit's case, diffed and discarded) after the step -- writing
 * the same way here would mean writing into the *real* host filesystem,
 * since this sandbox's rootfs is not a layer at all.
 *
 * Instead, the two files below are written into this run's own scratch
 * directory and mounted *over* the sandbox's own view of the relevant
 * paths (see caTrustAdditions / buildOciConfig) -- a mount-namespace-scoped
 * overlay, not a host write. Nothing needs to be undone afterward:
 * run-isolated.sh's `umount -R` (and the scratch dir's own cleanup) removes
 * both, along with the rest of the rootfs bind-mount, when the step ends.
 * The real host files these paths would otherwise resolve to are never
 * touched.
 */
export interface CaTrustFiles {
  /** A CA-only file, mounted at OWN_CA_DESTINATION -- for variables that add
   *  to a tool's built-in trust set (NODE_EXTRA_CA_CERTS, DENO_CERT). */
  ownCaPath: string;
  /** The runner's own system CA store with this CA appended, mounted at
   *  SYSTEM_CA_DESTINATION -- for variables that replace a tool's trust
   *  bundle outright (REQUESTS_CA_BUNDLE, PIP_CERT, SSL_CERT_FILE), and for
   *  every other tool (curl, ...) that already reads the system store by
   *  default. Undefined if the runner has no system store at any of the
   *  well-known candidate paths -- SYSTEM_CA_CANDIDATES[0] is the only one
   *  a GitHub-hosted (passwordless-sudo) Linux runner actually has; the
   *  rest are kept only as a defensive fallback.
   */
  systemCaPath: string | undefined;
}

const SYSTEM_CA_CANDIDATES = [
  "/etc/ssl/certs/ca-certificates.crt", // Debian/Ubuntu
  "/etc/pki/tls/certs/ca-bundle.crt", // RHEL/Fedora
  "/etc/ssl/ca-bundle.pem", // openSUSE
  "/etc/pki/tls/cacert.pem", // OpenELEC
  "/etc/ssl/cert.pem", // Alpine
];

/** Where the two files above are mounted inside the sandbox. */
export const OWN_CA_DESTINATION = "/etc/buildcage-ca.pem";
export const SYSTEM_CA_DESTINATION = SYSTEM_CA_CANDIDATES[0];

/**
 * Pull the proxy's own CA (generated once per container by
 * init-inspect-cfg) out of the inspect proxy image, the same way
 * extractRuncBootstrap pulls runc and gen-seccomp-profile: `docker cp`, run
 * once per `run:` step, into this run's own scratch dir.
 */
export function extractCaCert(containerName: string, destDir: string): string {
  const caCertPath = join(destDir, "proxy-ca.pem");
  execFileSync(
    "docker",
    buildDockerCpArgs({
      containerName,
      containerPath: "/opt/buildcage/ca.pem",
      hostPath: caCertPath,
    }),
  );
  chmodSync(caCertPath, 0o644);
  return caCertPath;
}

/**
 * Write the CA trust files a step's env vars will point at, into `dir`
 * (this run's own scratch directory). `caCertPath` is the proxy's own CA,
 * already `docker cp`'d onto the host -- see extractCaCert.
 */
export function writeCaTrustFiles(caCertPath: string, dir: string): CaTrustFiles {
  const ca = readFileSync(caCertPath, "utf8").trimEnd();

  const ownCaPath = join(dir, "buildcage-ca.pem");
  writeFileSync(ownCaPath, `${ca}\n`, { mode: 0o644 });

  const systemStoreSource = SYSTEM_CA_CANDIDATES.find((p) => existsSync(p));
  let systemCaPath: string | undefined;
  if (systemStoreSource) {
    const existing = readFileSync(systemStoreSource, "utf8").trimEnd();
    systemCaPath = join(dir, "system-ca-bundle.pem");
    writeFileSync(systemCaPath, `${existing}\n${ca}\n`, { mode: 0o644 });
  }

  return { ownCaPath, systemCaPath };
}

// Mirrors buildcage/docker's buildkit-runc CA-injection policy table (see
// docs/security.md): NODE_EXTRA_CA_CERTS/DENO_CERT add to a built-in trust
// set, so they're pointed at a CA-only file; REQUESTS_CA_BUNDLE/PIP_CERT/
// SSL_CERT_FILE replace a tool's bundle outright, so they're pointed at the
// (augmented) system store instead, never a CA-only file -- doing so would
// leave the tool trusting nothing else. CURL_CA_BUNDLE is left unset: curl
// already reads the system store by default.
//
// Only applied when a variable is unset. A step that already points one of
// these somewhere keeps doing so unmodified: safely appending to an
// arbitrary already-set path would need the same host-escape-safe symlink
// resolution buildkit-runc's castore.go does, which this port does not
// implement yet.
const POINT_AT_OWN_CA = ["NODE_EXTRA_CA_CERTS", "DENO_CERT"];
const POINT_AT_SYSTEM_STORE = ["REQUESTS_CA_BUNDLE", "PIP_CERT", "SSL_CERT_FILE"];

export interface CaTrustAdditions {
  mounts: MountEntry[];
  env: Record<string, string>;
}

/**
 * The extra mounts and env vars buildOciConfig should add on top of the
 * step's own, so the sandboxed process trusts the proxy's CA -- see the
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

  if (files.systemCaPath) {
    mounts.push({
      destination: SYSTEM_CA_DESTINATION,
      type: "none",
      source: files.systemCaPath,
      options: ["rbind", "ro"],
    });
    for (const name of POINT_AT_SYSTEM_STORE) {
      if (!env[name]) extraEnv[name] = SYSTEM_CA_DESTINATION;
    }
  }

  return { mounts, env: extraEnv };
}

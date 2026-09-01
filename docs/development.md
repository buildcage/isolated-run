# Development Guide

This document covers local development, testing, and the project structure of isolated-run.

## Contents

- [Local Usage](#local-usage)
- [Testing](#testing)
- [Local Development](#local-development)
- [Formatting & Linting](#formatting--linting)
- [Viewing Logs](#viewing-logs)
- [Makefile Commands](#makefile-commands)
- [Directory Structure](#directory-structure)
- [Action Internals](#action-internals)
- [Inspect Engine Internals](#inspect-engine-internals)
- [Troubleshooting](#troubleshooting)

## Local Usage

You can run isolated-run's proxy locally without GitHub Actions using Docker Compose and Make.

GitHub Actions inputs are lowercase (`proxy_mode`); the environment variables for local usage are
the uppercase form of the same names (`PROXY_MODE`).

### Sandbox Dev Loop (mac-friendly)

The action's own isolation mechanism (`run-isolated.sh`) uses Linux-only primitives (`ip netns`,
`nsenter`, `runc`) that can't run natively on macOS. `make setup_sandbox_dev` /
`make test_sandbox_dev` instead drive it from inside a container with `pid: host` (see
`dev/Dockerfile` and `docker/compose.sandbox-dev.yaml`), which can see the proxy container's
PID/netns via `/proc`. That is close enough to the real "runner host + separate proxy container"
arrangement for day-to-day iteration, though it can't validate the container-boundary parts of
production (see [Action Internals](#action-internals) below). `runc` and `gen-seccomp-profile` are
built directly into the dev-loop image (mirroring `docker/universal/Dockerfile`) rather than
`docker cp`-extracted from the proxy image at runtime, so the dev loop doesn't need the Docker
socket mounted in just to reach a sibling container; `dev/build-test-bundle.sh` stands in for
`lib/sandbox/oci-config.ts`'s `buildOciConfig` to build a minimal OCI bundle for the smoke test.
CI's `test_sandbox_*` e2e jobs run `run-isolated.sh` directly on the runner host instead, matching
production exactly. Treat those as the final word on whether a change actually works, not this dev
loop.

```bash
make setup_sandbox_dev  # start the proxy + dev-loop runner container
make test_sandbox_dev   # run a sample isolated command and verify allow/block + capability drop
```

## Testing

```bash
make test_unit_core      # core library unit tests (src/core)
make test_unit_sandbox   # action's own unit tests (src/lib, src/main.ts)
make test_unit_qjs       # dual-runs the acl module's tests under real QuickJS in a throwaway image
make test_unit           # all of the above
```

`make test_sandbox_dev` is the dev-loop end-to-end check described above; `make
test_integration_sandbox_linux` drives `dist/main.cjs` directly for checks that don't depend on
the real action wrapper (see `test/integration-test-*.sh`) and is what CI's `test_sandbox` job in
`test-integration.yml` runs. The CI-only `test_sandbox_*` end-to-end jobs (real runner host, no
nested container) are described in [Action Internals](#action-internals) below.

## Formatting & Linting

Formatting, linting, and type-aware linting are handled by [vp (Vite+)](https://viteplus.dev/),
installed globally on your machine like `pnpm`/`corepack` rather than through `pnpm exec`:

```bash
curl -fsSL https://vite.plus | bash   # macOS/Linux
# Windows: irm https://viteplus.dev/install.ps1 | iex
```

The project pins its own toolchain version via the `vite-plus` devDependency in `package.json`
(the same way `packageManager` pins `pnpm`) — the globally installed `vp` binary detects and
delegates to that pinned version automatically, so plain `vp ...` commands are reproducible
without going through `pnpm exec`.

```bash
vp check       # format + lint + type-aware lint (read-only; what CI runs)
vp check --fix # same, but auto-fixes format/lint issues in place
vp lint --fix
vp fmt --write
```

`vp run typecheck` (`tsc`) remains the authoritative full type check; `vp check`'s type-aware
linting (via `oxlint-tsgolint`) catches a subset of type-driven issues fast but doesn't replace it.

Running `vp install` (in place of `pnpm install`) automatically sets up a pre-commit hook — via
the `prepare` script — that formats and lints your staged files (`vite.config.ts`'s `staged`
config) before each commit, auto-fixing and re-staging what it can.

## Action Internals

This section walks through how the action isolates one `run:` command, in the order it actually
happens. For the user-facing behavior and threat model, see [Security Details](./security.md) and
the [README](../README.md).

1. Verify the proxy image's provenance and resolve a digest-pinned image ref (`src/main.ts`).
2. Start a dedicated, throwaway proxy container for this one step (`src/main.ts`).
   - The container provides network-layer isolation only (iptables `REDIRECT`/`DROP` rules,
     dnsmasq, HAProxy) — no build daemon.
   - Every `docker compose` invocation passes an explicit `-p <containerName>`, so concurrent
     `run:` steps in the same job (GitHub Actions' `background`/`wait`/`parallel` keywords) never
     share an implicit, directory-derived Compose project — otherwise one step's `up`/`down` could
     recreate or tear down another step's still-running container.
3. Extract `runc` and a seccomp-profile generator onto the runner host
   (`src/lib/sandbox/runc-bootstrap.ts`).
   - Both ship inside the proxy image and are pulled onto the host via `docker cp`, then run
     natively there — not `docker exec`'d — since the seccomp profile's content depends on the
     real host's kernel and architecture.
   - Extracted fresh into this step's own scratch directory on every invocation (no shared,
     cross-step/cross-job cache), so each `run:` step is fully independent and everything extracted
     is torn down with the scratch directory afterward.
4. Build an OCI runtime bundle (`config.json`) describing the sandbox
   (`src/lib/sandbox/oci-config.ts`).
   - Starts from `runc`'s own default spec, then patches in: a root filesystem pointing at a
     not-yet-created bind-mount directory, made read-only (every real host mount point is forced
     individually read-only outside workdir/home/tmp/RUNNER_TEMP/writable, since the top-level
     read-only flag alone doesn't cover separate mount points); a network namespace reference to the
     netns created in the next step; all Linux capabilities cleared plus no-new-privileges; the
     step's real environment; and a seccomp filter resolved from Docker's own default profile,
     applied against an empty capability set to match the sandbox.
   - The writable exceptions are recursive bind-mounts (so legitimately nested mounts under them
     stay visible). The `mount --rbind /` rootfs is therefore staged under `/var/tmp/buildcage-<uid>` —
     never one of the writable exceptions — so those recursive rbinds don't re-expose it as a
     second, _writable_ copy of the whole host `/` inside the sandbox. A `writable:` input naming
     that directory (or an ancestor of it) is rejected outright rather than silently accepted. The
     sandbox's real host view (its own `/` and every nested mount) is untouched and stays read-only
     outside the writable set.
5. Stage the sandbox's network and filesystem as root, via `sudo -n` (`run-isolated.sh`).
   - Re-execs itself into a fresh, private mount namespace before touching anything else, so the
     mount work below is invisible to every other `run:` step running concurrently on the same
     host.
   - Bind-mounts the host's own root filesystem onto a fresh directory to serve as the sandbox's
     rootfs (a plain `pivot_root` can't target the real root directly). Done before the network
     setup below, since it has no dependency on it and doing it first minimizes the gap between the
     mount-table snapshot the read-only patching above was computed from and this actually
     capturing the host's mount table.
   - Creates a network namespace and a veth pair, with one end moved into it (as `eth0`) and the
     other moved into the proxy container's own netns, renamed to `sandbox0`, and given the
     proxy's fixed gateway address directly — no bridge, since this is always a 1:1 connection
     (one sandbox, one proxy) and a plain named interface is enough for `init-iptables`'s
     `-i sandbox0` rule (added at container startup) to match once this device appears later.
6. Run the sandboxed command via `runc`.
   - runc creates its own further-nested namespaces per `config.json` and enforces every
     isolation guarantee declared there — capability drop, seccomp filter, read-only filesystem,
     network namespace.
   - A two-hop process-supervision chain ties the sandboxed process's life to the staging step
     above: the process that starts `runc` and, separately, the sandboxed command itself both
     die if their immediate parent does, so killing the staging step tears down the whole chain
     instead of leaving the sandboxed command running as an orphan.
7. Clean up once the command exits (`run-isolated.sh`).
   - An exit trap tears the container down, unmounts the rootfs bind-mount, removes the veth, and
     deletes the network namespace.
   - As a second layer of defense, anything still mounted under the run's own scratch directory
     is force-detached before that directory is deleted, in case the trap above didn't run to
     completion.
8. Append this step's report to the Job Summary and stop the proxy container (`src/main.ts`).
   - The report is built in-process on the runner: `src/lib/report.ts` reads the container's own
     communication log via `docker exec ... cat`, then the container is stopped.
   - If the whole process is killed before reaching this point, a fallback step reads the
     container's identity back from job state and stops it anyway, and reclaims the step's scratch
     directory — whose path it reconstructs deterministically from that same identity, then
     force-detaches any surviving mount before deleting (`src/post.ts`).

## Local Development

### Local testing of the action

Sigstore verification requires a real, published GHCR image, so the action normally can't run
against an unpublished branch or local changes. This repo's own CI (the `test_sandbox_*` jobs in
`.github/workflows/test-e2e.yml`) tests the real action end-to-end against a locally built image
instead, via a build-time-gated mechanism: `BUILDCAGE_BUILD_TEST_HOOKS=1 vp run build` compiles
`dist/main.cjs` where the `BUILDCAGE_LOCAL_IMAGE_REF` override is reachable. The override logic
lives in its own module (`src/core/lib/provenance/local-image-override.ts`), loaded only via a
dynamic `import()` gated by that build-time flag. Without the flag (i.e. every normal/committed
build), rolldown's own module-graph tree-shaking excludes that entire file from the bundle. It is
physically absent, not just unreachable. A CI check (`unit_test` job) additionally confirms a
normal build never contains a live runtime read of `BUILDCAGE_BUILD_TEST_HOOKS` in `dist/`,
guarding against a future refactor silently breaking that guarantee.

To exercise it locally:

1. Build the image: `docker compose build proxy`.
2. `BUILDCAGE_BUILD_TEST_HOOKS=1 vp run build`
3. Run it with `BUILDCAGE_LOCAL_IMAGE_REF=<image ref from step 1>` set (e.g. via `act`, or by
   invoking `node dist/main.cjs` directly with the relevant `INPUT_*` env vars; note the action's
   own isolation step still needs a real Linux host, so this only gets you past image verification,
   not a full local run on macOS). Never commit a `dist/main.cjs` built this way: run
   `vp run build` again (without the flag) before committing.

See [security.md](./security.md#verification-limitations) for more details.

## Formatting & Linting

Formatting, linting, and type-aware linting are handled by [vp (Vite+)](https://viteplus.dev/),
installed globally on your machine like `pnpm`/`corepack` rather than through `pnpm exec`:

```bash
curl -fsSL https://vite.plus | bash   # macOS/Linux
# Windows: irm https://viteplus.dev/install.ps1 | iex
```

The project pins its own toolchain version via the `vite-plus` devDependency in `package.json`
(the same way `packageManager` pins `pnpm`), and the globally installed `vp` binary detects and
delegates to that pinned version automatically, so plain `vp ...` commands are reproducible without
going through `pnpm exec`.

```bash
vp check       # format + lint + type-aware lint (read-only; what CI runs)
vp check --fix # same, but auto-fixes format/lint issues in place
vp lint --fix
vp fmt --write
```

`vp run typecheck` (`tsc`) remains the authoritative full type check; `vp check`'s type-aware
linting (via `oxlint-tsgolint`) catches a subset of type-driven issues fast but doesn't replace it.

Running `vp install` (in place of `pnpm install`) automatically sets up a pre-commit hook, via the
`prepare` script, that formats and lints your staged files (`vite.config.ts`'s `staged` config)
before each commit, auto-fixing and re-staging what it can.

## Viewing Logs

```bash
# Communication logs from the locally-built proxy
docker compose logs proxy

# Real-time log monitoring
docker compose logs -f proxy
```

**Log format (`universal`):**

```
[28/Feb/2026:10:15:30 +0000] buildcage [ALLOWED] "github.com:443" -
[28/Feb/2026:10:15:31 +0000] buildcage [BLOCKED] "malicious.com:443" not-allowed
[28/Feb/2026:10:15:32 +0000] buildcage [AUDIT] "npmjs.org:80" -
```

Fields: `[timestamp] buildcage [status] "domain:port" reason`

**`inspect` reads two logs instead**, since a name CoreDNS refused never reaches HAProxy at all:

```bash
docker compose exec proxy cat /var/log/haproxy/current
docker compose exec proxy cat /var/log/coredns/current
```

HAProxy's log carries one line per request, oldest first, with its method, full URL, status and
size. Refusals are interleaved with the rest:

```
✅ 00:00.512: GET https://registry.npmjs.org/express -> 200 (99.9KB)
🚫 00:01.048: DNS secret-data.attacker.example -> dns-not-allowed
🚫 00:01.390: POST https://registry.npmjs.org/express/-rev/1-abc -> not-allowed
✅ 00:02.115: TLS db.example.com:5432 -> (12.3KB)
```

Times are relative to when the proxy started. A refusal names its reason rather than a status: 403,
502 and 503 mean a rule, a name that would not resolve, and an origin that could not be reached or
verified.

Each log is an s6-log directory rather than a single file: `current` rotates into a timestamped
archive once it crosses 1MB, up to 100 archives kept. The report reads every archive, oldest first,
then `current`, so early traffic is never dropped just because a later part of the same run pushed
the log past a rotation. Reading `current` by hand, as above, only shows what has accumulated since
the most recent one.

## Makefile Commands

`make help` lists every target with its own description. The ones you type most:

| Command                                 | Description                                                        |
| --------------------------------------- | ------------------------------------------------------------------ |
| `make setup_sandbox_dev`                | Start the proxy and the mac-friendly dev-loop runner               |
| `make test_sandbox_dev`                 | Run a sample isolated command in the dev loop and verify isolation |
| `make clean_sandbox_dev`                | Stop and remove the dev-loop containers                            |
| `make test_unit`                        | Every unit test: core, the action's own, and the QuickJS run       |
| `make test_integration_sandbox_linux`   | The action's integration tests on a Linux host                     |
| `make test_integration_sandbox_inspect` | The same for the inspect engine, round trip included               |

The two integration targets need `BUILDCAGE_LOCAL_IMAGE_REF` and a test-hook build of
`dist/main.cjs`; see [Local Development](#local-development) above.

## Directory Structure

```text
.
├── action.yml                 # Action entry (node24 → dist/main.cjs, dist/post.cjs)
├── src/                       # Source (ESM)
│   ├── main.ts / post.ts      # Start proxy, run isolated command, report, stop
│   ├── lib/                   # Action-specific implementation: container, report, sudo-preflight,
│   │                          # sandbox/ (OCI config, runc bootstrap, netns/mountinfo helpers)
│   └── core/                  # Code shared with the isolated-run proxy image's QuickJS scripts
│       ├── lib/                # acl/ (rule parsing, dual-consumed by Node and QuickJS),
│       │                      # actions/, docker/, provenance/ (Sigstore, OCI registry lookups,
│       │                      # image ref resolution, local-image test-hook override), report/,
│       │                      # log/, test/test-shim.ts (portable node:test-alike shim used by
│       │                      # *.test.ts across Node and QuickJS alike)
│       └── scripts/            # QuickJS entry point (convert-rule.qjs.ts), run inside the built
│                              # image (rolldown-bundled into /opt/buildcage/scripts/ at image
│                              # build time; see rolldown.scripts.config.js). test/ is a qjs test
│                              # runner, types/ is the qjs:std/qjs:os ambient type declaration
├── dist/                      # Bundled output (rolldown → CommonJS); dist/qjs, dist/qjs-test are
│                              # gitignored build-time scratch output, not committed
├── docker/                    # Proxy image build contexts, one per proxy_engine
│   ├── universal/             # alpine + haproxy/dnsmasq/iptables/s6-overlay + pinned runc +
│   │                          # gen-seccomp-profile, plus their config and s6 service definitions
│   ├── inspect/               # alpine + haproxy/CoreDNS/s6-overlay, plus scripts/ (gen-configs
│   │                          # runs under QuickJS at container startup)
│   ├── gen-seccomp-profile/   # Go module: derives a seccomp filter from Docker's default profile
│   ├── compose.action.yaml    # Runtime compose file the action itself uses (verified,
│   │                          # digest-pinned image ref), distinct from the top-level compose.yaml
│   ├── compose.action.test-inspect.yaml  # Same, for the inspect-engine integration tests
│   └── compose.sandbox-dev.yaml  # Mac dev-loop overlay (see dev/)
├── scripts/run-isolated.sh    # netns/veth/rootfs-bind setup around `runc run`, invoked via
│                              # `sudo -n` (see Action Internals)
├── test/                      # assert-sandbox*.sh + integration-test-*.sh (capability/filesystem/
│                              # seccomp/die-with-parent checks driving dist/main.cjs directly)
├── dev/                       # Mac dev-loop-only Dockerfile + smoke-test.sh + build-test-bundle.sh
│                              # (see docker/compose.sandbox-dev.yaml), not used in production or CI
├── docs/                      # development.md, security.md, plus the reference.md/rules.md/
│                              # inspect-engine.md link stubs
├── compose.yaml               # Docker Compose config for local dev (builds docker/universal/Dockerfile;
│                              # also what CI's test_sandbox/test_sandbox_* jobs build from)
└── Makefile                   # Operational commands
```

## Action Internals

This section walks through how the action isolates one `run:` command, in the order it actually
happens. For the user-facing behavior and threat model, see [Security Details](./security.md) and
the [README](../README.md).

1. Verify the proxy image's provenance and resolve a digest-pinned image ref (`src/main.ts`).
2. Start a dedicated, throwaway proxy container for this one step (`src/main.ts`).
   - The container provides network-layer isolation only (iptables `REDIRECT`/`DROP` rules,
     dnsmasq, HAProxy), with no build daemon.
   - Every `docker compose` invocation passes an explicit `-p <containerName>`, so concurrent
     `run:` steps in the same job (GitHub Actions' `background`/`wait`/`parallel` keywords) never
     share an implicit, directory-derived Compose project; otherwise one step's `up`/`down` could
     recreate or tear down another step's still-running container.
3. Extract `runc` and a seccomp-profile generator onto the runner host
   (`src/lib/sandbox/runc-bootstrap.ts`).
   - Both ship inside the proxy image and are pulled onto the host via `docker cp`, then run
     natively there rather than `docker exec`'d, since the seccomp profile's content depends on
     the real host's kernel and architecture.
   - Extracted fresh into this step's own scratch directory on every invocation (no shared,
     cross-step/cross-job cache), so each `run:` step is fully independent and everything extracted
     is torn down with the scratch directory afterward.
4. Build an OCI runtime bundle (`config.json`) describing the sandbox
   (`src/lib/sandbox/oci-config.ts`).
   - Starts from `runc`'s own default spec, then patches in: a root filesystem pointing at a
     not-yet-created bind-mount directory, made read-only (every real host mount point is forced
     individually read-only outside workdir/home/tmp/RUNNER_TEMP/writable, since the top-level
     read-only flag alone doesn't cover separate mount points); a network namespace reference to the
     netns created in the next step; all Linux capabilities cleared plus no-new-privileges; the
     step's real environment; and a seccomp filter resolved from Docker's own default profile,
     applied against an empty capability set to match the sandbox.
   - The writable exceptions are recursive bind-mounts (so legitimately nested mounts under them
     stay visible). The `mount --rbind /` rootfs is therefore staged under `/var/tmp/buildcage`,
     never one of the writable exceptions, so those recursive rbinds don't re-expose it as a
     second, _writable_ copy of the whole host `/` inside the sandbox. A `writable:` input naming
     that directory (or an ancestor of it) is rejected outright rather than silently accepted. The
     sandbox's real host view (its own `/` and every nested mount) is untouched and stays read-only
     outside the writable set.
5. Stage the sandbox's network and filesystem as root, via `sudo -n` (`run-isolated.sh`).
   - Re-execs itself into a fresh, private mount namespace before touching anything else, so the
     mount work below is invisible to every other `run:` step running concurrently on the same
     host.
   - Bind-mounts the host's own root filesystem onto a fresh directory to serve as the sandbox's
     rootfs (a plain `pivot_root` can't target the real root directly). Done before the network
     setup below, since it has no dependency on it and doing it first minimizes the gap between the
     mount-table snapshot the read-only patching above was computed from and this actually
     capturing the host's mount table.
   - Creates a network namespace and a veth pair, with one end moved into it (as `eth0`) and the
     other moved into the proxy container's own netns, renamed to `sandbox0`, and given the
     proxy's fixed gateway address directly. There is no bridge, since this is always a 1:1
     connection (one sandbox, one proxy) and a plain named interface is enough for `init-iptables`'s
     `-i sandbox0` rule (added at container startup) to match once this device appears later.
6. Run the sandboxed command via `runc`.
   - runc creates its own further-nested namespaces per `config.json` and enforces every
     isolation guarantee declared there: capability drop, seccomp filter, read-only filesystem,
     network namespace.
   - A two-hop process-supervision chain ties the sandboxed process's life to the staging step
     above: the process that starts `runc` and, separately, the sandboxed command itself both
     die if their immediate parent does, so killing the staging step tears down the whole chain
     instead of leaving the sandboxed command running as an orphan.
7. Clean up once the command exits (`run-isolated.sh`).
   - An exit trap tears the container down, unmounts the rootfs bind-mount, removes the veth, and
     deletes the network namespace.
   - As a second layer of defense, anything still mounted under the run's own scratch directory
     is force-detached before that directory is deleted, in case the trap above didn't run to
     completion.
8. Append this step's report to the Job Summary and stop the proxy container (`src/main.ts`).
   - The report is built in-process on the runner: `src/lib/report.ts` reads the container's own
     communication log via `docker exec ... cat`, then the container is stopped.
   - If the whole process is killed before reaching this point, a fallback step reads the
     container's identity back from job state and stops it anyway, and reclaims the step's scratch
     directory, whose path it reconstructs deterministically from that same identity, then
     force-detaches any surviving mount before deleting (`src/post.ts`).

## Inspect Engine Internals

This section covers how `proxy_engine: inspect` is implemented internally. For the user-facing
behavior, see [Inspect Proxy Engine](./security.md#inspect-proxy-engine) in Security Details.

- `PROXY_ENGINE=inspect` selects `docker/inspect/Dockerfile` at build time (see `compose.yaml`'s
  `build.dockerfile: docker/${PROXY_ENGINE:-universal}/Dockerfile`), and the action's own runtime
  compose file for the engine is `docker/compose.action.yaml`, with
  `docker/compose.action.test-inspect.yaml` overlaying it for the integration tests.
- **HAProxy** is the single listener. `req.ssl_hello_type` tells a TLS handshake from a plain
  request by its first bytes, so one `bind` line handles both without the config declaring per-port
  whether it's plaintext or TLS. Two HAProxy features carry the rest of the enforcement:
  `normalize-uri` (an upstream directive still marked experimental, gated behind
  `expose-experimental-directives` in `src/core/lib/acl/haproxy-config.ts`) resolves `..` in the
  path before ACLs see it, and `do-resolve` + `set-dst` resolve the requested name and rewrite the
  connection's destination to it, run only after the ACL check for that request has already passed.
- **CoreDNS** answers every query with the proxy's own address, allowed or not, using an `expr`
  plugin view compiled from the same host patterns HAProxy's own ACLs use, so what's logged as
  `allowed` matches exactly what HAProxy would actually let through:

  ```
  # Allowlisted names are logged as allowed, but answered exactly like a denied
  # one below: this resolver never gets a request any closer to a real address.
  . {
      view allowlist {
        expr name() matches '^(abc[^.]*\.amazonaws\.com|registry\.npmjs\.org)\.$'
      }
      template IN A   { answer "{{ .Name }} 60 IN A <proxy-ip>" }
      template IN AAAA { }
      log . "buildcage dns allowed name={name}"
  }
  ```

- **The CA trust mount** is built by `src/lib/sandbox/` rather than written into the sandbox. The CA
  and, where the step has one, an augmented copy of the system CA store are written into this run's
  own scratch directory and mounted over the sandbox's view of those paths in its OCI
  `config.json`, so nothing is written to the runner and `run-isolated.sh`'s teardown removes them
  with the rest of the mount namespace. Which variables get set, and when, is in
  [CA trust and compatibility](../README.md#ca-trust-and-compatibility).
- The `allowed_url_rules` compiler enumerates hosts rather than generalizing them
  (`a.example.com`/`b.example.com` never becomes `*.example.com`), because CoreDNS's own allow/deny
  view is generated from the same host patterns. Widening a host widens what's logged as allowed
  DNS-side, not only what matches HTTP-side.
- `make test_integration_sandbox_inspect` (see [Testing](#testing) above) ends with
  `test/integration-test-inspect-roundtrip.sh`, which runs an audit step, feeds its own generated
  `allowed_url_rules` back as `restrict`, and checks both halves: every request the audit saw still
  passes, and a path, method, host, or port it never saw is refused.

## Troubleshooting

If you encounter issues, try reproducing the problem locally to get detailed logs:

1. **Check logs:**

   ```bash
   docker compose logs proxy
   ```

2. **Run in audit mode** to understand your command's network behavior:

   ```bash
   make setup_sandbox_dev
   # or drive the action directly, see README.md
   ```

3. **Open an issue** at [github.com/buildcage/isolated-run/issues](https://github.com/buildcage/isolated-run/issues) with:
   - The Job Summary report (audit or restrict mode)
   - The relevant `docker compose logs proxy` output
   - Your workflow YAML (with secrets redacted)

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
- [Troubleshooting](#troubleshooting)

## Local Usage

You can run isolated-run's proxy locally without GitHub Actions using Docker Compose and Make.

GitHub Actions inputs are lowercase (`proxy_mode`); the environment variables for local usage are
the uppercase form of the same names (`PROXY_MODE`).

### Sandbox Dev Loop (mac-friendly)

The action's own isolation mechanism (`run-isolated.sh`) uses Linux-only primitives (`ip netns`,
`nsenter`, `runc`) that can't run natively on macOS. `make setup_sandbox_dev` /
`make test_sandbox_dev` instead drive it from inside a container with `pid: host` and
`/var/run/docker/netns` mounted in (see `dev/Dockerfile` and `docker/compose.sandbox-dev.yaml`),
which is enough to reach the proxy container's `SandboxKey` netns the same way production does.
That is close enough to the real "runner host + separate proxy container"
arrangement for day-to-day iteration, though it can't validate the container-boundary parts of
production. `runc` and `gen-seccomp-profile` are
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

`EXTERNAL_RESOLVER` is the one variable here with no action input behind it: locally it takes a
comma-separated list of IPv4 addresses for HAProxy to resolve against in place of the container's own
`/etc/resolv.conf`. The integration tests set it to reach their own fixture resolver.

## Testing

```bash
make test_unit_core      # core library unit tests (src/core)
make test_unit_sandbox   # action's own unit tests (src/lib, src/main.ts)
make test_unit_qjs       # dual-runs the acl module's tests under real QuickJS in a throwaway image
make test_unit           # all of the above
make test_unit_coverage  # every Node test in one run, with a coverage report in coverage/
```

CI runs `make test_unit_coverage` and pastes `coverage/summary.txt` into the job summary. The
threshold is 100% on all four counters, so anything added without a test fails the run. Code that is
deliberately not tested carries a `/* v8 ignore */` comment saying why, which keeps that decision in
the source rather than buried in a percentage. Only two things qualify: code whose body lives
outside the process, and the default implementation behind a seam whose callers are already tested.
The QuickJS run is not measured separately, since it executes the same `.test.ts` files as the Node
run.

`make test_sandbox_dev` is the dev-loop end-to-end check described above; `make
test_integration_sandbox_linux` drives `dist/main.cjs` directly for checks that don't depend on
the real action wrapper (see `test/integration-test-*.sh`) and is what CI's `test_sandbox` job in
`test-integration.yml` runs. The ones that need the fixture origin live in
`test_integration_sandbox_universal` instead, whether they need it for what only a fixture can
cover or just to keep off the real internet. The CI-only `test_sandbox_*` end-to-end jobs run on a real
runner host with no nested container, and are the final word on whether a change works.

### Running the integration tests from several git worktrees

`test_integration_sandbox_universal` and `test_integration_sandbox_inspect` use the fixture origins
in `compose.test-*.yaml`, whose network name is global to the daemon, so two worktrees would
otherwise fight over it and over the fixtures' `10.200.0.x` addresses.

Nothing has to be configured. The Makefile takes the worktree's name from `git rev-parse
--git-dir`, suffixes the network name with it and derives the network's own subnet from it, and
exports both so the test scripts and the proxy the action starts agree. The main checkout gets the
unsuffixed name and the subnet CI uses.

The fixtures' addresses are not part of that. Each assigns its own `10.200.0.x` inside its own
network namespace instead of taking one from Compose IPAM (see each fixture's entrypoint, and
`test/test-net-addr` for the proxy's side of it), so the daemon never allocates `10.200.0.0/24` and
every worktree uses the same addresses. That is why the assertions name those addresses literally.

A fresh worktree needs `vp install` first: `node_modules` is per checkout, and these tests run
`dist/main.cjs` with the repo's own dependencies.

The rest of `test/integration-test-*.sh` clean up only the proxy containers they started
themselves, read back from their own `GITHUB_STATE` (`main.ts` writes the name there before
creating the container). A `buildcage-proxy-*` sweep would otherwise remove, or call a leak,
whatever another worktree has running. `integration-test-listener-scope.sh` is the one script with
fixed Compose and container names of its own, and those carry the suffix too.

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

`universal` also reads the resolver's log (`/var/log/coredns`), since a name CoreDNS refused never
reaches HAProxy at all: it is the only trace of a name looked up but never connected to.

**`inspect`'s proxy log is richer**, since it terminates TLS and sees each request whole; it reads the
same resolver log alongside it:

```bash
docker compose exec proxy cat /var/log/haproxy/current
docker compose exec proxy cat /var/log/coredns/current
```

HAProxy's log carries one line per request, oldest first, with its method, status, size, the `Host`
header it carried, and its request target last:

```
buildcage 1787471975123 https GET 200 708 ts=-- reason=- tlserr=- dst=104.16.1.34:443 sni=registry.npmjs.org host=registry.npmjs.org /express
buildcage 1787471976000 pass tls 3421 ts=-- reason=- dst=10.200.0.100:5432 sni=db.example.com
```

`host` and the target are two fields rather than one URL because a request target need not be a
path: `OPTIONS *` and a `CONNECT`'s authority are both legal, and both leave the target as `-`, so a
reader splitting a URL back apart would take the host for `registry.npmjs.org-`. A missing `Host`
prints as `-` too.

`ts` is HAProxy's termination state and `reason` the refusal reason where the rule that refused
knew one the line could not otherwise show. `tlserr` carries haproxy's own error from the handshake
with the origin, which is what tells a connection the proxy would not make from one it could not
make; the passthrough stage terminates no TLS and logs no such field. What the report makes of the two is in
[Requests that never arrived whole](./reference.md#requests-that-never-arrived-whole), for a
connection that never delivered a whole request, and in
[Connections that failed](./reference.md#connections-that-failed), for one the rules allowed that
then came to nothing.

Each log is an s6-log directory rather than a single file: `current` rotates into a timestamped
archive once it crosses 1MB, up to 100 archives kept, and a line is only ever split past 32KB. The
report reads every archive, oldest first, then `current`, so early traffic is never dropped just
because a later part of the same run pushed the log past a rotation. Reading `current` by hand, as
above, only shows what has accumulated since the most recent one.

HAProxy writes to s6-log through a pipe without blocking, so a line it cannot write at once is
dropped rather than delayed, and nothing in the log marks where. A thread that keeps finding another
mid-write on the pipe drops its line, so HAProxy runs one thread (`nbthread 1`). A stalled s6-log
can still fill the pipe, so `pipesz` widens it from 64KB to 1MB before HAProxy starts. HAProxy
counts the lines it drops itself: its `health` socket serves the Prometheus exporter, and the report
reads `haproxy_process_dropped_logs_total` from it. A nonzero count, or one the report cannot read,
marks the report incomplete. To read it by hand:

```bash
docker compose exec proxy curl -s --unix-socket /var/run/haproxy-health.sock \
  'http://localhost/metrics?scope=global' | grep dropped_logs
```

## Makefile Commands

`make help` lists every target with its own description. The ones you type most:

| Command                                   | Description                                                        |
| ----------------------------------------- | ------------------------------------------------------------------ |
| `make setup_sandbox_dev`                  | Start the proxy and the mac-friendly dev-loop runner               |
| `make test_sandbox_dev`                   | Run a sample isolated command in the dev loop and verify isolation |
| `make clean_sandbox_dev`                  | Stop and remove the dev-loop containers                            |
| `make test_unit`                          | Every unit test: core, the action's own, and the QuickJS run       |
| `make test_unit_coverage`                 | Every Node unit test in one run, with a coverage report            |
| `make test_integration`                   | Every integration test CI runs, as the four groups below           |
| `make test_integration_sandbox_linux`     | The action's integration tests on a Linux host                     |
| `make test_integration_sandbox_universal` | The ones that need the universal engine's fixture origin           |
| `make test_integration_sandbox_inspect`   | The same for the inspect engine, round trip included               |
| `make test_integration_listener_scope`    | `:10024`/`:53` stay unreachable outside `buildcage0`, both engines |

The first three integration groups need `BUILDCAGE_LOCAL_IMAGE_REF` and a test-hook build of
`dist/main.cjs`; see [Local Development](#local-development) above. They do not all want the same
image: the inspect group needs one built from `docker/inspect`, and `test_integration_listener_scope`
builds both images itself and wants the variable unset. So `make test_integration` records what CI
runs rather than running it in one go; build the image a group needs, then run that group.

## Directory Structure

```text
.
├── action.yml                 # Action entry (node24 → dist/main.cjs, dist/post.cjs)
├── src/                       # Source (ESM)
│   ├── main.ts / post.ts      # Start proxy, run isolated command, report, stop
│   ├── lib/                   # Action-specific implementation: container, report, sudo-preflight,
│   │                          # sandbox/ (OCI config, runc bootstrap, netns/mountinfo helpers)
│   └── core/                  # Code shared with the proxy image's QuickJS scripts
│       ├── lib/               # acl/ (rule parsing and the proxy config generators) is built for
│       │                      # both runtimes, and so is anything it imports — errors.ts today.
│       │                      # actions/, docker/, provenance/, report/ and log/ are Node-only,
│       │                      # and test/test-shim.ts is the node:test-alike shim *.test.ts uses
│       │                      # under either runtime
│       └── scripts/           # QuickJS entry points, rolldown-bundled into
│                              # /opt/buildcage/scripts/ at image build time
├── dist/                      # Bundled output (rolldown → CommonJS), committed. dist/qjs and
│                              # dist/qjs-test are gitignored scratch
├── docker/                    # Proxy image build contexts, one per proxy_engine
│   ├── universal/             # alpine + haproxy/CoreDNS/iptables/s6-overlay + pinned runc +
│   │                          # gen-seccomp-profile, with their config and s6 service definitions
│   ├── inspect/               # alpine + haproxy/CoreDNS/s6-overlay, plus scripts/ (gen-configs
│   │                          # runs under QuickJS at container startup)
│   ├── gen-seccomp-profile/   # Go module: derives a seccomp filter from Docker's default profile
│   ├── compose.action.yaml    # Runtime compose file the action uses (verified, digest-pinned
│   │                          # image ref), distinct from the top-level compose.yaml below
│   ├── compose.action.test-inspect.yaml  # Same, for the inspect-engine integration tests
│   └── compose.sandbox-dev.yaml          # Mac dev-loop overlay (see dev/)
├── scripts/run-isolated.sh    # netns/veth/rootfs-bind setup around `runc run`, via `sudo -n`
├── test/                      # assert-sandbox*.sh + integration-test-*.sh driving dist/main.cjs,
│                              # and *-scenarios.sh run inside the sandbox as a step's own `run:`.
│                              # helpers.sh carries what both halves share
├── dev/                       # Mac dev-loop-only image and scripts, not used in production or CI
├── docs/                      # development.md, security.md, plus the reference.md/rules.md/
│                              # inspect-engine.md link stubs
├── licenses/                  # gen-license-file.mjs, which regenerates THIRD_PARTY_LICENSES_NPM
│                              # during `vp run build`, and what .glf.jsonc substitutes in
├── compose.yaml               # Local-dev compose config (builds docker/universal/Dockerfile;
│                              # also what CI's test_sandbox/test_sandbox_* jobs build from)
└── Makefile                   # Operational commands
```

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

3. **The step fails with "never became ready"**: the proxy came up but one of its services never
   answered its own readiness check. The step prints the container log; locally:

   ```bash
   docker inspect --format '{{json .State.Health}}' buildcage-proxy
   ```

4. **Open an issue** at [github.com/buildcage/isolated-run/issues](https://github.com/buildcage/isolated-run/issues) with:
   - The Job Summary report (audit or restrict mode)
   - The relevant `docker compose logs proxy` output
   - Your workflow YAML (with secrets redacted)

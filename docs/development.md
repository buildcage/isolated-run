# Development Guide

This page is for working on isolated-run itself: setting up, finding your way around the
repository, running and testing it locally, and what to keep in mind when changing it. What the
action does is in the [README](../README.md), the [Reference](./reference.md) and the
[Security Details](./security.md).

## Contents

- [Getting set up](#getting-set-up)
- [Repository layout](#repository-layout)
- [Running it locally](#running-it-locally)
- [Testing](#testing)
- [Rules when changing code](#rules-when-changing-code)
- [Debugging](#debugging)

## Getting set up

The toolchain is [vp (Vite+)](https://viteplus.dev/), installed globally:

```bash
curl -fsSL https://vite.plus | bash   # macOS/Linux
# Windows: irm https://viteplus.dev/install.ps1 | iex
```

`vp` delegates to the version the `vite-plus` devDependency in `package.json` pins, so plain
`vp …` commands are reproducible. Run `vp install`, not `pnpm install`, in each checkout: it
installs `node_modules` and sets up a pre-commit hook that formats and lints the staged files
(`vite.config.ts`'s `staged` config), fixing and re-staging what it can. The proxy, the QuickJS
unit tests and the integration tests also need Docker, and the sandbox itself needs Linux; on
macOS, use the [dev loop](#the-sandbox-dev-loop).

```bash
vp check          # format, lint and type-aware lint, read-only (what CI runs)
vp check --fix    # the same, fixing what it can
vp run typecheck  # tsc, the authoritative type check
vp run build      # rolldown → the committed dist/ bundles
```

`vp check`'s type-aware lint catches a subset of type errors quickly but does not replace
`vp run typecheck`. Build with `vp run build`, never `vp build`.

## Repository layout

```text
.
├── action.yml               # Action entry (node24 → dist/main.cjs, dist/post.cjs)
├── src/                     # Source (ESM)
│   ├── main.ts / post.ts    # Start the proxy, run the isolated command, report, stop
│   ├── lib/                 # The action's own modules; sandbox/ builds the OCI bundle and mounts,
│   │                        # filesystem-audit/ turns the tracer's recording into the summary
│   ├── proxy/               # The AWS access key check, built for both runtimes
│   └── core/
│       ├── lib/             # acl/ and its imports also run under QuickJS; the rest is Node-only
│       └── scripts/         # QuickJS only: the config generators, the test runner, qjs's types
├── dist/                    # Bundled output (rolldown → CommonJS), committed
├── docker/
│   ├── common/              # Image files every engine shares: s6 services, init-iptables
│   ├── universal/           # proxy_engine: universal
│   ├── inspect/             # proxy_engine: inspect
│   ├── gen-seccomp-profile/ # Go: derives the seccomp filter from Docker's default profile
│   ├── filesystem-audit/    # Go and eBPF: the filesystem audit tracer
│   ├── compose.*.yaml       # The action's compose file, and the overlays its tests and dev loop add
│   └── *-licenses.sh        # License collection and checks run at image build time
├── scripts/
│   ├── run-isolated.sh      # netns, veth and rootfs setup around `runc run`, via `sudo -n`
│   └── buildcage-init.sh    # The sandbox's PID 1
├── test/                    # integration-test-*.sh drivers, assert-*.sh/.mjs, *-scenarios.sh
│   └── scenarios/           # Each engine's restrict-mode cases, in POSIX sh
├── dev/                     # The macOS dev-loop image and scripts, and the fixture refresh
├── compose.yaml             # The action's compose file plus a build from source; CI builds through it
├── compose.test-*.yaml      # Fixture origins for the integration tests
├── licenses/                # License texts copied into the images, and the npm license generator
├── docs/
└── Makefile
```

Each engine's config generator is `src/core/scripts/gen-configs-<engine>.qjs.ts`, except that the
`inspect` image takes `src/proxy/scripts/gen-configs-inspect.qjs.ts`, which adds the AWS access key
check to core's. Each runs under QuickJS when the proxy container starts and writes haproxy.cfg and
the Corefile from the rules, through the generators in `src/core/lib/acl/` (`haproxy-config.ts`
for `inspect`, `haproxy-universal-config.ts` for `universal`). The AWS access key check's rules are
built in `src/proxy/haproxy-aws-keys.ts`, from the hosts and parameter names in
`src/proxy/aws-hosts.ts`.

Each engine's image also carries runc, `gen-seccomp-profile` and `filesystem-audit`. The action
copies them out of the image onto the runner host at startup and runs them there, outside the
container: runc runs the isolated command, `gen-seccomp-profile` writes the seccomp filter for the
running kernel, and `filesystem-audit` is the tracer.

## Running it locally

Action inputs become uppercase environment variables locally (`proxy_mode` is `PROXY_MODE`).

### The sandbox dev loop

The isolation (`scripts/run-isolated.sh`) uses Linux-only primitives (`ip netns`, `nsenter`,
`runc`). `make setup_sandbox_dev` and `make test_sandbox_dev` drive it from inside a container
with `pid: host` and `/var/run/docker/netns` mounted in (`dev/Dockerfile`,
`docker/compose.sandbox-dev.yaml`), which reaches the proxy container's network namespace the way
the action does:

```bash
make setup_sandbox_dev   # start the proxy and the dev-loop container
make test_sandbox_dev    # run a sample command and check allow, block and the capability drop
make clean_sandbox_dev   # stop and remove both
PROXY_MODE=audit make setup_sandbox_dev
```

The dev-loop image has `runc`, `gen-seccomp-profile` and `filesystem-audit` built in rather than
extracted from the proxy image, and `dev/build-test-bundle.sh` stands in for `buildOciConfig` in
`src/lib/sandbox/oci-config.ts`. It cannot check what depends on the real runner host, so CI's
`test_sandbox_*` jobs, which run `run-isolated.sh` on the runner itself, are the final word on
whether a change works.

### The action against an unpublished image

Sigstore verification needs a real, published GHCR image, so the action cannot normally run
against local changes. A test-hook build lets it: `BUILDCAGE_BUILD_TEST_HOOKS=1 vp run build`
produces a `dist/main.cjs` that honors `BUILDCAGE_LOCAL_IMAGE_REF`. CI's `test_sandbox_*` jobs in
`.github/workflows/test-e2e.yml` run the real action this way.

1. Build the image: `docker compose build proxy`.
2. `BUILDCAGE_BUILD_TEST_HOOKS=1 vp run build`
3. Run it with `BUILDCAGE_LOCAL_IMAGE_REF=<image ref from step 1>` set, through `act` or by
   invoking `node dist/main.cjs` with the relevant `INPUT_*` variables. On macOS this gets only as
   far as image verification, since the isolation itself needs Linux.

Run `vp run build` again, without the flag, before committing; see
[Rules when changing code](#rules-when-changing-code).

## Testing

`make help` lists every target with its own description.

### Unit tests and coverage

```bash
make test_unit               # core, the action's own, and the QuickJS run
make test_unit_coverage      # every Node unit test in one run, with a report in coverage/
vp test run src/core/lib/acl # the Node tests whose path contains the argument
```

The threshold is 100% on all four counters, so anything added without a test fails CI, which
pastes `coverage/summary.txt` into the job summary. Code that is deliberately not tested carries a
`/* v8 ignore */` comment saying why, which keeps that decision in the source rather than buried in
a percentage. Only two things qualify: code whose body lives outside the process, and the default
implementation behind a seam whose callers are already tested. The QuickJS run
(`make test_unit_qjs`) is not measured separately, since it executes the same `.test.ts` files as
the Node run.

### Integration tests

| Command                                          | What it runs                                                               |
| ------------------------------------------------ | -------------------------------------------------------------------------- |
| `make test_integration`                          | Every integration test CI runs, as the four groups below                   |
| `make test_integration_sandbox_linux`            | The action's integration tests on a Linux host                             |
| `make test_integration_sandbox_linux_filesystem` | Its first half: filesystem modes, `write_through:`, scratch, mounts        |
| `make test_integration_sandbox_linux_runtime`    | Its second half: defaults, processes, signals, the proxy's lifecycle       |
| `make test_integration_sandbox_linux_signals`    | The second half's cancel tests alone, which CI runs on 22.04 too           |
| `make test_integration_sandbox_universal`        | The ones that need the universal engine's fixture origin                   |
| `make test_integration_sandbox_inspect`          | The same for the inspect engine, round trip included                       |
| `make test_integration_sandbox_inspect_rules`    | Its first half: restrict, audit, round trip and the AWS key check          |
| `make test_integration_sandbox_inspect_ca`       | Its second half: Chromium's NSS database and the CA mount's reserved paths |
| `make test_integration_listener_scope`           | `:10024`/`:53` stay unreachable outside `buildcage0`, every engine         |
| `make test_integration_haproxy_configs`          | Every HAProxy config the generators write loads in its engine's image      |

They drive `dist/main.cjs` directly (`test/integration-test-*.sh`). The first three groups need
`BUILDCAGE_LOCAL_IMAGE_REF` and a [test-hook build](#the-action-against-an-unpublished-image).
They do not all want the same image: the inspect group needs one built from `docker/inspect`. The
last two take a universal and an inspect image at once, in `BUILDCAGE_LOCAL_IMAGE_REF_UNIVERSAL` and
`BUILDCAGE_LOCAL_IMAGE_REF_INSPECT`; the listener check's inspect image is built without test hooks,
as it ships. So `make test_integration` records what CI runs rather than
running it in one go; build the images a group needs, then run that group. CI also checks that every
`test/integration-test-*.sh` is run by a target.

The fixture groups start the proxy with `docker/compose.action.test-<engine>.yaml` layered on the
shipped `docker/compose.action.yaml` (`BUILDCAGE_TEST_COMPOSE_OVERLAY`), so they run what ships
plus the fixture network and nothing in place of it. The config check loads every golden config
(`src/**/__fixtures__/*.cfg`), and one the image's own
generator writes from a large rule set, with `haproxy -c`. CoreDNS has no way to check a Corefile
without serving it, so the Corefile is not checked.

A test that needs a fixture origin, whether for what only a fixture can cover or just to keep off
the real internet, goes in `test_integration_sandbox_universal` or
`test_integration_sandbox_inspect`. The CI-only `test_sandbox_*` end-to-end jobs run on a real
runner host with no nested container.

### Several worktrees at once

`test_integration_sandbox_universal` and `test_integration_sandbox_inspect` use the fixture origins
in `compose.test-*.yaml`, whose network name is global to the daemon. The Makefile takes the
worktree's name from `git rev-parse --git-dir`, suffixes the network name with it and derives the
network's subnet from it, and exports both so the test scripts and the proxy the action starts
agree. The main checkout gets the unsuffixed name and the subnet CI uses.

The fixtures' addresses need no suffix. Each fixture assigns its own `10.200.0.x` inside its own
network namespace (see each fixture's entrypoint, and `test/test-net-addr` for the proxy's side),
so every worktree uses the same addresses, and the assertions name them literally.

Each `test/integration-test-*.sh` script cleans up only the proxy containers it started, read back
from its own `GITHUB_STATE`, so it never removes, or calls a leak, what another worktree has
running. `integration-test-listener-scope.sh` is the one script with fixed Compose and container
names of its own, and those carry the suffix too. A fresh worktree needs `vp install` first, since
these tests run `dist/main.cjs` with the repo's own dependencies.

### The filesystem audit tracer

The tracer's Go tests run while the proxy image is built, so every job that builds it runs them.
GitHub-hosted runners' kernels never preempt the tracer's programs mid-run, so no job there can
catch two of them sharing a buffer. After changing the BPF program, run "Test / Filesystem audit
under preemption" by hand: it boots Ubuntu's 7.0 and 6.8 `generic` kernels in a VM, lets three
processes on one CPU make changes under names of their own, and fails on a record mixing two of
them (`test/filesystem-audit-preemption/`).

`docker/filesystem-audit/testdata/contract.jsonl` holds a line of each form the tracer writes, made
by running a sample of each through its decoder and recorder. Its Go tests fail when the file no
longer matches, and the summary's tests read it to check that every field and kind is handled.
After changing what the tracer writes, rewrite it. The Go tests need `go generate` first, which
compiles the BPF program with clang and libbpf's headers, so run both in the image's build stage:

```bash
docker run --rm -v "$PWD/docker/filesystem-audit:/src" -w /src golang:1.27-alpine sh -c \
  'apk add -q clang llvm libbpf-dev linux-headers && go generate ./... &&
   go test -run TestRecordingContractIsUpToDate -update .'
```

The golden test renders a real recording from the `test_sandbox_filesystem_audit` e2e job, kept in
`src/lib/__fixtures__/filesystem-audit/`. When the tracer's output changes, take a new one from a
passing run of that job:

```bash
dev/update-filesystem-audit-fixture.sh <run id of "Test / E2E">
```

It pulls the raw recording out of the run's log, normalizes the runner's uid in the scratch base to
0, and regenerates the stripped recording and the summary through the golden test. Read the diff
before committing: it is the change in what the audit records and shows.

## Rules when changing code

- **`dist/` is committed.** After changing anything under `src/`, run `vp run build` and commit
  the bundles with the change; CI's "Check dist is up to date" step rebuilds and compares them.
  The bundles are never formatted or linted.
- **A test-hook build never ships.** The `BUILDCAGE_LOCAL_IMAGE_REF` override lives in
  `src/core/lib/provenance/local-image-override.ts`, reached only through a dynamic `import()`
  gated by `BUILDCAGE_BUILD_TEST_HOOKS` at build time, so a normal build tree-shakes it out. CI and
  the pre-commit hook fail a `dist/` that names `BUILDCAGE_BUILD_TEST_HOOKS`,
  `BUILDCAGE_LOCAL_IMAGE_REF`, or any `BUILDCAGE_TEST_*` or `BUILDCAGE_RUN_DEBUG_*` name. A new
  test hook goes behind the same gate.
- **`acl/` runs under QuickJS too.** `src/core/lib/acl/`, everything it imports,
  `src/core/lib/test/`, `src/core/scripts/` and `src/proxy/` also run inside the image under
  QuickJS (`tsconfig.qjs.json`), so they cannot use Node's APIs. `make test_unit_qjs` runs the
  tests under `src/core/lib/acl/` and `src/proxy/` there.
- **An engine keeps only what differs.** Each Dockerfile copies `docker/common/files/` first and
  the engine's own `files/` on top. A path in both would be settled silently by copy order, so
  `src/core/lib/docker/engine-files.test.ts` rejects one.
- **Pinned downloads move together.** runc and CoreDNS are downloaded at a pinned version and
  checked against one SHA256 per architecture, set as `ARG`s in each engine's Dockerfile (runc also
  in `dev/Dockerfile`). Renovate updates the version and the SHA256 lines together, taking the
  digests from the release's own checksum files; the `digestVersion` in the comment above each
  SHA256 line tells it which release that digest belongs to. A bump by hand changes all of them.

## Debugging

### Logs

```bash
docker compose logs proxy    # the proxy's output; -f to follow
docker compose exec proxy cat /var/log/haproxy/current
docker compose exec proxy cat /var/log/coredns/current
```

The proxy's line formats are the `log-format` lines the generators in `src/core/lib/acl/` write,
and `src/core/lib/log/` parses them back. A line from each engine looks like this:

```
buildcage 1787471970500 [ALLOWED] (HTTPS) "github.com:443" - 1024
buildcage 1787471975123 https GET 200 708 ts=-- reason=- tlserr=- dst=104.16.1.34:443 fcerr=- sni=registry.npmjs.org host=registry.npmjs.org /express
```

Each log is an s6-log directory: `current` rotates into a timestamped archive at 1MB, up to 100
archives kept. The report reads every archive, so `current` alone shows only what came after the
last rotation.

HAProxy drops a log line it cannot write at once rather than wait, and counts the lines it drops;
the report reads that count and marks itself incomplete when it is not zero. To read it by hand:

```bash
docker compose exec proxy curl -s --unix-socket /var/run/haproxy-health.sock \
  'http://localhost/metrics?scope=global' | grep dropped_logs
```

### The step fails with "never became ready"

The proxy came up but one of its services never answered its own readiness check. The step prints
the container log; locally:

```bash
docker inspect --format '{{json .State.Health}}' buildcage-proxy
```

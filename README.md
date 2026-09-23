# Buildcage for `run:` Steps

![Buildcage](./assets/banner.png)

[![GitHub](https://img.shields.io/badge/GitHub-buildcage%2Fisolated--run-blue?logo=github)](https://github.com/buildcage/isolated-run)
[![Marketplace](https://img.shields.io/badge/marketplace-Buildcage%20for%20run%20steps-blue?logo=github)](https://github.com/marketplace/actions/buildcage-for-run-steps)
![build](https://img.shields.io/github/actions/workflow/status/buildcage/isolated-run/docker-publish.yml)
![test](https://img.shields.io/github/actions/workflow/status/buildcage/isolated-run/test-e2e.yml?label=test)
![license](https://img.shields.io/github/license/buildcage/isolated-run)

A workflow `run:` step, and every tool and dependency it invokes, can connect anywhere on the
network. Buildcage runs the command behind an allowlist: it reaches only the destinations you name,
and anything else is refused and reported.

- The command doesn't change: no proxy to configure, no certificate to install, and it runs as the
  same user with the same `$HOME` as the rest of the job, so credentials, caches and toolchains set
  up by earlier steps keep working.
- Run once in [`audit`](#operation-modes) mode and the report writes the allowlist for you, ready to
  paste back into the step.
- A rule can name an HTTP method and a URL, inside TLS as well, so a step can fetch a package from a
  registry without being able to publish one to it.
- It all runs inside your GitHub Actions job, with no agent and no external service.

See [buildcage.github.io](https://buildcage.github.io/) for what it does and why. To isolate a
Docker build's `RUN` steps rather than a workflow step, use
[Buildcage for Docker](https://github.com/buildcage/docker).

## Contents

- [Requirements](#requirements)
- [Usage](#usage)
- [Engines](#engines)
- [Inputs](#inputs)
- [The report](#the-report)
- [How `run` is executed](#how-run-is-executed)
- [Passing values to `run`](#passing-values-to-run)
- [Filesystem access](#filesystem-access)
- [How it works](#how-it-works)
- [CA trust and compatibility](#ca-trust-and-compatibility)
- [Scope](#scope)
- [Limitations](#limitations)
- [FAQ](#faq)
- [GitHub's native egress firewall](#githubs-native-egress-firewall)
- [Documentation](#documentation)

## Requirements

This action sets up its isolation directly on the runner host (via `sudo -n`), so it needs a Linux
runner with passwordless `sudo` and a working Docker installation:

- **GitHub-hosted**
  - `ubuntu-latest`, the versioned `ubuntu-*` images, and their `-arm` variants
  - Lightweight images such as `ubuntu-slim` are not supported: they ship a Docker client with no
    daemon
- **Self-hosted**
  - Docker Engine 25.0 or later, with Compose v2.20.2 or later
  - A sudoers policy that lets `sudo` pick the user and group to run as. One naming a single user
    can't create a missing `write_through:` path; see
    [`write_through` paths](./docs/reference.md#write_through-paths)
  - A non-root runner user. The sandbox keeps the runner's own uid, and as uid 0 it refuses to start:
    filesystem permissions alone can't separate the command from root-owned host sockets. Don't run
    the runner with `RUNNER_ALLOW_RUNASROOT`, and note a root `container:` job runs as uid 0 too.

A runner that falls short fails while the proxy starts, before the command runs.

## Usage

Wrap the command you want to isolate with this action instead of a plain `run:` step. Run once in
[`audit`](#operation-modes) mode to collect what the command reaches, then switch to `restrict`. The
examples below use the default `inspect` engine; [Engines](#engines) covers the choice between the two.

### 1. Find out what the command reaches

```yaml
- name: Discover what the command reaches
  uses: buildcage/isolated-run@430838ca8673c47824189ad3fef38808f0fadaf1 # v1.2.2
  with:
    proxy_mode: audit # Log every destination, block nothing
    run: |
      npm ci
      npm test
```

The step writes every destination the command contacted to the Job Summary:

<img src="assets/report-inspect-audit-mode.png" alt="Outbound Traffic Report (audit mode)" width="568">

Its **Switch to restrict mode** section holds the allowlist, already written out from what the
command actually did. A request whose method, host or path a rule would read as a wildcard is listed
under it rather than written in, since copying it would permit more than was sent.

### 2. Enforce the allowlist

Paste that allowlist into the step and switch the mode:

```yaml
- name: Run tests with outbound network isolation
  uses: buildcage/isolated-run@430838ca8673c47824189ad3fef38808f0fadaf1 # v1.2.2
  with:
    proxy_mode: restrict
    allowed_url_rules: |
      GET https://registry.npmjs.org/**
      POST https://registry.npmjs.org/-/npm/v1/security/advisories/bulk
    run: |
      npm ci
      npm test
```

Each rule names the methods it permits, so these let npm install packages without letting it publish
any: `npm publish` is a `PUT` to the same host, which no rule here covers.

<img src="assets/report-inspect-restrict-mode.png" alt="Outbound Traffic Report (restrict mode)" width="568">

A blocked connection fails the step, so a command that starts reaching somewhere new doesn't pass
unnoticed.

### Example workflows

Each pair runs the same command with and without rules:
`inspect` on an npm and pip install ([audit](.github/workflows/example-inspect-audit.yml) ·
[restrict](.github/workflows/example-inspect-restrict.yml)), `universal` on a Maven build
([audit](.github/workflows/example-universal-audit.yml) ·
[restrict](.github/workflows/example-universal-restrict.yml)).

A separate
[ephemeral filesystem example](.github/workflows/example-ephemeral-filesystem.yml) shows which
writes survive a `filesystem_mode: ephemeral` step and which the overlay discards.

## Engines

`proxy_engine` selects how closely the command's traffic is examined.

|                                               | `inspect`<br>terminates TLS, checks method and URL         | `universal`<br>reads the SNI only, checks host and port |
| --------------------------------------------- | ---------------------------------------------------------- | ------------------------------------------------------- |
| A rule can say                                | `GET\|HEAD https://registry.npmjs.org/**`                  | `registry.npmjs.org:443`                                |
| Allow a fetch, refuse a publish, same host    | ✅                                                         | -                                                       |
| The report shows                              | Every request with its URL                                 | Host and port                                           |
| The command's TLS                             | Terminated and re-signed with a CA generated for that step | Untouched                                               |
| Certificate pinning, or a bundled trust store | -                                                          | ✅                                                      |

Start with `inspect`, and fall back to `universal` when something the command runs won't accept the
mounted CA. `inspect` is the default value of `proxy_engine`, so `universal` has to be set
explicitly.

Both intercept at the network level, so a tool that ignores `HTTP_PROXY` is covered either way, and
both use the same sandbox and the same network boundary.

## Inputs

`run` is the only required input, and the ones below are the rules you write by hand. The full list,
with defaults and the engines each input applies to, is in
[Reference](./docs/reference.md#action-inputs), and the grammar those rules are written in is in
[Rule syntax](./docs/reference.md#rule-syntax).

Use `label` to tell several steps' report sections apart when the action appears more than once in a
job.

### Operation modes

`proxy_mode: audit` logs every destination the command reaches and blocks nothing. `restrict`, the
default, allows only what the rules match and blocks and logs everything else. Start with `audit`
when you first adopt Buildcage or when a dependency changes, and keep `restrict` for everyday runs.

If you forget a domain the command needs, `restrict` blocks it and the step fails with the
destination named, which is why it is worth running `audit` first.

### Rules for the `inspect` engine

`allowed_url_rules` is the one to reach for. Each line is a method list, a space, and a URL pattern.
`*` stays inside one domain label or path segment, `**` crosses dots and slashes, and a rule with no
path allows any path on that host:

```yaml
allowed_url_rules: |
  # npm: fetch packages, and the audit endpoint it posts to
  GET https://registry.npmjs.org/**
  POST https://registry.npmjs.org/-/npm/v1/security/advisories/bulk

  # pip: one registry, two domains
  GET https://pypi.org/simple/**
  GET https://files.pythonhosted.org/packages/**

  # a private registry is an ordinary host
  GET|HEAD https://registry.internal.example.com:8443/**
```

`allowed_tls_rules` passes a TLS destination through undecrypted, judged on its SNI and port. It is
for TLS that isn't HTTPS, and for the hosts an `inspect` step must not decrypt:

```yaml
allowed_tls_rules: |
  db.example.com:5432
  repo.maven.apache.org:443
```

`allowed_ip_rules` covers connections made straight to an address, which never go through DNS. Under
`inspect` a rule may be an address or a CIDR block:

```yaml
allowed_ip_rules: |
  192.168.1.10:443
  10.0.0.0/8:443
```

### Rules for the `universal` engine

`universal` never decrypts, so rules name a host and a port. `allowed_https_rules` and
`allowed_http_rules` split by scheme, and `allowed_ip_rules` takes an address or a wildcard:

```yaml
allowed_https_rules: |
  # npm and maven
  registry.npmjs.org:443
  repo.maven.apache.org:443
  *.internal.example.com:443  # everything on the internal network

allowed_http_rules: |
  deb.debian.org:80

allowed_ip_rules: |
  192.168.1.10:443
```

A `#` starts a comment at the start of a line or after whitespace, so a group of rules can carry a
heading or a rule can carry its reason. It works the same in every rule input. `write_through` takes
only whole-line `#` comments, since a path may contain a `#`.

### Destinations you expect to stay blocked

A noisy dependency, or a domain you are deliberately keeping off the allowlist to confirm it stays
blocked, belongs in `known_blocked_rules`. Those rows are marked **Expected** in the report and stop
failing the step, and the destination stays unreachable:

```yaml
known_blocked_rules: |
  telemetry.example.com
```

A name refused at resolution, before any connection, has no port. A bare `telemetry.example.com` (or
`telemetry.example.com:*`) covers it; `telemetry.example.com:443` does not, since no port was involved.

One rule per line, and on `inspect` a line can also be a URL rule (a method and a URL, the
`allowed_url_rules` syntax) to acknowledge a single endpoint on a host whose other traffic is
allowed — a telemetry POST to an API you otherwise use, say:

```yaml
known_blocked_rules: |
  POST https://api.example.com/telemetry
```

Any other blocked request to that host still fails the step. See
[Blocked rules](./docs/reference.md#blocked-rules-known_blocked_rules) for the full syntax.

## The report

Every step appends its own section to the Job Summary: the hosts it reached, the ones it was
refused, and, in `audit`, the allowlist to switch to `restrict` with. Under `inspect` a
**Communication details** section lists every request in order with its method, URL, status and
size, refusals included, so a blocked entry names the URL that was attempted rather than a bare
host. A query parameter that names a credential has its value replaced, see
[Credentials in a URL](docs/security.md#credentials-in-a-url).

In `restrict` mode a blocked connection fails the step, and so does a report that could not be read
or written, since it can't show that nothing was blocked. Set `fail_on_blocked: false` to report
without failing, or list what you expect to stay blocked in `known_blocked_rules`. In `audit` mode
nothing fails the step. How the report folds expected rows, and what a `dns-service-not-allowed` row
means, is in [Reference](./docs/reference.md#report-details).

`upload_traffic_artifact: true` uploads the whole timeline as a `traffic.json`, one row per request
and per name lookup, with the method, URL, status, size and the address it resolved to. It is
uploaded even when the step fails, and `inspect` is the only engine that has anything to put in it.
The fields are listed in [Reference](./docs/reference.md#traffic-artifact).

## How `run` is executed

`run` runs under `bash -e`, the same as a native `run:` step without `shell:`. To use another
interpreter, start `run` with a shebang line; the script is then run as written, with no `set -e`
added:

```yaml
- uses: buildcage/isolated-run@430838ca8673c47824189ad3fef38808f0fadaf1 # v1.2.2
  with:
    run: |
      #!/usr/bin/env python3
      print("hello")
```

`shell:`, `working-directory:` and the workflow's `defaults.run` do not apply to a `uses:` step, so
they have no effect here. Use a shebang and `cd` instead.

## Passing values to `run`

Use the step's own `env:` (not a `with:` input) to pass values into `run`, exactly like a native
`run:` step. The action forwards its process environment into the isolated command, so anything set
via `env:` is available there too:

```yaml
- uses: buildcage/isolated-run@430838ca8673c47824189ad3fef38808f0fadaf1 # v1.2.2
  env:
    PR_TITLE: ${{ github.event.pull_request.title }}
  with:
    run: |
      echo "Building for: $PR_TITLE"
      npm test
```

Avoid interpolating `${{ }}` expressions directly into `run` itself (e.g.
`run: echo "${{ github.event.pull_request.title }}"`). GitHub substitutes them into the script text
before any shell runs, so an attacker-controlled value (a PR title, branch name, issue body) can
inject arbitrary commands. Passing the same value through `env:` instead means it reaches the
isolated command as a single environment variable, never interpreted as shell syntax. This is the
same
[script injection guidance](https://docs.github.com/en/actions/security-guides/security-hardening-for-github-actions#understanding-the-risk-of-script-injections)
GitHub gives for any workflow, and applies to this action's `run` input exactly as it would to a
native `run:` step.

## Filesystem access

<img src="assets/diagram-filesystem.png" alt="The layers the run command's filesystem is made of" width="1000">

Only `$GITHUB_WORKSPACE`, `$HOME`, `/tmp`, and `$RUNNER_TEMP` are writable by default. Every other
path is remounted read-only for the duration of the `run` command. What the command can _read_ is
not restricted. The build CA in the figure is the `inspect` engine's, and it is mounted after every
writable path, so a `write_through:` entry cannot take the sandbox's CA trust with it.

`filesystem_mode` controls what happens to those writes once the step ends:

| `filesystem_mode`          | What it does                                                                                                                                      |
| -------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------- |
| `persistent` (default)     | Writes to `$GITHUB_WORKSPACE`/`$HOME`/`/tmp`/`$RUNNER_TEMP` stay on the host after the step ends, exactly as today. Everything else is read-only. |
| `ephemeral` (experimental) | Every writable path is discarded when the step ends (via an overlay).                                                                             |

`write_through:` names the paths whose writes reach the real host filesystem in either mode, the
paths that opt out of whichever default applies:

| `filesystem_mode` | What `write_through:` does                                               |
| ----------------- | ------------------------------------------------------------------------ |
| `persistent`      | Makes the path writable, on top of the four always-writable paths above. |
| `ephemeral`       | Exempts the path from the overlay, so writes to it survive the step.     |

`filesystem_mode` only decides what happens to writes the sandbox is already allowed to make. It
never widens that set: `ephemeral` does not make a read-only path writable. Nor does either mode
change file ownership, and the sandboxed command runs as the runner's own user with every capability
dropped and `no_new_privileges` set, so `sudo` and setuid binaries do nothing for it. A path the
runner user could not write outside the sandbox stays unwritable inside it.

The docker CLI's config directory (`$DOCKER_CONFIG`, else `~/.docker`) and this action's own
checkout stay read-only, since the action runs `docker` and its post script from them after the
command exits. The exceptions are a `write_through:` entry naming the directory itself, and
`uses: ./`, whose checkout is the workspace. A command that writes docker config (`docker login`, `gcloud auth configure-docker`)
needs a step of its own.

> [!WARNING]
> `filesystem_mode: ephemeral` is **experimental**: its behavior, inputs, and error messages may still
> change in a future release without following semver, and it has seen less real-world use than the
> rest of this action. `persistent` (the default) is unaffected and stays stable. Try `ephemeral` in
> a non-critical workflow first, and pin this action to a commit SHA rather than a version tag if you
> adopt it.

Use `filesystem_mode: ephemeral` when the command is untrusted and you want to stop it from planting
something a later, non-isolated step in the same job would pick up: a rewritten `~/.bashrc`,
`~/.npmrc`, `~/.docker/config.json`, or a `$GITHUB_ENV`/`$GITHUB_PATH`/`$GITHUB_OUTPUT` edit meant
to run code once the sandbox is gone.

```yaml
- uses: buildcage/isolated-run@430838ca8673c47824189ad3fef38808f0fadaf1 # v1.2.2
  with:
    filesystem_mode: ephemeral
    write_through: |
      $GITHUB_WORKSPACE
      $GITHUB_OUTPUT
      ./dist
    run: npm ci && npm run build && npm test
```

> [!NOTE]
> Discarding those writes is the point, but the same overlay also drops output the command was
> meant to produce. `$GITHUB_OUTPUT`, `$GITHUB_ENV`, `$GITHUB_PATH`, and `$GITHUB_STEP_SUMMARY` all
> live under `$RUNNER_TEMP`, so whatever the command writes to them is gone once the step ends
> unless you name that file in `write_through:`. Naming `$GITHUB_STEP_SUMMARY` puts the command's
> markdown in the same Job Summary this action writes its own report to. That report and the
> `traffic_artifact_name` output are unaffected either way: both are written from the runner host
> after the sandboxed command has exited, outside the overlay.

`$GITHUB_WORKSPACE` has to persist for the job to do anything with it, and a later step routinely
runs whatever ends up there, so `write_through: $GITHUB_WORKSPACE` is effectively required for any
real build and is exactly as exposed to a planted payload as `persistent` mode is. What `ephemeral`
buys you is closing off everything else: `$HOME`, `$RUNNER_TEMP`, and the runner's own generated
files unless you name them explicitly. If you `write_through: $GITHUB_OUTPUT`, treat every output it
sets the same as any other value from untrusted code, as in
[Passing values to `run`](#passing-values-to-run) above.

If `run` needs to write somewhere else in `persistent` mode, a build output or a tool-specific cache
directory for example, list it under `write_through:`:

```yaml
- uses: buildcage/isolated-run@430838ca8673c47824189ad3fef38808f0fadaf1 # v1.2.2
  with:
    write_through: |
      /opt/some-tool/cache
    run: some-tool build
```

How an entry is resolved, which paths are reserved, what `write_through: /` does, and what happened
to the old `writable:` and `allow_write:` inputs are all in
[Reference](./docs/reference.md#write_through-paths).

## How it works

<img src="assets/diagram-overview.png" alt="How Buildcage restricts what a run: step can reach" width="1000">

The step starts its own throwaway proxy container, runs the command in an isolated sandbox on the
runner, appends its report to the Job Summary, and stops the container again, all within that one
step. Traffic is caught at the network level rather than through proxy environment variables, so a
tool that ignores them is covered too, and the CA the `inspect` engine needs is mounted into the
sandbox's own view of the filesystem, never written to the runner. The figure is the `inspect`
engine; `universal` follows the same path without terminating TLS, and so needs no CA.

Using the action several times in one job gives each step its own allowlist, including when the
steps run concurrently through GitHub Actions' `background`/`wait`/`wait-all`/`parallel` keywords:
the proxy container, network, and Compose project are namespaced per step, and each container
records which step started it, so concurrent steps never tear down each other's containers.

[Security Details](./docs/security.md) has the architecture of each engine and the isolation
mechanisms, with a diagram of what runs where.

## CA trust and compatibility

`proxy_engine: inspect` terminates TLS and re-signs it with a CA generated for that step, so the
command has to trust that CA. The CA, and where relevant an augmented copy of the system CA store,
is mounted over the sandbox's own view of those paths, and the mount goes away with the sandbox when
the step ends. Where the command's environment leaves them unset, Buildcage also points the
variables the common toolchains read at a store that holds the CA: `NODE_EXTRA_CA_CERTS`,
`DENO_CERT`, `SSL_CERT_FILE`, `REQUESTS_CA_BUNDLE` and `PIP_CERT`. `CURL_CA_BUNDLE` is left unset,
since curl reads the system store already. A JVM already on the runner reads none of those, only its
own keystore, so the CA is added to a copy of `$JAVA_HOME/lib/security/cacerts` (and `jssecacerts`
when present) with the runner's own `keytool` and mounted over it, letting `mvn`/`gradle`/`java`
reach the proxy without `proxy_engine: universal`.

The full table is in [Reference](./docs/reference.md#ca-trust-variables). What this cannot cover is
in [Limitations](#limitations), below.

## Scope

Buildcage controls _where_ your command can connect, not _what code_ it runs. A malicious package
delivered through an allowed domain still runs. Treat it as one layer in a defense-in-depth
strategy, a last line of defense so that if something slips through your other measures, at least it
can't call home.

This action isolates the step it wraps, not the job. What the command sets in `$GITHUB_ENV`,
`$GITHUB_PATH`, or an output reaches later steps unchanged, and so does anything it writes under
`$HOME`, `/tmp`, `$RUNNER_TEMP`, or `$GITHUB_WORKSPACE`. The same is true of `$GITHUB_STATE`, which
this action's own post step reads back after the step ends. Those steps run without this action's
restrictions unless you wrap them too. If a step runs untrusted code, isolate the steps after it in
the same job as well, or move them to a separate job, and don't treat an env var, `$PATH` entry, or
output an isolated step set as trustworthy. Post steps cannot be wrapped and run after the last step.
This action's own keeps `docker` and `sudo` out of the command's reach, but like any other it
inherits `$GITHUB_ENV`, so in `persistent` mode an untrusted command can reach every post step.
`filesystem_mode: ephemeral` with a narrow `write_through:` prevents that.

An allowlist also cannot stop anything leaving through a service you had to allow anyway. That is a
structural limit. What it does stop is traffic to a destination that is not on the list, and
infrastructure an attacker set up is normally not on it, because the command has no reason to reach
it. That is also the hardest kind of leak to find afterwards.

An allowlist generated from an audit run already blocks every destination the audit did not record.
Whether to go further depends on what the step has access to:
[Hardening](./docs/security.md#hardening) is what to look at when it holds credentials, personal
data, or source you do not publish. For the full threat model, see
[Security Details](./docs/security.md).

## Limitations

### What isn't covered

- `allowed_tls_rules` is not decrypted. The SNI and the port are checked, and the proxy resolves
  that name itself, so the connection reaches the host the rule named, but nothing inside the TLS
  session is seen.
- `allowed_ip_rules` is not inspected at all, and doesn't require TLS either: once an `ip:port` pair
  is allowed, any TCP-based protocol can use that path. Prefer a domain rule wherever the
  destination has a stable name.
- `universal` never sees the method or the path. They travel inside TLS, so neither is enforced and
  neither reaches the report or the traffic artifact. A request fronted behind an allowed SNI is
  invisible to it as well, while `inspect` matches on the real `Host` and refuses it. See
  [Domain fronting](./docs/security.md#domain-fronting).
- The generated allowlist covers only what the engine classified. `allowed_tls_rules` and
  `allowed_ip_rules` come back exactly as the audit run was configured with them, since nothing
  behind a passthrough was ever decrypted.

### Protocols

- UDP is dropped, so QUIC and HTTP/3 either fall back to TCP or fail. Port 53 to the proxy, which is
  the resolver, is the one exception. ICMP is dropped too.
- IPv6 is not used anywhere. The rule syntax refuses an IPv6 address, forwarded IPv6 is dropped, and
  the proxy reaches allowed names over IPv4 only, so an allowed name with AAAA records and no A
  record never resolves and no rule can clear it.

### Service discovery

The resolver has no upstream, so it returns nothing for a discovery record: `SRV`, `TXT`, `TLSA` and
`URI` queries come back empty, and the command connects to the name a rule allowed rather than to
one a nameserver picked for it. Clients that treat `SRV` as a discovery layer fall back to the host
name itself, so the host a rule names is the host the command reaches.

What this breaks is a client with no fallback, where the record is the only way it can find the
service at all. A `mongodb+srv://` connection string is the one to expect: use `mongodb://` with the
shard hostnames written out and allowlist those instead. Active Directory and Kerberos discovery
have the same shape.

Under `inspect`, a lookup for a `_service._proto.<host>` name is reported as `discovery` when the
rules allow that host, and is not counted as blocked. A service name under any other host is
reported as blocked; see
[Blocked service names](./docs/reference.md#blocked-service-names).

### Inside the sandbox

- The isolated command cannot use Docker. If `docker`, or another container or VM runtime group, is
  the runner's primary group, it is substituted for a safe one before the command runs, and the
  host's `/run`, where the container runtimes, systemd-resolved, snapd and the rest keep their
  sockets, is covered by an empty tmpfs. See
  [Isolation Mechanisms](docs/security.md#isolation-mechanisms).
- `/dev` holds the standard container device set, so a command needing a host device node such as
  `/dev/kvm` or `/dev/fuse` won't work. Open-file limits, `/dev/shm` size, and the hostname match
  the runner.
- In `persistent` mode `/tmp` and `$RUNNER_TEMP` are the same real directories for every invocation
  in the job, so two concurrent steps can reach each other's scratch files there. `ephemeral` gives
  each invocation its own overlay.

### Under the `inspect` engine

- A tool that pins a specific certificate, or ships a bundled trust store it never lets the system
  update, still needs `proxy_engine: universal` or an `allowed_tls_rules` passthrough, since it will
  not accept the re-signed certificate.
- The JVM (Java, Kotlin, Scala) reads only its own keystore rather than the CA-trust variables, and
  a JVM already on the runner is handled: the CA is added to a copy of its
  `$JAVA_HOME/lib/security/cacerts` for the step. Two cases fall back to `proxy_engine: universal`: a
  keystore sealed with a non-default password, which the runner's `keytool` cannot rewrite, and a
  runner with no `keytool` at all.
- `audit` terminates TLS as well. It drops the rules, not the interception, so a tool that cannot
  accept the CA fails in `audit` exactly as it would in `restrict`. `universal`'s audit mode
  decrypts nothing and breaks nothing.
- A CA-trust variable that is already set is left alone rather than appended to. Appending safely
  would mean resolving the path it points at against the sandbox rootfs without following a symlink
  back out to the host, which this engine does not do yet.
- The CA is added to a store that already exists, never created. A command whose filesystem has
  nothing resembling a system CA bundle at a well-known path has nothing to add to, which matters
  only to a tool that needs TLS trust for something.

### The Job Summary size cap

GitHub caps a Job Summary at 1 MiB per step and drops the whole summary rather than truncating it,
so if the timeline would push the step over that limit, that section alone is cut at a line boundary
and a note takes its place. The report is written to the Job Summary only, so a cut section is
recovered from the [traffic artifact](./docs/reference.md#traffic-artifact) and nowhere else.

## FAQ

**Can I keep `inspect` but leave a few hosts undecrypted?**

Yes, that is what `allowed_tls_rules` is for. The SNI and port are checked and the connection passes
through untouched, so a JVM build or a tool that pins a certificate can sit inside an otherwise
inspected step. Those hosts are enforced at host-and-port granularity, the same as `universal`.

**A host only ever gets looked up, never connected to. How do I write a rule for it?**

The report gives it a row with `DNS` as the rule kind and no port. If you want it to stay
unreachable without failing the step, put the name in `known_blocked_rules`, which is the one input
where a rule may omit the port. If the command actually needs it, write an ordinary host or URL rule
and the lookup is reported as allowed.

**One registry needs several domains. How do I find them all?**

Run `audit` and read the report. PyPI, for example, uses both `pypi.org` and
`files.pythonhosted.org`, and the audit report lists every domain the command touched, so the
generated allowlist already has them.

**My step's outputs disappear under `filesystem_mode: ephemeral`.**

`$GITHUB_OUTPUT`, `$GITHUB_ENV`, `$GITHUB_PATH` and `$GITHUB_STEP_SUMMARY` live under
`$RUNNER_TEMP`, which the overlay discards. Name the ones the command writes to in
`write_through:`. See [Filesystem access](#filesystem-access).

## GitHub's native egress firewall

GitHub is building an egress firewall directly into Actions runners
([technical preview](https://github.com/github-early-access/actions-native-egress-firewall) as of
September 2026): opt a job into a firewall-enabled runner image and its traffic is inspected outside
the runner VM, in `log` or `enforce` mode, from a single `.github/egress-firewall.yaml` in the
repository. Because it sits outside the VM, a workflow that gains root inside the runner cannot
switch it off. Firewall-enabled images are GitHub-hosted and Linux only.

One policy for the whole run is one allowlist for every step in it: the destinations
`actions/checkout`, the caches and the setup actions need stay open to every other step as well.
Buildcage writes a separate allowlist for the one step you don't trust, so it gets the hosts its
command needs and nothing else, and a rule there can name a method and a URL rather than only a
host. The two compose: a perimeter the job can't switch off, and a tighter policy inside it.

Buildcage also runs on any Linux runner with Docker, self-hosted included, rather than on a
firewall-enabled runner image.

## Documentation

| Doc                                        | What's in it                                                      |
| ------------------------------------------ | ----------------------------------------------------------------- |
| [Reference](./docs/reference.md)           | Every input, the rule syntax in full, the report's own output     |
| [Security Details](./docs/security.md)     | Architecture and threat model for every engine, attack resistance |
| [Development Guide](./docs/development.md) | Local usage, testing, logs, and the repository layout             |

## Contributing

Contributions are welcome! Please feel free to submit issues or pull requests at
[github.com/buildcage/isolated-run](https://github.com/buildcage/isolated-run).

## Show Your Support

If you find this action helpful, please consider giving it a star ⭐ on GitHub!

## Disclaimer

This software is provided "as is", without warranty of any kind, express or implied. The authors
and contributors are not liable for any damages, losses, or security incidents arising from the
use of this software. Use at your own risk.

## License

The isolated-run source code is licensed under the MIT License. See [LICENSE](./LICENSE) file for
details.

The Docker image includes third-party components under their own licenses (GPL, Apache 2.0, ISC,
etc.). See [THIRD_PARTY_LICENSES](./THIRD_PARTY_LICENSES) for the full list.

The Action bundles its npm dependencies (MIT, Apache 2.0, ISC) into the committed `dist/` files.
See [THIRD_PARTY_LICENSES_NPM](./THIRD_PARTY_LICENSES_NPM) for their license texts.

# Reference

Runs an arbitrary command with outbound network isolation — an allowlist enforced directly on the
runner, not just inside a Docker build.

```yaml
- name: Run tests with outbound network isolation
  uses: buildcage/isolated-run@ac2e29dec8ab46d717d6b1ba1688d63ff7983ffe # v1.0.0
  with:
    proxy_mode: restrict
    allowed_https_rules: registry.npmjs.org:443
    run: |
      npm install
      npm test
```

Each step is self-contained: it starts its own throwaway proxy container, runs the command
inside the isolated sandbox, appends a report section to the Job Summary, and stops the proxy
container again — all within that one step. Using this action multiple times in the same job
starts a fresh proxy container each time, so different steps can use different allowlists. This
is also safe when those steps run truly concurrently via GitHub Actions'
`background`/`wait`/`wait-all`/`parallel` step keywords — each step's proxy container, network,
and Compose project are all namespaced by the same per-step random suffix, so concurrent steps
never recreate or tear down each other's containers.

In `audit` mode, the Job Summary also includes a ready-to-paste `restrict` mode example — a step
with `proxy_mode: restrict` and allowlist rules generated from the hosts observed during the
audited run.

See the [restrict mode](../.github/workflows/example-restrict.yml) and
[audit mode](../.github/workflows/example-audit.yml) example workflows for each in full.

## Parameters

| Parameter             | Required | Default    | Description                                                                                                                                                                   |
| --------------------- | -------- | ---------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `run`                 | Yes      | —          | Command(s) to run inside the isolated sandbox (multi-line supported, like a workflow `run:` step)                                                                             |
| `proxy_mode`          | No       | `restrict` | Operation mode (`audit` / `restrict`)                                                                                                                                         |
| `allowed_https_rules` | No       | empty      | HTTPS allow rules (wildcard or regex, port required)                                                                                                                          |
| `allowed_http_rules`  | No       | empty      | HTTP allow rules (wildcard or regex, port required)                                                                                                                           |
| `allowed_ip_rules`    | No       | empty      | IP address allow rules (wildcard or regex, port required)                                                                                                                     |
| `fail_on_blocked`     | No       | `true`     | Fail the step if blocked connections are detected (restrict mode only; ignored in audit mode)                                                                                 |
| `known_blocked_rules` | No       | empty      | Domains expected to be blocked intentionally (wildcard or regex, port required); blocked connections matching these don't fail the step even when `fail_on_blocked` is `true` |
| `writable`            | No       | empty      | Additional writable directories (newline-separated), on top of `$GITHUB_WORKSPACE`, `$HOME`, `/tmp`, and `$RUNNER_TEMP` — see [Filesystem Access](#filesystem-access) below   |
| `label`               | No       | empty      | Label appended to this step's Job Summary heading, e.g. `npm install` — useful to tell steps apart when this action is used more than once in the same job                    |

See [Rule Syntax](./rules.md) for the full wildcard/regex/IP rule grammar shared by
`allowed_*_rules` and `known_blocked_rules`.

## Passing Values to `run`

Use the step's own `env:` (not a `with:` input) to pass values into `run` — exactly like a native
`run:` step. The action forwards its whole process environment into the isolated command, so
anything set via `env:` is available there too:

```yaml
- uses: buildcage/isolated-run@ac2e29dec8ab46d717d6b1ba1688d63ff7983ffe # v1.0.0
  env:
    PR_TITLE: ${{ github.event.pull_request.title }}
  with:
    run: |
      echo "Building for: $PR_TITLE"
      npm test
```

Avoid interpolating `${{ }}` expressions directly into `run` itself (e.g. `run: echo "${{
github.event.pull_request.title }}"`) — GitHub substitutes them into the script text before any
shell runs, so an attacker-controlled value (a PR title, branch name, issue body, etc.) can inject
arbitrary commands. Passing the same value through `env:` instead means it reaches the isolated
command as a single environment variable, never interpreted as shell syntax. This is the same
[script injection guidance](https://docs.github.com/en/actions/security-guides/security-hardening-for-github-actions#understanding-the-risk-of-script-injections)
GitHub gives for any workflow, and applies to this action's `run` input exactly as it would to a
native `run:` step.

## How It Works

The action isolates the runner host itself (not a Docker build) using network-level enforcement
(iptables redirect, DNS redirect, SNI/Host-based allowlist proxy):

1. A throwaway proxy container starts — just the iptables, DNS, and HAProxy pieces needed for
   network enforcement, no build daemon.
2. The `run` command executes directly on the runner host inside a fresh network/PID/mount/UTS/
   IPC/cgroup namespace, connected to the proxy container's own netns by a dedicated veth pair (no
   bridge — always a 1:1 connection).
3. Before executing `run`, all capabilities are dropped, `no_new_privileges` is set, and
   supplementary groups (e.g. `docker`) are cleared — the isolated command cannot re-escalate
   privileges, touch the Docker socket, or reconfigure networking, even if it runs as the same
   user/UID as the runner (kept unchanged so `actions/setup-node`-installed toolchains,
   `$GITHUB_WORKSPACE` ownership, and `$HOME`-based caches keep working normally).
   PID namespace isolation also means the isolated command structurally cannot `ptrace` or read
   `/proc/<pid>/mem` for the Actions runner process itself — the kernel forbids reaching into a
   parent PID namespace regardless of capabilities.

See [Security Details](./security.md) for the full mechanism and threat model.

## Filesystem Access

Only `$GITHUB_WORKSPACE`, `$HOME`, `/tmp`, and `$RUNNER_TEMP` are writable by default — every other
path is remounted read-only for the duration of the `run` command. This closes off using the
filesystem to plant a payload for a later, non-sandboxed step in the same job (e.g. rewriting a
binary earlier on `$PATH`); it doesn't restrict what the command can _read_ (see
[Known Limitations](./security.md#known-limitations) in Security Details).

If `run` needs to write somewhere else — a tool-specific cache directory, for example — list it
under `writable`:

```yaml
- uses: buildcage/isolated-run@ac2e29dec8ab46d717d6b1ba1688d63ff7983ffe # v1.0.0
  with:
    writable: |
      /opt/some-tool/cache
    run: some-tool build
```

To disable the read-only restriction entirely, set `writable` to `/`:

```yaml
writable: /
```

> [!NOTE]
> This action sets up its isolation directly on the runner host (via `sudo -n`), so it requires a
> Linux runner with passwordless `sudo` and a working Docker installation — both are the default on
> GitHub-hosted `ubuntu-*` runners, but lightweight images such as `ubuntu-slim` (a Docker client
> with no daemon) are not supported. It applies a seccomp filter derived from Docker's own default
> profile; it does not apply an AppArmor/SELinux profile or Landlock rules. See
> [Security Details](./security.md) for the full threat model and known limitations.

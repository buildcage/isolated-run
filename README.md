# isolated-run

[![GitHub](https://img.shields.io/badge/GitHub-buildcage%2Fisolated--run-blue?logo=github)](https://github.com/buildcage/isolated-run)
![build](https://img.shields.io/github/actions/workflow/status/buildcage/isolated-run/docker-publish.yml)
![test](https://img.shields.io/github/actions/workflow/status/buildcage/isolated-run/test-e2e.yml?label=test)
![license](https://img.shields.io/github/license/buildcage/isolated-run)

**Restrict outbound network access for a GitHub Actions `run:` step to an explicit allowlist of domains.**

When a compromised dependency pulled in by `npm install`, `pip install`, or any other command in a
`run:` step tries to exfiltrate secrets or phone home, `isolated-run` blocks it: only the domains
you specify are reachable. No changes to the command itself, no proxy configuration, no
certificates to install — works with any language or package manager.

- **Wraps any `run:` step**: install dependencies, run tests, execute a build script — isolation
  applies to the command, not to a Docker build
- **Self-contained on GitHub**: no external service, no telemetry, free and open source
- **Same UID and `$HOME`**: earlier steps' credentials, caches, and toolchains keep working
  unmodified inside the isolated command

This is built on the same network-isolation technology as
[Buildcage](https://github.com/dash14/buildcage) (which applies it to `docker build` `RUN` steps),
split into its own repository so the `run:` step use case can version and release independently.

## Features

- 🚀 **Zero command changes**: your `run:` step's shell commands stay exactly as they are
- 🔍 **Dependency discovery**: discover what a command already talks to before enforcing anything
  (`audit` mode)
- 🛡️ **Allowlist enforcement**: block every destination except the ones you explicitly allow
  (`restrict` mode)
- 🔒 **Per-step isolation**: each `run:` step gets its own throwaway proxy and network namespace,
  so only explicitly allowed destinations are reachable
- 📊 **Detailed logging**: every destination the command reaches, reported directly in GitHub's
  Job Summary

## Quick Start

Wrap the command you want to isolate with this action instead of a plain `run:` step. Same
audit → restrict flow either way.

### Step 1: Discover what domains your command needs (Audit Mode)

```yaml
- name: Discover required domains
  uses: buildcage/isolated-run@ac2e29dec8ab46d717d6b1ba1688d63ff7983ffe # v1.0.0
  with:
    proxy_mode: audit # Log every destination, block nothing
    run: |
      npm install
      npm test
```

See the [complete example workflow](.github/workflows/example-audit.yml).

### Step 2: Check the report

The action appends a Job Summary section listing every destination the command contacted, and
(in audit mode) a ready-to-paste restrict-mode example built from those domains.

Copy the domain names into `allowed_https_rules` or `allowed_http_rules` for Step 3.

### Step 3: Create your allowlist and switch to restrict mode

```yaml
- name: Run tests with outbound network isolation
  uses: buildcage/isolated-run@ac2e29dec8ab46d717d6b1ba1688d63ff7983ffe # v1.0.0
  with:
    proxy_mode: restrict # Block every destination except the ones you allow
    allowed_https_rules: |
      registry.npmjs.org:443
    run: |
      npm install
      npm test
```

See the [complete example workflow](.github/workflows/example-restrict.yml).

---

Your `run:` step is now protected. Any unexpected connections will be blocked and reported.

For the full parameter reference and rule syntax, see the [Reference](./docs/reference.md) doc.

## How It Works

The action isolates the command directly on the runner: a dedicated network namespace enforces an
SNI/Host-based allowlist proxy, while capability and namespace restrictions keep the command from
escaping to the rest of the runner. It keeps the same UID and `$HOME` as the rest of the job,
though, so things configured by earlier steps — AWS credentials, an npm cache, etc. — keep working
unmodified.

No agent installed on the runner is required.

See [Reference](./docs/reference.md) for the full mechanism.

> [!IMPORTANT]
> `isolated-run` controls _where_ your command can connect, not _what code_ it runs. If a malicious
> package is delivered through a legitimate repository (e.g., a compromised npm package hosted on
> `registry.npmjs.org`), `isolated-run` cannot detect or prevent it: the connection goes to an
> allowed domain.
>
> Don't make this your only supply chain security measure. Use it as one layer in a
> defense-in-depth strategy, a last line of defense. If something slips through your other
> measures, at least it can't call home.
>
> See [Security Considerations](./docs/security.md) for full details.

## FAQ

- **Does this slow down my step?**

  Minimal impact. The proxy runs locally, alongside your command, so checking a destination
  against your allowlist adds no meaningful latency.

- **Does this work with private package registries?**

  Yes. Just add your private registry's domain to `allowed_https_rules` (e.g.,
  `registry.example.com:443`).

- **What happens if I forget to add a required domain?**

  In restrict mode, the step fails with a clear error message. Run in audit mode first to
  discover all required domains.

- **Can I allow access to an IP address (e.g., `http://192.168.1.1`)?**

  Yes. Add the IP address with a port to `allowed_ip_rules` (e.g., `192.168.1.1:80`). Only IPv4
  addresses are supported, and CIDR notation isn't, but a regex rule can match a range (e.g.,
  `~^192\.168\.1\.\d+:80$`).

- **Does this protect against malicious code execution?**

  No. This action only controls network access. It doesn't prevent malicious code from running;
  it prevents that code from communicating with external servers.

- **Can a wrapped `run:` step use Docker itself?**

  No. The action clears the `docker` group before the command executes, so even if the Docker
  socket is visible on the filesystem, the isolated command has no permission to use it.

- **Can I host this in my own private repository?**

  Yes, see the [Self-Hosting Guide](./docs/self-hosting.md). Most projects don't need to, though:
  pinning the action to a commit SHA (`uses: buildcage/isolated-run@ac2e29dec8ab46d717d6b1ba1688d63ff7983ffe # v1.0.0`) locks in an
  exact, Sigstore-verified image for that release, which covers most of the same risk self-hosting
  is meant to address, without the overhead of maintaining a fork.

## Documentation

| Doc                                          | What's in it                                                     |
| -------------------------------------------- | ---------------------------------------------------------------- |
| [Reference](./docs/reference.md)             | Full parameter reference and how the action works under the hood |
| [Rule Syntax](./docs/rules.md)               | Wildcard, regex, and IP rule syntax in detail                    |
| [Security Details](./docs/security.md)       | Architecture, attack resistance, and known limitations           |
| [Self-Hosting Guide](./docs/self-hosting.md) | Hosting your own image in a private repository                   |
| [Development Guide](./docs/development.md)   | Local usage, testing, logs, and implementation internals         |

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

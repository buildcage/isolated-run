# Security Policy

## Scope

I welcome reports about:

- **Proxy bypass** — ways to make network connections from an isolated `run:` command that evade
  the allowlist proxy (other than the [known domain fronting limitation](./docs/security.md#known-limitations))
- **Network isolation escape** — bypassing the network namespace/iptables setup to reach the
  internet directly
- **DNS filtering bypass** — bypassing the DNS redirect mechanism
- **Sandbox escape** — privilege escalation, capability re-acquisition, or reaching the Docker
  socket from inside the isolated command
- **GitHub Actions setup** — vulnerabilities in the action itself (e.g., injection, credential
  leak)

The following are **out of scope** (please report to the respective projects instead):

- Vulnerabilities in `runc`, Docker, or other upstream dependencies
- Issues that require the attacker to already have privileged access to the host
- Domain fronting via shared CDN infrastructure (documented in [Security Details](./docs/security.md#known-limitations))

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 1.x     | :white_check_mark: |

## Verifying Releases

isolated-run ships one artifact: a Docker image at `ghcr.io/buildcage/isolated-run`, tagged
`vX.Y.Z`. Each release is signed keylessly with [cosign](https://github.com/sigstore/cosign) and
carries a GitHub build-provenance attestation, both issued via GitHub Actions OIDC at release time
— there is no long-lived signing key to leak or rotate. The action verifies this automatically,
in-process, on every run (see [Image Provenance Verification](./docs/security.md#image-provenance-verification)
for exactly how); to verify a release manually instead:

```sh
cosign verify ghcr.io/buildcage/isolated-run:<tag> \
  --certificate-identity-regexp '^https://github.com/buildcage/isolated-run/' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
gh attestation verify oci://ghcr.io/buildcage/isolated-run:<tag> --owner buildcage
```

The Sigstore bundle for each release is also attached as a downloadable asset
(`isolated-run-container.sigstore.json`) on the corresponding
[GitHub Release](https://github.com/buildcage/isolated-run/releases).

## Dependency Management

- Dependencies are pinned: JS packages via `pnpm-lock.yaml`, Go modules via `go.sum`, GitHub
  Actions by commit SHA (with a version comment for readability), and container base images by
  digest.
- [Renovate](https://docs.renovatebot.com/) opens dependency, GitHub Actions, and base-image
  update PRs automatically; each still goes through CI and manual review before merging.
- New dependencies are chosen for necessity, an OSI-approved license, and active maintenance; the
  standard library is preferred where practical.
- [Trivy](https://github.com/aquasecurity/trivy) scans the built image for known vulnerabilities
  (on each push to `main` and monthly on schedule), and Dependabot alerts are enabled on the
  repository — both report into this repository's Security tab.

## Reporting a Vulnerability

**Please do not report security vulnerabilities through public GitHub issues.**

Use [GitHub Security Advisories](https://github.com/buildcage/isolated-run/security/advisories/new) to report vulnerabilities privately:

1. Go to the **Security** tab of this repository
2. Click **Report a vulnerability**
3. Fill in the details and submit

### What to include

- Description of the vulnerability and its impact
- Steps to reproduce
- Proof of concept, if possible
- Affected versions

## Response Timeline

This project is maintained by a single developer. Realistic timelines:

- **Acknowledgment**: within 1 week
- **Validation**: a few days to 2 weeks, depending on complexity
- **Fix release**: varies by severity and complexity; critical issues are prioritized

I'll credit reporters in the security advisory unless they prefer to remain anonymous.

## Code Auditing

All code is public and I welcome security reviews. If you prefer to audit or control the code yourself, feel free to fork and self-host.

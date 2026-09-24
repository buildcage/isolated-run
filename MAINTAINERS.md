# Maintainers

## Current Maintainer

| Name   | GitHub                                | Role       | Access                                                                                                            |
| ------ | -------------------------------------- | ---------- | ------------------------------------------------------------------------------------------------------------------ |
| dash14 | [@dash14](https://github.com/dash14)   | Maintainer | Repository admin (write access, branch protection, secrets), GHCR package publishing, GitHub Security Advisories |

## Responsibilities

The maintainer is responsible for:

- Reviewing and merging pull requests
- Triaging and responding to issues
- Cutting releases and publishing the Docker image to GHCR
- Responding to security reports (see [SECURITY.md](./SECURITY.md))
- Maintaining project documentation

## Release secrets

`TAG_CREATION_TOKEN` pushes the release tag in `release.yml`. It is a personal access token rather
than `GITHUB_TOKEN` because a tag pushed with `GITHUB_TOKEN` does not trigger `docker-publish.yml`.
Keep it a fine-grained token limited to this repository, with **Contents: Read and write** and no
other permissions, and give it an expiry.

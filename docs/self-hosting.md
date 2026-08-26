# Self-Hosting Guide

This guide explains how to host your own isolated-run Docker image in a private GitHub repository. This is useful when you want to:

- Keep the build infrastructure private within your organization
- Control exactly which version of isolated-run is deployed and when updates are applied
- Meet compliance requirements that mandate use of an internal container registry

> [!NOTE]
> The upstream image (`ghcr.io/buildcage/isolated-run`) is verified at action startup via Sigstore, confirming it was built from the exact source commit of the release — sufficient provenance assurance for most use cases. Self-hosting adds operational overhead: keeping your fork in sync with upstream and managing your own signing pipeline.

## Prerequisites

- A GitHub organization (any plan, including Free) to hold the private repository and its container package. Private packages are available on all plans, though GitHub Packages storage/transfer beyond the plan's included quota (shared with Actions artifacts) is billed — see [GitHub Packages billing](https://docs.github.com/en/billing/concepts/product-billing/github-packages).

## 1. Import the Repository

Since forking creates a public repository, use **GitHub's import** feature to create a private copy.

1. Go to [github.com/new/import](https://github.com/new/import)
2. Enter the source URL: `https://github.com/buildcage/isolated-run.git`
3. Select your organization as the owner
4. Set the repository name (e.g., `isolated-run`)
5. Choose **Private**
6. Click **Begin import**

## 2. Build and Publish the Docker Image

Your imported repository already contains the **Build and Push Docker Image** workflow (`.github/workflows/docker-publish.yml`). This workflow builds the proxy image from `docker/transparent/Dockerfile` and publishes it to your repository's GitHub Container Registry (GHCR), signed.

To trigger the build:

1. Go to your repository on GitHub
2. Navigate to **Actions** > **Build and Push Docker Image**
3. Click **Run workflow**

Once complete, the image will be available at:

```
ghcr.io/<your_org>/isolated-run:<version>
```

The action resolves the correct tag automatically — you don't need to reference it directly in your own workflows.

## 3. Configure Package Visibility

The published package needs to be accessible from the repositories that will use it.

1. Go to `github.com/<your_org>/isolated-run/pkgs/container/isolated-run`
2. Click **Package settings**
3. Under **Manage Actions access**, add the repositories that need to pull the image

## 4. Configure Actions Access

Allow other repositories in your organization to use the action from your private repository:

1. Go to your isolated-run repository's **Settings** > **Actions** > **General**
2. Under **Access**, select **Accessible from repositories in the '\<your_org\>' organization**

## 5. Update Your Workflows

In the repositories where you want to use isolated-run, make two changes:

### Add GHCR login step

Add a login step before the action, and ensure the job has `packages: read` permission:

```yaml
jobs:
  build:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      packages: read
    steps:
      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1

      - name: Login to GHCR
        uses: docker/login-action@dbcb813823bdd20940b903addbd779551569679f # v4.6.0
        with:
          registry: ghcr.io
          username: ${{ github.actor }}
          password: ${{ secrets.GITHUB_TOKEN }}

      - name: Run tests with outbound network isolation
        uses: <your_org>/isolated-run@<40-char-sha> # vX.Y.Z
        with:
          proxy_mode: audit
          run: npm test
      # ... rest of your workflow
```

Note that `uses:` now points to `<your_org>/isolated-run@<40-char-sha> # vX.Y.Z` instead of
`buildcage/isolated-run@...`. Replace `<40-char-sha>` with the commit SHA of the release tag in
your fork.

### Image provenance verification

The action automatically verifies the Docker image's build provenance before pulling it. When you fork the repository:

- The `docker-publish.yml` workflow in your fork will sign images with **your fork's** GitHub Actions OIDC identity.
- The action will verify against your fork's workflow identity, so verification passes correctly.
- If you use `uses: <your_org>/isolated-run@<40-char-sha>`, `github.action_repository` resolves to `<your_org>/isolated-run` and the image is pulled from `ghcr.io/<your_org>/isolated-run` automatically.

External image overrides are not supported because they would bypass the provenance verification that guarantees image integrity. Self-hosting via fork is the supported alternative.

If provenance verification fails, the action will exit with an error. Make sure you have published at least one signed release in your fork before using a version tag.

You can independently confirm that a specific image digest has a valid signature using standard signing tooling, e.g. the cosign CLI:

```bash
cosign verify \
  --certificate-identity-regexp "^https://github.com/<your_org>/isolated-run/.github/workflows/docker-publish.yml@refs/tags/.*$" \
  --certificate-oidc-issuer "https://token.actions.githubusercontent.com" \
  ghcr.io/<your_org>/isolated-run@sha256:<digest>
```

## Syncing with Upstream

### Initial setup

Clone your private repository and register the upstream remote:

```bash
git clone https://github.com/<your_org>/isolated-run.git
cd isolated-run
git remote add upstream https://github.com/buildcage/isolated-run.git
```

### Pulling updates

Fetch the latest changes from the original repository and merge them into your copy:

```bash
git fetch upstream --tags --force
git merge upstream/main
git push origin HEAD --tags --force
```

After pushing a new version tag, the **Build and Push Docker Image** workflow will automatically trigger and publish the updated image.

> [!NOTE]
> If the workflow does not trigger automatically, run it manually from **Actions** > **Build and Push Docker Image** > **Run workflow**. The branch selection can be left as `main` — the workflow will build from the latest version tag.

Once the image is published, run the **Update major/minor/latest tags** workflow to update the major/minor Docker tags (`:1`, `:1.1`) and the major git tag (`v1`):

1. Navigate to **Actions** > **Update major/minor/latest tags**
2. Click **Run workflow**
3. Enter the release tag (e.g., `v1.1.0`)
4. Click **Run workflow**

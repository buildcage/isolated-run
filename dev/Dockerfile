# Mac-friendly dev-loop counterpart to the real run action.
#
# Buildcage's own runc/kernel-namespace operations can't run natively on
# macOS (Darwin), so local development drives run-isolated.sh from inside a
# container instead: this one runs with `pid: host` (see
# ../docker/compose.sandbox-dev.yaml) so it can see the proxy
# container's PID/netns via /proc, exactly like the real GitHub Actions
# runner host does for the real proxy container in production. It is not
# used in production or in CI's test_sandbox job (see
# docs/development.md): those run run-isolated.sh directly on the runner
# host, matching what actually happens when a user's workflow executes.
#
# runc and gen-seccomp-profile are built directly into this image (mirroring
# ../docker/universal/Dockerfile's own stages) rather than `docker cp`-extracted from
# the proxy image at runtime, so this dev loop doesn't need the Docker
# socket mounted in just to reach a sibling container: it stays scoped to
# testing run-isolated.sh itself.
# renovate: datasource=github-release-attachments depName=opencontainers/runc
ARG RUNC_VERSION=v1.5.2
# renovate: datasource=github-release-attachments depName=opencontainers/runc digestVersion=v1.5.2
ARG RUNC_SHA256_AMD64=599f6f94ff8c5057241eff0d54c3c74f95c34935b6457b33fe545defc61e9488
# renovate: datasource=github-release-attachments depName=opencontainers/runc digestVersion=v1.5.2
ARG RUNC_SHA256_ARM64=d10ecae898361832a059be2089bab92d158aec54661b18ed7346ed79628b46b0

FROM alpine:3.24.2@sha256:294b683cb724975bec92580e1e685676bd4b50bda910ddb8c51d4cabeaec77e6 AS deps
ARG RUNC_VERSION
ARG RUNC_SHA256_AMD64
ARG RUNC_SHA256_ARM64
RUN apk add --no-cache curl && \
    mkdir -p /opt/buildcage/bin && \
    ARCH=$(uname -m | sed 's/x86_64/amd64/' | sed 's/aarch64/arm64/') && \
    EXPECTED_SHA256=$([ "$ARCH" = "amd64" ] && echo "$RUNC_SHA256_AMD64" || echo "$RUNC_SHA256_ARM64") && \
    curl -fsSL "https://github.com/opencontainers/runc/releases/download/${RUNC_VERSION}/runc.${ARCH}" \
      -o /opt/buildcage/bin/runc && \
    echo "${EXPECTED_SHA256}  /opt/buildcage/bin/runc" | sha256sum -c && \
    chmod +x /opt/buildcage/bin/runc

FROM --platform=$BUILDPLATFORM golang:1.27-alpine@sha256:4cb7ac979db5fcc41cae44b2227ba5ab8a51e8807f40d9ba4dee20a0ad960b5b AS gen-seccomp-profile-build
ARG TARGETOS
ARG TARGETARCH
WORKDIR /src
COPY docker/gen-seccomp-profile/go.mod docker/gen-seccomp-profile/go.sum ./
RUN go mod download
COPY docker/gen-seccomp-profile/main.go ./
RUN CGO_ENABLED=0 GOOS="${TARGETOS}" GOARCH="${TARGETARCH}" go build -trimpath -ldflags="-s -w" -o /out/gen-seccomp-profile .

# filesystem-audit, the file-access tracer, is compiled here and, like runc
# and gen-seccomp-profile, extracted onto the runner host and run there; see
# docker/filesystem-audit/main.go. bpf2go compiles its eBPF object with clang
# (architecture-independent, -target bpfel) and embeds it, so the Go loader
# cross-compiles via BUILDPLATFORM without QEMU.
FROM --platform=$BUILDPLATFORM golang:1.27-alpine@sha256:4cb7ac979db5fcc41cae44b2227ba5ab8a51e8807f40d9ba4dee20a0ad960b5b AS filesystem-audit-build
RUN apk add --no-cache clang llvm libbpf-dev linux-headers
ARG TARGETARCH
WORKDIR /src
COPY docker/filesystem-audit/go.mod docker/filesystem-audit/go.sum ./
RUN go mod download
COPY docker/filesystem-audit/ ./
RUN go generate ./... && \
    CGO_ENABLED=0 GOARCH="${TARGETARCH}" go build -trimpath -ldflags="-s -w" -o /out/filesystem-audit .

FROM alpine:3.24.2@sha256:294b683cb724975bec92580e1e685676bd4b50bda910ddb8c51d4cabeaec77e6

RUN apk add --no-cache bash util-linux iproute2 findutils jq

COPY --from=deps /opt/buildcage/bin/runc /usr/local/bin/runc
COPY --from=gen-seccomp-profile-build /out/gen-seccomp-profile /usr/local/bin/gen-seccomp-profile
COPY --from=filesystem-audit-build /out/filesystem-audit /usr/local/bin/filesystem-audit

CMD ["sleep", "infinity"]

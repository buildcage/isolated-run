# renovate: datasource=github-releases depName=opencontainers/runc
ARG RUNC_VERSION=v1.5.1
ARG RUNC_SHA256_AMD64=177df879d50c913eb205e898d5c1c05a18f574053c0ce5524c471208eaf06f6f
ARG RUNC_SHA256_ARM64=ca70e7dbd6616ca782a59b5d3ac86909123fdaa9fa3f89dcf29051c70eee7ce9

# renovate: datasource=github-releases depName=coredns/coredns
ARG COREDNS_VERSION=1.14.7
ARG COREDNS_SHA256_AMD64=9a09356438c6d9591cb80011a2a7a52f87fc3a113f6690e41f243f98b98faac9
ARG COREDNS_SHA256_ARM64=bf26782d19b5340e3e6cb50f1ed6df72f58e4a30932c79d167f0f0a8b1e92e16

# Prepare dependencies — runc's official release binaries are already
# statically linked (including libseccomp), so no compilation is needed,
# only a checksum-pinned download, same as docker/universal/Dockerfile.
# CoreDNS ships the same way.
FROM alpine:3.24.1@sha256:28bd5fe8b56d1bd048e5babf5b10710ebe0bae67db86916198a6eec434943f8b AS deps
ARG RUNC_VERSION
ARG RUNC_SHA256_AMD64
ARG RUNC_SHA256_ARM64
ARG COREDNS_VERSION
ARG COREDNS_SHA256_AMD64
ARG COREDNS_SHA256_ARM64
RUN apk add --no-cache curl && \
    mkdir -p /opt/buildcage/bin && \
    ARCH=$(uname -m | sed 's/x86_64/amd64/' | sed 's/aarch64/arm64/') && \
    RUNC_SHA=$([ "$ARCH" = "amd64" ] && echo "$RUNC_SHA256_AMD64" || echo "$RUNC_SHA256_ARM64") && \
    curl -fsSL "https://github.com/opencontainers/runc/releases/download/${RUNC_VERSION}/runc.${ARCH}" \
      -o /opt/buildcage/bin/runc && \
    echo "${RUNC_SHA}  /opt/buildcage/bin/runc" | sha256sum -c && \
    chmod +x /opt/buildcage/bin/runc && \
    COREDNS_SHA=$([ "$ARCH" = "amd64" ] && echo "$COREDNS_SHA256_AMD64" || echo "$COREDNS_SHA256_ARM64") && \
    curl -fsSL "https://github.com/coredns/coredns/releases/download/v${COREDNS_VERSION}/coredns_${COREDNS_VERSION}_linux_${ARCH}.tgz" \
      -o /tmp/coredns.tgz && \
    echo "${COREDNS_SHA}  /tmp/coredns.tgz" | sha256sum -c && \
    tar -C /usr/local/bin -xz -f /tmp/coredns.tgz coredns

# Building gen-seccomp-profile here only compiles the binary — it's
# extracted onto the runner host and run natively there, not at image
# build time; see gen-seccomp-profile/main.go for why. Pure Go
# (CGO_ENABLED=0), so this cross-compiles natively via BUILDPLATFORM
# without needing QEMU.
FROM --platform=$BUILDPLATFORM golang:1.26-alpine@sha256:0178a641fbb4858c5f1b48e34bdaabe0350a330a1b1149aabd498d0699ff5fb2 AS gen-seccomp-profile-build
ARG TARGETOS
ARG TARGETARCH
WORKDIR /src
COPY docker/gen-seccomp-profile/go.mod docker/gen-seccomp-profile/go.sum ./
RUN go mod download
COPY docker/gen-seccomp-profile/main.go ./
RUN CGO_ENABLED=0 GOOS="${TARGETOS}" GOARCH="${TARGETARCH}" go build -trimpath -ldflags="-s -w" -o /out/gen-seccomp-profile .

# Bundle the QuickJS scripts (rolldown; see rolldown.scripts.config.js) —
# qjs has no TypeScript support. Architecture-independent output, so
# pinned to --platform=$BUILDPLATFORM like gen-seccomp-profile-build above
# (no QEMU).
FROM --platform=$BUILDPLATFORM ghcr.io/pnpm/pnpm:11@sha256:e26f380828856f205feaaf42abd157df9ce41bc8e17b662eeaa3379a9638dee0 AS qjs-build
WORKDIR /build
COPY package.json pnpm-lock.yaml pnpm-workspace.yaml ./
RUN --mount=type=cache,id=pnpm-store,target=/pnpm/store \
    pnpm install --frozen-lockfile --ignore-scripts
COPY rolldown.scripts.config.js ./
COPY src/core/ ./src/core/
COPY docker/inspect/scripts/ ./docker/inspect/scripts/
RUN --mount=type=cache,id=pnpm-store,target=/pnpm/store \
    pnpm run build:qjs

# Final image
FROM alpine:3.24.1@sha256:28bd5fe8b56d1bd048e5babf5b10710ebe0bae67db86916198a6eec434943f8b

LABEL org.opencontainers.image.title="isolated-run-inspect-proxy" \
      org.opencontainers.image.description="Network-isolated, method/path-inspecting proxy for arbitrary GitHub Actions commands" \
      org.opencontainers.image.licenses="MIT AND GPL-2.0-or-later AND Apache-2.0 AND ISC" \
      org.opencontainers.image.source="https://github.com/buildcage/isolated-run"

# haproxy carries what this engine needs in one binary: it tells a TLS
# handshake from a plain request by its first bytes, generates certificates
# for an SNI, resolves names itself, and normalises a path before matching
# it. No dnsmasq, no gettext/envsubst: CoreDNS replaces dnsmasq, and
# gen-configs.js generates haproxy.cfg directly instead of templating it.
RUN apk add --no-cache \
      s6-overlay \
      haproxy \
      openssl \
      iptables \
      curl \
      quickjs-ng

ENV S6_KEEP_ENV=1
ENV S6_LOGGING=0

COPY --from=deps /usr/local/bin/coredns /usr/local/bin/coredns

RUN mkdir -p /etc/haproxy/rules /etc/coredns /var/log/haproxy /var/log/coredns

# Tools (QuickJS scripts, rolldown-bundled by qjs-build above) —
# gen-configs.js is used by init-inspect-cfg to generate both haproxy.cfg
# and the CoreDNS Corefile from one shared rule parse, so the two can't
# describe different allowlists. No report-action.js here: src/lib/report.ts
# builds its own report in-process instead of fetching one from the
# container, same as docker/universal/Dockerfile.
COPY --from=qjs-build /build/dist/qjs/docker/inspect/scripts/gen-configs.js /opt/buildcage/scripts/gen-configs.js

# runc — extracted onto the runner host at action startup and used by
# run-isolated.sh to execute the isolated command (see docs/development.md)
COPY --from=deps /opt/buildcage/bin/runc /opt/buildcage/bin/runc

# gen-seccomp-profile — extracted onto the runner host and run natively
# there (not inside this container) to produce the seccomp filter embedded
# in runc's config.json; see the build stage comment above for why.
COPY --from=gen-seccomp-profile-build /out/gen-seccomp-profile /opt/buildcage/bin/gen-seccomp-profile

# License
COPY docker/inspect/files/THIRD_PARTY_LICENSES /opt/buildcage/THIRD_PARTY_LICENSES

# s6 service definitions and init scripts
COPY docker/inspect/files/s6-rc.d/ /etc/s6-overlay/s6-rc.d/
COPY docker/inspect/files/s6-scripts/ /etc/s6-overlay/scripts/

# Test-only. The integration fixtures serve a self-signed certificate no
# public store contains, so the proxy has to be told to trust it when it
# verifies the origin. The marker exists only in an image built with this
# arg set, so a released image has no way to be told the same thing: the
# check in init-inspect-cfg finds nothing to act on. Never set for a real
# build.
ARG BUILDCAGE_TEST_HOOKS=""
RUN if [ -n "$BUILDCAGE_TEST_HOOKS" ]; then touch /opt/buildcage/.test-hooks; fi

ENTRYPOINT ["/init"]

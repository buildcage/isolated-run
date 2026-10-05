#!/bin/sh
# PoC: rebuild the tracer and copy it and the dev scripts into the
# sandbox-dev runner. Run from the repository root.
set -e
docker run --rm -v "$PWD/docker/file-audit:/src" -v buildcage-file-audit-gocache:/root/go \
  buildcage-file-audit-build ./build.sh >/dev/null
docker cp docker/file-audit/out/file-audit-arm64 buildcage-sandbox-dev-runner:/usr/local/bin/file-audit
for f in dev/file-audit-*.sh; do
  docker cp "$f" buildcage-sandbox-dev-runner:/usr/local/bin/
done
docker cp docker/file-audit/out/evasion-arm64 buildcage-sandbox-dev-runner:/usr/local/bin/file-audit-evasion

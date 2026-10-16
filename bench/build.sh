#!/usr/bin/env bash
# Builds the tracer from origin/main and from this branch, each with the
# measuring hooks, and the stress program, into out/.
set -euo pipefail
cd "$(dirname "$0")/.."
root=$PWD
mkdir -p out
git worktree add -q /tmp/main origin/main
git worktree add -q /tmp/base origin/stack/filesystem-audit-reader/time-text
for t in main:/tmp/main base:/tmp/base pr:$root; do
	name=${t%%:*} tree=${t#*:}
	fa=$tree/docker/filesystem-audit
	cp bench/bench.go "$fa/zz_bench.go"
	perl -0pi -e 's/(\t\tif err := rec\.add\(sample\.RawSample\); err != nil \{)/\t\tbenchCount(sample.RawSample)\n$1/; s/(\t(?:return rec\.finish\(readLoss|l := readLoss)\(coll, <-missedRun\))/\tbenchReport(coll)\n$1/' "$fa/main.go"
	grep -q benchCount "$fa/main.go" && grep -q benchReport "$fa/main.go"
	docker run --rm -v "$fa":/src -v "$root/out":/out -w /src \
		golang:1.27-alpine@sha256:4cb7ac979db5fcc41cae44b2227ba5ab8a51e8807f40d9ba4dee20a0ad960b5b sh -c "
			apk add --no-cache clang llvm libbpf-dev linux-headers >/dev/null &&
			go generate ./... >/dev/null && CGO_ENABLED=0 go build -o /out/$name ."
done
mkdir -p docker/filesystem-audit/cmd/stress
cp bench/stress/main.go docker/filesystem-audit/cmd/stress/
docker run --rm -v "$root/docker/filesystem-audit":/src -v "$root/out":/out -w /src \
	golang:1.27-alpine@sha256:4cb7ac979db5fcc41cae44b2227ba5ab8a51e8807f40d9ba4dee20a0ad960b5b \
	sh -c "CGO_ENABLED=0 go build -o /out/stress ./cmd/stress"
ls -l out

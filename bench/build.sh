#!/usr/bin/env bash
# Builds the tracer from origin/main and from this branch, each with the
# measuring hooks, and the stress program, into out/.
set -euo pipefail
cd "$(dirname "$0")/.."
root=$PWD
mkdir -p out
git worktree add -q /tmp/main origin/main
git worktree add -q /tmp/l5 origin/stack/filesystem-audit-reader/wakeup-on-crossing
git worktree add -q /tmp/base origin/stack/filesystem-audit-reader/reader-hot-path
for t in main:/tmp/main base:/tmp/base pr:$root l5:/tmp/l5; do
	name=${t%%:*} tree=${t#*:}
	fa=$tree/docker/filesystem-audit
	cp bench/bench.go "$fa/zz_bench.go"
	perl -0pi -e 's/(\t\tif err := rec\.add\(sample\.RawSample\); err != nil \{)/\t\tbenchCount(rd, sample.RawSample)\n$1/; s/rd\.read\(rec\.add,/rd.read(func(b []byte) error { benchCount(nil, b); return rec.add(b) },/; s/(\t(?:return rec\.finish\(readLoss|l := readLoss)\(coll, <-missedRun\))/\tbenchReport(coll)\n$1/' "$fa/main.go"
	grep -q benchCount "$fa/main.go" && grep -q benchReport "$fa/main.go"
	if [ -e "$fa/ring.go" ]; then
		cp bench/dropscan.go "$fa/zz_dropscan.go"
		perl -0pi -e 's/(\tdefer rd\.Close\(\)\n)/$1\tbenchStart(rd, coll)\n/; s/(\tbenchReport\(coll\)\n)/\tbenchDropDump()\n$1/' "$fa/main.go"
		perl -0pi -e 's/(\t\tflushed, timedOut, err := r\.wait\(wait\)\n)/\t\tbenchWait(\x27w\x27)\n$1\t\tbenchWait(map[bool]byte{true: \x27T\x27, false: map[bool]byte{true: \x27F\x27, false: \x27D\x27}[flushed]}[timedOut])\n/' "$fa/ring.go"
		grep -q benchStart "$fa/main.go" && grep -q benchDropDump "$fa/main.go" && grep -q benchWait "$fa/ring.go"
	fi
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

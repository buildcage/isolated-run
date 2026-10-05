#!/bin/sh
# PoC build, run inside Dockerfile.build's image with this directory at /src.
set -e
[ -f go.mod ] || go mod init github.com/buildcage/file-audit
[ -f go.sum ] || go get github.com/cilium/ebpf@latest golang.org/x/sys@latest
export BPF2GO_CFLAGS="-O2 -g -Wall -I/usr/include/$(uname -m)-linux-gnu"
go generate ./...
go mod tidy
for a in amd64 arm64; do
  CGO_ENABLED=0 GOARCH=$a go build -trimpath -ldflags="-s -w" -o out/file-audit-$a .
done
ls -la out
CGO_ENABLED=0 GOARCH=arm64 go build -o out/evasion-arm64 ./evasion
CGO_ENABLED=0 GOARCH=amd64 go build -o out/evasion-amd64 ./evasion

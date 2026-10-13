#!/bin/sh
# collect-go-licenses.sh <out dir>: copies the license files of the Go standard
# library and of every module the main package in the working directory links
# into <out dir>/go/ and <out dir>/<module path>/. Run with the GOOS, GOARCH
# and CGO_ENABLED of the build. Fails on a module that ships none.
set -eu
out=$1
mods=$(mktemp)

mkdir -p "$out/go"
cp "$(go env GOROOT)/LICENSE" "$out/go/"

# Into a file first: sh has no pipefail, so a failing go list would go unseen.
go list -deps -f '{{if not .Standard}}{{with .Module}}{{if not .Main}}{{.Path}} {{.Dir}}{{end}}{{end}}{{end}}' . > "$mods"
sort -u "$mods" |
  while read -r path dir; do
    mkdir -p "$out/$path"
    found=
    for f in "$dir"/LICENSE* "$dir"/COPYING* "$dir"/NOTICE*; do
      if [ -f "$f" ]; then
        cp "$f" "$out/$path/"
        found=1
      fi
    done
    if [ -z "$found" ]; then
      echo "no license file in $path ($dir)" >&2
      exit 1
    fi
  done
rm -f "$mods"

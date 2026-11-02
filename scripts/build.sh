#!/usr/bin/env bash
set -euo pipefail
cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.."
if [[ -x .tools/go/bin/go ]]; then go_bin="$PWD/.tools/go/bin/go"; else go_bin="$(command -v go || true)"; fi
if [[ -z "$go_bin" ]]; then echo "Go 1.23+ required: https://go.dev/doc/install" >&2; exit 1; fi
export GOCACHE="$PWD/.tools/go-cache" GOMODCACHE="$PWD/.tools/go-mod"
mkdir -p bin
CGO_ENABLED=0 "$go_bin" build -trimpath -buildvcs=false -ldflags="-s -w" -o bin/nucleus ./cmd/nucleus
CGO_ENABLED=0 "$go_bin" build -trimpath -buildvcs=false -ldflags="-s -w" -o bin/nebula ./cmd/nebula
printf 'Built %s/bin/nucleus and %s/bin/nebula\n' "$PWD" "$PWD"

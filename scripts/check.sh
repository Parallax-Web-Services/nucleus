#!/usr/bin/env bash
set -euo pipefail
cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.."
if [[ -x .tools/go/bin/go ]]; then go_bin="$PWD/.tools/go/bin/go"; else go_bin="$(command -v go || true)"; fi
if [[ -z "$go_bin" ]]; then echo "Go 1.23+ required" >&2; exit 1; fi
export GOCACHE="$PWD/.tools/go-cache" GOMODCACHE="$PWD/.tools/go-mod"
gofmt_bin="$(dirname "$go_bin")/gofmt"
unformatted="$("$gofmt_bin" -l cloud hostedworker fabric inventory inference positronic internal cmd apps/resource-map/embed.go)"
if [[ -n "$unformatted" ]]; then printf 'Unformatted files:\n%s\n' "$unformatted" >&2; exit 1; fi
"$go_bin" vet ./...
"$go_bin" test -race ./...


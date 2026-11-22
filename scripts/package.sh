#!/usr/bin/env bash
# Build private, portable prototype bundles. No node state or enrollment files are included.
set -euo pipefail
umask 077
cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.."
repo_root="$PWD"
release_dir="$repo_root/dist/0.5.0-alpha"
if [[ -x .tools/go/bin/go ]]; then go_bin="$repo_root/.tools/go/bin/go"; else go_bin="$(command -v go || true)"; fi
if [[ -z "$go_bin" ]]; then echo "Go 1.23+ is required: https://go.dev/doc/install" >&2; exit 1; fi
for tool in python3 tar gzip sha256sum; do
  if ! command -v "$tool" >/dev/null 2>&1; then printf '%s is required for packaging\n' "$tool" >&2; exit 1; fi
done
if [[ -L .runtime || -L dist || -L "$release_dir" ]]; then echo "Refusing a symlinked packaging output directory" >&2; exit 1; fi
mkdir -p .runtime "$release_dir"
export GOCACHE="$repo_root/.tools/go-cache" GOMODCACHE="$repo_root/.tools/go-mod"
go_root="$(GOTOOLCHAIN=local "$go_bin" env GOROOT)"
go_version="$(GOTOOLCHAIN=local "$go_bin" env GOVERSION)"
revision="$(git rev-parse --verify HEAD 2>/dev/null || true)"
branch="$(git branch --show-current 2>/dev/null || true)"
dirty=true
if [[ -n "$revision" ]] && [[ -z "$(git status --porcelain --untracked-files=normal)" ]]; then dirty=false; fi
source_epoch="${SOURCE_DATE_EPOCH:-$(git show -s --format=%ct HEAD 2>/dev/null || printf 0)}"
if [[ ! "$source_epoch" =~ ^[0-9]+$ ]]; then echo "SOURCE_DATE_EPOCH must be a nonnegative integer" >&2; exit 1; fi
stage="$(mktemp -d "$repo_root/.runtime/package.XXXXXXXX")"
cleanup() {
  case "$stage" in
    "$repo_root"/.runtime/package.*) rm -rf -- "$stage" ;;
    *) echo "Refusing to clean an unexpected staging path" >&2 ;;
  esac
}
trap cleanup EXIT

# Include untracked implementation files, not merely the initial Git commit.
# Restrict enumeration to build inputs and packaged documentation; .tools, state,
# pairing files, logs and test installations never enter either archive or digest.
snapshot() {
  python3 - "$repo_root" <<'PY'
import hashlib
from pathlib import Path
import sys
root = Path(sys.argv[1])
files = [root / name for name in (
    "LICENSE", "go.mod", "go.sum", "nebula/testdata/php-capability-v1.json", "THIRD_PARTY_NOTICES/coder-websocket-LICENSE", "docs/NEBULA.md", "README.md", "docs/PROTOCOL.md", "docs/CROSS_DEVICE.md", "docs/HOSTED.md", "scripts/package.sh",
    "hostedworker/README.md", "docs/CPU_INFERENCE.md", "docs/MODEL_PROVENANCE_POLICY.md", "docs/MELD_INFERENCE.md",
    "inference/catalog/gemma-3-4b-it-text.json"
)]
for name in ("docs/VALIDATION.md", "docs/validation/slipstream-cross-device.json"):
    path = root / name
    if path.exists() or path.is_symlink():
        files.append(path)
for name in ("apps/resource-map", "cloud", "cmd", "fabric", "hostedworker", "inference", "internal", "inventory", "positronic", "nebula"):
    files.extend(path for path in (root / name).rglob("*")
                 if path.is_file() and path.suffix in {".go", ".html", ".css", ".js"})
for path in sorted(set(files), key=lambda path: path.relative_to(root).as_posix()):
    if path.is_symlink() or not path.is_file():
        raise SystemExit("Required packaging input is not a regular file: " + str(path))
    print(hashlib.sha256(path.read_bytes()).hexdigest() + "  " + path.relative_to(root).as_posix())
PY
}
snapshot > "$stage/source-before.sha256"
source_digest="$(sha256sum "$stage/source-before.sha256")"
source_digest="${source_digest%% *}"

for arch in amd64 arm64; do
  bundle="nucleus-0.5.0-alpha-linux-$arch"
  payload="$stage/$bundle"
  mkdir -p "$payload/bin" "$payload/docs" "$payload/THIRD_PARTY_NOTICES"
  CGO_ENABLED=0 GOOS=linux GOARCH="$arch" GOTOOLCHAIN=local \
    "$go_bin" build -trimpath -buildvcs=false -ldflags="-s -w" -o "$payload/bin/nucleus" ./cmd/nucleus
  chmod 0755 "$payload/bin/nucleus"
  cp -- LICENSE README.md "$payload/"
  cp -- docs/PROTOCOL.md docs/CROSS_DEVICE.md docs/HOSTED.md \
      docs/CPU_INFERENCE.md docs/MODEL_PROVENANCE_POLICY.md docs/MELD_INFERENCE.md docs/NEBULA.md "$payload/docs/"
  cp -- hostedworker/README.md "$payload/docs/HOSTED_WORKER.md"
  mkdir -p "$payload/inference/catalog"
  cp -- inference/catalog/gemma-3-4b-it-text.json "$payload/inference/catalog/"
  # These are the only permitted evidence inputs; never gather .runtime or logs.
  if [[ -f docs/VALIDATION.md || -f docs/validation/slipstream-cross-device.json ]]; then
    if [[ ! -f docs/VALIDATION.md || ! -f docs/validation/slipstream-cross-device.json ]]; then
      echo "Cross-device evidence is incomplete; finish both public evidence files before packaging" >&2
      exit 1
    fi
    mkdir -p "$payload/docs/validation"
    cp -- docs/VALIDATION.md "$payload/docs/VALIDATION.md"
    cp -- docs/validation/slipstream-cross-device.json "$payload/docs/validation/slipstream-cross-device.json"
  fi
  cp -- "$stage/source-before.sha256" "$payload/SOURCE_SHA256SUMS"
  cp -- "$go_root/LICENSE" "$payload/THIRD_PARTY_NOTICES/Go-LICENSE"
  cp -- THIRD_PARTY_NOTICES/coder-websocket-LICENSE "$payload/THIRD_PARTY_NOTICES/coder-websocket-LICENSE"
  if [[ -f "$go_root/PATENTS" ]]; then cp -- "$go_root/PATENTS" "$payload/THIRD_PARTY_NOTICES/Go-PATENTS"; fi
  # Preserve the standard library's vendored license notices without bundling code.
  python3 - "$go_root" "$payload" <<'PY'
from pathlib import Path
import shutil
import sys
root, payload = map(Path, sys.argv[1:])
vendor = root / "src/vendor"
if vendor.is_dir():
    for source in vendor.rglob("*"):
        if source.is_file() and source.name in {"LICENSE", "COPYING", "NOTICE", "PATENTS"}:
            target = payload / "THIRD_PARTY_NOTICES/Go-vendor" / source.relative_to(vendor)
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(source, target)
PY
  python3 - "$payload" "$arch" "$go_version" "$revision" "$branch" "$dirty" "$source_digest" "$source_epoch" <<'PY'
import hashlib
import json
from pathlib import Path
import struct
import sys
payload = Path(sys.argv[1])
arch, go_version, revision, branch, dirty, digest, epoch = sys.argv[2:]
# Static ELF executables have no PT_INTERP; validate both architectures without
# trying to run the arm64 build on an amd64 host.
with (payload / "bin/nucleus").open("rb") as binary:
    header = binary.read(64)
    if header[:6] != b"\x7fELF\x02\x01":
        raise SystemExit("Expected a little-endian 64-bit Linux ELF")
    expected_machine = {"amd64": 62, "arm64": 183}[arch]
    if struct.unpack_from("<H", header, 18)[0] != expected_machine:
        raise SystemExit("ELF architecture does not match package target")
    phoff = struct.unpack_from("<Q", header, 32)[0]
    phentsize, phnum = struct.unpack_from("<HH", header, 54)
    for index in range(phnum):
        binary.seek(phoff + index * phentsize)
        if struct.unpack("<I", binary.read(4))[0] == 3:
            raise SystemExit("Package binary unexpectedly requires a dynamic loader")
evidence = None
evidence_path = payload / "docs/validation/slipstream-cross-device.json"
if evidence_path.is_file():
    report = json.loads(evidence_path.read_text())
    binary_hash = hashlib.sha256((payload / "bin/nucleus").read_bytes()).hexdigest()
    evidence = {
        "report": "docs/validation/slipstream-cross-device.json",
        "report_sha256": hashlib.sha256(evidence_path.read_bytes()).hexdigest(),
        "reported_status": report.get("status"),
        "matches_packaged_binary": report.get("local_binary_sha256") == binary_hash and report.get("remote_binary_sha256") == binary_hash,
        "verified_at_utc": report.get("verified_at_utc")
    }
manifest = {
    "schema_version": 1,
    "name": "nucleus",
    "version": "0.5.0-alpha",
    "target": {"os": "linux", "arch": arch, "cgo_enabled": False, "static_elf": True},
    "go_version": go_version,
    "source": {
        "git_revision": revision or None,
        "git_branch": branch or None,
        "dirty": dirty == "true",
        "input_sha256": digest,
        "source_date_epoch": int(epoch),
        "note": "When dirty, git_revision alone does not reproduce this prototype; SOURCE_SHA256SUMS records the packaged build-input snapshot."
    },
    "state_included": False,
    "physical_cross_device_validation": "not_asserted_by_packaging",
    "cross_device_evidence": evidence
}
(payload / "MANIFEST.json").write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n")
PY
  snapshot > "$stage/source-after.sha256"
  if ! cmp -s "$stage/source-before.sha256" "$stage/source-after.sha256"; then
    echo "Source changed during packaging; no archive was published for this target. Re-run after edits finish." >&2
    exit 1
  fi
  (
    cd -- "$payload"
    find . -type f ! -name SHA256SUMS -print0 | sort -z | xargs -0 sha256sum > SHA256SUMS
    sha256sum --check --quiet SHA256SUMS
  )
  # Normalize timestamps, ownership, order and gzip headers for reproducible bundles.
  archive="$release_dir/$bundle.tar.gz"
  tar --sort=name --mtime="@$source_epoch" --owner=0 --group=0 --numeric-owner \
      -C "$stage" -cf - "$bundle" | gzip -n > "$stage/$bundle.tar.gz"
  mv -- "$stage/$bundle.tar.gz" "$archive"
  printf 'Packaged %s\n' "$archive"
done
(
  cd -- "$release_dir"
  sha256sum nucleus-0.5.0-alpha-linux-amd64.tar.gz nucleus-0.5.0-alpha-linux-arm64.tar.gz > SHA256SUMS
  sha256sum --check --quiet SHA256SUMS
)
printf 'Archive checksums: %s/SHA256SUMS\n' "$release_dir"

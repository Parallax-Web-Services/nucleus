#!/usr/bin/env python3
"""Build standalone NEBULA preview bundles without including local machine state."""
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import stat
import struct
import subprocess
import tarfile
import tempfile
import gzip

ROOT = Path(__file__).resolve().parent.parent
CODE = ('apps/resource-map', 'cloud', 'cmd', 'fabric', 'hostedworker', 'inference',
        'internal', 'inventory', 'positronic', 'nebula')
DOCS = ('README.md', 'docs/NEBULA_CLI.md', 'docs/NEBULA.md', 'docs/NEBULA_PLATFORM.md',
        'docs/PROTOCOL.md', 'docs/HOSTED.md', 'docs/CROSS_DEVICE.md', 'docs/CPU_INFERENCE.md',
        'docs/MODEL_PROVENANCE_POLICY.md', 'docs/MELD_INFERENCE.md', 'hostedworker/README.md')
EXACT = ('go.mod', 'go.sum', 'scripts/package-nebula.py',
         'THIRD_PARTY_NOTICES/coder-websocket-LICENSE',
         'nebula/testdata/php-capability-v1.json', 'inference/catalog/gemma-3-4b-it-text.json') + DOCS


def regular(path):
    for parent in (path, *path.parents):
        if parent == ROOT.parent:
            break
        info = parent.lstat()
        if stat.S_ISLNK(info.st_mode):
            raise SystemExit('Refusing symlinked packaging input: ' + str(path.relative_to(ROOT)))
    if not stat.S_ISREG(path.lstat().st_mode):
        raise SystemExit('Required regular packaging input: ' + str(path.relative_to(ROOT)))
    return path.read_bytes()


def inputs():
    names = set(EXACT)
    for name in CODE:
        for here, dirs, files in os.walk(ROOT / name, followlinks=False):
            for item in dirs:
                if (Path(here) / item).is_symlink():
                    raise SystemExit('Refusing symlink in code tree: ' + name)
            for item in files:
                path = Path(here) / item
                if path.suffix in ('.go', '.html', '.css', '.js'):
                    names.add(path.relative_to(ROOT).as_posix())
    return {name: regular(ROOT / name) for name in sorted(names)}


def sha(data):
    return hashlib.sha256(data).hexdigest()


def manifest(snapshot):
    return ''.join(sha(data) + '  ' + name + '\n' for name, data in snapshot.items()).encode()


def run(args, **kwargs):
    return subprocess.run(args, check=True, capture_output=True, **kwargs).stdout


def safe_directory(path):
    for part in list(reversed(path.parents)) + [path]:
        if part.exists() or part.is_symlink():
            if part.is_symlink() or not part.is_dir():
                raise SystemExit('Refusing non-directory packaging output: ' + str(part))
        else:
            part.mkdir(mode=0o700)


def static_elf(path, arch):
    with path.open('rb') as handle:
        data = handle.read(64)
        if data[:6] != b'\x7fELF\x02\x01' or struct.unpack_from('<H', data, 18)[0] != {'amd64': 62, 'arm64': 183}[arch]:
            raise SystemExit('Unexpected ELF target')
        offset = struct.unpack_from('<Q', data, 32)[0]
        size, count = struct.unpack_from('<HH', data, 54)
        for i in range(count):
            handle.seek(offset + i * size)
            if struct.unpack('<I', handle.read(4))[0] == 3:
                raise SystemExit('NEBULA unexpectedly requires a dynamic loader')


def main():
    os.umask(0o077)
    source = inputs()
    match = re.search(rb'^const NebulaVersion = "([0-9]+\.[0-9]+\.[0-9]+-(?:dev|alpha[0-9]*))"$',
                      source['internal/nucleusapp/nebula_cli.go'], re.M)
    if not match:
        raise SystemExit('Expected an explicitly named NEBULA development/alpha version')
    version = match[1].decode()
    source_sums = manifest(source)
    digest = sha(source_sums)
    go = ROOT / '.tools/go/bin/go'
    if not go.is_file():
        found = shutil.which('go')
        if not found:
            raise SystemExit('Go 1.23+ is required')
        go = Path(found)
    env = dict(os.environ, GOTOOLCHAIN='local', CGO_ENABLED='0')
    env['GOCACHE'] = str(ROOT / '.tools/go-cache')
    env['GOMODCACHE'] = str(ROOT / '.tools/go-mod')
    go_version = run([str(go), 'env', 'GOVERSION'], env=env).decode().strip()
    go_root = Path(run([str(go), 'env', 'GOROOT'], env=env).decode().strip())
    out = ROOT / 'dist/nebula' / version / digest
    safe_directory(out)
    with tempfile.TemporaryDirectory(prefix='nebula-package-') as work_name:
        work = Path(work_name)
        build = work / 'source'
        for name, data in source.items():
            path = build / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(data)
        archives = {}
        for arch in ('amd64', 'arm64'):
            name = 'nebula-' + version + '-linux-' + arch
            payload = work / name
            (payload / 'bin').mkdir(parents=True)
            binary = payload / 'bin/nebula'
            run([str(go), 'build', '-trimpath', '-buildvcs=false', '-ldflags=-s -w', '-o', str(binary), './cmd/nebula'],
                cwd=build, env=dict(env, GOOS='linux', GOARCH=arch))
            binary.chmod(0o755)
            static_elf(binary, arch)
            for doc in DOCS:
                target = payload / ('docs/HOSTED_WORKER.md' if doc == 'hostedworker/README.md' else doc)
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes(source[doc])
            for item in ('THIRD_PARTY_NOTICES/coder-websocket-LICENSE', 'inference/catalog/gemma-3-4b-it-text.json'):
                target = payload / item
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes(source[item])
            for item in ('LICENSE', 'PATENTS'):
                path = go_root / item
                if path.is_file():
                    target = payload / 'THIRD_PARTY_NOTICES' / ('Go-' + item)
                    target.write_bytes(path.read_bytes())
            vendor = go_root / 'src/vendor'
            if vendor.is_dir():
                for path in vendor.rglob('*'):
                    if path.is_file() and path.name in ('LICENSE', 'COPYING', 'NOTICE', 'PATENTS'):
                        target = payload / 'THIRD_PARTY_NOTICES/Go-vendor' / path.relative_to(vendor)
                        target.parent.mkdir(parents=True, exist_ok=True)
                        target.write_bytes(path.read_bytes())
            (payload / 'SOURCE_SHA256SUMS').write_bytes(source_sums)
            info = dict(schema_version=1, name='nebula', version=version,
                        target=dict(os='linux', arch=arch, cgo_enabled=False, static_elf=True),
                        go_version=go_version, source_input_sha256=digest, source_date_epoch=0,
                        state_included=False, release_channel='preview',
                        scope='Machine/fabric/network operations and hosted organization/cluster reads. Cluster provisioning is not included.')
            (payload / 'MANIFEST.json').write_text(json.dumps(info, indent=2, sort_keys=True) + '\n')
            sums = ''.join(sha(p.read_bytes()) + '  ' + p.relative_to(payload).as_posix() + '\n'
                           for p in sorted(payload.rglob('*')) if p.is_file())
            (payload / 'SHA256SUMS').write_text(sums)
            archive = work / (name + '.tar.gz')
            with archive.open('xb') as raw, gzip.GzipFile(filename='', mode='wb', fileobj=raw, mtime=0) as zipped:
                with tarfile.open(fileobj=zipped, mode='w') as tar:
                    for path in [payload] + sorted(payload.rglob('*')):
                        meta = tar.gettarinfo(str(path), arcname=name + (('/' + path.relative_to(payload).as_posix()) if path != payload else ''))
                        meta.uid = meta.gid = meta.mtime = 0
                        meta.uname = meta.gname = ''
                        meta.mode = 0o755 if path.is_dir() or path == binary else 0o644
                        if path.is_file():
                            with path.open('rb') as data:
                                tar.addfile(meta, data)
                        else:
                            tar.addfile(meta)
            archives[archive.name] = archive.read_bytes()
        if inputs() != source:
            raise SystemExit('Source changed during packaging; no bundle published')
        archives['SHA256SUMS'] = ''.join(sha(data) + '  ' + name + '\n' for name, data in archives.items()).encode()
        # Each source set has its own output. Existing bytes are immutable.
        for name, data in archives.items():
            dest = out / name
            try:
                fd = os.open(dest, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o644)
            except FileExistsError:
                if dest.is_symlink() or not dest.is_file() or dest.read_bytes() != data:
                    raise SystemExit('Existing package differs; preserving ' + str(dest))
            else:
                with os.fdopen(fd, 'wb') as handle:
                    handle.write(data)
                    handle.flush()
                    os.fsync(handle.fileno())
        print(json.dumps(dict(status='prepared-not-published', output=str(out), source_input_sha256=digest,
                              archives={name: sha(data) for name, data in archives.items()}), indent=2))


if __name__ == '__main__':
    main()

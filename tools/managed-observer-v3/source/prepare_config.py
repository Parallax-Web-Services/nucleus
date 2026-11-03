#!/usr/bin/env python3
"""Prepare a private binding candidate only; no HTTP requests, snapshot or services."""
import argparse
import hashlib
import json
import os
import re
import stat
import subprocess
import sys
import types
from pathlib import Path

PRODUCER_SHA = '910defc107310d48cd1f4d8679a38a0c60f8df411680faadaa7fbd1eb8dd92a7'
PREPARED = Path('/var/lib/parallax-nebula-capacity-prepared')

def need(value):
    if not value:
        raise RuntimeError()

def load_reviewed():
    path = Path(__file__).with_name('producer.py')
    fd = os.open(path,os.O_RDONLY | os.O_NOFOLLOW)
    try:
        before = os.fstat(fd)
        need(stat.S_ISREG(before.st_mode) and before.st_size <= 65536)
        raw = bytearray()
        while True:
            part = os.read(fd,65536)
            if not part:
                break
            raw.extend(part)
            need(len(raw) <= 65536)
        need(hashlib.sha256(raw).hexdigest() == PRODUCER_SHA)
        need((before.st_dev,before.st_ino,before.st_size,before.st_mtime_ns,before.st_ctime_ns) ==
             (os.fstat(fd).st_dev,os.fstat(fd).st_ino,os.fstat(fd).st_size,os.fstat(fd).st_mtime_ns,os.fstat(fd).st_ctime_ns))
    finally:
        os.close(fd)
    module = types.ModuleType('_reviewed_capacity_producer')
    module.__file__ = str(path)
    sys.modules[module.__name__] = module
    exec(compile(bytes(raw),str(path),'exec'),module.__dict__)
    return module

def main():
    os.umask(0o077)
    need(os.geteuid() == 0)
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--admission',required=True,type=Path,
                        help='root-private reviewed schema2 durable unit/identity admission')
    parser.add_argument('--stage',required=True,type=Path)
    args = parser.parse_args()
    m = load_reviewed()
    config,before = m.load_config(args.admission)
    need('microsoft' not in os.uname().release.lower())
    # Resolve the admitted managed invocation first, then explicitly validate its
    # native public identity. No HTTP request or service action is performed.
    source = m.ManagedSource(config)
    try:
        source.resolve()
        v = config['coordinator']
        # Explicit admission only, outside the collector's read-only sandbox.
        # The legacy native Load may fchmod its own state.lock while validating.
        response = subprocess.run(['/proc/self/fd/'+str(source.fd),'identity'],
            pass_fds=(source.fd,),stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,
            env={'PATH':'/usr/bin:/bin','HOME':str(m.STATE_HOME),'NUCLEUS_HOME':str(m.STATE_HOME)},
            user=v['uid'],group=v['gid'],extra_groups=[],cwd=m.STATE_HOME,umask=0o077,timeout=3)
        need(response.returncode == 0 and len(response.stdout) <= 8192)
        public = m.decode(response.stdout)
        need(type(public.get('schema_version')) is int and public['schema_version'] == 1
             and public.get('node_id') == public.get('owner_id') == config['local_node_id']
             and public.get('fabric_id') == config['fabric_id'])
        source.guard()
        need(args.stage.parent == PREPARED and re.fullmatch(r'binding-[a-f0-9]{16}',args.stage.name))
        m.safe_parents(PREPARED)
        if not os.path.lexists(PREPARED):
            PREPARED.mkdir(mode=0o700)
        m.directory_identity(PREPARED,0,0,0o700)
        need(not os.path.lexists(args.stage))
        need(m.record(args.admission,8192) == before)
        source.guard()
        args.stage.mkdir(mode=0o700)
        path = args.stage/'producer.json'
        fd = os.open(path,os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,0o600)
        with os.fdopen(fd,'w') as f:
            json.dump(config,f,sort_keys=True);f.write('\n');f.flush();os.fsync(f.fileno())
        candidate,_ = m.load_config(path)
        need(candidate == config and m.record(args.admission,8192) == before)
        source.guard()
    finally:
        source.close()
    print('{"prepared":true,"owner_on_wsl":false,"owner_on_server":true}')

if __name__ == '__main__':
    try:
        main()
    except Exception:
        print('{"prepared":false,"error":"binding_refused"}',file=sys.stderr)
        raise SystemExit(1)

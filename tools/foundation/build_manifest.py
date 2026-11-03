"""Generate a candidate source manifest on stdout. This does not review/bless it."""
import hashlib
import json
from pathlib import Path
import re
import sys
from foundation.framework import MODULES,SCRIPTS,PROFILE,need,read_regular

def build(root):
    root=Path(root).resolve(strict=True)
    exact={'__init__.py','__main__.py','framework.py','build_manifest.py','README.md','MIGRATION.md',
           'reference/README.md','provenance/reference-sources.json',PROFILE,
           'locks/kubernetes-v1.37.1-linux-amd64.json','locks/calico-v3.33.0-images.json','locks/calico-v3.33.0-nebula.yaml',
           'host/__init__.py','guest/__init__.py','adapters/__init__.py','tests/__init__.py','tests/support.py',
           *[x[0]for x in MODULES.values()],*SCRIPTS.values()}
    references={'reference/alpha-20261102/'+n for n in['host-preflight.py.reference','host-lifecycle.py.reference','fleet-health.py.reference','guest-bootstrap.py.reference','guest-cluster.py.reference']}
    files=[]
    for p in sorted(root.rglob('*')):
        if p.is_dir():need(not p.is_symlink(),'source_directory_symlink');continue
        logical=p.relative_to(root).as_posix()
        if logical=='source-manifest.json':continue
        need(logical in exact or logical in references or re.fullmatch(r'tests/test_[a-z_]+\.py',logical),'nonwhitelisted_source_path')
        raw,_=read_regular(p);files.append({'path':logical,'sha256':hashlib.sha256(raw).hexdigest(),'bytes':len(raw)})
    return {'schema_version':1,'package':'nebula-foundation-source','status':'source_only_not_live_accepted',
            'files':files,'modules':{k:{'path':v[0],'requires':v[1]}for k,v in MODULES.items()},'scripts':SCRIPTS,'profile':PROFILE}
if __name__=='__main__':
    need(len(sys.argv)==1,'no_command_knobs');print(json.dumps(build(Path(__file__).parent),indent=2,sort_keys=True))

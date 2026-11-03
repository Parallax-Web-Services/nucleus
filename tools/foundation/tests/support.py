"""Synthetic offline fixture support; never a production trust-pin source."""
import hashlib
from pathlib import Path
from foundation.framework import Bundle,FoundationContext
ROOT=Path(__file__).resolve().parents[1]
_cache={}
def bundle(root=None):
    path=ROOT if root is None else Path(root)
    # Tests intentionally trust their local candidate manifest. Real callers must
    # obtain the expected digest from a separately reviewed package/receipt.
    pin=hashlib.sha256((path/'source-manifest.json').read_bytes()).hexdigest()
    key=(str(path),pin)
    if key not in _cache:_cache[key]=Bundle.open(path,pin)
    return _cache[key]
def load_module(name):return bundle().load_module(name)
def context_fixture(role='host',root=None):
    inputs={'schema_version':1,'role':role,'host_name':'synthetic-host','libvirt_network':'synthetic-net','libvirt_pool':'synthetic-pool',
            'host_state_root':'/var/lib/nebula-foundation/synthetic/host','guest_state_root':'/var/lib/nebula-foundation/synthetic/guest',
            'run_id':'0123456789ab','expected_guest_uuid':'00000000-0000-4000-8000-000000000001',
            'api_address':'192.168.240.23','expected_protected_domain_count':1,'expected_health_member_count':5}
    return FoundationContext(bundle(root),inputs)

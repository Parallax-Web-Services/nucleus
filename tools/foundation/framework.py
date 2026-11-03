"""Explicit profile inputs and same-buffer, manifest-bound source loading.

No discovery, subprocess, network, runtime-state or privileged operation occurs here.
"""
from __future__ import annotations
import hashlib
import ipaddress
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
import sys
import types
import uuid

class Refused(RuntimeError):pass
def need(ok,code):
    if not ok:raise Refused(code)
def digest(raw):return hashlib.sha256(raw).hexdigest()
def canonical_json(value):return json.dumps(value,sort_keys=True,separators=(',',':'),allow_nan=False).encode()
def decode(raw):
    def pairs(items):
        value={}
        for key,item in items:
            need(key not in value,'duplicate_json_key');value[key]=item
        return value
    return json.loads(raw,object_pairs_hook=pairs,parse_constant=lambda _:(_ for _ in()).throw(Refused('nonfinite_json')))
def relative(value):
    need(isinstance(value,str)and value and chr(92)not in value and not any(ord(c)<32 or ord(c)==127 for c in value),'invalid_bundle_path')
    p=PurePosixPath(value)
    need(not p.is_absolute()and str(p)==value and all(x not in['.','..']for x in value.split('/')),'unsafe_bundle_path')
    return value

def read_regular(path,limit=2*1024*1024):
    need(path.is_absolute()and path.resolve()==path,'bundle_symlink_or_noncanonical_path')
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
    fields=('st_dev','st_ino','st_mode','st_uid','st_gid','st_nlink','st_size','st_mtime_ns','st_ctime_ns')
    identity=lambda s:tuple(getattr(s,k)for k in fields)
    try:
        before=os.fstat(fd)
        need(stat.S_ISREG(before.st_mode)and before.st_nlink==1 and 0<=before.st_size<=limit
             and not stat.S_IMODE(before.st_mode)&0o022,'unsafe_bundle_file')
        raw=bytearray()
        while True:
            part=os.read(fd,min(65536,limit+1-len(raw)))
            if not part:break
            raw.extend(part);need(len(raw)<=limit,'bundle_file_limit')
        need(identity(before)==identity(os.fstat(fd))==identity(path.lstat()),'bundle_file_changed_during_read')
        return bytes(raw),identity(before)
    finally:os.close(fd)

MODULES={
    'host/preflight':('host/preflight.py',[]),
    'host/lifecycle':('host/lifecycle.py',['host/preflight']),
    'guest/bootstrap':('guest/bootstrap.py',['provenance/verifier']),
    'guest/cluster':('guest/cluster.py',['guest/bootstrap']),
    'adapters/fleet-health':('adapters/nucleus_fleet_health.py',[]),
}
SCRIPTS={'provenance/verifier':'provenance/verify_official_packages.py'}
PROFILE='profiles/noble-amd64-single-v1.json'

class Bundle:
    def __init__(self,root,expected_manifest_sha256):
        self.root=Path(root)
        need(self.root.is_absolute()and self.root.resolve()==self.root and self.root.is_dir(),'canonical_bundle_root_required')
        need(isinstance(expected_manifest_sha256,str)and re.fullmatch(r'[a-f0-9]{64}',expected_manifest_sha256),'explicit_reviewed_manifest_pin_required')
        self.instance_tag=uuid.uuid4().hex
        self.expected_manifest_sha256=expected_manifest_sha256
        raw,self.manifest_record=read_regular(self.root/'source-manifest.json')
        need(digest(raw)==expected_manifest_sha256,'reviewed_manifest_mismatch');self.manifest=decode(raw)
        need(set(self.manifest)=={'schema_version','package','status','files','modules','scripts','profile'},'manifest_schema')
        need(type(self.manifest['schema_version'])is int and self.manifest['schema_version']==1
             and self.manifest['package']=='nebula-foundation-source'
             and self.manifest['status']=='source_only_not_live_accepted'and self.manifest['profile']==PROFILE,'manifest_identity')
        need(self.manifest['modules']=={k:{'path':v[0],'requires':v[1]}for k,v in MODULES.items()},'reviewed_module_graph_required')
        need(self.manifest['scripts']==SCRIPTS,'reviewed_script_inventory_required')
        self.entries={};self.records=None;self.modules={};self.loading=set()
        need(isinstance(self.manifest['files'],list)and 1<=len(self.manifest['files'])<=256,'manifest_file_count')
        for item in self.manifest['files']:
            need(isinstance(item,dict)and set(item)=={'path','sha256','bytes'},'manifest_file_schema')
            name=relative(item['path']);need(name!='source-manifest.json'and name not in self.entries,'duplicate_or_recursive_manifest_path')
            need(isinstance(item['sha256'],str)and re.fullmatch(r'[a-f0-9]{64}',item['sha256'])
                 and type(item['bytes'])is int and 0<=item['bytes']<=2*1024*1024,'manifest_digest_or_size')
            self.entries[name]=item
        need(PROFILE in self.entries and all(path in self.entries for path,_ in MODULES.values())and all(path in self.entries for path in SCRIPTS.values()),'required_package_source_missing')
        self.verify()
    @classmethod
    def open(cls,root=None,expected_manifest_sha256=None):
        need(root is not None,'explicit_bundle_root_required');return cls(root,expected_manifest_sha256)
    def verify(self):
        raw,record=read_regular(self.root/'source-manifest.json')
        need(digest(raw)==self.expected_manifest_sha256 and record==self.manifest_record,'manifest_changed')
        actual=set();records={};total=0
        for directory,names,files in os.walk(self.root,followlinks=False):
            parent=Path(directory);need(parent.resolve()==parent,'bundle_directory_symlink')
            for name in names:need(not(parent/name).is_symlink(),'bundle_directory_symlink')
            for name in files:
                path=parent/name;logical=relative(path.relative_to(self.root).as_posix())
                if logical=='source-manifest.json':continue
                need(logical in self.entries,'unlisted_bundle_file')
                data,identity=read_regular(path);item=self.entries[logical];total+=len(data)
                need(total<=8*1024*1024 and len(data)==item['bytes']and digest(data)==item['sha256'],'bundle_source_pin_mismatch')
                actual.add(logical);records[logical]=identity
        need(actual==set(self.entries),'bundle_inventory_mismatch')
        if self.records is not None:need(records==self.records,'bundle_identity_changed')
        self.records=records
    def bytes(self,name):
        name=relative(name);need(name in self.entries,'unlisted_bundle_input');self.verify()
        raw,record=read_regular(self.root/name);entry=self.entries[name]
        need(record==self.records[name]and len(raw)==entry['bytes']and digest(raw)==entry['sha256'],'bundle_input_changed')
        return raw
    def script_bytes(self,logical_name):
        need(logical_name in SCRIPTS,'unknown_verified_script');return self.bytes(SCRIPTS[logical_name])
    def load_module(self,logical_name):
        need(logical_name in MODULES,'unknown_module');self.verify()
        if logical_name in self.modules:return self.modules[logical_name]
        need(logical_name not in self.loading,'module_dependency_cycle');self.loading.add(logical_name)
        try:
            for dependency in MODULES[logical_name][1]:
                if dependency in SCRIPTS:self.script_bytes(dependency)
                else:self.load_module(dependency)
            path=MODULES[logical_name][0];raw=self.bytes(path)
            name='foundation_reviewed_'+self.expected_manifest_sha256[:16]+'_'+logical_name.replace('/','_').replace('-','_')+'_'+self.instance_tag
            module=types.ModuleType(name);module.__file__=str(self.root/path);module.__package__='foundation.'+path.split('/')[0]
            sys.modules[name]=module
            try:
                exec(compile(raw,str(self.root/path),'exec'),module.__dict__);self.verify()
            except BaseException:
                if sys.modules.get(name)is module:sys.modules.pop(name,None)
                raise
            self.modules[logical_name]=module;return module
        finally:self.loading.remove(logical_name)

class FoundationContext:
    def __init__(self,bundle,inputs):
        need(isinstance(bundle,Bundle),'reviewed_bundle_required');bundle.verify();self.bundle=bundle
        profile=decode(bundle.bytes(PROFILE));need(isinstance(profile,dict)and set(profile)=={'schema_version','id','status','platform','resources','libvirt','cluster','limits','capabilities'}and type(profile.get('schema_version'))is int and profile.get('schema_version')==1
             and profile.get('id')=='noble-amd64-single-v1'and profile.get('status')=='source_only_not_live_accepted','reviewed_profile_required')
        need(profile.get('platform')=={'os':'ubuntu','version':'24.04','codename':'noble','architecture':'amd64','machine':'x86_64'},'unsupported_platform')
        need(profile.get('resources')=={'vcpus':2,'memory_bytes':4*1024**3,'raw_disk_bytes':20*1024**3,
             'host_ram_reserve_bytes':2*1024**3,'host_cpu_reserve':2,'host_disk_reserve_bytes':10*1024**3,
             'image_staging_reserve_bytes':2*1024**3},'unreviewed_resource_profile')
        need(profile.get('libvirt')=={'uri':'qemu:///system','network_kind':'nat','pool_kind':'dir','virsh':'/usr/bin/virsh','qemu':'/usr/bin/qemu-system-x86_64'},'unreviewed_libvirt_profile')
        need(profile.get('cluster')=={'version':'v1.37.1','control_plane_count':1,'api_port':6443,'pod_cidr':'10.244.0.0/16',
             'service_cidr':'10.96.0.0/12','dns_domain':'cluster.local','cri':'unix:///run/containerd/containerd.sock'},'unreviewed_cluster_profile')
        need(profile.get('capabilities')=={'ha':False,'arm64':False,'public_installer':False,'worker_enrollment':False},'unsupported_capabilities')
        need(profile['limits']=={'max_protected_domains':128,'max_fleet_members':128},'unreviewed_safety_limits')
        need(all(type(v)is int for v in profile['resources'].values())and all(type(v)is int for v in profile['limits'].values())
             and all(type(v)is bool for v in profile['capabilities'].values())and type(profile['cluster']['control_plane_count'])is int
             and type(profile['cluster']['api_port'])is int,'profile_value_types')
        self._profile=canonical_json(profile);self._inputs=canonical_json(self.validate_inputs(inputs));self._binding={
             'manifest_sha256':bundle.expected_manifest_sha256,'profile_id':profile['id'],
             'profile_sha256':bundle.entries[PROFILE]['sha256'],'inputs_sha256':digest(self._inputs)}
    @staticmethod
    def validate_inputs(v):
        keys={'schema_version','role','host_name','libvirt_network','libvirt_pool','host_state_root','guest_state_root','run_id',
              'expected_guest_uuid','api_address','expected_protected_domain_count','expected_health_member_count'}
        need(isinstance(v,dict)and set(v)==keys and type(v['schema_version'])is int and v['schema_version']==1,'explicit_input_schema')
        need(v['role']in['host','guest','offline'],'explicit_role_required')
        for key in['host_name','libvirt_network','libvirt_pool']:
            need(isinstance(v[key],str)and re.fullmatch(r'[a-zA-Z][a-zA-Z0-9_-]{0,62}',v[key]),'invalid_admitted_name')
        for key in['host_state_root','guest_state_root']:
            name=v[key];need(isinstance(name,str),'explicit_state_root_required');path=Path(name)
            need(path.is_absolute()and str(path)==name and all(x not in['.','..']for x in name.split('/'))
                 and Path('/var/lib/nebula-foundation')in path.parents and len(path.parts)>=6
                 and all(re.fullmatch(r'[a-z0-9][a-z0-9_-]{0,63}',part)for part in path.parts[4:]),'safe_foundation_state_namespace_required')
        a,b=Path(v['host_state_root']),Path(v['guest_state_root']);need(a!=b and a not in b.parents and b not in a.parents,'state_roots_must_be_distinct')
        need(isinstance(v['run_id'],str)and re.fullmatch(r'[a-f0-9]{12}',v['run_id']),'invalid_run_id')
        need(type(v['expected_protected_domain_count'])is int and 0<=v['expected_protected_domain_count']<=128
             and type(v['expected_health_member_count'])is int and 1<=v['expected_health_member_count']<=128,'explicit_bounded_counts_required')
        if v['expected_guest_uuid']is not None:
            need(isinstance(v['expected_guest_uuid'],str),'canonical_guest_uuid_required')
            try:parsed_uuid=str(uuid.UUID(v['expected_guest_uuid']))
            except (ValueError,AttributeError):raise Refused('canonical_guest_uuid_required')from None
            need(parsed_uuid==v['expected_guest_uuid'],'canonical_guest_uuid_required')
        if v['api_address']is not None:
            need(isinstance(v['api_address'],str),'private_nonoverlapping_api_required')
            try:ip=ipaddress.ip_address(v['api_address'])
            except ValueError:raise Refused('private_nonoverlapping_api_required')from None
            need(ip.version==4 and not ip.is_loopback
              and any(ip in ipaddress.ip_network(c)for c in['10.0.0.0/8','172.16.0.0/12','192.168.0.0/16'])
              and all(ip not in ipaddress.ip_network(c)for c in['10.244.0.0/16','10.96.0.0/12']),'private_nonoverlapping_api_required')
        need(v['role']!='guest'or(v['expected_guest_uuid']is not None and v['api_address']is not None),'explicit_guest_identity_required')
        return json.loads(json.dumps(v))
    @property
    def profile(self):return json.loads(self._profile)
    @property
    def inputs(self):return json.loads(self._inputs)
    def path(self,key):
        need(key in['host_state_root','guest_state_root'],'unknown_state_path');return Path(self.inputs[key])
    def binding(self):return dict(self._binding)
    def guard(self):
        self.bundle.verify();need(canonical_json(self.validate_inputs(self.inputs))==self._inputs,'context_inputs_changed')
        need(digest(self.bundle.bytes(PROFILE))==self._binding['profile_sha256'],'context_profile_changed')
    def load_module(self,name):self.guard();return self.bundle.load_module(name)
    def script_bytes(self,name):self.guard();return self.bundle.script_bytes(name)

def require_context(context,role):
    need(isinstance(context,FoundationContext),'explicit_validated_foundation_context_required');context.guard()
    need(context.inputs['role']==role,'context_role_mismatch');return context

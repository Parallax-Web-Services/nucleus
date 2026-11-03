"""Strict source-bundle portability fixtures. No runtime profiles or host probes."""
import builtins
import copy
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import types
import unittest
from unittest.mock import patch
from foundation import framework as f
from tests.support import ROOT,context_fixture


def write(path,raw):
    path.parent.mkdir(parents=True,exist_ok=True)
    path.write_bytes(raw)
    path.chmod(0o644)


class PublicBundleFixture:
    """Copy only the manifest's explicit public inventory, never a directory tree."""
    def __init__(self):
        self.temp=tempfile.TemporaryDirectory(prefix='foundation-public-bundle-')
        self.base=Path(self.temp.name)
        self.root=self.base/'foundation'
        raw=(ROOT/'source-manifest.json').read_bytes()
        self.manifest=f.decode(raw)
        for item in self.manifest['files']:
            name=f.relative(item['path'])
            data,_=f.read_regular(ROOT/name)
            if len(data)!=item['bytes']or f.digest(data)!=item['sha256']:
                raise AssertionError('source fixture manifest must be regenerated before tests')
            write(self.root/name,data)
        write(self.root/'source-manifest.json',raw)
        self.pin=f.digest(raw)

    def close(self):self.temp.cleanup()
    def open(self):return f.Bundle.open(self.root,self.pin)
    def manifest_bytes(self,raw):
        write(self.root/'source-manifest.json',raw)
        self.pin=f.digest(raw)
    def save_manifest(self):self.manifest_bytes(f.canonical_json(self.manifest)+b'\n')
    def repin(self,name,raw):
        write(self.root/name,raw)
        entry=next(item for item in self.manifest['files']if item['path']==name)
        entry.update(sha256=f.digest(raw),bytes=len(raw))
        self.save_manifest()
    def replace_same(self,path):
        other=self.base/'replacement'
        write(other,path.read_bytes())
        os.replace(other,path)


class FrameworkBundleTests(unittest.TestCase):
    def fixture(self):
        fixture=PublicBundleFixture();self.addCleanup(fixture.close);return fixture

    def test_relocated_inventory_and_modules_use_only_copied_public_files(self):
        fixture=self.fixture();bundle=fixture.open()
        self.assertEqual(set(bundle.entries),{p.relative_to(fixture.root).as_posix()for p in fixture.root.rglob('*')if p.is_file()}-{'source-manifest.json'})
        original=f.read_regular
        def local_only(path,*args,**kwargs):
            self.assertIn(fixture.root,Path(path).parents)
            return original(path,*args,**kwargs)
        with patch.object(f,'read_regular',side_effect=local_only):
            module=bundle.load_module('host/lifecycle')
            self.assertTrue(Path(module.__file__).is_relative_to(fixture.root))
            self.assertIn('host/preflight',bundle.modules)
        self.assertEqual(bundle.bytes('locks/kubernetes-v1.37.1-linux-amd64.json'),(fixture.root/'locks/kubernetes-v1.37.1-linux-amd64.json').read_bytes())

    def test_fresh_python_imports_relocated_package_without_original_pythonpath(self):
        fixture=self.fixture()
        code="import json,sys;from pathlib import Path;root=Path(sys.argv[1]);sys.path.insert(0,str(root.parent));from foundation.framework import Bundle;b=Bundle.open(root,sys.argv[2]);m=b.load_module('host/preflight');print(json.dumps({'module':m.__file__,'framework':sys.modules['foundation.framework'].__file__}))"
        result=subprocess.run([sys.executable,'-B','-c',code,str(fixture.root),fixture.pin],cwd=fixture.base,
                              env={'PATH':os.environ.get('PATH','/usr/bin:/bin'),'PYTHONDONTWRITEBYTECODE':'1'},capture_output=True,text=True,timeout=10)
        self.assertEqual(result.returncode,0,result.stderr)
        loaded=json.loads(result.stdout)
        self.assertTrue(all(Path(path).is_relative_to(fixture.root)for path in loaded.values()))

    def test_source_content_and_identical_inode_replacement_are_refused(self):
        for change in ['content','inode','same_inode_write']:
            with self.subTest(change=change):
                fixture=self.fixture();bundle=fixture.open();path=fixture.root/'host/preflight.py'
                if change=='content':write(path,path.read_bytes()+b'\n# changed public source\n')
                elif change=='inode':fixture.replace_same(path)
                else:path.write_bytes(path.read_bytes())
                with self.assertRaises(f.Refused):bundle.verify()

    def test_manifest_pin_content_and_identical_replacement_drift_are_refused(self):
        for change in ['wrong_pin','changed_bytes','new_inode']:
            with self.subTest(change=change):
                fixture=self.fixture()
                if change=='wrong_pin':
                    with self.assertRaises(f.Refused):f.Bundle.open(fixture.root,'0'*64)
                    continue
                bundle=fixture.open()
                if change=='changed_bytes':write(fixture.root/'source-manifest.json',(fixture.root/'source-manifest.json').read_bytes()+b' ')
                else:fixture.replace_same(fixture.root/'source-manifest.json')
                with self.assertRaises(f.Refused):bundle.verify()

    def test_unlisted_unknown_file_is_rejected_without_reading_its_bytes(self):
        fixture=self.fixture();bundle=fixture.open();unknown=fixture.root/'synthetic-unlisted.env'
        write(unknown,b'UNREAD-SYNTHETIC-CANARY')
        original=f.read_regular;read_paths=[]
        def guarded(path,*args,**kwargs):
            read_paths.append(Path(path));self.assertNotEqual(Path(path),unknown)
            return original(path,*args,**kwargs)
        with patch.object(f,'read_regular',side_effect=guarded),self.assertRaisesRegex(f.Refused,'unlisted_bundle_file'):bundle.verify()
        self.assertNotIn(unknown,read_paths)

    def test_symlink_files_directories_hardlinks_and_writable_code_are_refused(self):
        for kind in ['file_link','directory_link','hardlink','writable']:
            with self.subTest(kind=kind):
                fixture=self.fixture();path=fixture.root/'host/preflight.py'
                if kind=='file_link':
                    retained=fixture.base/'retained.py';path.rename(retained);path.symlink_to(retained)
                elif kind=='directory_link':
                    retained=fixture.base/'retained-host';(fixture.root/'host').rename(retained);(fixture.root/'host').symlink_to(retained,target_is_directory=True)
                elif kind=='hardlink':os.link(path,fixture.base/'retained-link')
                else:path.chmod(0o666)
                with self.assertRaises(f.Refused):fixture.open()

    def test_manifest_paths_reject_traversal_backslashes_controls_and_duplicates(self):
        for name in ['../escape.py','/absolute.py','host/../escape.py','host\\escape.py','host/./preflight.py','host//preflight.py','host/line\nname.py','host/tab\tname.py','host/delete\x7fname.py']:
            with self.subTest(name=repr(name)):
                fixture=self.fixture();fixture.manifest['files'][0]['path']=name;fixture.save_manifest()
                with self.assertRaises(f.Refused):fixture.open()
        fixture=self.fixture();fixture.manifest['files'].append(copy.deepcopy(fixture.manifest['files'][0]));fixture.save_manifest()
        with self.assertRaises(f.Refused):fixture.open()

    def test_manifest_unknown_schema_modules_scripts_and_duplicate_json_are_refused(self):
        changes=[lambda x:x.update(unexpected=True),lambda x:x.update(schema_version=True),
                 lambda x:x['modules'].update({'unknown/module':{'path':'host/preflight.py','requires':[]}}),
                 lambda x:x['modules']['host/lifecycle'].update(requires=['unknown/module']),
                 lambda x:x['scripts'].update({'unknown/script':'host/preflight.py'}),
                 lambda x:x['files'][0].update(bytes=True),lambda x:x['files'][0].update(sha256='g'*64)]
        for change in changes:
            with self.subTest(change=changes.index(change)):
                fixture=self.fixture();change(fixture.manifest);fixture.save_manifest()
                with self.assertRaises(f.Refused):fixture.open()
        fixture=self.fixture();raw=f.canonical_json(fixture.manifest);fixture.manifest_bytes(b'{"schema_version":1,'+raw[1:])
        with self.assertRaisesRegex(f.Refused,'duplicate_json_key'):fixture.open()

    def test_declared_script_dependency_is_verified_data_and_never_executed(self):
        fixture=self.fixture();script=b"raise AssertionError('a verified data script must not execute during import')\n"
        fixture.repin('provenance/verify_official_packages.py',script);bundle=fixture.open()
        module=bundle.load_module('guest/bootstrap')
        self.assertIsInstance(module,types.ModuleType)
        self.assertEqual(bundle.script_bytes('provenance/verifier'),script)
        self.assertNotIn('provenance/verifier',bundle.modules)
        with self.assertRaisesRegex(f.Refused,'unknown_module'):bundle.load_module('provenance/verifier')
        with self.assertRaisesRegex(f.Refused,'unknown_verified_script'):bundle.script_bytes('unknown/script')

    def test_loader_compiles_accepted_buffer_and_removes_module_after_post_read_race(self):
        fixture=self.fixture();accepted=b"import builtins\nbuiltins._foundation_buffer_events.append('accepted')\n"
        fixture.repin('host/preflight.py',accepted);bundle=fixture.open();path=fixture.root/'host/preflight.py'
        before=set(sys.modules);compiler=builtins.compile
        def replaced_after_read(raw,filename,mode,*args,**kwargs):
            if filename==str(path):write(path,b"raise AssertionError('foreign path must never execute')\n")
            return compiler(raw,filename,mode,*args,**kwargs)
        with patch.object(builtins,'_foundation_buffer_events',[],create=True),patch.object(f,'compile',side_effect=replaced_after_read,create=True):
            with self.assertRaises(f.Refused):bundle.load_module('host/preflight')
            self.assertEqual(builtins._foundation_buffer_events,['accepted'])
        self.assertNotIn('host/preflight',bundle.modules);self.assertEqual(bundle.loading,set())
        self.assertFalse(any(name not in before and name.startswith('foundation_reviewed_')and name.endswith(bundle.instance_tag)for name in sys.modules))

    def test_execution_failure_cleans_module_and_loading_state(self):
        fixture=self.fixture();fixture.repin('host/preflight.py',b"raise RuntimeError('synthetic_import_refused')\n");bundle=fixture.open();before=set(sys.modules)
        with self.assertRaisesRegex(RuntimeError,'synthetic_import_refused'):bundle.load_module('host/preflight')
        self.assertEqual(bundle.loading,set());self.assertNotIn('host/preflight',bundle.modules)
        self.assertFalse(any(name not in before and name.startswith('foundation_reviewed_')and name.endswith(bundle.instance_tag)for name in sys.modules))

    def test_independent_relocated_bundle_instances_do_not_share_module_objects(self):
        a=self.fixture().open();b=self.fixture().open()
        first=a.load_module('host/preflight');second=b.load_module('host/preflight')
        self.assertIsNot(first,second);self.assertNotEqual(first.__name__,second.__name__)
        self.assertIs(a.load_module('host/preflight'),first)

    def test_unknown_loader_names_are_refused_before_bundle_file_reads(self):
        bundle=self.fixture().open()
        with patch.object(f,'read_regular')as reader:
            with self.assertRaises(f.Refused):bundle.load_module('../host/preflight')
            with self.assertRaises(f.Refused):bundle.script_bytes('unknown')
            reader.assert_not_called()


class FrameworkContextTests(unittest.TestCase):
    def fixture(self):
        fixture=PublicBundleFixture();self.addCleanup(fixture.close);return fixture

    def test_context_copies_inputs_profile_and_binding_and_requires_exact_role(self):
        fixture=self.fixture();bundle=fixture.open();inputs=context_fixture(role='host').inputs
        context=f.FoundationContext(bundle,inputs);original=context.binding();inputs['host_name']='changed-after-admission'
        copied=context.inputs;copied['run_id']='f'*12
        profile=context.profile;profile['capabilities']['ha']=True
        binding=context.binding();binding['manifest_sha256']='0'*64
        self.assertEqual(context.binding(),original);self.assertNotEqual(context.inputs['host_name'],inputs['host_name'])
        self.assertFalse(context.profile['capabilities']['ha']);self.assertIs(f.require_context(context,'host'),context)
        with self.assertRaisesRegex(f.Refused,'context_role_mismatch'):f.require_context(context,'guest')
        with self.assertRaises(f.Refused):context.path('arbitrary')

    def test_context_and_bundle_have_no_implicit_root_profile_or_host_probe(self):
        with patch.object(f,'read_regular')as reader,patch.object(subprocess,'run')as command:
            with self.assertRaises(f.Refused):f.Bundle.open()
            with self.assertRaises(f.Refused):f.Bundle.open(ROOT)
            with self.assertRaises(f.Refused):f.require_context(None,'host')
            with self.assertRaises(f.Refused):f.FoundationContext(object(),{})
            reader.assert_not_called();command.assert_not_called()

    def test_explicit_inputs_refuse_unsafe_paths_ids_counts_addresses_and_roles(self):
        base=context_fixture(role='host').inputs
        changes=[('role','unknown'),('run_id','../foreign'),('host_name','host;command'),
                 ('libvirt_network','-foreign'),('libvirt_pool','qemu:///session'),
                 ('host_state_root','/tmp/source-default'),('host_state_root','/var/lib/nebula-foundation/site/../host'),
                 ('host_state_root','/var/lib/nebula-foundation/site/host\\escape'),
                 ('host_state_root','/var/lib/nebula-foundation/site/host\nline'),
                 ('guest_state_root',base['host_state_root']),('guest_state_root',base['host_state_root']+'/child'),
                 ('expected_protected_domain_count',True),('expected_health_member_count',0),
                 ('expected_guest_uuid','not-a-uuid'),('api_address','8.8.8.8'),('api_address','127.0.0.1'),
                 ('api_address','10.244.1.2'),('api_address','10.96.1.2'),('api_address',3232235777)]
        for key,value in changes:
            with self.subTest(key=key,value=repr(value)),self.assertRaises(f.Refused):f.FoundationContext.validate_inputs({**base,key:value})
        with self.assertRaises(f.Refused):f.FoundationContext.validate_inputs({key:value for key,value in base.items()if key!='expected_health_member_count'})
        with self.assertRaises(f.Refused):f.FoundationContext.validate_inputs({**base,'unexpected':True})
        with self.assertRaises(f.Refused):f.FoundationContext.validate_inputs({**base,'role':'guest','expected_guest_uuid':None})

    def test_profile_requires_exact_reviewed_platform_resources_limits_and_value_types(self):
        changes=[lambda p:p.update(unexpected=True),lambda p:p.update(schema_version=True),
                 lambda p:p['platform'].update(architecture='arm64'),lambda p:p['resources'].update(vcpus=4),
                 lambda p:p['resources'].update(vcpus=2.0),lambda p:p['cluster'].update(control_plane_count=True),
                 lambda p:p['capabilities'].update(ha=0),lambda p:p['limits'].update(max_fleet_members=128.0),
                 lambda p:p['libvirt'].update(uri='qemu:///session')]
        inputs=context_fixture(role='host').inputs
        for change in changes:
            with self.subTest(change=changes.index(change)):
                fixture=self.fixture();profile=f.decode((fixture.root/f.PROFILE).read_bytes());change(profile);fixture.repin(f.PROFILE,f.canonical_json(profile)+b'\n')
                with self.assertRaises(f.Refused):f.FoundationContext(fixture.open(),inputs)

    def test_context_guard_refuses_profile_source_or_manifest_drift(self):
        fixture=self.fixture();context=f.FoundationContext(fixture.open(),context_fixture(role='host').inputs)
        path=fixture.root/f.PROFILE;write(path,path.read_bytes()+b' ')
        with self.assertRaises(f.Refused):context.guard()


if __name__=='__main__':unittest.main(verbosity=2)

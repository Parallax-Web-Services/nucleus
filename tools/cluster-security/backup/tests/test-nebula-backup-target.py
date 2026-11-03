#!/usr/bin/env python3
"""Offline target fixtures: synthetic keys/ciphertext/snapshots and fake runner only."""
import base64
import contextlib
import copy
import importlib.util
import io
import json
import os
from pathlib import Path
import stat
import sys
import tarfile
import tempfile
import time
import unittest
from contextlib import ExitStack
from unittest.mock import patch

sys.dont_write_bytecode=True
SOURCE=Path('/tmp/nebula-backup-target.py')
spec=importlib.util.spec_from_file_location('backup_target_under_test',SOURCE)
M=importlib.util.module_from_spec(spec);sys.modules[spec.name]=M;spec.loader.exec_module(M)
OP='0123456789abcdef0123456789abcdef'
OWN={'primary_fingerprint':'A'*40,'encryption_subkey_fingerprint':'B'*40}
OTHER={'primary_fingerprint':'C'*40,'encryption_subkey_fingerprint':'D'*40}
PUBLIC=b'-----BEGIN PGP PUBLIC KEY BLOCK-----\nSYNTHETIC PUBLIC FIXTURE ONLY\n-----END PGP PUBLIC KEY BLOCK-----\n'
TOOL=b'SYNTHETIC ETCDUTL FIXTURE; NEVER EXECUTE\n'
SNAP=b'SYNTHETIC SNAPSHOT FIXTURE; NOT AN ETCD DATABASE\n'
CIPHER=b'SYNTHETIC CIPHERTEXT; NOT ENCRYPTED DATA\n'


def private_file(path,raw,mode=0o600):
    path.parent.mkdir(parents=True,exist_ok=True,mode=0o700)
    path.write_bytes(raw);path.chmod(mode)


def tar_bytes(entries,format=tarfile.USTAR_FORMAT):
    output=io.BytesIO()
    with tarfile.open(fileobj=output,mode='w',format=format)as archive:
        for name,body,kind in entries:
            item=tarfile.TarInfo(name);item.mode=0o600
            if kind=='pax':item.pax_headers={'comment':'hidden metadata'};item.size=len(body)
            elif kind=='symlink':item.type=tarfile.SYMTYPE;item.linkname='foreign'
            elif kind=='hardlink':item.type=tarfile.LNKTYPE;item.linkname='backup.tar.gpg'
            else:item.size=len(body)
            archive.addfile(item,io.BytesIO(body)if item.isfile()else None)
    return output.getvalue()


def key_metadata(sub=True,curve='cv25519',primary_caps='cEC',lifetime=365*86400):
    now=int(time.time())-10
    def key(kind,algorithm,cap,curve):
        row=['']*17;row[0]=kind;row[1]='u';row[2]='255';row[3]=algorithm;row[5]=str(now);row[6]=str(now+lifetime);row[11]=cap;row[16]=curve
        return ':'.join(row)
    def fingerprint(value):return ':'.join(['fpr']+['']*8+[value])
    rows=[key('pub','22',primary_caps,'ed25519'),fingerprint(OWN['primary_fingerprint'])]
    if sub:rows +=[key('sub','18','e',curve),fingerprint(OWN['encryption_subkey_fingerprint'])]
    return '\n'.join(rows)+'\n'


class FakeRunner:
    def __init__(self,fixture):
        self.f=fixture;self.calls=[];self.subkey=False;self.fail=set();self.hooks={}
        self.version=b'gpg (GnuPG) 2.4.4\n';self.etcd_version=b'etcdutl version: 3.7.0\n'
        self.status_override=None;self.restored_override=None
    def __call__(self,work,args,label,**kwargs):
        self.calls.append((label,list(args),dict(kwargs)))
        if label in ['keyinit-memory-profile','restore-memory-profile','offline-etcd-restore']:
            if kwargs.get('execution_profile')!='etcd-restore'or kwargs.get('address_limit')!=16*1024**3:raise AssertionError('explicit fixed etcd-restore memory profile required')
        if label in ['etcdutl-version','independent-snapshot-status','restored-database-status']:
            if kwargs.get('address_limit')!=2*1024**3 or kwargs.get('execution_profile')is not None:raise AssertionError('version/status commands must retain default2GiB profile')
        if label in ['keyinit-memory-profile','restore-memory-profile']:
            if args[:2]!=['/usr/bin/python3','-c']or args[2]!=M.PROFILE_PROBE:raise AssertionError('fixed probe source only')
            fd=int(args[-1]);metadata=os.fstat(fd)
            if kwargs.get('pass_fds')!=(fd,)or(metadata.st_uid,metadata.st_gid,stat.S_IMODE(metadata.st_mode),metadata.st_size)!=(0,0,0o600,4096):raise AssertionError('probe must receive exactly our held root0600 4096-byte file')
            cohort='keyinit'if label.startswith('keyinit')else'restore'
            if Path(os.readlink('/proc/self/fd/'+str(fd)))!=Path(work)/(cohort+'-memory-probe.bin'):raise AssertionError('probe FD must name this operation output')
            if os.pread(fd,4097,0)!=b'\0'*4096:raise AssertionError('probe input must contain only synthetic zero bytes')
        if label in self.hooks:return self.hooks[label](work,args,kwargs)
        if label in self.fail:raise self.f.m.Refused('synthetic_'+label.replace('-','_'))
        if label in ['keyinit-memory-profile','restore-memory-profile']:return self.f.m.json_bytes({'schema_version':1,'readonly_file_mapping_verified':True,'anonymous_mapping_cap_verified':True})
        if label=='gpg-version':return self.version
        if label=='generate-primary':
            keys=Path(work)/'gnupg/private-keys-v1.d';keys.mkdir(mode=0o700);private_file(keys/('1'*40+'.key'),b'SYNTHETIC PRIVATE PLACEHOLDER; NOT A CRYPTOGRAPHIC KEY');return b''
        if label=='generate-subkey':
            self.subkey=True;private_file(Path(work)/'gnupg/private-keys-v1.d'/('2'*40+'.key'),b'SYNTHETIC PRIVATE PLACEHOLDER; NOT A CRYPTOGRAPHIC KEY');return b''
        if label=='public-key-metadata':return key_metadata(sub=self.subkey).encode()
        if label=='export-public':return PUBLIC
        if label=='etcdutl-version':return self.etcd_version
        if label=='verify-envelope-signature':return b''
        if label=='decrypt-private-envelope':
            destination=args[args.index('--output')+1]
            if '--yes'not in args or not destination.startswith('/proc/self/fd/'):raise AssertionError('GPG --yes must be paired with our retained output FD')
            out=int(destination.rsplit('/',1)[1]);status=int(args[args.index('--status-fd')+1])
            metadata=os.fstat(out)
            if (metadata.st_uid,metadata.st_gid,stat.S_IMODE(metadata.st_mode))!=(0,0,0o600)or Path(os.readlink(destination))!=Path(work)/'plaintext.tar':raise AssertionError('decrypt output must be our exclusive private plaintext file')
            if out not in kwargs['pass_fds']or status not in kwargs['pass_fds']:raise AssertionError('private output descriptors must be retained')
            os.write(out,self.f.plaintext);os.write(status,self.f.gpg_status);return b''
        if label=='independent-snapshot-status':return self.f.m.json_bytes(self.status_override or self.f.snapshot_status)
        if label=='offline-etcd-restore':
            destination=args[args.index('--data-dir')+1]
            if not destination.startswith('/proc/self/fd/'):raise AssertionError('restore must use held directory fd')
            fd=int(destination.rsplit('/',1)[1])
            if fd not in kwargs['pass_fds']:raise AssertionError('restore dir fd must remain open')
            root=Path(os.readlink(destination))
            (root/'member'/'snap').mkdir(parents=True,mode=0o700)
            (root/'member').chmod(0o700);(root/'member'/'snap').chmod(0o700)
            private_file(root/'member'/'snap'/'db',b'SYNTHETIC RESTORED DATABASE; NO REAL RESTORE\n')
            return b''
        if label=='restored-database-status':
            return self.f.m.json_bytes(self.restored_override or {**self.f.snapshot_status,'revision':self.f.snapshot_status['revision']+1_000_000_000})
        raise AssertionError('unexpected executable/phase label: '+label)
    def labels(self):return [label for label,_,_ in self.calls]


class Fixture:
    def __init__(self):
        self.temp=tempfile.TemporaryDirectory(prefix='nebula-backup-target-test-',dir='/root')
        self.root=Path(self.temp.name);self.root.chmod(0o700);self.stack=ExitStack();self.jobs=[]
        sources=self.root/'sources';sources.mkdir(mode=0o700)
        for name in ['nebula-backup-common.py','nebula-backup-envelope-policy.py']:
            private_file(sources/name,(Path('/tmp')/name).read_bytes(),0o644)
        self.stack.enter_context(patch.object(M,'__file__',str(sources/'nebula-backup-target.py')))
        self.m=M.load_common();self.p=self.m.policy()
        parent=self.root/'targets';parent.mkdir(mode=0o700)
        self.namespace=parent/'tarragon';self.other=parent/'slipstream'
        self.stack.enter_context(patch.object(M,'NAMESPACES',{'Tarragon':(str(self.namespace),4096),'Slipstream':(str(self.other),4096)}))
        self.stack.enter_context(patch.object(M.socket,'gethostname',return_value='tarragon.synthetic'))
        self.stack.enter_context(patch.object(M.Target,'require_memory',return_value=True))
        self.plan=self.root/'plan.json';self.plan_data={'schema_version':1,'operation_id':OP,'target':'Tarragon','namespace':str(self.namespace),'minimum_free_bytes':4096}
        private_file(self.plan,self.m.json_bytes(self.plan_data));self.runner=FakeRunner(self)
        self.snapshot_status={'hash':123,'revision':42,'totalKey':2,'totalSize':len(SNAP),'version':'3.7.0'}
        self.gpg_status=('[GNUPG:] DECRYPTION_KEY '+OWN['encryption_subkey_fingerprint']+' '+OWN['primary_fingerprint']+' u\n[GNUPG:] DECRYPTION_INFO 2 9\n[GNUPG:] DECRYPTION_OKAY\n[GNUPG:] GOODMDC\n').encode()
        self.signer='-----BEGIN PUBLIC KEY-----\n'+base64.b64encode(bytes.fromhex('302a300506032b6570032100')+bytes(range(32))).decode()+'\n-----END PUBLIC KEY-----'
        self.payloads={name:(SNAP if name=='snapshot.db'else b'SYNTHETIC RECOVERY PLACEHOLDER; NOT REAL KEY OR CREDENTIAL: '+name.encode())for name in M.CRITICAL_FILES}
        self.manifest=self.inner_manifest()
        self.plaintext=self.inner()
    def close(self):
        for job in self.jobs:job.close()
        self.stack.close();self.temp.cleanup()
    def job(self,phase='check'):
        job=M.Target(self.plan,phase,self.m,runner=self.runner);self.jobs.append(job);return job
    def init(self):
        job=self.job('init-keys');job.init_keys();return job
    def config(self):
        return {'schema_version':1,'operation_id':OP,'recipients':{'Tarragon':dict(OWN),'Slipstream':dict(OTHER)},
                'signer_public_pem':self.signer,'signer_public_sha256':self.m.sha(self.signer.encode()),
                'etcd_version':'3.7.0','etcdutl_sha256':self.m.sha(TOOL),'etcdutl_bytes':len(TOOL)}
    def configured(self):
        job=self.init();job.stage_etcdutl(io.BytesIO(TOOL),self.m.sha(TOOL),len(TOOL));job.configure(self.m.json_bytes(self.config()));return job
    def inner_manifest(self):
        return {'schema_version':1,'operation_id':OP,'expected_uuid':'00000000-0000-4000-8000-000000000001','run_id':'0123456789ab','api_address':'192.168.240.23','etcd_version':'3.7.0','snapshot_status':dict(self.snapshot_status),'source_cluster_sha256':M.CLUSTER_SHA,
                'archive_members':[{'name':name,'kind':'regular','size':len(raw)}for name,raw in sorted(self.payloads.items())]}
    def inner(self):
        return tar_bytes([(name,raw,'file')for name,raw in sorted(self.payloads.items())]+[('restore-manifest.json',self.m.json_bytes(self.manifest),'file')])
    def envelope(self,config=None,cipher=CIPHER,manifest=None,signature=b'S'*64):
        config=self.config()if config is None else config
        raw=self.p.ciphertext_manifest(OP,self.m.sha(CIPHER),len(CIPHER),config['recipients'],config['signer_public_sha256'],int(time.time()))if manifest is None else manifest
        return tar_bytes([('backup.tar.gpg',cipher,'file'),('manifest.json',raw,'file'),('manifest.sig',signature,'file')])
    def received(self):
        job=self.configured();job.receive(io.BytesIO(self.envelope()));return job
    def parse(self,raw,outer=True):
        path=self.root/('outer-fixture.tar'if outer else'inner-fixture.tar');private_file(path,raw)
        with self.m.pinned(path,len(raw),True)as(fd,meta):return M.strict_tar(fd,meta[6],outer,self.m)


@unittest.skipUnless(os.geteuid()==0,'isolated root-private fixtures only')
class TargetTests(unittest.TestCase):
    def fixture(self):
        fixture=Fixture();self.addCleanup(fixture.close);return fixture

    def test_each_required_provenance_input_missing_or_empty_blocks_restore(self):
        names=['restore-inputs/control-plane-images.lock.json','restore-inputs/calico-image-pins.json','restore-inputs/calico-3.33.0-nebula.yaml']
        self.assertTrue(set(names)<=M.CRITICAL_FILES)
        for name in names:
            for kind in ['missing','empty']:
                with self.subTest(name=name,kind=kind):
                    f=self.fixture()
                    if kind=='missing':f.payloads.pop(name)
                    else:f.payloads[name]=b''
                    f.manifest=f.inner_manifest();f.plaintext=f.inner();job=f.received()
                    with self.assertRaisesRegex(RuntimeError,'critical_recovery_material_missing'):job.verify_restore()
                    self.assertNotIn('offline-etcd-restore',f.runner.labels())
                    self.assertFalse((job.work/'state-restored.json').exists())

    def test_memory_available_parser_requires_single_six_gib_or_greater_value(self):
        f=self.fixture();exact=6*1024**2
        self.assertTrue(M.memory_available(('MemAvailable: '+str(exact)+' kB\n').encode(),f.m))
        bad=[('MemAvailable: '+str(exact-1)+' kB\n').encode(),b'MemTotal: 99999999 kB\n',('MemAvailable: '+str(exact)+' kB\n') .encode()*2,b'MemAvailable: 99999999 MB\n']
        for raw in bad:
            with self.subTest(raw=raw[:30]),self.assertRaises(RuntimeError):M.memory_available(raw,f.m)

    def test_insufficient_memory_refuses_init_before_namespace_or_runner(self):
        f=self.fixture()
        with patch.object(M.Target,'require_memory',side_effect=f.m.Refused('restore_memory_headroom_required')):
            with self.assertRaisesRegex(RuntimeError,'restore_memory_headroom_required'):f.job('init-keys')
        self.assertFalse(f.namespace.exists());self.assertEqual(f.runner.calls,[])

    def test_bad_keyinit_memory_probe_result_blocks_key_generation(self):
        results=[{'schema_version':True,'readonly_file_mapping_verified':True,'anonymous_mapping_cap_verified':True},
                 {'schema_version':2,'readonly_file_mapping_verified':True,'anonymous_mapping_cap_verified':True},
                 {'schema_version':1,'readonly_file_mapping_verified':False,'anonymous_mapping_cap_verified':True},
                 {'schema_version':1,'readonly_file_mapping_verified':True,'anonymous_mapping_cap_verified':False},
                 {'schema_version':1,'readonly_file_mapping_verified':True}]
        for result in results:
            with self.subTest(result=result):
                f=self.fixture();job=f.job('init-keys')
                f.runner.hooks['keyinit-memory-profile']=lambda work,args,kwargs:f.m.json_bytes(result)
                with self.assertRaisesRegex(RuntimeError,'memory_profile_not_verified'):job.init_keys()
                self.assertNotIn('generate-primary',f.runner.labels());self.assertFalse((job.work/'gnupg').exists());self.assertFalse((job.work/'state-keys.json').exists())

    def test_bad_restore_memory_probe_result_blocks_decryption(self):
        f=self.fixture();job=f.received()
        f.runner.hooks['restore-memory-profile']=lambda work,args,kwargs:f.m.json_bytes({'schema_version':1,'readonly_file_mapping_verified':True,'anonymous_mapping_cap_verified':False})
        with self.assertRaisesRegex(RuntimeError,'memory_profile_not_verified'):job.verify_restore()
        self.assertNotIn('decrypt-private-envelope',f.runner.labels());self.assertFalse((job.work/'plaintext.tar').exists());self.assertFalse((job.work/'state-restored.json').exists())

    def test_copied_common_and_policy_are_loaded_by_exact_public_pins(self):
        f=self.fixture();self.assertEqual(f.m.sha((f.root/'sources/nebula-backup-common.py').read_bytes()),M.COMMON_SHA)
        self.assertEqual(f.m.sha((f.root/'sources/nebula-backup-envelope-policy.py').read_bytes()),f.m.POLICY_SHA)
        self.assertEqual(f.p.TARGETS,('Tarragon','Slipstream'))

    def test_check_does_not_create_namespace_or_invoke_runner(self):
        f=self.fixture();job=f.job();original=f.m.pinned
        for name in ['gpg','openssl']:private_file(f.root/('fake-'+name),b'SYNTHETIC PUBLIC TOOL',0o644)
        def pinned(path,*args,**kwargs):
            alternate=f.root/('fake-'+path.name)if str(path)in['/usr/bin/gpg','/usr/bin/openssl']else path
            return original(alternate,*args,**kwargs)
        with patch.object(f.m,'pinned',side_effect=pinned):result=job.check()
        self.assertTrue(result['no_mutation']);self.assertFalse(f.namespace.exists());self.assertEqual(f.runner.calls,[])

    def test_init_exact_gpg_profile_and_public_only_export_stay_local(self):
        f=self.fixture();job=f.init();export=job.export_public()
        generate=next(args for label,args,kw in f.runner.calls if label=='generate-primary');subkey=next(args for label,args,kw in f.runner.calls if label=='generate-subkey')
        self.assertEqual(generate[-3:],['ed25519','cert','365d']);self.assertEqual(subkey[-3:],['cv25519','encr','365d'])
        self.assertIn('--no-options',generate);self.assertIn('--no-auto-key-retrieve',generate)
        self.assertEqual(export['public_key_armored'],PUBLIC.decode());self.assertNotIn('PRIVATE KEY',json.dumps(export))
        self.assertEqual(stat.S_IMODE((job.work/'gnupg').stat().st_mode),0o700)
        self.assertEqual(stat.S_IMODE((job.work/'recovery-public.asc').stat().st_mode),0o600)
        self.assertTrue(all(kw.get('address_limit')==768*1024**2 for label,_,kw in f.runner.calls if label in ['gpg-version','generate-primary','generate-subkey','public-key-metadata','export-public']))

    def test_key_initialization_is_one_use_and_partial_failure_is_not_retried(self):
        for partial in [False,True]:
            with self.subTest(partial=partial):
                f=self.fixture();job=f.job('init-keys')
                if partial:f.runner.fail.add('generate-primary')
                if partial:
                    with self.assertRaises(RuntimeError):job.init_keys()
                else:job.init_keys()
                calls=len(f.runner.calls)
                with self.assertRaises(RuntimeError):job.init_keys()
                self.assertEqual(len(f.runner.calls),calls);self.assertTrue((job.work/'state-key-intent.json').is_file())
                with self.assertRaises(RuntimeError):f.job('init-keys')

    def test_wrong_gpg_version_refuses_before_key_generation(self):
        f=self.fixture();f.runner.version=b'gpg (GnuPG) 2.4.5\n';job=f.job('init-keys')
        with self.assertRaisesRegex(RuntimeError,'gpg_2_4_4_required'):job.init_keys()
        self.assertNotIn('generate-primary',f.runner.labels());self.assertFalse((job.work/'gnupg').exists())

    def test_key_curve_capability_lifetime_and_full_fingerprints_are_exact(self):
        f=self.fixture();job=f.init()
        for text in [key_metadata(curve='nistp256'),key_metadata(primary_caps='scEC'),key_metadata(lifetime=730*86400),key_metadata().replace(OWN['encryption_subkey_fingerprint'],'E'*40)]:
            with self.subTest(text=text[:20]),self.assertRaises(RuntimeError):job.validate_key(text,OWN)

    def test_export_never_reads_private_key_material_or_adopts_replaced_public_file(self):
        f=self.fixture();job=f.init();private=job.work/'gnupg/private-canary';private_file(private,b'SYNTHETIC-PRIVATE-CANARY');original=f.m.read
        def read(path,*args,**kwargs):self.assertNotEqual(path,private);return original(path,*args,**kwargs)
        with patch.object(f.m,'read',side_effect=read):self.assertNotIn('CANARY',json.dumps(job.export_public()))
        replacement=f.root/'foreign-public';private_file(replacement,PUBLIC);os.replace(replacement,job.work/'recovery-public.asc');inode=(job.work/'recovery-public.asc').stat().st_ino
        with self.assertRaises(RuntimeError):job.export_public()
        self.assertEqual((job.work/'recovery-public.asc').stat().st_ino,inode)

    def test_private_key_custody_refuses_unknown_or_writable_placeholder_without_export(self):
        for kind in ['extra','mode']:
            with self.subTest(kind=kind):
                f=self.fixture();job=f.init();keys=job.work/'gnupg/private-keys-v1.d'
                if kind=='extra':private_file(keys/('3'*40+'.key'),b'FOREIGN SYNTHETIC PRIVATE PLACEHOLDER')
                else:(keys/('1'*40+'.key')).chmod(0o644)
                before={p.name:(p.read_bytes(),p.stat().st_ino)for p in keys.iterdir()}
                with self.assertRaises(RuntimeError):job.export_public()
                self.assertEqual({p.name:(p.read_bytes(),p.stat().st_ino)for p in keys.iterdir()},before)

    def test_stage_tool_requires_exact_bounds_digest_and_exclusive_publication(self):
        f=self.fixture();job=f.init()
        for digest,size in [('bad',len(TOOL)),(f.m.sha(TOOL),0),(f.m.sha(TOOL),True),(f.m.sha(TOOL),64*1024**2+1)]:
            with self.subTest(size=size),self.assertRaises(RuntimeError):job.stage_etcdutl(io.BytesIO(TOOL),digest,size)
        self.assertFalse((job.work/'state-tool-intent.json').exists())
        job.stage_etcdutl(io.BytesIO(TOOL),f.m.sha(TOOL),len(TOOL));self.assertEqual((job.work/'etcdutl').read_bytes(),TOOL)
        with self.assertRaises(RuntimeError):job.stage_etcdutl(io.BytesIO(TOOL),f.m.sha(TOOL),len(TOOL))

    def test_stage_wrong_digest_or_length_retains_partial_without_success(self):
        for kind in ['digest','length']:
            with self.subTest(kind=kind):
                f=self.fixture();job=f.init()
                with self.assertRaises(RuntimeError):job.stage_etcdutl(io.BytesIO(TOOL),('0'*64 if kind=='digest'else f.m.sha(TOOL)),len(TOOL)+(kind=='length'))
                self.assertTrue((job.work/'state-tool-intent.json').exists());self.assertFalse((job.work/'state-tool.json').exists());self.assertEqual((job.work/'etcdutl').read_bytes(),TOOL)

    def test_configure_binds_both_recipients_signer_spki_and_private_tool(self):
        f=self.fixture();job=f.configured();trusted,state=job.trusted();self.assertEqual(trusted['recipients'],f.config()['recipients'])
        self.assertEqual(state['tool_record']['sha256'],f.m.sha(TOOL));self.assertEqual(stat.S_IMODE((job.work/'tools/etcdutl').stat().st_mode),0o500)
        self.assertEqual((job.work/'signer-public.pem').read_bytes(),f.signer.encode())

    def test_configure_rejects_wrong_own_or_duplicate_pins_spki_and_hash(self):
        for kind in ['own','duplicate','spki','signerhash','toolpin']:
            with self.subTest(kind=kind):
                f=self.fixture();job=f.init();job.stage_etcdutl(io.BytesIO(TOOL),f.m.sha(TOOL),len(TOOL));config=f.config()
                if kind=='own':config['recipients']['Tarragon']['primary_fingerprint']='E'*40
                elif kind=='duplicate':config['recipients']['Slipstream']=dict(OWN)
                elif kind=='spki':config['signer_public_pem']='-----BEGIN PRIVATE KEY-----\nINVALID\n-----END PRIVATE KEY-----'
                elif kind=='signerhash':config['signer_public_sha256']='0'*64
                else:config['etcdutl_sha256']='0'*64
                with self.assertRaises(RuntimeError):job.configure(f.m.json_bytes(config))
                self.assertFalse((job.work/'state-config.json').exists());self.assertNotIn('decrypt-private-envelope',f.runner.labels())

    def test_configure_wrong_etcd_version_leaves_private_unadopted_partial(self):
        f=self.fixture();f.runner.etcd_version=b'etcdutl version: 3.7.1\n';job=f.init();job.stage_etcdutl(io.BytesIO(TOOL),f.m.sha(TOOL),len(TOOL))
        with self.assertRaisesRegex(RuntimeError,'etcdutl_3_7_0_required'):job.configure(f.m.json_bytes(f.config()))
        self.assertTrue((job.work/'state-config-intent.json').exists());self.assertFalse((job.work/'state-config.json').exists())

    def test_strict_outer_accepts_only_exact_three_regular_ustar_members(self):
        f=self.fixture();items=f.parse(f.envelope());self.assertEqual({i['name']for i in items},{'backup.tar.gpg','manifest.json','manifest.sig'})
        self.assertTrue(all(i['kind']=='regular'for i in items))

    def test_hidden_pax_links_duplicate_traversal_and_extra_outer_member_are_refused(self):
        base=[('backup.tar.gpg',CIPHER,'file'),('manifest.json',b'{}','file'),('manifest.sig',b'S'*64,'file')]
        cases=[(base+[('extra',b'x','file')],tarfile.USTAR_FORMAT),([base[0],base[0],base[2]],tarfile.USTAR_FORMAT),([('../escape',CIPHER,'file'),*base[1:]],tarfile.USTAR_FORMAT),([('backup.tar.gpg',CIPHER,'symlink'),*base[1:]],tarfile.USTAR_FORMAT),([('backup.tar.gpg',CIPHER,'hardlink'),*base[1:]],tarfile.USTAR_FORMAT),([('backup.tar.gpg',CIPHER,'pax'),*base[1:]],tarfile.PAX_FORMAT)]
        f=self.fixture()
        for entries,format in cases:
            with self.subTest(first=entries[0][0],kind=entries[0][2]),self.assertRaises(RuntimeError):f.parse(tar_bytes(entries,format))

    def test_signature_length_nonzero_padding_and_truncation_are_refused(self):
        f=self.fixture()
        for raw in [f.envelope(signature=b'S'*63),f.envelope()[:1024],f.envelope()[:-1]+b'X']:
            with self.subTest(size=len(raw)),self.assertRaises(RuntimeError):f.parse(raw)

    def test_failed_signature_never_decrypts_or_records_received_success(self):
        f=self.fixture();job=f.configured();f.runner.fail.add('verify-envelope-signature')
        with self.assertRaises(RuntimeError):job.receive(io.BytesIO(f.envelope()))
        self.assertNotIn('decrypt-private-envelope',f.runner.labels());self.assertFalse((job.work/'state-received.json').exists());self.assertTrue((job.work/'received/backup.tar.gpg').exists())

    def test_cipher_digest_recipient_and_signer_mismatch_never_reach_decrypt(self):
        for kind in ['cipher','recipient','signer']:
            with self.subTest(kind=kind):
                f=self.fixture();job=f.configured();config=f.config()
                if kind=='recipient':config['recipients']['Slipstream']['encryption_subkey_fingerprint']='E'*40
                if kind=='signer':config['signer_public_sha256']='0'*64
                envelope=f.envelope(config=config,cipher=(b'foreign ciphertext'if kind=='cipher'else CIPHER))
                with self.assertRaises(RuntimeError):job.receive(io.BytesIO(envelope))
                self.assertNotIn('decrypt-private-envelope',f.runner.labels());self.assertNotIn('verify-envelope-signature',f.runner.labels())

    def test_received_outer_or_cipher_replacement_is_refused_before_decrypt(self):
        for name in ['envelope.tar','backup.tar.gpg']:
            with self.subTest(name=name):
                f=self.fixture();job=f.received();path=job.work/'received'/name;replacement=f.root/'foreign';private_file(replacement,path.read_bytes());os.replace(replacement,path);inode=path.stat().st_ino
                with self.assertRaises(RuntimeError):job.verify_restore()
                self.assertNotIn('decrypt-private-envelope',f.runner.labels());self.assertEqual(path.stat().st_ino,inode)

    def test_gpg_status_requires_full_own_key_aes256_and_authenticated_mdc(self):
        f=self.fixture();job=f.init();job.gpg_status(f.gpg_status,OWN)
        bad=[f.gpg_status.replace(OWN['encryption_subkey_fingerprint'].encode(),b'B'*16),f.gpg_status.replace(b'DECRYPTION_INFO 2 9',b'DECRYPTION_INFO 0 9'),f.gpg_status.replace(b'GOODMDC',b'BADMDC'),f.gpg_status.replace(b'DECRYPTION_INFO 2 9',b'DECRYPTION_INFO 2 7'),f.gpg_status+b'[GNUPG:] ERROR synthetic\n']
        for raw in bad:
            with self.subTest(raw=raw[:30]),self.assertRaises(RuntimeError):job.gpg_status(raw,OWN)

    def test_restore_manifest_exact_inventory_identity_and_numeric_bounds(self):
        f=self.fixture();job=f.init();items=f.parse(f.plaintext,outer=False);job.restore_manifest(f.m.json_bytes(f.manifest),items)
        for kind in ['inventory','operation','version','source','revision','count','uuid','publicapi']:
            with self.subTest(kind=kind):
                value=copy.deepcopy(f.manifest)
                if kind=='inventory':value['archive_members'][0]['size']+=1
                elif kind=='operation':value['operation_id']='0'*32
                elif kind=='version':value['etcd_version']='3.7.1'
                elif kind=='source':value['source_cluster_sha256']='0'*64
                elif kind=='revision':value['snapshot_status']['revision']=2**63-1
                elif kind=='count':value['snapshot_status']['totalKey']=True
                elif kind=='uuid':value['expected_uuid']='foreign'
                else:value['api_address']='8.8.8.8'
                with self.assertRaises(RuntimeError):job.restore_manifest(f.m.json_bytes(value),items)

    def test_mocked_restore_uses_pinned_fds_no_skiphash_and_never_starts_listener(self):
        f=self.fixture();job=f.received();result=job.verify_restore();self.assertTrue(result['offline_restore_verified']);self.assertFalse(result['listeners_started'])
        labels=f.runner.labels();self.assertLess(labels.index('verify-envelope-signature'),labels.index('decrypt-private-envelope'));self.assertIn('restored-database-status',labels)
        args=next(args for label,args,kw in f.runner.calls if label=='offline-etcd-restore')
        self.assertEqual(args[1:3],['snapshot','restore']);self.assertNotIn('--skip-hash-check',args);self.assertIn('--mark-compacted',args);self.assertEqual(args[args.index('--bump-revision')+1],'1000000000')
        self.assertTrue(args[0].startswith('/proc/self/fd/'));self.assertTrue(args[3].startswith('/proc/self/fd/'));self.assertTrue(args[args.index('--data-dir')+1].startswith('/proc/self/fd/'))
        self.assertTrue((job.work/'state-restored.json').is_file());self.assertFalse(any('systemctl'in arg or arg.endswith('/etcd')for _,argv,_ in f.runner.calls for arg in argv))

    def test_bad_decryption_status_or_restored_revision_never_records_success(self):
        for kind in ['mdc','revision']:
            with self.subTest(kind=kind):
                f=self.fixture();job=f.received()
                if kind=='mdc':f.gpg_status=f.gpg_status.replace(b'GOODMDC',b'BADMDC')
                else:f.runner.restored_override={**f.snapshot_status,'revision':f.snapshot_status['revision']}
                with self.assertRaises(RuntimeError):job.verify_restore()
                self.assertFalse((job.work/'state-restored.json').exists())
                if kind=='mdc':self.assertNotIn('offline-etcd-restore',f.runner.labels())

    def test_existing_restore_directory_or_link_is_preserved(self):
        for kind in ['directory','link']:
            with self.subTest(kind=kind):
                f=self.fixture();job=f.received();path=job.work/'offline-restore';marker=f.root/'foreign-marker';private_file(marker,b'FOREIGN')
                if kind=='directory':path.mkdir(mode=0o700);private_file(path/'foreign',b'FOREIGN')
                else:path.symlink_to(marker)
                with self.assertRaisesRegex(RuntimeError,'restore_destination_must_be_new'):job.verify_restore()
                self.assertEqual(marker.read_bytes(),b'FOREIGN');self.assertNotIn('offline-etcd-restore',f.runner.labels())
                if kind=='directory':self.assertEqual((path/'foreign').read_bytes(),b'FOREIGN')
                else:self.assertTrue(path.is_symlink())

    def test_inner_archive_allowlist_and_restored_tree_reject_foreign_files(self):
        f=self.fixture();job=f.init();items=f.parse(tar_bytes([('snapshot.db',SNAP,'file'),('restore-manifest.json',b'{}','file'),('etc/shadow',b'FOREIGN','file')]),outer=False)
        with self.assertRaises(RuntimeError):f.p.archive_inventory([{k:i[k]for k in ['name','kind','size']}for i in items])
        tree=f.root/'restored';tree.mkdir(mode=0o700);private_file(tree/'foreign.txt',b'FOREIGN')
        with self.assertRaises(RuntimeError):job.restored_tree(tree)
        self.assertEqual((tree/'foreign.txt').read_bytes(),b'FOREIGN')

    def test_changed_plan_namespace_lock_and_journal_records_are_not_adopted(self):
        for kind in ['plan','namespace','lock','journal']:
            with self.subTest(kind=kind):
                f=self.fixture();job=f.init();path={'plan':f.plan,'namespace':f.namespace/'namespace.json','lock':job.work/'operation.lock','journal':job.work/'state-keys.json'}[kind]
                replacement=f.root/'foreign';private_file(replacement,path.read_bytes());os.replace(replacement,path);before=f.m.ident(path.lstat())
                with self.assertRaises(RuntimeError):job.guard()
                self.assertEqual(f.m.ident(path.lstat()),before)

    def test_stream_postimage_replacement_preserves_foreign_file(self):
        f=self.fixture();path=f.root/'streamed';foreign=f.root/'foreign';private_file(foreign,b'FOREIGN');swapped=[]
        class Stream:
            def read(self,n):
                if not swapped:os.replace(foreign,path);swapped.append(True);return b'own bytes'
                return b''
        with self.assertRaisesRegex(RuntimeError,'output_postimage_changed'):M.stream_exclusive(path,Stream(),100,f.m)
        self.assertEqual(path.read_bytes(),b'FOREIGN')

    def test_invalid_target_namespace_hostname_and_capacity_refuse_before_creation(self):
        for kind in ['namespace','hostname','capacity']:
            with self.subTest(kind=kind):
                f=self.fixture()
                if kind=='namespace':value={**f.plan_data,'namespace':str(f.root/'foreign')};private_file(f.plan,f.m.json_bytes(value))
                context=patch.object(M.socket,'gethostname',return_value='foreign-host')if kind=='hostname'else patch.object(f.m,'require_free',side_effect=f.m.Refused('synthetic_capacity'))if kind=='capacity'else contextlib.nullcontext()
                with context,self.assertRaises(RuntimeError):f.job('init-keys')
                self.assertFalse(f.namespace.exists());self.assertEqual(f.runner.calls,[])


    def test_restore_path_replaced_during_status_refuses_before_offline_tool(self):
        f=self.fixture();job=f.received();foreign={}
        def replaced(work,args,kwargs):
            path=job.work/'offline-restore';path.rename(job.work/'retained-original-restore');path.mkdir(mode=0o700);private_file(path/'foreign-marker',b'FOREIGN RESTORE DIRECTORY')
            foreign['inode']=path.stat().st_ino;foreign['marker']=(path/'foreign-marker').read_bytes()
            return f.m.json_bytes(f.snapshot_status)
        f.runner.hooks['independent-snapshot-status']=replaced
        with self.assertRaisesRegex(RuntimeError,'restore_directory_changed'):job.verify_restore()
        path=job.work/'offline-restore'
        self.assertEqual(path.stat().st_ino,foreign['inode']);self.assertEqual((path/'foreign-marker').read_bytes(),foreign['marker'])
        self.assertNotIn('offline-etcd-restore',f.runner.labels());self.assertFalse((job.work/'state-restored.json').exists())

    def test_restore_path_replaced_after_writing_held_directory_is_never_adopted(self):
        f=self.fixture();job=f.received();foreign={};retained=job.work/'retained-original-restore'
        def replaced(work,args,kwargs):
            held=args[args.index('--data-dir')+1];descriptor=int(held.rsplit('/',1)[1]);self.assertIn(descriptor,kwargs['pass_fds'])
            original=Path(os.readlink(held));(original/'member'/'snap').mkdir(parents=True,mode=0o700);(original/'member').chmod(0o700)
            private_file(original/'member'/'snap'/'db',b'SYNTHETIC RESTORE WRITTEN THROUGH HELD DIRECTORY')
            original.rename(retained);original.mkdir(mode=0o700);private_file(original/'foreign-marker',b'FOREIGN REPLACEMENT MUST SURVIVE')
            foreign['record']=f.m.ident(original.lstat());return b''
        f.runner.hooks['offline-etcd-restore']=replaced
        with self.assertRaisesRegex(RuntimeError,'restore_directory_changed'):job.verify_restore()
        path=job.work/'offline-restore';self.assertEqual(f.m.ident(path.lstat()),foreign['record'])
        self.assertEqual((path/'foreign-marker').read_bytes(),b'FOREIGN REPLACEMENT MUST SURVIVE')
        self.assertEqual((retained/'member/snap/db').read_bytes(),b'SYNTHETIC RESTORE WRITTEN THROUGH HELD DIRECTORY')
        self.assertNotIn('restored-database-status',f.runner.labels());self.assertFalse((job.work/'state-restored.json').exists())

    def test_exclusive_public_and_trusted_control_replacement_is_refused_at_adoption(self):
        for name in ['recovery-public.asc','trusted.json','signer-public.pem']:
            with self.subTest(name=name):
                f=self.fixture()
                if name=='recovery-public.asc':job=f.job('init-keys')
                else:job=f.init();job.stage_etcdutl(io.BytesIO(TOOL),f.m.sha(TOOL),len(TOOL))
                exclusive=f.m.exclusive;foreign={}
                def replaced(path,raw,mode=0o600):
                    expected=exclusive(path,raw,mode)
                    if path.name==name:
                        replacement=f.root/'foreign-control';private_file(replacement,raw,mode);os.replace(replacement,path);foreign['record']=f.m.ident(path.lstat());foreign['bytes']=raw
                    return expected
                with patch.object(f.m,'exclusive',side_effect=replaced),self.assertRaises(RuntimeError):
                    job.init_keys()if name=='recovery-public.asc'else job.configure(f.m.json_bytes(f.config()))
                path=job.work/name;self.assertEqual(f.m.ident(path.lstat()),foreign['record']);self.assertEqual(path.read_bytes(),foreign['bytes'])
                self.assertFalse((job.work/('state-keys.json'if name=='recovery-public.asc'else'state-config.json')).exists())

    def test_executable_replacement_before_validated_fd_chmod_preserves_foreign_mode(self):
        f=self.fixture();job=f.init();job.stage_etcdutl(io.BytesIO(TOOL),f.m.sha(TOOL),len(TOOL));regular=f.m.regular_fd;foreign={};path=job.work/'tools/etcdutl'
        def replaced(candidate,*args,**kwargs):
            if candidate==path and not foreign:
                replacement=f.root/'foreign-executable';private_file(replacement,b'FOREIGN EXECUTABLE MUST NOT BE CHMODDED',0o600);os.replace(replacement,path);foreign['record']=f.m.ident(path.lstat())
            return regular(candidate,*args,**kwargs)
        with patch.object(f.m,'regular_fd',side_effect=replaced),self.assertRaisesRegex(RuntimeError,'public_tool_postimage_changed'):job.configure(f.m.json_bytes(f.config()))
        self.assertEqual(f.m.ident(path.lstat()),foreign['record']);self.assertEqual(stat.S_IMODE(path.stat().st_mode),0o600)
        self.assertEqual(path.read_bytes(),b'FOREIGN EXECUTABLE MUST NOT BE CHMODDED');self.assertNotIn('etcdutl-version',f.runner.labels());self.assertFalse((job.work/'state-config.json').exists())

    def test_namespace_marker_replacement_after_exclusive_creation_is_not_adopted(self):
        f=self.fixture();exclusive=f.m.exclusive;foreign={}
        def replaced(path,raw,mode=0o600):
            expected=exclusive(path,raw,mode)
            if path.name=='namespace.json':
                replacement=f.root/'foreign-namespace-marker';private_file(replacement,raw,mode);os.replace(replacement,path);foreign['record']=f.m.ident(path.lstat());foreign['bytes']=raw
            return expected
        with patch.object(f.m,'exclusive',side_effect=replaced),self.assertRaisesRegex(RuntimeError,'namespace_changed'):f.job('init-keys')
        path=f.namespace/'namespace.json';self.assertEqual(f.m.ident(path.lstat()),foreign['record']);self.assertEqual(path.read_bytes(),foreign['bytes'])
        self.assertFalse((f.namespace/OP).exists());self.assertEqual(f.runner.calls,[])


    def test_unknown_empty_restored_directory_is_refused_and_preserved(self):
        f=self.fixture();job=f.init();tree=f.root/'synthetic-restored-tree';tree.mkdir(mode=0o700)
        foreign=tree/'unknown-empty-directory';foreign.mkdir(mode=0o700);before=f.m.ident(foreign.lstat())
        with self.assertRaises(RuntimeError):job.restored_tree(tree)
        self.assertEqual(f.m.ident(foreign.lstat()),before);self.assertEqual(list(foreign.iterdir()),[])

    @contextlib.contextmanager
    def synthetic_capacity(self,fixture,free,credits):
        # Only st_blocks is synthetic; every ownership/inode/size/time guard stays real.
        original_fstat=os.fstat;original_require=fixture.m.require_free;calls=[]
        class AllocationStat:
            def __init__(self,actual):
                self.actual=actual;self.st_blocks=credits.get((actual.st_dev,actual.st_ino),0)//512
            def __getattr__(self,name):return getattr(self.actual,name)
        def observed(fd):return AllocationStat(original_fstat(fd))
        def require(parent,minimum):
            calls.append(minimum)
            return original_require(parent,minimum)
        class FreeStat:
            f_frsize=1
            @property
            def f_bavail(self):return free[0]
        with patch.object(fixture.m.os,'fstat',side_effect=observed),patch.object(fixture.m.os,'statvfs',return_value=FreeStat()),patch.object(fixture.m,'require_free',side_effect=require):
            yield calls

    def full_tarragon_budget(self,fixture):
        budget=40*1024**3
        M.NAMESPACES['Tarragon']=(str(fixture.namespace),budget)
        fixture.plan_data['minimum_free_bytes']=budget
        private_file(fixture.plan,fixture.m.json_bytes(fixture.plan_data))
        return budget

    def test_capacity_credits_known_received_ciphertext_and_restored_database_allocations(self):
        for kind in ['received_ciphertext','restored_database']:
            with self.subTest(kind=kind):
                f=self.fixture();budget=self.full_tarragon_budget(f);free=[budget];credits={}
                with self.synthetic_capacity(f,free,credits)as required:
                    job=f.received()
                    if kind=='restored_database':job.verify_restore()
                    path=job.work/('received/backup.tar.gpg'if kind=='received_ciphertext'else'offline-restore/member/snap/db')
                    meta=path.stat();credits[(meta.st_dev,meta.st_ino)]=1024**3
                    free[0]=budget-1024**3
                    if kind=='received_ciphertext':
                        job.close();job=f.job('verify-restore')
                    job._capacity()
                    self.assertEqual(required[-1],budget-1024**3)
                    self.assertIn(budget,required)

    def test_capacity_unrelated_extra_free_space_loss_is_refused(self):
        f=self.fixture();budget=self.full_tarragon_budget(f);free=[budget];credits={}
        with self.synthetic_capacity(f,free,credits)as required:
            job=f.received();path=job.work/'received/backup.tar.gpg';meta=path.stat();credits[(meta.st_dev,meta.st_ino)]=1024**3
            free[0]=budget-1024**3;job._capacity()
            free[0]-=4096
            with self.assertRaisesRegex(RuntimeError,'combined_capacity_gate_failed'):job._capacity()
            self.assertEqual(required[-1],budget-1024**3)

    def test_capacity_foreign_untracked_allocation_earns_no_credit(self):
        f=self.fixture();budget=self.full_tarragon_budget(f);free=[budget];credits={}
        with self.synthetic_capacity(f,free,credits)as required:
            job=f.init();unknown=job.work/'foreign-untracked-allocation';private_file(unknown,b'FOREIGN UNTRACKED SYNTHETIC FILE');meta=unknown.stat();credits[(meta.st_dev,meta.st_ino)]=1024**3
            free[0]=budget-1024**3
            with self.assertRaisesRegex(RuntimeError,'combined_capacity_gate_failed'):job._capacity()
            self.assertEqual(required[-1],budget);self.assertEqual(unknown.read_bytes(),b'FOREIGN UNTRACKED SYNTHETIC FILE')

    def test_capacity_changed_or_replaced_credited_file_is_refused_and_preserved(self):
        for kind in ['inplace','replacement']:
            with self.subTest(kind=kind):
                f=self.fixture();budget=self.full_tarragon_budget(f);free=[budget];credits={}
                with self.synthetic_capacity(f,free,credits)as required:
                    job=f.received();path=job.work/'received/backup.tar.gpg';meta=path.stat();credits[(meta.st_dev,meta.st_ino)]=1024**3;free[0]=budget-1024**3;job._capacity()
                    if kind=='inplace':path.write_bytes(b'FOREIGN CHANGED CREDITED CIPHERTEXT')
                    else:
                        replacement=f.root/'foreign-credited-replacement';private_file(replacement,path.read_bytes());os.replace(replacement,path)
                    before=f.m.ident(path.lstat());body=path.read_bytes();required.clear()
                    with self.assertRaises(RuntimeError):job._capacity()
                    self.assertEqual(required,[]);self.assertEqual(f.m.ident(path.lstat()),before);self.assertEqual(path.read_bytes(),body)


class ExecuteGateTests(unittest.TestCase):
    def test_cli_execute_gate_precedes_source_load_plan_read_or_commands(self):
        for phase in ['init-keys','stage-etcdutl','configure','receive','verify-restore']:
            with self.subTest(phase=phase),patch.object(sys,'argv',['target','--plan','/unread/synthetic-plan.json','--phase',phase]),patch.object(M,'load_common')as loader,contextlib.redirect_stderr(io.StringIO()),self.assertRaises(SystemExit)as result:M.main()
            self.assertEqual(result.exception.code,2);loader.assert_not_called()


if __name__=='__main__':unittest.main(verbosity=2)

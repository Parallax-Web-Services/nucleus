#!/usr/bin/env python3
import errno,hashlib,importlib.util,io,json,os,stat,sys,tarfile,tempfile,threading,time,unittest
from pathlib import Path
from unittest.mock import patch
def load(name,path):
 s=importlib.util.spec_from_file_location(name,path);m=importlib.util.module_from_spec(s);s.loader.exec_module(m);return m
g=load('backup_guest','/tmp/nebula-backup-guest.py');m=load('backup_common','/tmp/nebula-backup-common.py');p=load('backup_policy','/tmp/nebula-backup-envelope-policy.py')
PINS={'Tarragon':{'primary_fingerprint':'A'*40,'encryption_subkey_fingerprint':'B'*40},'Slipstream':{'primary_fingerprint':'C'*40,'encryption_subkey_fingerprint':'D'*40}}
def layer(files):
 b=io.BytesIO()
 with tarfile.open(fileobj=b,mode='w',format=tarfile.USTAR_FORMAT) as t:
  for name,value in files:
   i=tarfile.TarInfo(name);i.size=len(value);i.mode=0o755;t.addfile(i,io.BytesIO(value))
 return b.getvalue()
class Stream(io.BytesIO):
 def close(self):self.saved=self.getvalue()
class Child:
 def __init__(self,args,**kw):self.args=args;self.kw=kw;self.stdin=Stream();self.pid=999999;self.done=False
 def wait(self,timeout=None):
  if not self.done:os.write(self.kw['stdout'],b'SYNTHETIC-CIPHERTEXT');self.done=True
  return 0
 def poll(self):return 0 if self.done else None
class GuestTests(unittest.TestCase):
 def setUp(self):
  self.temp=tempfile.TemporaryDirectory(prefix='nebula-backup-guest-test-',dir='/root');self.work=Path(self.temp.name);os.chmod(self.work,0o700)
 def tearDown(self):self.temp.cleanup()
 def job(self):
  j=object.__new__(g.Guest);j.m=m;j.p=p;j.id='1'*32;j.work=self.work;j.guard=lambda:None
  j.journal=m.Journal(self.work,['state-prepared.json','state-configured.json','state-seal-started.json','state-sealed.json'])
  j.cluster=type('C',(),{'base':self.work})()
  return j
 def seal_job(self,fail=False):
  j=self.job();key=self.work/'signing-private.pem';m.exclusive(key,b'SYNTHETIC-NOT-A-PRIVATE-KEY')
  tools={}
  for tool in ['etcdctl','etcdutl']:
   path=self.work/tool;m.exclusive(path,('SYNTHETIC-PUBLIC-'+tool).encode(),0o700)
   tools[tool]={'sha256':hashlib.sha256(path.read_bytes()).hexdigest(),'bytes':path.stat().st_size,'identity':m.ident(path.stat())}
  prepared={'operation_id':j.id,'tools':tools,'signer_public_sha256':'3'*64,'signing_private_metadata':m.ident(key.stat())}
  j.journal.append('state-prepared.json',prepared);j.journal.append('state-configured.json',{'recipients':PINS})
  j.prepared=lambda:(prepared,b'SYNTHETIC-PUBLIC');j.plan={'expected_uuid':'00000000-0000-4000-8000-000000000001','run_id':'a'*12,'api_address':'192.0.2.1'}
  recovery=self.work/'synthetic-recovery-material';m.exclusive(recovery,b'SYNTHETIC-RECOVERY-NOT-REAL-KEYS')
  j.archive_inputs=lambda snapshot:{name:(snapshot if name=='snapshot.db' else recovery) for name in g.REQUIRED_RECOVERY_FILES}
  j.commands=[]
  def cmd(args,label,**kw):
   j.commands.append((args,label))
   if label=='snapshot-own-cluster':
    if fail:raise m.Refused('synthetic_snapshot_failed')
    m.exclusive(Path(args[-1]),b'SYNTHETIC-SNAPSHOT');return b''
   if label=='verify-snapshot-status':return b'{"hash":123,"revision":10,"totalKey":1,"totalSize":100,"version":"3.7.0"}'
   if label=='encrypt-archive':
    kw['on_start']();plain=bytearray()
    while True:
     raw=os.read(kw['stdin_fd'],65536)
     if not raw:break
     plain.extend(raw)
    j.synthetic_inner_tar=bytes(plain);j.encryption_args=args
    os.write(kw['stdout_fd'],b'SYNTHETIC-CIPHERTEXT');return b''
   if label=='sign-ciphertext-manifest':
    fd=int(args[-1].split('/')[-1]);os.write(fd,b's'*64);return b''
   raise AssertionError(label)
  j.cmd=cmd;return j
 def test_tool_members_only_exact_regular_binaries(self):
  raw=layer([('usr/local/bin/etcdctl',b'fixture1'),('usr/local/bin/etcdutl',b'fixture2'),('etc/unrelated',b'ignored')])
  with tarfile.open(fileobj=io.BytesIO(raw)) as t:self.assertEqual(set(g.tool_members(t)),{'usr/local/bin/etcdctl','usr/local/bin/etcdutl'})
 def test_tool_whiteout_rejected(self):
  raw=layer([('usr/local/bin/.wh.etcdctl',b'')])
  with tarfile.open(fileobj=io.BytesIO(raw)) as t:
   with self.assertRaises(RuntimeError):g.tool_members(t)
 def test_tool_traversal_rejected(self):
  raw=layer([('../usr/local/bin/etcdctl',b'fixture')])
  with tarfile.open(fileobj=io.BytesIO(raw)) as t:
   with self.assertRaises(RuntimeError):g.tool_members(t)
 def test_tool_symlink_rejected(self):
  raw=io.BytesIO()
  with tarfile.open(fileobj=raw,mode='w') as t:
   i=tarfile.TarInfo('usr/local/bin/etcdctl');i.type=tarfile.SYMTYPE;i.linkname='/etc/shadow';t.addfile(i)
  with tarfile.open(fileobj=io.BytesIO(raw.getvalue())) as t:
   with self.assertRaises(RuntimeError):g.tool_members(t)
 def test_tool_duplicate_rejected(self):
  raw=layer([('usr/local/bin/etcdctl',b'one'),('usr/local/bin/etcdctl',b'two')])
  with tarfile.open(fileobj=io.BytesIO(raw)) as t:
   with self.assertRaises(RuntimeError):g.tool_members(t)
 def test_short_writes_complete_exact_binary(self):
  f=m.new_output(self.work/'short-write');actual=os.write
  try:
   with patch.object(g.os,'write',side_effect=lambda fd,data:actual(fd,data[:2])):g.write_all(f,b'1234567')
   self.assertEqual(os.fstat(f).st_size,7);os.lseek(f,0,0);self.assertEqual(os.read(f,7),b'1234567')
  finally:os.close(f)
 def test_hash_fd_bounded_and_rewinds(self):
  f=m.new_output(self.work/'bytes');os.write(f,b'1234')
  try:
   self.assertEqual(g.hash_fd(f,4),(hashlib.sha256(b'1234').hexdigest(),4));self.assertEqual(os.lseek(f,0,os.SEEK_CUR),0)
   with self.assertRaises(RuntimeError):g.hash_fd(f,3)
  finally:os.close(f)
 def test_oci_tool_extraction_proves_digests_versions(self):
  j=self.job();blob=layer([('usr/local/bin/etcdctl',b'fake-tool1'),('usr/local/bin/etcdutl',b'fake-tool2')]);ld='sha256:'+hashlib.sha256(blob).hexdigest()
  manifest=json.dumps({'config':{'digest':'sha256:'+'c'*64},'layers':[{'digest':ld,'size':len(blob)}]}).encode();md='sha256:'+hashlib.sha256(manifest).hexdigest()
  j.cluster.images={'registry.k8s.io/etcd:3.7.0-0':{'linux_amd64_manifest_digest':md,'config_digest':'sha256:'+'c'*64,'layer_digests':[ld]}}
  def cmd(args,label,**kw):
   if label=='read-etcd-manifest':return manifest
   if label=='copy-etcd-layer':os.write(kw['stdout_fd'],blob);return b''
   if label.startswith('verify-'):return (label.removeprefix('verify-').removesuffix('-version')+' version: 3.7.0\n').encode()
   raise AssertionError(label)
  j.cmd=cmd;tools=j.public_tools();self.assertEqual(set(tools),{'etcdctl','etcdutl'});self.assertEqual((self.work/'etcdutl').read_bytes(),b'fake-tool2')
 def test_oci_wrong_layer_digest_no_tool_adoption(self):
  j=self.job();blob=layer([('usr/local/bin/etcdctl',b'fixture')]);manifest=json.dumps({'config':{'digest':'sha256:'+'c'*64},'layers':[{'digest':'sha256:'+'f'*64,'size':len(blob)}]}).encode();md='sha256:'+hashlib.sha256(manifest).hexdigest()
  j.cluster.images={'registry.k8s.io/etcd:3.7.0-0':{'linux_amd64_manifest_digest':md,'config_digest':'sha256:'+'c'*64,'layer_digests':['sha256:'+'f'*64]}}
  j.cmd=lambda args,label,**kw:manifest if label=='read-etcd-manifest' else os.write(kw['stdout_fd'],blob)
  with self.assertRaisesRegex(m.Refused,'etcd_layer_digest'):j.public_tools()
  self.assertFalse((self.work/'etcdctl').exists())
 def test_snapshot_attempt_consumed_before_command(self):
  j=self.seal_job(True)
  with self.assertRaises(m.Refused):j.seal()
  self.assertTrue(j.journal.get('state-seal-started.json')['one_use_snapshot_attempt_consumed'])
  with self.assertRaisesRegex(m.Refused,'seal_once_only'):j.seal()
  self.assertEqual(sum(label=='snapshot-own-cluster' for _,label in j.commands),1)
 def test_seal_never_exports_plaintext_uses_exact_dual_recipients(self):
  j=self.seal_job();j.seal()
  self.assertEqual((self.work/'backup.tar.gpg').read_bytes(),b'SYNTHETIC-CIPHERTEXT');self.assertFalse((self.work/'backup.tar').exists())
  args=j.encryption_args;self.assertEqual(args.count('--recipient'),2);self.assertNotIn('--sign',args)
  self.assertEqual(len((self.work/'manifest.sig').read_bytes()),64)
  state=j.journal.get('state-sealed.json');self.assertFalse(state['source_plaintext_exported']);self.assertEqual(state['ciphertext_identity'],m.ident((self.work/'backup.tar.gpg').stat()))
  inner=j.synthetic_inner_tar
  with tarfile.open(fileobj=io.BytesIO(inner)) as t:self.assertEqual(set(t.getnames()),g.REQUIRED_RECOVERY_FILES|{'restore-manifest.json'})
 def test_source_snapshot_symlink_or_excessive_size_refused(self):
  j=self.seal_job()
  def cmd(args,label,**kw):
   if label=='snapshot-own-cluster':
    target=self.work/'foreign';m.exclusive(target,b'x');Path(args[-1]).symlink_to(target);return b''
   raise AssertionError('must-not-reach-status')
  j.cmd=cmd
  with self.assertRaises(m.Refused):j.seal()
  self.assertFalse('state-sealed.json' in j.journal.records)
 def test_signature_key_metadata_change_refused(self):
  j=self.seal_job();old=j.cmd
  def cmd(*a,**k):
   result=old(*a,**k)
   if a[1]=='verify-snapshot-status':os.chmod(self.work/'signing-private.pem',0o400)
   return result
  j.cmd=cmd
  with self.assertRaises(m.Refused):j.seal()
  self.assertNotIn('state-sealed.json',j.journal.records)

 def test_tool_executes_sealed_verified_bytes_and_refuses_replaced_path(self):
  j=self.job();raw=Path('/bin/echo').read_bytes();path=self.work/'etcdctl';m.exclusive(path,raw,0o700)
  known={'sha256':hashlib.sha256(raw).hexdigest(),'bytes':len(raw),'identity':m.ident(path.stat())}
  with self.assertRaisesRegex(m.Refused,'input_changed'):
   with j.tool_fd('etcdctl',known) as fd:
    foreign=self.work/'foreign-tool';m.exclusive(foreign,b'FOREIGN-NOT-EXECUTED',0o700);os.replace(foreign,path)
    result=m.command(self.work,['/proc/self/fd/'+str(fd),'verified-original'],'held-tool-exec',pass_fds=(fd,))
    self.assertEqual(result,b'verified-original\n')
  self.assertEqual(path.read_bytes(),b'FOREIGN-NOT-EXECUTED')
 def test_sealed_public_input_cannot_be_written_or_resized(self):
  raw=b'PUBLIC-CANONICAL-MANIFEST'
  with g.sealed_chunks([raw],m.sha(raw),len(raw),8192,m) as fd:
   self.assertEqual(os.read(fd,len(raw)),raw)
   with self.assertRaises(OSError) as write_error:os.write(fd,b'X')
   self.assertEqual(write_error.exception.errno,errno.EPERM)
   with self.assertRaises(OSError) as truncate_error:os.ftruncate(fd,0)
   self.assertEqual(truncate_error.exception.errno,errno.EPERM)
 def test_manifest_replacement_never_changes_signed_bytes_or_is_adopted(self):
  j=self.seal_job();old=j.cmd;signed=[]
  def cmd(args,label,**kw):
   if label=='sign-ciphertext-manifest':
    original=self.work/'manifest.json';expected=original.read_bytes()
    replacement=self.work/'foreign-manifest';m.exclusive(replacement,b'FOREIGN-MANIFEST');os.replace(replacement,original)
    fd=int(args[args.index('-in')+1].rsplit('/',1)[-1]);signed.append(os.pread(fd,8192,0));self.assertEqual(signed[-1],expected)
   return old(args,label,**kw)
  j.cmd=cmd
  with self.assertRaisesRegex(m.Refused,'signed_envelope_namespace_changed'):j.seal()
  self.assertEqual(len(signed),1);self.assertEqual((self.work/'manifest.json').read_bytes(),b'FOREIGN-MANIFEST')
  self.assertNotIn('state-sealed.json',j.journal.records)
 def test_early_leader_exit_pipe_descendant_is_reaped_and_tar_writer_quiesces(self):
  j=self.seal_job();old=j.cmd;pidfile=self.work/'owned-synthetic-child.pid';before=len(list(Path('/proc/self/fd').iterdir()))
  script="import os,time; pid=os.fork(); "+\
   "fd=os.open("+repr(str(pidfile))+",os.O_CREAT|os.O_EXCL|os.O_WRONLY,0o600) if pid==0 else -1; "+\
   "os.write(fd,str(os.getpid()).encode()) if pid==0 else None; "+\
   "os.close(fd) if pid==0 else None; "+\
   "os.write(2,b'synthetic-descendant') if pid==0 else None; "+\
   "time.sleep(60) if pid==0 else None"
  def cmd(args,label,**kw):
   if label=='encrypt-archive':
    kw['timeout']=0.25
    return m.command(self.work,[sys.executable,'-c',script],label,**kw)
   return old(args,label,**kw)
  j.cmd=cmd;started=time.monotonic()
  with self.assertRaisesRegex(m.Refused,'command_timeout_private_receipt'):j.seal()
  self.assertLess(time.monotonic()-started,8)
  self.assertTrue(pidfile.exists());child=int(pidfile.read_text())
  try:child_state=(Path('/proc')/str(child)/'stat').read_bytes().rsplit(b') ',1)[1].split()[0]
  except FileNotFoundError:child_state=b'gone'
  self.assertIn(child_state,[b'Z',b'X',b'gone'])
  receipts=list(self.work.glob('command-encrypt-archive-*/metadata.json'));self.assertEqual(len(receipts),1)
  self.assertTrue(json.loads(receipts[0].read_bytes())['owned_command_reaped'])
  self.assertFalse(any(t.name=='owned-backup-tar-producer' for t in threading.enumerate()))
  self.assertEqual(len(list(Path('/proc/self/fd').iterdir())),before)
  self.assertNotIn('state-sealed.json',j.journal.records)
 def test_start_callback_failure_closes_cipher_pipe_and_owned_command(self):
  j=self.seal_job();old=j.cmd;before=len(list(Path('/proc/self/fd').iterdir()))
  def cmd(args,label,**kw):
   if label=='encrypt-archive':
    kw['on_start']=lambda:(_ for _ in ()).throw(m.Refused('synthetic_start_callback_refusal'))
    return m.command(self.work,[sys.executable,'-c','import time;time.sleep(60)'],label,**kw)
   return old(args,label,**kw)
  j.cmd=cmd
  with self.assertRaisesRegex(m.Refused,'synthetic_start_callback_refusal'):j.seal()
  self.assertFalse(any(t.name=='owned-backup-tar-producer' for t in threading.enumerate()))
  self.assertEqual(len(list(Path('/proc/self/fd').iterdir())),before)
  self.assertNotIn('state-sealed.json',j.journal.records)


 def test_envelope_export_holds_exact_validated_files_across_path_replacement(self):
  j=self.seal_job();j.seal();real_open=g.tarfile.open;output=io.BytesIO();swapped=[]
  class Output:
   buffer=output
  def replaced(*args,**kwargs):
   if kwargs.get('mode')=='w|' and not swapped:
    path=self.work/'backup.tar.gpg';foreign=self.work/'foreign-cipher';m.exclusive(foreign,b'FOREIGN-MUST-NOT-BE-STREAMED');os.replace(foreign,path);swapped.append(True)
   return real_open(*args,**kwargs)
  with patch.object(g.sys,'stdout',Output()),patch.object(g.tarfile,'open',side_effect=replaced),self.assertRaisesRegex(m.Refused,'input_changed'):j.export_file('envelope')
  with real_open(fileobj=io.BytesIO(output.getvalue()),mode='r:') as archive:self.assertEqual(archive.extractfile('backup.tar.gpg').read(),b'SYNTHETIC-CIPHERTEXT')
  self.assertEqual((self.work/'backup.tar.gpg').read_bytes(),b'FOREIGN-MUST-NOT-BE-STREAMED')
 def test_public_tool_export_uses_sealed_verified_bytes_not_replacement(self):
  j=self.seal_job();output=io.BytesIO();path=self.work/'etcdutl';original=path.read_bytes()
  class Output:
   class Buffer:
    def write(inner,raw):
     if not output.tell():
      foreign=self.work/'foreign-tool-export';m.exclusive(foreign,b'FOREIGN-MUST-NOT-LEAVE-GUEST',0o700);os.replace(foreign,path)
     return output.write(raw)
   buffer=Buffer()
  with patch.object(g.sys,'stdout',Output()),self.assertRaisesRegex(m.Refused,'input_changed'):j.export_file('tool')
  self.assertEqual(output.getvalue(),original);self.assertEqual(path.read_bytes(),b'FOREIGN-MUST-NOT-LEAVE-GUEST')

if __name__=='__main__':unittest.main()

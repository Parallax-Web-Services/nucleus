#!/usr/bin/env python3
"""Cross-component real USTAR serialization/parser tests; synthetic payloads, NO real crypto."""
import contextlib,hashlib,importlib.util,io,json,os,tarfile,tempfile,unittest
from pathlib import Path
from unittest.mock import patch
def load(name,path):
 spec=importlib.util.spec_from_file_location(name,path);m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m);return m
guest=load('guest_wire','/tmp/nebula-backup-guest.py');target=load('target_wire','/tmp/nebula-backup-target.py');common=load('common_wire','/tmp/nebula-backup-common.py');policy=load('policy_wire','/tmp/nebula-backup-envelope-policy.py');fixtures=load('guest_fixtures','/tmp/test-nebula-backup-guest.py')
PINS=fixtures.PINS
class BinaryOut:
 def __init__(self):self.buffer=io.BytesIO()
class WireTests(unittest.TestCase):
 def setUp(self):
  self.temp=tempfile.TemporaryDirectory(prefix='nebula-backup-wire-test-',dir='/root');self.root=Path(self.temp.name);self.root.chmod(0o700)
 def tearDown(self):self.temp.cleanup()
 def fd(self,name,raw):
  p=self.root/name;f=common.new_output(p);common.need(os.write(f,raw)==len(raw),'synthetic_fixture_short_write');os.fsync(f);return f
 def test_real_guest_envelope_writer_matches_strict_target_parser(self):
  j=object.__new__(guest.Guest);j.work=self.root;j.m=common;j.p=policy;j.id='1'*32;j.guard=lambda:None;j.prepared=lambda:({},b'synthetic-public')
  cipher=b'SYNTHETIC-CIPHER';common.exclusive(self.root/'backup.tar.gpg',cipher)
  manifest=policy.ciphertext_manifest(j.id,hashlib.sha256(cipher).hexdigest(),len(cipher),PINS,'3'*64,2000000000);common.exclusive(self.root/'manifest.json',manifest);common.exclusive(self.root/'manifest.sig',b's'*64)
  sealed={'ciphertext_sha256':hashlib.sha256(cipher).hexdigest(),'ciphertext_bytes':len(cipher),'ciphertext_identity':common.ident((self.root/'backup.tar.gpg').stat()),'manifest':common.read(self.root/'manifest.json')[1],'signature':common.read(self.root/'manifest.sig')[1]}
  j.journal=type('J',(),{'get':lambda self,n:sealed})()
  out=BinaryOut()
  with patch.object(guest.sys,'stdout',out):j.export_file('envelope')
  raw=out.buffer.getvalue();f=self.fd('wire.tar',raw)
  try:
   items=target.strict_tar(f,len(raw),True,common);self.assertEqual({i['name'] for i in items},{'backup.tar.gpg','manifest.json','manifest.sig'})
   for item in items:
    expected={'backup.tar.gpg':cipher,'manifest.json':manifest,'manifest.sig':b's'*64}[item['name']]
    self.assertEqual(os.pread(f,item['size'],item['offset']),expected)
  finally:os.close(f)
 def test_real_guest_inner_writer_matches_target_allowlist_and_critical_material(self):
  case=fixtures.GuestTests();case.setUp()
  try:
   j=case.seal_job();j.seal()
   raw=j.synthetic_inner_tar;f=self.fd('inner.tar',raw)
   try:
    items=target.strict_tar(f,len(raw),False,common)
    inventory=[{k:i[k] for k in ['name','kind','size']} for i in items];policy.archive_inventory(inventory)
    self.assertTrue(target.CRITICAL_FILES<=set(i['name'] for i in items))
    record=next(i for i in items if i['name']=='restore-manifest.json');v=json.loads(os.pread(f,record['size'],record['offset']))
    actual=sorted((i['name'],i['size']) for i in items if i['name']!='restore-manifest.json');declared=sorted((i['name'],i['size']) for i in v['archive_members']);self.assertEqual(actual,declared)
    self.assertEqual(v['etcd_version'],'3.7.0');self.assertEqual(set(v['snapshot_status']),{'hash','revision','totalKey','totalSize','version'})
   finally:os.close(f)
  finally:case.tearDown()
 def test_actual_writer_padding_accepted_but_payload_after_end_refused(self):
  b=io.BytesIO()
  with tarfile.open(fileobj=b,mode='w',format=tarfile.USTAR_FORMAT) as t:
   for name,data in [('backup.tar.gpg',b'x'),('manifest.json',b'{}'),('manifest.sig',b's'*64)]:
    i=tarfile.TarInfo(name);i.size=len(data);t.addfile(i,io.BytesIO(data))
  raw=b.getvalue();f=self.fd('good.tar',raw)
  try:self.assertEqual(len(target.strict_tar(f,len(raw),True,common)),3)
  finally:os.close(f)
  bad=raw[:-1]+b'x';f=self.fd('bad.tar',bad)
  try:
   with self.assertRaises(common.Refused):target.strict_tar(f,len(bad),True,common)
  finally:os.close(f)
if __name__=='__main__':unittest.main()

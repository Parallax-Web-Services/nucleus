import hashlib,importlib.util,json,unittest
spec=importlib.util.spec_from_file_location('policy','/tmp/nebula-backup-envelope-policy.py');m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
PINS={'Tarragon':{'primary_fingerprint':'A'*40,'encryption_subkey_fingerprint':'B'*40},'Slipstream':{'primary_fingerprint':'C'*40,'encryption_subkey_fingerprint':'D'*40}}
NOW=2000000000
def row(kind,fp='',caps='',expiry=NOW+365*86400,valid='u'):
 fields=['']*13;fields[0]=kind;fields[1]=valid;fields[2]='255';fields[3]='22' if kind=='pub' else '18';fields[5]=str(NOW-60);fields[6]=str(expiry);fields[9]=fp;fields[11]=caps;return ':'.join(fields)
def metadata(primary='A'*40,sub='B'*40):
 return '\n'.join([row('pub',caps='scSC'),row('fpr',fp=primary),row('uid'),row('sub',caps='e'),row('fpr',fp=sub)])
class PolicyTests(unittest.TestCase):
 def test_exact_two_distinct_recipients(self):self.assertEqual(m.pins(PINS),PINS)
 def test_single_recipient_rejected(self):
  with self.assertRaises(m.Refused):m.pins({'Tarragon':PINS['Tarragon']})
 def test_shared_primary_rejected(self):
  p=json.loads(json.dumps(PINS));p['Slipstream']['primary_fingerprint']='A'*40
  with self.assertRaises(m.Refused):m.pins(p)
 def test_shared_encryption_subkey_rejected(self):
  p=json.loads(json.dumps(PINS));p['Slipstream']['encryption_subkey_fingerprint']='B'*40
  with self.assertRaises(m.Refused):m.pins(p)
 def test_short_id_and_alias_rejected(self):
  for x in ['A'*16,'target@example.test','-r attacker','a'*40]:
   with self.assertRaises(m.Refused):m.fingerprint(x)
 def test_public_metadata_pins_and_validity(self):self.assertEqual(m.parsed_key(metadata(),PINS['Tarragon'],NOW),PINS['Tarragon'])
 def test_secret_metadata_rejected(self):
  for record in ['sec','ssb']:
   with self.assertRaisesRegex(m.Refused,'secret_or_unrecognized'):m.parsed_key(metadata()+'\n'+row(record),PINS['Tarragon'],NOW)
 def test_wrong_primary_or_subkey_rejected(self):
  for text in [metadata(primary='F'*40),metadata(sub='F'*40)]:
   with self.assertRaises(m.Refused):m.parsed_key(text,PINS['Tarragon'],NOW)
 def test_revoked_expired_disabled_key_rejected(self):
  for changed in [metadata().replace('pub:u:','pub:r:'),metadata().replace('sub:u:','sub:e:'),metadata().replace(':e:',':eD:'),metadata().replace(str(NOW+365*86400),str(NOW-1))]:
   with self.assertRaises(m.Refused):m.parsed_key(changed,PINS['Tarragon'],NOW)
 def test_non_encryption_subkey_rejected(self):
  with self.assertRaises(m.Refused):m.parsed_key(metadata().replace(':e:',':s:'),PINS['Tarragon'],NOW)
 def test_unreviewed_algorithm_profile_rejected(self):
  for changed in [metadata().replace('pub:u:255:22:','pub:u:1024:1:'),metadata().replace('sub:u:255:18:','sub:u:2048:16:')]:
   with self.assertRaisesRegex(m.Refused,'reviewed_ed25519_cv25519'):m.parsed_key(changed,PINS['Tarragon'],NOW)
 def test_public_key_requires_exact_public_armor(self):
  good=b'-----BEGIN PGP PUBLIC KEY BLOCK-----\nfixture\n-----END PGP PUBLIC KEY BLOCK-----\n'
  self.assertEqual(m.public_key_file(good),hashlib.sha256(good).hexdigest())
  for bad in [good+good,good+b'PRIVATE KEY',b'-----BEGIN PGP PRIVATE KEY BLOCK-----']:
   with self.assertRaises(m.Refused):m.public_key_file(bad)
 def test_gpg_config_isolation_and_exact_recipients(self):
  args=m.encrypt_args('/root/owned/source-public-only',PINS)
  self.assertIn('--no-options',args);self.assertIn('--no-encrypt-to',args);self.assertIn('--no-groups',args);self.assertEqual(args.count('--recipient'),2)
  self.assertEqual([args[i+1] for i,a in enumerate(args) if a=='--recipient'],['B'*40+'!','D'*40+'!']);self.assertNotIn('--sign',args);self.assertEqual(args[-1],'--encrypt')
 def test_paths_are_not_shell_or_relative(self):
  for home in ['relative','/root/../foreign']:
   with self.assertRaises(m.Refused):m.encrypt_args(home,PINS)
 def test_archive_traversal_special_files_and_unapproved_inputs(self):
  for name,kind in [('../etc/shadow','regular'),('/etc/shadow','regular'),('restore-inputs/../escape','regular'),('restore-inputs/socket','socket'),('root/.env','regular'),('restore-inputs/link','symlink')]:
   with self.assertRaises(m.Refused):m.archive_member(name,kind,1)
 def test_archive_requires_snapshot_and_restore_manifest(self):
  good=[{'name':'snapshot.db','kind':'regular','size':100},{'name':'restore-manifest.json','kind':'regular','size':100},{'name':'etc/kubernetes/pki/ca.key','kind':'regular','size':100}]
  self.assertEqual(len(m.archive_inventory(good)),3)
  for bad in [good[1:],good[:1],good+good[:1]]:
   with self.assertRaises(m.Refused):m.archive_inventory(bad)
 def test_archive_total_and_snapshot_bounds(self):
  with self.assertRaises(m.Refused):m.archive_member('snapshot.db','regular',m.MAX_SNAPSHOT+1)
  with self.assertRaises(m.Refused):m.archive_inventory([{'name':'snapshot.db','kind':'regular','size':1},{'name':'restore-manifest.json','kind':'regular','size':m.MAX_OTHER},{'name':'restore-inputs/extra','kind':'regular','size':1}])
 def test_manifest_exact_canonical_and_trusted_pins(self):
  raw=m.ciphertext_manifest('1'*32,'2'*64,100,PINS,'3'*64,NOW)
  self.assertEqual(m.validate_received_manifest(raw,PINS,'3'*64,'1'*32)['ciphertext']['bytes'],100)
  for bad in [raw.replace(b'"schema_version":1',b'"schema_version":2'),raw.replace(b'"backup.tar.gpg"',b'"../backup.tar.gpg"'),raw.replace(b'"3',b'"4'),b'[]',b'{"ciphertext":null}',raw+b' ']:
   with self.assertRaises(m.Refused):m.validate_received_manifest(bad,PINS,'3'*64,'1'*32)
 def test_manifest_bounds(self):
  for n in [0,m.MAX_CIPHERTEXT+1,True]:
   with self.assertRaises(m.Refused):m.ciphertext_manifest('1'*32,'2'*64,n,PINS,'3'*64,NOW)
 def test_decrypt_only_exclusive_fd_and_bounded_plaintext(self):
  args=m.decrypt_args('/root/owned/recovery',5,1000);self.assertEqual(args[-3:],['--output','/proc/self/fd/5','--decrypt']);self.assertNotIn('--ignore-mdc-error',args)
  for fd,n in [(1,100),(5,0),(5,m.MAX_SNAPSHOT+m.MAX_OTHER+16*1024**2+1)]:
   with self.assertRaises(m.Refused):m.decrypt_args('/root/owned/recovery',fd,n)
 def test_module_has_no_mutation_or_execution(self):
  import ast
  from pathlib import Path
  tree=ast.parse(Path('/tmp/nebula-backup-envelope-policy.py').read_text())
  banned={'subprocess','os','sys','socket','urllib','requests'}
  for node in ast.walk(tree):
   if isinstance(node,ast.Import):self.assertFalse(any(x.name.split('.')[0] in banned for x in node.names))
   if isinstance(node,ast.Call) and isinstance(node.func,ast.Name):self.assertNotIn(node.func.id,['open','exec','eval','compile'])
if __name__=='__main__':unittest.main()

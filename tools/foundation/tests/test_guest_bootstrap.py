import ast,hashlib,io,json,os,sys,tarfile,tempfile,unittest,uuid
from pathlib import Path
from unittest.mock import patch
from tests.support import load_module,context_fixture
m=load_module('guest/bootstrap')
class PublicationTests(unittest.TestCase):
 def test_exclusive_file_publication_has_retained_inode_and_refuses_foreign(self):
  with tempfile.TemporaryDirectory(prefix='nebula-guest-test-') as d:
   root=Path(d);p=root/'new';r=m.write_exclusive(p,b'public fixture',0o644)
   self.assertEqual(r,m.file_snapshot(p));self.assertEqual(p.stat().st_nlink,1)
   with self.assertRaises(m.Refused):m.write_exclusive(p,b'overwrite')
   self.assertEqual(p.read_bytes(),b'public fixture')
 def test_symlink_destination_and_writable_parent_refused(self):
  with tempfile.TemporaryDirectory(prefix='nebula-guest-test-') as d:
   root=Path(d);other=root/'foreign';other.write_bytes(b'foreign');p=root/'new';p.symlink_to(other)
   with self.assertRaises(m.Refused):m.write_exclusive(p,b'ours')
   self.assertEqual(other.read_bytes(),b'foreign')
   p.unlink();root.chmod(0o777)
   with self.assertRaisesRegex(m.Refused,'destination_directory'):m.write_exclusive(p,b'ours')
   self.assertFalse(p.exists());root.chmod(0o700)
 def test_held_artifact_fd_refuses_replacement_and_wrong_digest(self):
  with tempfile.TemporaryDirectory(prefix='nebula-guest-test-') as d:
   root=Path(d);p=root/'artifact';m.write_exclusive(p,b'original')
   with self.assertRaisesRegex(m.Refused,'digest_mismatch'):
    with m.verified_fd(p,'0'*64):pass
   with self.assertRaisesRegex(m.Refused,'changed_during_use'):
    with m.verified_fd(p,m.digest(b'original')) as fd:
     other=root/'foreign';m.write_exclusive(other,b'foreign');os.replace(other,p)
     self.assertEqual(os.read(fd,100),b'original')
   self.assertEqual(p.read_bytes(),b'foreign')
 def test_extracted_member_edit_is_not_installed_as_trusted_bytes(self):
  with tempfile.TemporaryDirectory(prefix='nebula-guest-test-') as d:
   p=Path(d)/'binary';record=m.write_exclusive(p,b'approved binary')
   self.assertEqual(m.prepared_bytes(p,record),b'approved binary')
   p.write_bytes(b'foreign modified binary')
   with self.assertRaises(m.Refused):m.prepared_bytes(p,record)
class ArchiveTests(unittest.TestCase):
 def archive(self,root,entries):
  path=root/'archive'
  with tarfile.open(path,'w:gz')as out:
   for name,kind,body in entries:
    item=tarfile.TarInfo(name)
    if kind=='file':item.size=len(body);out.addfile(item,io.BytesIO(body))
    elif kind=='dir':item.type=tarfile.DIRTYPE;out.addfile(item)
    else:item.type=tarfile.SYMTYPE;item.linkname=body.decode();out.addfile(item)
  path.chmod(0o600);return path
 def test_strict_regular_members_extract_only_selected_bytes(self):
  with tempfile.TemporaryDirectory(prefix='nebula-guest-test-') as d:
   root=Path(d);p=self.archive(root,[('public','file',b'approved'),('unused','file',b'unused')])
   with m.verified_fd(p,hashlib.sha256(p.read_bytes()).hexdigest()) as fd:
    records=m.extract_selected(fd,{'public','unused'},{'public'},root/'prepared')
   self.assertEqual(set(records),{'public'});self.assertEqual(m.prepared_bytes(root/'prepared/public',records['public']),b'approved');self.assertFalse((root/'prepared/unused').exists())
 def test_traversal_symlinks_duplicate_or_unknown_members_refused(self):
  for entries,allowed in [
   ([('../escape','file',b'x')],{'../escape'}),
   ([('link','symlink',b'/etc/passwd')],{'link'}),
   ([('same','file',b'a'),('same','file',b'b')],{'same'}),
   ([('unknown','file',b'a')],{'expected'})]:
   with self.subTest(entries=entries),tempfile.TemporaryDirectory(prefix='nebula-guest-test-') as d:
    root=Path(d);p=self.archive(root,entries);fd=os.open(p,os.O_RDONLY)
    try:
     with self.assertRaises(m.Refused):m.archive_members(fd,allowed)
    finally:os.close(fd)
    self.assertFalse((root.parent/'escape').exists())
 def test_generated_profile_archive_inventories_do_not_claim_actual_artifact_acceptance(self):
  # Synthetic payloads exercise exact admitted inventories, not release binaries.
  for filename,allowed in [('containerd-2.3.7-linux-amd64.tar.gz',m.RUNTIME_MEMBERS),('nebula-kubernetes-v1.37.1-amd64-verified.tar.gz',m.BUNDLE_MEMBERS)]:
   with self.subTest(profile_archive=filename),tempfile.TemporaryDirectory(prefix='nebula-guest-test-')as d:
    entries=[(name,'dir'if name.endswith('/')else'file',b'synthetic public fixture: '+name.encode())for name in sorted(allowed)]
    path=self.archive(Path(d),entries);synthetic_digest=m.digest(path.read_bytes());self.assertNotEqual(synthetic_digest,m.PINS[filename])
    with m.verified_fd(path,synthetic_digest)as fd:self.assertEqual(set(m.archive_members(fd,allowed)),allowed)
class IdentityAndConfigurationTests(unittest.TestCase):
 def test_uuid_hostname_distro_and_swap_are_exactly_guarded(self):
  context=context_fixture(role='guest');expected=context.inputs['expected_guest_uuid'];run_id=context.inputs['run_id']
  mapping={
   '/sys/class/dmi/id/product_uuid':expected,
   '/etc/os-release':'ID=ubuntu\nVERSION_ID="24.04"\nVERSION_CODENAME=noble\n',
   '/proc/swaps':'Filename Type Size Used Priority\n'}
  def text(path,*a,**k):return mapping[str(path)]
  with patch.object(m.os,'geteuid',return_value=0),patch.object(m.os,'cpu_count',return_value=2),patch.object(m.socket,'gethostname',return_value='nebula-control-'+run_id),patch.object(m.platform,'machine',return_value='x86_64'),patch.object(Path,'read_text',text),patch.object(Path,'is_file',return_value=True):
   m.guest_identity(expected,run_id,context=context)
   for field,value in [('/sys/class/dmi/id/product_uuid',str(uuid.uuid4())),('/etc/os-release','ID=ubuntu\nVERSION_ID="22.04"\nVERSION_CODENAME=jammy'),('/proc/swaps','header\nforeign active swap\n')]:
    original=mapping[field];mapping[field]=value
    with self.subTest(field=field),self.assertRaises(m.Refused):m.guest_identity(expected,run_id,context=context)
    mapping[field]=original
   with patch.object(m.socket,'gethostname',return_value='wrong-synthetic-host'),self.assertRaises(m.Refused):m.guest_identity(expected,run_id,context=context)
 def test_route_collision_includes_broader_routes_and_skips_default(self):
  self.assertTrue(m.routes_clear([{'dst':'default'},{'dst':'192.168.240.0/24'}]))
  for dest in ['10.0.0.0/8','10.244.1.0/24','10.96.0.0/16']:
   with self.subTest(dest=dest):self.assertFalse(m.routes_clear([{'dst':dest}]))
 def test_runtime_config_requires_approved_pause_digest_and_systemd_cgroup(self):
  raw=m.containerd_config().decode()
  self.assertIn(m.PAUSE_IMAGE,raw);self.assertIn('SystemdCgroup = true',raw);self.assertIn('BinaryName = "/usr/local/sbin/runc"',raw)
  for value in [None,'registry.k8s.io/pause:latest','https://unapproved/image']:
   with self.subTest(value=value),patch.object(m,'PAUSE_IMAGE',value),self.assertRaises(m.Refused):m.containerd_config()
 def test_mutating_phase_without_explicit_flag_refuses_before_guest_or_filesystem(self):
  with patch.object(m,'require_context')as context,patch.object(m,'Bootstrap')as constructor,patch.object(m,'guest_identity')as guest,patch.object(m.os,'open')as opened:
   with self.assertRaisesRegex(m.Refused,'explicit_execute_required'):m.run_phase(None,'00000000-0000-4000-8000-000000000001','0123456789ab',Path('/unread/synthetic/plan'),'install')
   context.assert_not_called();constructor.assert_not_called();guest.assert_not_called();opened.assert_not_called()
 def test_guest_lock_and_source_contain_no_cluster_init_or_reset(self):
  self.assertEqual([x[0] for x in m.PACKAGES],['kubernetes-cni','cri-tools','kubelet','kubeadm','kubectl'])
  self.assertNotIn(b'kubelet',m.UNIT);self.assertIn(b'/usr/local/bin/containerd --config /etc/containerd/config.toml',m.UNIT)
  with self.assertRaisesRegex(m.Refused,'source_api_only_no_public_installer'):m.main()
class ReceiptTests(unittest.TestCase):
 def job(self,root):
  j=object.__new__(m.Bootstrap);j.context=context_fixture(role='guest');j.work=root;j.state_path=root/'install-state.json';j.expected_control=None;j.state={'files':{},'phase':'started'}
  def guard():
   if j.expected_control is None:m.need(not os.path.lexists(j.state_path),'install_control_state_changed')
   else:m.need(m.file_snapshot(j.state_path,private=True)==j.expected_control,'install_control_state_changed')
   for path,known in j.state['files'].items():m.need(m.file_snapshot(Path(path))==known,'installed_file_changed')
  j.guard=guard;return j
 def test_control_replacement_is_never_overwritten(self):
  with tempfile.TemporaryDirectory(prefix='nebula-guest-test-') as d:
   root=Path(d);j=self.job(root);j.persist();before=j.expected_control;j.state['phase']='next';j.persist();self.assertNotEqual(j.expected_control,before)
   foreign=root/'foreign';m.write_exclusive(foreign,b'FOREIGN OPERATOR RECEIPT');os.replace(foreign,j.state_path);inode=j.state_path.stat().st_ino
   with self.assertRaisesRegex(m.Refused,'control_state_changed'):j.persist()
   self.assertEqual(j.state_path.read_bytes(),b'FOREIGN OPERATOR RECEIPT');self.assertEqual(j.state_path.stat().st_ino,inode)
 def test_publication_race_never_overwrites_or_adopts_foreign_target(self):
  with tempfile.TemporaryDirectory(prefix='nebula-guest-test-') as d:
   root=Path(d);p=root/'new';link=os.link
   def race(source,target,**kw):
    p.write_bytes(b'FOREIGN OPERATOR FILE');p.chmod(0o600);return link(source,target,**kw)
   with patch.object(m.os,'link',side_effect=race),self.assertRaises(FileExistsError):m.write_exclusive(p,b'ours')
   self.assertEqual(p.read_bytes(),b'FOREIGN OPERATOR FILE')

if __name__=='__main__':unittest.main(verbosity=2)


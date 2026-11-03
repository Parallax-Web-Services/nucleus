import ast,base64,json,tempfile,unittest,uuid
from pathlib import Path
from types import SimpleNamespace
from foundation.framework import FoundationContext
from unittest.mock import patch
from tests.support import load_module,context_fixture
m=load_module('host/preflight')
class HostPreflightTests(unittest.TestCase):
 def test_capacity_checks_reserve_existing_and_new_guests(self):
  full=m.capacity(6*m.GIB,20*m.GIB,8,32*m.GIB,14*m.GIB,4);self.assertTrue(all(full.values()))
  for args in [(6*m.GIB-1,20*m.GIB,8,32*m.GIB,14*m.GIB,4),(6*m.GIB,20*m.GIB-1,8,32*m.GIB,14*m.GIB,4),(6*m.GIB,20*m.GIB,7,32*m.GIB,14*m.GIB,4),(6*m.GIB,20*m.GIB,8,32*m.GIB-1,14*m.GIB,4)]:
   self.assertFalse(all(m.capacity(*args).values()))
 def test_libvirt_mutating_verbs_refused_before_subprocess(self):
  with patch.object(m.subprocess,'run') as run:
   for verb in ['start','destroy','undefine','define','vol-create-as','net-start','pool-refresh']:
    with self.subTest(verb=verb),self.assertRaises(m.Refused):m.query(verb,'anything',context=context_fixture(role='host'))
   run.assert_not_called()
 def test_seed_has_public_key_and_no_private_key_or_execution(self):
  key='ssh-ed25519 '+base64.b64encode(b'\0\0\0\x0bssh-ed25519\0\0\0\x20'+bytes(range(32))).decode()+' test'
  plan={'run_id':'0123456789ab','proposed_name':'nebula-control-0123456789ab','new_domain_uuid':'00000000-0000-4000-8000-000000000001'}
  user,meta=m.cloud_init(plan,key);data=json.loads(user.decode().split('\n',1)[1])
  self.assertEqual(data['users'][0]['ssh_authorized_keys'],[' '.join(key.split()[:2])])
  self.assertNotIn('runcmd',data);self.assertNotIn('bootcmd',data);self.assertNotIn(b'PRIVATE KEY',user);self.assertNotIn(b'password',user.lower())
  self.assertEqual(json.loads(meta)['instance-id'],'nebula-0123456789ab')
 def test_bad_or_private_keys_are_refused(self):
  for key in ['-----BEGIN OPENSSH PRIVATE KEY-----','ssh-rsa AAAA','ssh-ed25519 AAAA','ssh-ed25519 bad\nnext']:
   with self.subTest(key=key),self.assertRaises(m.Refused):m.public_ssh_key(key)
 def test_source_has_no_apply_flag_or_mutating_invocations(self):
  self.assertTrue(all(verb not in m.READONLY_VERBS for verb in ['start','create','define','destroy','undefine']))
class ContextAdmissionTests(unittest.TestCase):
 def test_queries_gather_and_capture_require_context_before_any_probe(self):
  with patch.object(m.subprocess,'run') as command,patch.object(m.os,'geteuid') as user,patch.object(m.socket,'gethostname') as host:
   for operation in [lambda:m.query('list'),lambda:m.gather(None),lambda:m.capture(Path('/unread/plan'),{},context=None)]:
    with self.assertRaises(RuntimeError):operation()
   command.assert_not_called();user.assert_not_called();host.assert_not_called()
 def test_query_cannot_override_reviewed_system_libvirt_uri(self):
  ctx=context_fixture(role='host')
  with patch.object(m.subprocess,'run') as command:
   for args in [('list','--connect','qemu+ssh://foreign/system'),('list','--connect=qemu:///session'),('list','-c','test:///default')]:
    with self.assertRaisesRegex(m.Refused,'fixed_libvirt_uri_required'):m.query(*args,context=ctx)
   command.assert_not_called()
 def test_wrong_host_refuses_gather_before_even_injected_metadata_queries(self):
  ctx=context_fixture(role='host');fetch=unittest.mock.Mock()
  with patch.object(m.os,'geteuid',return_value=0),patch.object(m.socket,'gethostname',return_value='different-host'):
   with self.assertRaisesRegex(m.Refused,'admitted_host_root_only'):m.gather(ctx,fetch=fetch)
  fetch.assert_not_called()
 def test_named_network_pool_fixed_resources_and_uuid_are_captured_once(self):
  base=context_fixture(role='host');inputs={**base.inputs,'libvirt_network':'fixture-network','libvirt_pool':'fixture-pool','expected_protected_domain_count':0,'expected_guest_uuid':None};ctx=FoundationContext(base.bundle,inputs)
  with tempfile.TemporaryDirectory() as directory:
   pool=Path(directory);calls=[]
   def fetch(*args):
    calls.append(args);verb=args[0]
    if verb=='list':return b''
    if verb=='net-info':return b'Active: yes\nPersistent: yes\n'
    if verb=='net-uuid':return b'00000000-0000-4000-8000-000000000010'
    if verb=='net-dumpxml':return b'<network><forward mode="nat"/><ip address="192.168.100.1" netmask="255.255.255.0"/><bridge name="virbr-fixture"/></network>'
    if verb=='pool-info':return ('State: running\nAvailable: '+str(64*m.GIB)+'\n').encode()
    if verb=='pool-uuid':return b'00000000-0000-4000-8000-000000000011'
    if verb=='pool-dumpxml':return ('<pool type="dir"><target><path>'+str(pool)+'</path></target></pool>').encode()
    if verb=='vol-list':return b''
    raise AssertionError('unexpected metadata query')
   original_open=m.os.open;original_text=Path.read_text;original_iter=Path.iterdir;original_stat=Path.stat
   def opened(path,*args,**kwargs):
    if str(path)=='/dev/kvm':raise OSError('synthetic missing KVM')
    return original_open(path,*args,**kwargs)
   def text(path,*args,**kwargs):
    if str(path)=='/proc/meminfo':return 'MemAvailable: 16777216 kB\nMemTotal: 33554432 kB\n'
    return original_text(path,*args,**kwargs)
   def entries(path):return iter([])if str(path)=='/proc'else original_iter(path)
   def metadata(path,*args,**kwargs):
    observed=original_stat(path,*args,**kwargs)
    if path==pool:
     values={key:getattr(observed,key)for key in ['st_dev','st_ino','st_mode','st_uid','st_gid','st_nlink','st_size','st_mtime_ns','st_ctime_ns']};values.update(st_uid=0,st_mode=0o40700);return SimpleNamespace(**values)
    return observed
   generated=uuid.UUID('00000000-0000-4000-8000-000000000099')
   with patch.object(m.os,'geteuid',return_value=0),patch.object(m.socket,'gethostname',return_value=inputs['host_name']),patch.object(m.os,'open',side_effect=opened),patch.object(Path,'read_text',text),patch.object(Path,'iterdir',entries),patch.object(Path,'stat',metadata),patch.object(m.os,'cpu_count',return_value=16),patch.object(m.shutil,'which',return_value='/synthetic/tool'),patch.object(m.uuid,'uuid4',return_value=generated) as generator:
    plan=m.gather(ctx,fetch=fetch)
   generator.assert_called_once_with()
   self.assertEqual(plan['new_domain_uuid'],str(generated));self.assertEqual(plan['foundation_binding'],ctx.binding())
   self.assertEqual(plan['network']['name'],'fixture-network');self.assertEqual(plan['pool']['name'],'fixture-pool')
   self.assertEqual(plan['resources']['memory_bytes'],4*m.GIB);self.assertEqual(plan['resources']['raw_disk_bytes'],20*m.GIB)
   self.assertTrue(all(args[1]=='fixture-network'for args in calls if args[0].startswith('net-')))
   self.assertTrue(all(args[1]=='fixture-pool'for args in calls if args[0].startswith('pool-')))
   self.assertIn(('vol-list','--pool','fixture-pool'),calls)
 def test_source_has_no_operational_main_or_developer_dependencies(self):
  raw=Path(m.__file__).read_text();tree=ast.parse(raw)
  self.assertFalse(any(isinstance(n,ast.FunctionDef)and n.name=='main'for n in tree.body))
  self.assertNotIn('/tmp/',raw);self.assertNotIn('Alpha',raw)
if __name__=='__main__':unittest.main(verbosity=2)


import ast,copy,fcntl,json,os,stat,tempfile,time,unittest,uuid
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch,MagicMock
from tests.support import load_module,context_fixture
m=load_module('host/lifecycle')
PLAN={'run_id':'0123456789ab','proposed_name':'nebula-control-0123456789ab','new_domain_uuid':'00000000-0000-4000-8000-000000000001','network':{'name':'synthetic-network','bridge':'virbr0'}}
class XMLTests(unittest.TestCase):
 def raw(self):return m.guest_xml(PLAN,Path('/pool/new.raw'),Path('/pool/new.iso'),'52:54:00:01:02:03')
 def validate(self,raw):return m.validate_xml(raw,PLAN,Path('/pool/new.raw'),Path('/pool/new.iso'),'52:54:00:01:02:03')
 def test_exact_new_definition_has_saved_uuid_private_nat_and_agent(self):
  raw=self.raw();self.validate(raw);x=m.E.fromstring(raw)
  self.assertEqual(x.findtext('uuid'),PLAN['new_domain_uuid']);self.assertEqual(x.findtext('memory'),'4194304')
  self.assertEqual(x.find('devices/channel/target').get('name'),'org.qemu.guest_agent.0')
  self.assertIsNone(x.find('devices/graphics'));self.assertIsNone(x.find('devices/filesystem'))
 def test_host_devices_folders_loader_extra_args_or_other_disks_rejected(self):
  for kind in ['hostdev','filesystem','extra-disk','backing','loader','network','quota','rng','serial','qemu-args','evdev','serial-log','agent-log','target-physical']:
   with self.subTest(kind=kind):
    x=m.E.fromstring(self.raw());dev=x.find('devices')
    if kind in ['hostdev','filesystem']:m.E.SubElement(dev,kind)
    elif kind=='extra-disk':dev.append(copy.deepcopy(dev.find('disk')))
    elif kind=='backing':m.E.SubElement(m.E.SubElement(dev.find('disk'),'backingStore'),'source',{'file':'/foreign/disk'})
    elif kind=='loader':m.E.SubElement(x.find('os'),'loader').text='/foreign/firmware'
    elif kind=='network':dev.find('interface/source').set('network','foreign')
    elif kind=='quota':x.find('cputune/quota').text='900000'
    elif kind=='rng':m.E.SubElement(m.E.SubElement(dev,'rng'),'backend').text='/etc/shadow'
    elif kind=='serial':dev.find('serial').set('type','file')
    elif kind=='evdev':m.E.SubElement(m.E.SubElement(dev,'input',{'type':'evdev'}),'source',{'dev':'/dev/input/event0'})
    elif kind=='serial-log':m.E.SubElement(dev.find('serial'),'log',{'file':'/foreign/file'})
    elif kind=='agent-log':m.E.SubElement(dev.find('channel'),'log',{'file':'/foreign/file'})
    elif kind=='target-physical':m.E.SubElement(dev.find('interface'),'target',{'dev':'eth0','managed':'no'})
    else:m.E.SubElement(x,'{http://libvirt.org/schemas/domain/qemu/1.0}commandline')
    with self.assertRaises(m.Refused):self.validate(m.E.tostring(x))
 def test_public_agent_socket_cannot_point_to_other_domain(self):
  x=m.E.fromstring(self.raw());m.E.SubElement(x.find('devices/channel'),'source',{'mode':'bind','path':'/var/lib/libvirt/qemu/channel/target/domain-1-foreign/agent'})
  with self.assertRaisesRegex(m.Refused,'agent_socket'):self.validate(m.E.tostring(x))
class VolumeTests(unittest.TestCase):
 def job(self,root,allocated=True):
  j=object.__new__(m.Lifecycle);j.context=context_fixture(role='host');j.plan={'pool':{'name':'synthetic-pool','path':str(root)}};j.state={'volumes':{}};j.guard=lambda:None;j.persist=lambda:None;j.admit_start=lambda:None;calls=[]
  def run(args,label,timeout=60):
   calls.append(args)
   if 'vol-create-as' in args:
    path=root/args[5];size=int(args[6]);fd=os.open(path,os.O_CREAT|os.O_EXCL|os.O_WRONLY,0o600)
    try:
     if allocated:os.posix_fallocate(fd,0,size)
     else:os.ftruncate(fd,size)
    finally:os.close(fd)
    return b''
   if 'vol-path' in args:return str(root/args[-1]).encode()
   raise AssertionError('Unexpected fixture command')
  j.runner=run;return j,calls
 def test_new_only_fully_allocated_volume_created(self):
  with tempfile.TemporaryDirectory() as d:
   root=Path(d);(root/'foreign.raw').write_bytes(b'preserved');j,calls=self.job(root);j.create_volume('new.raw',4096)
   self.assertEqual((root/'foreign.raw').read_bytes(),b'preserved');self.assertEqual(j.state['volumes']['new.raw']['size'],4096)
   self.assertGreaterEqual(j.state['volumes']['new.raw']['allocated'],4096);self.assertEqual(len(calls),2)
 def test_existing_path_refused_before_libvirt_mutation(self):
  with tempfile.TemporaryDirectory() as d:
   root=Path(d);p=root/'new.raw';p.write_bytes(b'foreign');j,calls=self.job(root)
   with self.assertRaisesRegex(m.Refused,'path_exists'):j.create_volume('new.raw',4096)
   self.assertEqual(p.read_bytes(),b'foreign');self.assertFalse(calls)
 def test_sparse_reservation_refused_and_never_claimed_owned(self):
  with tempfile.TemporaryDirectory() as d:
   j,calls=self.job(Path(d),False)
   with self.assertRaisesRegex(m.Refused,'fully_reserved'):j.create_volume('new.raw',1024*1024)
   self.assertEqual(j.state['volumes'],{})
 def test_combined_guard_failure_prevents_first_volume_mutation(self):
  with tempfile.TemporaryDirectory() as d:
   j,calls=self.job(Path(d))
   def fail():raise m.Refused('protected_vm_changed')
   j.guard=fail
   with self.assertRaisesRegex(m.Refused,'protected_vm'):j.create_volume('new.raw',4096)
   self.assertFalse(calls);self.assertEqual(list(Path(d).iterdir()),[])
class SignatureTests(unittest.TestCase):
 def fixture(self,root,signer=None,digest=None,backing=False):
  j=object.__new__(m.Lifecycle);j.context=context_fixture(role='host');j.work=root;j.state={};j.persist=lambda:None
  pin={'url':'https://cloud-images.ubuntu.com/releases/noble/release-20261017/image.img','sha256':'a'*64};j.plan={'public_artifact_pins':{'ubuntu':pin},'resources':{'raw_disk_bytes':20*1024**3}}
  (root/'SHA256SUMS').write_text('a'*64+' *image.img\n');(root/'SHA256SUMS.gpg').write_bytes(b'public signature fixture');(root/'image.img').write_bytes(b'verified image fixture');key=root/'key.gpg';key.write_bytes(b'public key fixture');calls=[]
  def runner(args,label,timeout=60,**kwargs):
   calls.append(label)
   if label=='verify-image-signature':return ('[GNUPG:] VALIDSIG '+(signer or m.SIGNER)+' 2026-01-01 0 0 4 0 1 10 00\n').encode()
   if label=='inspect-verified-image':
    self.assertTrue(args[-1].startswith('/proc/self/fd/'));self.assertEqual(kwargs['pass_fds'],(int(args[-1].rsplit('/',1)[1]),))
    self.assertEqual(os.pread(kwargs['pass_fds'][0],100,0),b'verified image fixture')
    return json.dumps({'format':'qcow2','virtual-size':4*1024**3,**({'backing-filename':'foreign'} if backing else {})}).encode()
   raise AssertionError('Unexpected signature fixture command')
  j.runner=runner;return j,key,calls
 def runverify(self,j,key,digest=None):
  original=Path.stat
  def statfn(path,*a,**k):
   if path==key:return SimpleNamespace(st_uid=0,st_mode=stat.S_IFREG|0o644)
   return original(path,*a,**k)
  original_read=m.read
  def readfn(path,*args,**kwargs):
   if path==key:return b'public key fixture'
   kwargs['private']=False
   return original_read(path,*args,**kwargs)
  def identity(fd):
   s=os.fstat(fd);return(s.st_dev,s.st_ino,s.st_mode,s.st_uid,s.st_gid,s.st_nlink,s.st_size,s.st_mtime_ns,s.st_ctime_ns)
  def hashed(fd):return digest or 'a'*64,os.fstat(fd).st_size,identity(fd)
  with patch.object(Path,'stat',statfn),patch.object(m,'read',side_effect=readfn),patch.object(m,'image_identity',side_effect=identity),patch.object(m,'hash_image_fd',side_effect=hashed):j.verify_image(key)
 def test_signature_then_exact_digest_before_qcow_parser(self):
  with tempfile.TemporaryDirectory() as d:
   j,key,calls=self.fixture(Path(d));self.runverify(j,key)
   self.assertEqual(calls,['verify-image-signature','inspect-verified-image']);self.assertEqual(j.state['verified_image'],'image.img')
 def test_wrong_signer_or_tampered_image_never_reaches_qcow_parser(self):
  for kind in ['signer','digest']:
   with self.subTest(kind=kind),tempfile.TemporaryDirectory() as d:
    j,key,calls=self.fixture(Path(d),signer='B'*40 if kind=='signer' else None)
    with self.assertRaises(m.Refused):self.runverify(j,key,'b'*64 if kind=='digest' else None)
    self.assertNotIn('inspect-verified-image',calls);self.assertNotIn('verified_image',j.state)
 def test_external_backing_chain_refused(self):
  with tempfile.TemporaryDirectory() as d:
   j,key,calls=self.fixture(Path(d),backing=True)
   with self.assertRaisesRegex(m.Refused,'image_layout'):self.runverify(j,key)
class HealthTests(unittest.TestCase):
 def test_stale_or_false_external_health_refused(self):
  j=object.__new__(m.Lifecycle);j.context=context_fixture(role='host');j.work=Path('/fixture');members=j.context.inputs['expected_health_member_count']
  base={'schema_version':1,'checked_at_unix':int(time.time()),'registered_node_count':members,'known_online_count':members,'same_fabric':True,'managed_relay_binary_matches':True,'managed_relay_process_unchanged':True}
  with patch.object(m,'read',return_value=json.dumps(base).encode()):j.external_health()
  for kind in ['stale','offline','stringflag']:
   p=copy.deepcopy(base)
   if kind=='stale':p['checked_at_unix']-=120
   elif kind=='offline':p['known_online_count']=members-1
   else:p['managed_relay_binary_matches']='true'
   with self.subTest(kind=kind),patch.object(m,'read',return_value=json.dumps(p).encode()),self.assertRaises(m.Refused):j.external_health()
class ControlStateTests(unittest.TestCase):
 def reads(self):
  original=m.read
  return patch.object(m,'read',side_effect=lambda p,limit=1024*1024,private=False:original(p,limit,False))
 def test_initial_state_publication_has_stable_postlink_identity(self):
  with tempfile.TemporaryDirectory() as d,self.reads():
   p=Path(d)/'lifecycle.json';expected=m.save(p,{'status':'one'},None)
   self.assertEqual(m.control_state(p),expected);updated=m.save(p,{'status':'two'},expected)
   self.assertEqual(m.control_state(p),updated);self.assertEqual(json.loads(p.read_bytes())['status'],'two')
 def test_foreign_control_replacement_is_never_overwritten(self):
  with tempfile.TemporaryDirectory() as d,self.reads():
   p=Path(d)/'lifecycle.json';expected=m.save(p,{'status':'one'},None)
   other=Path(d)/'foreign';other.write_bytes(b'foreign operator state');other.chmod(0o600);os.replace(other,p)
   inode=p.stat().st_ino
   with self.assertRaisesRegex(m.Refused,'control_state_changed'):m.save(p,{'status':'ours'},expected)
   self.assertEqual(p.read_bytes(),b'foreign operator state');self.assertEqual(p.stat().st_ino,inode)
 def test_initial_state_creation_race_preserves_foreign_file(self):
  with tempfile.TemporaryDirectory() as d,self.reads():
   p=Path(d)/'lifecycle.json';link=os.link
   def race(source,target,**kwargs):
    p.write_bytes(b'foreign created state');p.chmod(0o600);return link(source,target,**kwargs)
   with patch.object(m.os,'link',side_effect=race),self.assertRaisesRegex(m.Refused,'control_state_changed'):m.save(p,{'status':'ours'},None)
   self.assertEqual(p.read_bytes(),b'foreign created state')
class GuestProbeTests(unittest.TestCase):
 def test_guest_public_key_is_pinned_before_isolated_ssh_command(self):
  with tempfile.TemporaryDirectory() as d:
   j=object.__new__(m.Lifecycle);j.context=context_fixture(role='host');j.work=Path(d);j.plan={**PLAN,'network':{'subnet':'192.168.100.0/24','gateway':'192.168.100.1'}};j.state={'domain_started':True,'mac':'52:54:00:01:02:03'};j.guard=lambda:None;j.persist=lambda:None
   public='ssh-ed25519 fixturepublic';j.pf=SimpleNamespace(public_ssh_key=lambda value:public)
   qmp=[];calls=[]
   def agent(execute,args=None):
    qmp.append((execute,args))
    if execute=='guest-file-open':return 1
    if execute=='guest-file-read':return {'buf-b64':m.base64.b64encode(public.encode()).decode()}
    return {}
   j.agent=agent
   def runner(args,label,timeout=60):
    calls.append(args)
    if label=='read-new-guest-address':return b'tap 52:54:00:01:02:03 ipv4 192.168.100.2/24\n'
    if label=='verify-private-guest-ssh':
     self.assertEqual((j.work/'guest-known-hosts').read_text(),'192.168.100.2 '+public+'\n');return b''
    raise AssertionError('Unexpected guest probe')
   j.runner=runner;j.verify_guest();args=calls[-1]
   self.assertEqual(args[args.index('-F')+1],'/dev/null')
   for option in ['PreferredAuthentications=publickey','GSSAPIAuthentication=no','HostbasedAuthentication=no','PasswordAuthentication=no','KbdInteractiveAuthentication=no','IdentityAgent=none','ForwardAgent=no','ClearAllForwardings=yes','ProxyCommand=none','ProxyJump=none','PermitLocalCommand=no','StrictHostKeyChecking=yes']:self.assertIn(option,args)
   self.assertEqual(qmp[0],('guest-file-open',{'path':'/etc/ssh/ssh_host_ed25519_key.pub','mode':'r'}))
   self.assertEqual(qmp[-1][0],'guest-file-close');self.assertTrue(j.state['guest_ssh_hostkey_pinned'])

class ImageCustodyTests(unittest.TestCase):
 def identity(self,fd):
  s=os.fstat(fd);return(s.st_dev,s.st_ino,s.st_mode,s.st_uid,s.st_gid,s.st_nlink,s.st_size,s.st_mtime_ns,s.st_ctime_ns)
 def test_primary_fingerprint_accepts_only_exact_validated_subkey_parent(self):
  subkey='A'*40
  self.assertTrue(m.pinned_primary_signature(('[GNUPG:] VALIDSIG '+subkey+' 2026-01-01 0 0 4 0 1 10 00 '+m.SIGNER+'\n').encode()))
  self.assertFalse(m.pinned_primary_signature(('[GNUPG:] VALIDSIG '+m.SIGNER+' 2026-01-01 0 0 4 0 1 10 00 '+'B'*40+'\n').encode()))
  self.assertFalse(m.pinned_primary_signature(('untrusted text '+m.SIGNER).encode()))
 def test_replacement_path_does_not_change_held_source_fd_and_is_rejected(self):
  with tempfile.TemporaryDirectory() as d:
   p=Path(d)/'image';p.write_bytes(b'original public image');fd=os.open(p,os.O_RDONLY|os.O_NOFOLLOW)
   try:
    with patch.object(m,'image_identity',side_effect=self.identity):
     digest,size,expected=m.hash_image_fd(fd);other=Path(d)/'replacement';other.write_bytes(b'foreign');os.replace(other,p)
     self.assertEqual(os.pread(fd,100,0),b'original public image')
     with self.assertRaisesRegex(m.Refused,'image_(?:fd|path)_changed'):m.image_unchanged(fd,expected,p)
   finally:os.close(fd)
 def test_inplace_image_edit_is_rejected_before_use(self):
  with tempfile.TemporaryDirectory() as d:
   p=Path(d)/'image';p.write_bytes(b'original public image');fd=os.open(p,os.O_RDONLY|os.O_NOFOLLOW)
   try:
    with patch.object(m,'image_identity',side_effect=self.identity):
     digest,size,expected=m.hash_image_fd(fd);p.write_bytes(b'changed public image')
     with self.assertRaisesRegex(m.Refused,'image_fd_changed'):m.image_unchanged(fd,expected,p)
   finally:os.close(fd)
 def test_nested_external_qcow_data_file_is_rejected(self):
  self.assertFalse(m.independent_qcow({'format':'qcow2','format-specific':{'data':{'data-file':'foreign'}}}))

class AllocationAccountingTests(unittest.TestCase):
 def record(self):
  return {'device':1,'inode':2,'uid':0,'gid':0,'mode':stat.S_IFREG|0o600,'size':4096,'allocated':8192,'mtime_ns':10,'ctime_ns':11}
 def test_fully_reserved_accounting_growth_or_shrink_is_accepted(self):
  known=self.record()
  for allocation in [4096,8192,16384]:
   value={**known,'allocated':allocation}
   self.assertTrue(m.owned_volume_matches(value,known,False))
 def test_underreservation_and_identity_permission_or_unstarted_timestamp_drift_refused(self):
  known=self.record()
  for field,value in [('allocated',4095),('inode',3),('mode',stat.S_IFREG|0o644),('uid',1),('size',8192),('mtime_ns',12),('ctime_ns',12)]:
   with self.subTest(field=field):self.assertFalse(m.owned_volume_matches({**known,field:value},known,False))
  self.assertTrue(m.owned_volume_matches({**known,'mtime_ns':99,'ctime_ns':99,'allocated':4096},known,True))
  self.assertFalse(m.owned_volume_matches({**known,'inode':3},known,True))
 def test_readonly_seed_content_hash_remains_mandatory_after_start(self):
  with tempfile.TemporaryDirectory() as d:
   p=Path(d)/'seed.iso';p.write_bytes(b'public seed one');p.chmod(0o600);known=m.disk_state(p);expected=m.file_hash(p)[0]
   m.require_owned_volume(p,known,True,expected)
   p.write_bytes(b'public seed two')
   with self.assertRaisesRegex(m.Refused,'readonly_seed_changed'):m.require_owned_volume(p,known,True,expected)
class StartResumeTests(unittest.TestCase):
 def fixture(self,root):
  j=object.__new__(m.Lifecycle);j.context=context_fixture(role='host');raw=root/'new.raw';raw.write_bytes(b'raw fixture');raw.chmod(0o600);seed=root/'new.iso';seed.write_bytes(b'public seed');seed.chmod(0o600)
  j.seed_name='new.iso';j.plan={**PLAN,'proposed_volume':'new.raw','pool':{'name':'synthetic-pool','path':str(root)},'public_artifact_pins':{'ubuntu':{'url':'https://example.test/image.img'}}}
  j.state={'domain_defined':True,'domain_started':False,'verified_image':'image.img','seed_sha256':m.file_hash(seed)[0],'volumes':{'new.raw':m.disk_state(raw),'new.iso':m.disk_state(seed)}}
  j.guard=lambda:None;j.persist=lambda:None;j.admit_start=lambda:None;calls=[]
  j.q=lambda verb,*args:(PLAN['new_domain_uuid'] if verb=='domuuid' else 'shut off').encode()
  j.runner=lambda args,label,timeout=60:(calls.append(args) or b'')
  return j,calls
 def owners(self):
  return patch.object(m.pwd,'getpwnam',return_value=SimpleNamespace(pw_uid=os.getuid(),pw_gid=os.getgid()))
 def test_start_only_targets_saved_uuid_and_never_creates_or_redefines(self):
  with tempfile.TemporaryDirectory() as d,self.owners():
   j,calls=self.fixture(Path(d));j.start_defined()
   self.assertEqual(calls,[['/usr/bin/virsh','--connect','qemu:///system','start',PLAN['new_domain_uuid']]])
   self.assertTrue(j.state['domain_started']);self.assertEqual(j.state['status'],'new_vm_started_private')
 def test_foreign_uuid_running_state_or_already_started_refused_before_command(self):
  for kind in ['uuid','running','started','missing-artifact']:
   with self.subTest(kind=kind),tempfile.TemporaryDirectory() as d,self.owners():
    j,calls=self.fixture(Path(d))
    if kind=='uuid':j.q=lambda verb,*args:('foreign' if verb=='domuuid' else 'shut off').encode()
    elif kind=='running':j.q=lambda verb,*args:(PLAN['new_domain_uuid'] if verb=='domuuid' else 'running').encode()
    elif kind=='started':j.state['domain_started']=True
    else:j.state['verified_image']='foreign'
    with self.assertRaises(m.Refused):j.start_defined()
    self.assertFalse(calls)

class StartAdmissionTests(unittest.TestCase):
 def test_postreservation_start_uses_six_gib_ram_ten_gib_disk_and_preserves_existing_allocations(self):
  j=object.__new__(m.Lifecycle);j.context=context_fixture(role='host');j.plan={'pool':{'name':'synthetic-pool','path':'/fixture'},'protected_domains':[{'vcpus':2,'max_memory_bytes':4*1024**3}]}
  def run(available=6,total=10,cpu=6,disk=10):
   text='MemAvailable: '+str(available*1024**2)+' kB\nMemTotal: '+str(total*1024**2)+' kB\n'
   with patch.object(Path,'read_text',return_value=text),patch.object(m.os,'cpu_count',return_value=cpu),patch.object(m.os,'statvfs',return_value=SimpleNamespace(f_bavail=disk*1024**3,f_frsize=1)):j.admit_start()
  run()
  for change in [{'available':5},{'total':9},{'cpu':5},{'disk':9}]:
   with self.subTest(change=change),self.assertRaisesRegex(m.Refused,'start_resource_admission'):run(**change)


class ReservationRepairTests(unittest.TestCase):
 def test_future_guest_driver_explicitly_disables_discard_and_zero_detection(self):
  x=m.E.fromstring(m.guest_xml(PLAN,Path('/pool/new.raw'),Path('/pool/new.iso'),'52:54:00:01:02:03'))
  driver=x.find('devices/disk/driver');self.assertEqual(driver.attrib,{'name':'qemu','type':'raw','discard':'ignore','detect_zeroes':'off'})
 def old_xml(self,plan,disk,seed,mac):
  x=m.E.fromstring(m.guest_xml(plan,disk,seed,mac));driver=x.find('devices/disk/driver');driver.attrib={'name':'qemu','type':'raw'}
  return m.E.tostring(x)
 def test_xml_repair_changes_only_the_two_observed_driver_options(self):
  original=self.old_xml(PLAN,Path('/pool/new.raw'),Path('/pool/new.iso'),'52:54:00:01:02:03')
  changed=m.repaired_xml(original,PLAN,Path('/pool/new.raw'),Path('/pool/new.iso'),'52:54:00:01:02:03')
  x=m.E.fromstring(changed);driver=x.find('devices/disk/driver')
  self.assertEqual(driver.get('discard'),'ignore');self.assertEqual(driver.get('detect_zeroes'),'off')
  del driver.attrib['discard'];del driver.attrib['detect_zeroes'];self.assertEqual(m.canonical_xml(m.E.tostring(x)),m.canonical_xml(original))
  for kind in ['uuid','memory','disk','driver']:
   x=m.E.fromstring(original)
   if kind=='uuid':x.find('uuid').text=str(uuid.uuid4())
   elif kind=='memory':x.find('memory').text='8388608'
   elif kind=='disk':x.find('devices/disk/source').set('file','/foreign')
   else:x.find('devices/disk/driver').set('discard','unmap')
   with self.subTest(kind=kind),self.assertRaises(m.Refused):m.repaired_xml(m.E.tostring(x),PLAN,Path('/pool/new.raw'),Path('/pool/new.iso'),'52:54:00:01:02:03')
 def test_fallocate_uses_same_inode_preserves_bytes_and_refuses_replacement(self):
  with tempfile.TemporaryDirectory() as d:
   p=Path(d)/'raw';fd=os.open(p,os.O_CREAT|os.O_EXCL|os.O_RDWR,0o600);os.ftruncate(fd,1024*1024);os.pwrite(fd,b'PUBLIC-FIXTURE-START',0);os.pwrite(fd,b'PUBLIC-FIXTURE-END',1024*1024-18);os.close(fd)
   before=m.disk_state(p);data=p.read_bytes();after=m.reserve_owned_fd(p,before,0)
   self.assertEqual(p.read_bytes(),data);self.assertEqual(after['inode'],before['inode']);self.assertEqual(after['size'],before['size']);self.assertGreaterEqual(after['allocated'],after['size'])
   allocation=m.os.posix_fallocate;foreign=b'foreign operator file';replacement=Path(d)/'replacement';replacement.write_bytes(foreign);replacement.chmod(0o600)
   def race(fd,offset,length):os.replace(replacement,p);return allocation(fd,offset,length)
   with patch.object(m.os,'posix_fallocate',side_effect=race),self.assertRaisesRegex(m.Refused,'path_replaced'):m.reserve_owned_fd(p,m.disk_state(p),0)
   self.assertEqual(p.read_bytes(),foreign)
 def test_underreserved_exception_allows_no_inode_size_permission_or_owner_drift(self):
  base={'device':1,'inode':2,'uid':0,'gid':0,'mode':stat.S_IFREG|0o600,'size':4096,'allocated':4096,'mtime_ns':10,'ctime_ns':10}
  value={**base,'allocated':0,'mtime_ns':12,'ctime_ns':12}
  self.assertTrue(m.repair_volume_matches(value,base))
  for field,val in [('inode',3),('size',8192),('mode',stat.S_IFREG|0o644),('uid',99999),('gid',99999),('device',2),('allocated',-1)]:
   with self.subTest(field=field):self.assertFalse(m.repair_volume_matches({**value,field:val},base))
  with patch.object(m,'allowed_volume_owners',return_value={(0,0),(107,107)}):
   self.assertTrue(m.repair_volume_matches({**value,'uid':107,'gid':107},base,True))
   self.assertFalse(m.repair_volume_matches({**value,'uid':107,'gid':0},base,True))
 def fixture(self,root):
  j=object.__new__(m.Lifecycle);j.context=context_fixture(role='host');j.work=root;j.disk=root/'new.raw';j.seed=root/'new.iso';j.seed_name='new.iso';j.disk.touch(mode=0o600)
  with j.disk.open('r+b') as out:out.truncate(1024*1024);out.write(b'PUBLIC-FIXTURE-CONTENT')
  j.seed.write_bytes(b'PUBLIC-FIXTURE-SEED');j.seed.chmod(0o600)
  baseline=m.disk_state(j.disk);baseline['allocated']=baseline['size']
  j.plan={**PLAN,'pool':{'name':'synthetic-pool','path':str(root)},'proposed_volume':'new.raw','resources':{'raw_disk_bytes':20*1024**3}}
  j.state={'domain_defined':True,'domain_started':True,'volumes':{'new.raw':baseline,'new.iso':m.disk_state(j.seed)},'seed_sha256':m.file_hash(j.seed)[0],'mac':'52:54:00:01:02:03'}
  current={'xml':self.old_xml(j.plan,j.disk,j.seed,j.state['mac']),'state':'running'};calls=[]
  def guard(health=True,volume_exception=None):
   if volume_exception:volume_exception(j.disk,j.state['volumes']['new.raw'])
   else:m.require_owned_volume(j.disk,j.state['volumes']['new.raw'],j.state['domain_started'])
   self.assertEqual(m.file_hash(j.seed)[0],j.state['seed_sha256'])
  j.guard=guard;j.persist=lambda:None;j.admit_start=lambda:None
  j.q=lambda verb,*args:(PLAN['new_domain_uuid'] if verb=='domuuid' else current['state']).encode()
  def runner(args,label,timeout=60,input_bytes=None,**kw):
   calls.append((args,label,input_bytes))
   if 'dumpxml' in args:return current['xml']
   if 'shutdown' in args:current['state']='shut off';return b''
   if 'define' in args:current['xml']=input_bytes;return b''
   raise AssertionError('Unexpected repair fixture command')
  j.runner=runner;return j,current,calls
 def patches(self):
  # The end-to-end fixture uses a bounded 1MiB public file; all other guards are real.
  from contextlib import ExitStack
  stack=ExitStack();stack.enter_context(patch.object(m,'allowed_volume_owners',return_value={(os.getuid(),os.getgid()),(0,0)}))
  stack.enter_context(patch.object(m,'live_devices_owned_by_new_qemu',return_value=None))
  original=m.need
  stack.enter_context(patch.object(m,'need',side_effect=lambda ok,code:None if code=='repair_disk_size_contract' else original(ok,code)))
  return stack
 def test_repair_only_gracefully_stops_own_uuid_redefines_via_bytes_and_finishes_stopped(self):
  with tempfile.TemporaryDirectory() as d,self.patches():
   j,current,calls=self.fixture(Path(d));original=j.disk.read_bytes();reserve=m.reserve_owned_fd
   with patch.object(m,'reserve_owned_fd',side_effect=lambda p,b:reserve(p,b,0)):j.repair_reservation()
   mutations=[(a,label,body) for a,label,body in calls if 'dumpxml' not in a]
   self.assertEqual([x[1] for x in mutations],['graceful-shutdown-only-owned-domain','update-only-owned-discard-driver'])
   self.assertEqual(mutations[0][0][-1],PLAN['new_domain_uuid']);self.assertEqual(mutations[1][0][-2:],['define','/dev/stdin']);self.assertIsInstance(mutations[1][2],bytes)
   self.assertFalse(j.state['domain_started']);self.assertEqual(current['state'],'shut off');self.assertEqual(j.state['status'],'reservation_repaired_stopped');self.assertEqual(j.disk.read_bytes(),original)
   self.assertNotIn('start',[a for args,_,_ in calls for a in args]);self.assertNotIn('destroy',[a for args,_,_ in calls for a in args])
 def test_protected_resource_or_concurrent_xml_change_prevents_shutdown(self):
  for kind in ['protected','xml']:
   with self.subTest(kind=kind),tempfile.TemporaryDirectory() as d,self.patches():
    j,current,calls=self.fixture(Path(d))
    if kind=='protected':j.guard=lambda **k:m.need(False,'protected_domain_changed')
    else:
     original=j.persist
     def edited():
      original();x=m.E.fromstring(current['xml']);x.find('clock').set('offset','localtime');current['xml']=m.E.tostring(x)
     j.persist=edited
    with self.assertRaises(m.Refused):j.repair_reservation()
    self.assertFalse(any('shutdown' in args or 'define' in args for args,_,_ in calls))
 def test_noncontract_disk_size_refused_before_shutdown(self):
  with tempfile.TemporaryDirectory() as d:
   j,current,calls=self.fixture(Path(d))
   with self.assertRaisesRegex(m.Refused,'repair_disk_size_contract'):j.repair_reservation()
   self.assertFalse(calls)
 def test_graceful_shutdown_timeout_never_destroys_or_allocates(self):
  with tempfile.TemporaryDirectory() as d,self.patches():
   j,current,calls=self.fixture(Path(d));original=j.runner
   def running(args,*a,**k):
    result=original(args,*a,**k)
    if 'shutdown' in args:current['state']='running'
    return result
   j.runner=running
   with patch.object(m.time,'monotonic',side_effect=[0,121]),patch.object(m.time,'sleep'),patch.object(m,'reserve_owned_fd') as reserve,self.assertRaisesRegex(m.Refused,'shutdown_timeout'):j.repair_reservation()
   reserve.assert_not_called();self.assertFalse(any('destroy' in args or 'define' in args for args,_,_ in calls))


class LivePTYAndAdoptionTests(unittest.TestCase):
 def live_xml(self):
  root=m.E.fromstring(m.guest_xml(PLAN,Path('/pool/new.raw'),Path('/pool/new.iso'),'52:54:00:01:02:03'))
  root.set('id','7')
  for node in root.findall('devices/serial')+root.findall('devices/console'):m.E.SubElement(node,'source',{'path':'/dev/pts/7'})
  m.E.SubElement(root.find('devices/channel'),'source',{'mode':'bind','path':'/var/lib/libvirt/qemu/channel/target/domain-7-nebula-control-01234/org.qemu.guest_agent.0'})
  m.E.SubElement(root.find('devices/interface'),'target',{'dev':'vnet7'})
  return m.E.tostring(root)
 def validate(self,raw,live):
  return m.validate_xml(raw,PLAN,Path('/pool/new.raw'),Path('/pool/new.iso'),'52:54:00:01:02:03',live=live)
 def test_only_live_pty_source_has_narrow_path_and_attribute_exception(self):
  raw=self.live_xml();self.validate(raw,True)
  with self.assertRaises(m.Refused):self.validate(raw,False)
  for kind in ['other-path','extra-attribute','log','nonpty']:
   x=m.E.fromstring(raw);node=x.find('devices/serial')
   if kind=='other-path':node.find('source').set('path','/dev/mem')
   elif kind=='extra-attribute':node.find('source').set('mode','bind')
   elif kind=='log':m.E.SubElement(node,'log',{'file':'/foreign'})
   else:node.set('type','file')
   with self.subTest(kind=kind),self.assertRaises(m.Refused):self.validate(m.E.tostring(x),True)
 def test_live_pty_must_belong_to_saved_uuid_qemu_master_fd(self):
  with tempfile.TemporaryDirectory() as d:
   root=Path(d);proc=root/'proc';pidroot=root/'pid';pidroot.mkdir();p=proc/'123';(p/'fd').mkdir(parents=True);(p/'fdinfo').mkdir()
   (pidroot/(PLAN['proposed_name']+'.pid')).write_text('123\n')
   (p/'stat').write_bytes(b'123 (qemu) '+b' '.join([b'S']+[b'0']*18+[b'42']))
   (p/'cmdline').write_bytes(b'qemu-system-x86_64\0-uuid\0'+PLAN['new_domain_uuid'].encode()+b'\0')
   (p/'exe').symlink_to('/usr/bin/qemu-system-x86_64');(p/'fd'/'3').symlink_to('/dev/pts/ptmx');(p/'fdinfo'/'3').write_text('tty-index: 7\n')
   channel='/var/lib/libvirt/qemu/channel/target/domain-7-nebula-control-01234/org.qemu.guest_agent.0'
   (p/'fd'/'4').symlink_to('socket:[999]');(p/'fd'/'5').symlink_to('/dev/net/tun');(p/'fdinfo'/'5').write_text('iff: vnet7\n')
   (p/'net').mkdir();(p/'net'/'unix').write_text('00000000: 00000000 00000000 00010000 0001 01 999 '+channel+'\n')
   xml=m.E.fromstring(self.live_xml())
   for index,disk in enumerate(xml.findall('devices/disk')):
    owned=root/('owned-'+str(index));owned.write_bytes(b'public-owned-file');disk.find('source').set('file',str(owned));(p/'fd'/str(index+6)).symlink_to(owned)
   live=m.E.tostring(xml)
   m.live_devices_owned_by_new_qemu(live,PLAN,proc,pidroot)
   (p/'fdinfo'/'3').write_text('tty-index: 8\n')
   with self.assertRaisesRegex(m.Refused,'not_owned'):m.live_devices_owned_by_new_qemu(live,PLAN,proc,pidroot)
   (p/'fdinfo'/'3').write_text('tty-index: 7\n')
   (p/'net'/'unix').write_text('00000000: 00000000 00000000 00010000 0001 01 998 '+channel+'\n')
   with self.assertRaisesRegex(m.Refused,'agent_socket_not_owned'):m.live_devices_owned_by_new_qemu(live,PLAN,proc,pidroot)
   (p/'net'/'unix').write_text('00000000: 00000000 00000000 00010000 0001 01 999 '+channel+'\n');(p/'fdinfo'/'5').write_text('iff: vnet8\n')
   with self.assertRaisesRegex(m.Refused,'nic_not_owned'):m.live_devices_owned_by_new_qemu(live,PLAN,proc,pidroot)
   (p/'fdinfo'/'5').write_text('iff: vnet7\n');(p/'cmdline').write_bytes(b'qemu\0-uuid\0'+str(uuid.uuid4()).encode()+b'\0')
   with self.assertRaisesRegex(m.Refused,'uuid_changed'):m.live_devices_owned_by_new_qemu(live,PLAN,proc,pidroot)
 def test_only_expected_agent_state_transition_allowed_during_graceful_shutdown(self):
  original=self.live_xml();x=m.E.fromstring(original);x.find('devices/channel/target').set('state','connected');before=m.E.tostring(x)
  x.find('devices/channel/target').set('state','disconnected');after=m.E.tostring(x)
  self.assertFalse(m.same_running_xml(after,before));self.assertTrue(m.same_running_xml(after,before,True))
  x.find('devices/interface/source').set('network','foreign')
  self.assertFalse(m.same_running_xml(m.E.tostring(x),before,True))
 def test_raw_or_seed_replacement_at_adoption_is_not_owned_and_never_redefined(self):
  for kind in ['raw','seed']:
   with self.subTest(kind=kind),tempfile.TemporaryDirectory() as d:
    helper=ReservationRepairTests()
    with helper.patches():
     j,current,calls=helper.fixture(Path(d));original_inode=j.state['volumes']['new.raw']['inode'];adopt=m.repaired_volume_postimages;reserve=m.reserve_owned_fd
     foreign=b'FOREIGN OPERATOR CONTENT'
     def replace_before_adoption(raw,after,seed,seed_before,digest):
      path=raw if kind=='raw' else seed;other=path.parent/'foreign';other.write_bytes(foreign);other.chmod(0o600);os.replace(other,path)
      return adopt(raw,after,seed,seed_before,digest)
     with patch.object(m,'reserve_owned_fd',side_effect=lambda p,b:reserve(p,b,0)),patch.object(m,'repaired_volume_postimages',side_effect=replace_before_adoption),self.assertRaisesRegex(m.Refused,'before_state_adoption'):j.repair_reservation()
     self.assertEqual(j.state['volumes']['new.raw']['inode'],original_inode);self.assertEqual((j.disk if kind=='raw' else j.seed).read_bytes(),foreign)
     self.assertFalse(any('define' in args for args,_,_ in calls))

class HostContextTests(unittest.TestCase):
 def test_constructor_requires_validated_context_before_private_plan_or_commands(self):
  with patch.object(m,'safe') as safe,patch.object(m,'read') as read,patch.object(m,'load_preflight') as dependency,patch.object(m.subprocess,'run') as command:
   with self.assertRaises(RuntimeError):m.Lifecycle(Path('/unread/private/plan.json'),None)
   safe.assert_not_called();read.assert_not_called();dependency.assert_not_called();command.assert_not_called()
 def test_preflight_dependency_is_resolved_only_by_context_manifest(self):
  ctx=context_fixture(role='host')
  self.assertIs(m.load_preflight(ctx),ctx.load_module('host/preflight'))
  with self.assertRaises(RuntimeError):m.load_preflight(Path('/unread/old-preflight.py'))
 def test_saved_context_binding_mismatch_refuses_before_runtime_guard_probes(self):
  ctx=context_fixture(role='host');j=object.__new__(m.Lifecycle);j.context=ctx;j.plan={'foundation_binding':{}}
  with patch.object(m.os,'geteuid',return_value=0),patch.object(m.socket,'gethostname',return_value=ctx.inputs['host_name']),patch.object(m,'control_state') as control,patch.object(m,'read') as read:
   with self.assertRaisesRegex(m.Refused,'plan_context_binding'):j.guard()
   control.assert_not_called();read.assert_not_called()
 def test_reviewed_network_is_used_in_xml_and_rejects_default_substitution(self):
  plan={**PLAN,'network':{'name':'isolated-test-network','bridge':'virbr-fixture'}}
  raw=m.guest_xml(plan,Path('/pool/new.raw'),Path('/pool/new.iso'),'52:54:00:01:02:03')
  m.validate_xml(raw,plan,Path('/pool/new.raw'),Path('/pool/new.iso'),'52:54:00:01:02:03')
  xml=m.E.fromstring(raw);self.assertEqual(xml.find('devices/interface/source').get('network'),'isolated-test-network')
  xml.find('devices/interface/source').set('network','default')
  with self.assertRaisesRegex(m.Refused,'domain_network_mapping'):m.validate_xml(m.E.tostring(xml),plan,Path('/pool/new.raw'),Path('/pool/new.iso'),'52:54:00:01:02:03')
 def test_library_has_no_operational_main_or_temporary_dependency_paths(self):
  raw=Path(m.__file__).read_text();tree=ast.parse(raw)
  self.assertFalse(any(isinstance(n,ast.FunctionDef)and n.name=='main'for n in tree.body))
  self.assertNotIn('/tmp/',raw);self.assertNotIn('PF_SHA',raw)
class HostPhaseGateTests(unittest.TestCase):
 def test_execute_and_unknown_phase_gates_precede_context_reads_and_probes(self):
  with patch.object(m,'require_context') as context,patch.object(m,'private_dir') as directory,patch.object(m.os,'open') as opened,patch.object(m,'Lifecycle') as constructor:
   for phase in m.PHASES-{'check'}:
    with self.subTest(phase=phase),self.assertRaisesRegex(m.Refused,'explicit_execute_required'):m.run_phase(None,Path('/unread/plan'),phase)
   with self.assertRaisesRegex(m.Refused,'supported_host_phase_required'):m.run_phase(None,Path('/unread/plan'),'destroy',execute=True)
   context.assert_not_called();directory.assert_not_called();opened.assert_not_called();constructor.assert_not_called()

@unittest.skipUnless(os.geteuid()==0,'isolated private root-lock fixtures only')
class HostPhaseLockTests(unittest.TestCase):
 def fixture(self,root):
  context=SimpleNamespace(inputs={'host_name':'synthetic-host','run_id':'0123456789ab'},guard=MagicMock(),path=lambda key:root)
  plan=root/'plan-0123456789ab'/'plan.json'
  job=MagicMock();job.state={'status':'synthetic_phase_complete'};job.state_path=root/'synthetic-lifecycle.json'
  job.guard.side_effect=lambda *args,**kwargs:job.external_guard()
  return context,plan,job
 def invoke(self,context,plan,job,phase='start',**kwargs):
  with patch.object(m,'require_context',return_value=context),patch.object(m.socket,'gethostname',return_value='synthetic-host'),patch.object(m,'Lifecycle',return_value=job):
   return m.run_phase(context,plan,phase,**kwargs)
 def test_each_exact_phase_dispatches_under_live_root_lock_without_cli(self):
  methods={'fetch-image':'fetch_image','verify-image':'resume_verified_image','create':'create','start':'start_defined','verify-guest':'verify_guest','repair-reservation':'repair_reservation'}
  for phase in sorted(m.PHASES):
   with self.subTest(phase=phase),tempfile.TemporaryDirectory(prefix='foundation-host-phase-',dir='/run')as directory:
    root=Path(directory);context,plan,job=self.fixture(root);keyring=Path('/synthetic/reviewed.gpg')
    result=self.invoke(context,plan,job,phase,execute=True,image_keyring=keyring)
    self.assertEqual(result['phase'],phase)
    lock=root/'lifecycle.lock';record=lock.stat();self.assertEqual((record.st_uid,record.st_gid,stat.S_IMODE(record.st_mode)),(0,0,0o600))
    if phase=='check':job.persist.assert_called_once_with();self.assertEqual(job.state['status'],'check_passed_no_vm_changes')
    else:
     wanted=getattr(job,methods[phase]);wanted.assert_called_once_with(*([keyring]if phase in['fetch-image','verify-image','create']else[]))
    if phase=='repair-reservation':job.guard.assert_not_called()
    else:job.guard.assert_called_once_with()
 def test_operation_flock_is_held_through_phase_and_released_after_return(self):
  with tempfile.TemporaryDirectory(prefix='foundation-host-phase-',dir='/run')as directory:
   root=Path(directory);context,plan,job=self.fixture(root);contenders=[]
   def phase():
    fd=os.open(root/'lifecycle.lock',os.O_RDONLY)
    try:
     with self.assertRaises(BlockingIOError):fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
     contenders.append(True);job.external_guard()
    finally:os.close(fd)
   job.start_defined.side_effect=phase;self.invoke(context,plan,job,execute=True);self.assertEqual(contenders,[True])
   fd=os.open(root/'lifecycle.lock',os.O_RDONLY)
   try:fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
   finally:os.close(fd)
 def test_lock_replacement_is_preserved_and_triggers_private_failure_path(self):
  with tempfile.TemporaryDirectory(prefix='foundation-host-phase-',dir='/run')as directory:
   root=Path(directory);context,plan,job=self.fixture(root);foreign=[]
   def phase():
    path=root/'replacement';path.write_bytes(b'');path.chmod(0o600);inode=path.stat().st_ino;os.replace(path,root/'lifecycle.lock');foreign.append(inode);job.external_guard()
   job.start_defined.side_effect=phase
   with self.assertRaisesRegex(m.Refused,'lifecycle_lock_replaced'):self.invoke(context,plan,job,execute=True)
   self.assertEqual((root/'lifecycle.lock').stat().st_ino,foreign[0]);self.assertEqual(job.state['status'],'stopped_manual_review_required');self.assertFalse(job.state['automatic_delete_or_foreign_rollback']);job.persist.assert_called_once_with()
 def test_control_cas_failure_keeps_explicit_manual_recovery_behavior(self):
  with tempfile.TemporaryDirectory(prefix='foundation-host-phase-',dir='/run')as directory:
   context,plan,job=self.fixture(Path(directory));job.start_defined.side_effect=m.Refused('synthetic_phase_refused');job.persist.side_effect=m.Refused('foreign_control')
   with self.assertRaisesRegex(m.Refused,'synthetic_phase_refused'):self.invoke(context,plan,job,execute=True)
   job.recovery.assert_called_once_with();self.assertFalse(job.state['automatic_delete_or_foreign_rollback'])
 def test_existing_nonempty_or_writable_lock_refuses_before_constructor(self):
  for bad in ['nonempty','writable']:
   with self.subTest(bad=bad),tempfile.TemporaryDirectory(prefix='foundation-host-phase-',dir='/run')as directory:
    root=Path(directory);context,plan,job=self.fixture(root);lock=root/'lifecycle.lock';lock.write_bytes(b'foreign'if bad=='nonempty'else b'');lock.chmod(0o600 if bad=='nonempty'else 0o644);before=lock.read_bytes()
    with patch.object(m,'require_context',return_value=context),patch.object(m.socket,'gethostname',return_value='synthetic-host'),patch.object(m,'Lifecycle')as constructor:
     with self.assertRaisesRegex(m.Refused,'unsafe_lifecycle_lock'):m.run_phase(context,plan,'check')
     constructor.assert_not_called()
    self.assertEqual(lock.read_bytes(),before)
 def test_wrong_context_plan_path_refuses_before_any_lock_creation(self):
  with tempfile.TemporaryDirectory(prefix='foundation-host-phase-',dir='/run')as directory:
   root=Path(directory);context,plan,job=self.fixture(root)
   with self.assertRaisesRegex(m.Refused,'plan_context_path_required'):self.invoke(context,root/'foreign-plan.json',job,'check')
   self.assertFalse((root/'lifecycle.lock').exists())
if __name__=='__main__':unittest.main(verbosity=2)


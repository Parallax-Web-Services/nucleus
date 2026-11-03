#!/usr/bin/env python3
import ast,base64,contextlib,hashlib,importlib.util,io,json,os,shlex,shutil,stat,subprocess,sys,tempfile,unittest
from pathlib import Path
from unittest.mock import patch
s=importlib.util.spec_from_file_location('backup_orchestrator','/tmp/nebula-managed-v3-consumers-rkss039w/source/nebula-backup-orchestrator.py');o=importlib.util.module_from_spec(s);s.loader.exec_module(o)
PINS={'Tarragon':{'primary_fingerprint':'A'*40,'encryption_subkey_fingerprint':'B'*40},'Slipstream':{'primary_fingerprint':'C'*40,'encryption_subkey_fingerprint':'D'*40}}
SSH_REQUIRED={'batchmode':'yes','stricthostkeychecking':'yes','controlmaster':'no','controlpath':'none','controlpersist':'no'}
def ssh_option_lists(args):
 selected={key:[] for key in SSH_REQUIRED}
 for index,value in enumerate(args[:-1]):
  if value=='-o' and isinstance(args[index+1],str) and '=' in args[index+1]:
   key,val=args[index+1].split('=',1)
   if key.lower() in selected:selected[key.lower()].append(val)
 return selected
class FakeCommand:
 def __init__(self,job):self.job=job;self.calls=[];self.before=None;self.after=None;self.transform=None
 def __call__(self,work,args,label,**kw):
  assert args[0]=='ssh' and isinstance(args,list) and 'shell' not in kw
  selected=ssh_option_lists(args);assert selected=={key:[value] for key,value in SSH_REQUIRED.items()},('unsafe SSH options',selected)
  assert kw['local_controller'] is True and 0<kw['timeout']<=420 and kw['stdout_fd']>=3
  fd=kw['stdout_fd'];st=os.fstat(fd);assert stat.S_ISREG(st.st_mode) and stat.S_IMODE(st.st_mode)==0o600 and st.st_nlink==1 and st.st_size==0
  tree=ast.parse(shlex.split(args[-1])[-1]);assignment=next(n for n in tree.body if isinstance(n,ast.Assign) and any(isinstance(t,ast.Name) and t.id=='q' for t in n.targets));q=json.loads(base64.b64decode(ast.literal_eval(assignment.value.args[0].args[0])))
  inp=None;input_fd=kw['stdin_fd']
  if input_fd is not None:
   assert stat.S_ISREG(os.fstat(input_fd).st_mode) and os.lseek(input_fd,0,os.SEEK_CUR)==0
   chunks=[]
   while True:
    raw=os.read(input_fd,65536)
    if not raw:break
    chunks.append(raw)
   inp=b''.join(chunks)
  role,phase=q['role'],q['phase'];assert q['managed_health_overlay']=='/root/synthetic-admitted-overlay.json';assert kw['timeout']<=(45 if role=='Guard' else 420);call={'role':role,'phase':phase,'input':inp,'artifact':{k:q[k] for k in ['artifact_sha256','artifact_bytes'] if k in q},'cap':kw['file_limit'],'args':args,'kw':kw};self.calls.append(call);self.job.history.append(call)
  if self.before:self.before(call)
  tool=b'SYNTHETIC-PUBLIC-ETCDUTL';signer='-----BEGIN PUBLIC KEY-----\nSYNTHETIC-PUBLIC\n-----END PUBLIC KEY-----\n';v={'status':'passed'}
  if role=='Guard':v.update(alpha_fleet_relay_guards=True,managed_owner_health_checked=True)
  if phase=='export-public' and role in PINS:v={'schema_version':1,'operation_id':self.job.id,'target':role,'public_key_armored':'-----BEGIN PGP PUBLIC KEY BLOCK-----\nSYNTHETIC\n-----END PGP PUBLIC KEY BLOCK-----\n',**PINS[role]}
  elif phase=='export-public':v={'schema_version':1,'operation_id':self.job.id,'signer_public_pem':signer,'signer_public_sha256':hashlib.sha256(signer.encode()).hexdigest(),'etcd_version':'3.7.0','etcdutl_sha256':hashlib.sha256(tool).hexdigest(),'etcdutl_bytes':len(tool)}
  elif phase=='verify-restore':v={'status':'passed','target':role,**{k:True for k in ['signature_verified','own_recovery_key_verified','independent_snapshot_status_verified','offline_restore_verified','authenticated_decryption_verified','isolated_restore_verified','no_listener_started','critical_recovery_material_verified','mark_compacted']},'listeners_started':False,'private_data_exported':False,'revision_bump':1000000000}
  raw=tool if phase=='export-etcdutl' else b'SYNTHETIC-CIPHERTEXT-ONLY-ENVELOPE' if phase=='export-envelope' else o.bytes_json(v)
  if self.transform:raw=self.transform(call,raw)
  os.write(fd,raw)
  if self.after:self.after(call)
  return b''
class OrchestratorTests(unittest.TestCase):
 def setUp(self):
  self.temp=tempfile.TemporaryDirectory(prefix='nebula-backup-orchestration-test-',dir='/root');self.root=Path(self.temp.name);self.root.chmod(0o700);self.id='1'*32;self.jobs=[];self.history=[];self.overlay='/root/synthetic-admitted-overlay.json';self.expected_head='none'
  self.bundle=self.root/'bundle';self.bundle.mkdir(mode=0o700);files={}
  for name in sorted(o.NAMES):
   raw=Path('/tmp',name).read_bytes() if name in ['nebula-backup-common.py','nebula-backup-envelope-policy.py'] else ('# synthetic public '+name+'\n').encode();p=self.bundle/name;p.write_bytes(raw);p.chmod(0o600);files[name]=o.sha(raw)
  self.manifest=self.bundle/'manifest.json';self.manifest.write_bytes(o.bytes_json({'schema_version':1,'files':files}));self.manifest.chmod(0o600)
  for folder,target in [('rollout-alpha','root@alpha.wphyperdrive.com'),('rollout-tarragon','root@tarragon.app')]:
   p=self.root/'.runtime'/folder;p.mkdir(parents=True);f=p/'session.json';f.write_text(json.dumps({'ssh_target':target,'unused_private_field':'SYNTHETIC-NEVER-PRINT'}));f.chmod(0o600)
  self.state=self.root/('nebula-backup-orchestrator-'+self.id)
 def tearDown(self):
  for j in self.jobs:j.close()
  self.temp.cleanup()
 def job(self,lock=True,overlay=None,deadline=None,expected_head=...):
  with patch.object(o,'ROOT',self.root):j=o.Orchestrator(self.manifest,o.sha(self.manifest.read_bytes()),self.id,self.state,self.overlay if overlay is None else overlay,self.expected_head if expected_head is ... else expected_head,deadline=deadline)
  self.jobs.append(j);j.history=self.history;j.real_command=j.common.command;j.fake=FakeCommand(j);j.common.command=j.fake;j.calls=j.fake.calls
  if lock:j.acquire_lock()
  original_step=j.run_step
  def capture_success(step):
   result=original_step(step)
   # Caller-held checkpoint: capture only the known successful invocation's
   # in-memory exclusive poststate, never derive expected from a new file read.
   if step in o.STEPS:self.expected_head=j.head_sha256()
   return result
  j.run_step=capture_success;return j
 def prepare(self,step):
  j=self.job()
  for previous in o.STEPS[:o.STEPS.index(step)]:j.run_step(previous);j.close();j=self.job()
  return j
 def test_embedded_receivers_compile(self):compile(o.BROKER,'broker','exec');compile(o.GUEST_RECEIVER,'guest','exec')
 def test_manifest_changed_source_refused(self):
  (self.bundle/'nebula-backup-target.py').write_text('#foreign')
  with self.assertRaisesRegex(o.Refused,'local_source_pin'):self.job()
 def test_old_common_manifest_is_refused_before_execution(self):
  v=json.loads(self.manifest.read_text());v['files']['nebula-backup-common.py']='c'*64;self.manifest.write_bytes(o.bytes_json(v))
  with self.assertRaisesRegex(o.Refused,'accepted_common_pin_required'):self.job()
 def test_explicit_remote_overlay_is_never_read_locally(self):
  read=o.local_read;seen=[]
  def spy(path,*a,**k):seen.append(str(path));return read(path,*a,**k)
  with patch.object(o,'local_read',side_effect=spy):j=self.job()
  self.assertNotIn(self.overlay,seen);self.assertEqual(j.managed_health_overlay,self.overlay)
 def test_bad_remote_overlay_paths_refused(self):
  for value in ['', 'relative','/root/../overlay','/root//overlay','/root/overlay/','/root/x\\y','/root/x\ny']:
   with self.subTest(value=value):
    with self.assertRaises(o.Refused):self.job(overlay=value)
 def test_check_runs_one_target_between_two_fresh_managed_guards(self):
  j=self.job();j.run_step('check-tarragon');self.assertEqual([(c['role'],c['phase']) for c in j.calls],[('Guard','check'),('Tarragon','check'),('Guard','check')]);self.assertFalse(list(j.state.glob('*.started.json')))
 def test_single_object_cannot_dispatch_second_step(self):
  j=self.job();j.run_step('stage-tarragon');count=len(j.calls)
  with self.assertRaisesRegex(o.Refused,'one_step_per_invocation'):j.run_step('stage-slipstream')
  self.assertEqual(len(j.calls),count)
 def test_aggregate_or_out_of_order_step_refused_before_remote(self):
  j=self.job()
  with self.assertRaisesRegex(o.Refused,'typed_step_required'):j.run_step('init')
  j.close();j=self.job()
  with self.assertRaisesRegex(o.Refused,'next_exact_step_required'):j.run_step('init-tarragon')
  self.assertEqual(j.calls,[])
 def test_attempt_precedes_failed_remote_and_cannot_resume(self):
  j=self.job()
  def fail(c):
   if c['phase']=='stage':raise o.Refused('synthetic_failure')
  j.fake.before=fail
  with self.assertRaises(o.Refused):j.run_step('stage-tarragon')
  self.assertTrue((j.state/'stage-tarragon.started.json').exists());self.assertFalse((j.state/'stage-tarragon.complete.json').exists());j.close();count=len(self.history)
  with self.assertRaisesRegex(o.Refused,'unknown_partial_requires_review'):self.job()
  self.assertEqual(len(self.history),count)
 def test_reopen_chain_verifies_every_record_and_exact_predecessor(self):
  j=self.prepare('init-tarragon');self.assertEqual(j.completed,list(o.STEPS[:3]));j.run_step('init-tarragon');j.close();j=self.job();self.assertEqual(j.completed,list(o.STEPS[:4]));v=json.loads((j.state/'init-tarragon.complete.json').read_text());self.assertEqual(v['predecessor']['name'],'stage-guest.complete.json');self.assertEqual(v['manifest_sha256'],o.sha(self.manifest.read_bytes()));self.assertEqual(v['managed_health_overlay'],self.overlay)
 def test_cross_step_replaced_payload_cannot_be_adopted(self):
  j=self.prepare('stage-slipstream');record=j.results['stage-tarragon'];j.close();record.path.write_bytes(o.bytes_json({'status':'passed','fabricated':True}))
  with self.assertRaises(o.Refused):self.job()
 def test_ledger_unknown_file_or_predecessor_change_refused(self):
  j=self.prepare('stage-slipstream');j.close();p=self.state/'stage-tarragon.complete.json';v=json.loads(p.read_text());v['predecessor']={'forged':True};p.write_bytes(o.bytes_json(v))
  with self.assertRaisesRegex(o.Refused,'step_completion_binding_changed'):self.job()
 def test_legacy_aggregate_receipt_never_becomes_step_ledger(self):
  j=self.job();j.put(j.state/'stage.complete',o.bytes_json({'status':'passed'}));j.close()
  with self.assertRaisesRegex(o.Refused,'unknown_or_legacy_step_ledger'):self.job()
 def test_overlay_change_cannot_rebind_existing_operation(self):
  j=self.job();j.close()
  with self.assertRaisesRegex(o.Refused,'operation_binding_changed'):self.job(overlay='/root/other-admitted.json')
 def test_saved_tool_is_reused_from_offset_zero_by_each_target(self):
  j=self.prepare('configure-slipstream');j.run_step('configure-slipstream');stages=[c for c in self.history if c['phase']=='stage-etcdutl'];self.assertEqual(len(stages),2);self.assertTrue(all(c['input']==b'SYNTHETIC-PUBLIC-ETCDUTL' for c in stages));self.assertEqual({c['role'] for c in stages},set(PINS))
 def test_saved_ciphertext_is_identical_for_both_receivers(self):
  j=self.prepare('receive-slipstream');j.run_step('receive-slipstream');receives=[c for c in self.history if c['phase']=='receive'];self.assertEqual(len(receives),2);self.assertTrue(all(c['input']==b'SYNTHETIC-CIPHERTEXT-ONLY-ENVELOPE' for c in receives))
 def test_public_trust_fields_match_target_contract(self):
  j=self.prepare('configure-tarragon');j.run_step('configure-tarragon');v=json.loads(next(c['input'] for c in j.calls if c['phase']=='configure'));self.assertEqual(set(v),{'schema_version','operation_id','recipients','signer_public_pem','signer_public_sha256','etcd_version','etcdutl_sha256','etcdutl_bytes'});self.assertEqual(v['recipients'],PINS)
 def test_wrong_tool_digest_never_completes_export(self):
  j=self.prepare('export-tool');j.fake.transform=lambda c,r:b'X'*len(r) if c['phase']=='export-etcdutl' else r
  with self.assertRaisesRegex(o.Refused,'public_etcdutl_transport_digest'):j.run_step('export-tool')
  self.assertFalse((j.state/'export-tool.complete.json').exists())
 def test_restore_acceptance_requires_exact_target_and_real_flags(self):
  j=self.prepare('restore-tarragon')
  def changed(c,r):
   if c['phase']=='verify-restore':v=json.loads(r);v['isolated_restore_verified']=False;return o.bytes_json(v)
   return r
  j.fake.transform=changed
  with self.assertRaisesRegex(o.Refused,'each_target_restore_acceptance_required'):j.run_step('restore-tarragon')
  self.assertFalse((j.state/'restore-tarragon.complete.json').exists())
 def test_complete_full_synthetic_chain_has_one_actual_remote_per_invocation(self):
  j=self.prepare('restore-slipstream');j.run_step('restore-slipstream');j.close();j=self.job();self.assertEqual(j.completed,list(o.STEPS));self.assertEqual(len([c for c in self.history if c['role']!='Guard']),len(o.STEPS));self.assertEqual(len(self.history),3*len(o.STEPS))
 def test_replaced_stdout_cannot_supply_fabricated_json(self):
  j=self.job();r=j.remote('Tarragon','check','known');r.path.write_bytes(o.bytes_json({'status':'passed','fabricated':True}))
  with self.assertRaisesRegex(o.Refused,'owned_file_changed'):j.require_pass(r)
 def test_unregistered_json_is_never_accepted(self):
  j=self.job();p=j.state/'fabricated';o.exclusive(p,o.bytes_json({'status':'passed'}))
  for value in [p,o.FileRecord(p,tuple(o.meta(p.stat())),o.sha(p.read_bytes()),512*1024)]:
   with self.assertRaisesRegex(o.Refused,'verified_transport_record_required'):j.require_pass(value)
 def test_held_handoff_replacement_refuses_and_preserves_foreign(self):
  j=self.job();r=j.put(j.state/'input',b'PUBLIC');foreign=j.state/'foreign';o.exclusive(foreign,b'FOREIGN-PRESERVE');j.fake.after=lambda c:os.replace(foreign,r.path)
  with self.assertRaises(o.Refused):j.remote('Tarragon','configure','handoff',input_path=r)
  self.assertEqual(r.path.read_bytes(),b'FOREIGN-PRESERVE');self.assertEqual(j.calls[0]['input'],b'PUBLIC')
 def test_exclusive_returned_poststate_refuses_replacement(self):
  j=self.job();original=o.exclusive
  def replaced(path,raw):
   known=original(path,raw);f=j.state/'foreign';original(f,b'OTHER');os.replace(f,path);return known
  with patch.object(o,'exclusive',side_effect=replaced):
   with self.assertRaisesRegex(o.Refused,'owned_file_changed'):j.put(j.state/'control',b'OWNED')
  self.assertEqual((j.state/'control').read_bytes(),b'OTHER')
 def test_regular_lock_is_required_and_replacement_stops_before_next_guard(self):
  j=self.job();foreign=j.state/'foreign-lock';o.exclusive(foreign,b'')
  def replace(c):
   if c['role']=='Tarragon':os.replace(foreign,j.state/'operation.lock')
  j.fake.after=replace
  with self.assertRaisesRegex(o.Refused,'local_lock_changed'):j.run_step('stage-tarragon')
  self.assertEqual(len(j.calls),2);self.assertFalse((j.state/'stage-tarragon.complete.json').exists())
 def test_fifo_lock_refused_without_transport(self):
  j=self.job(lock=False);os.mkfifo(j.state/'operation.lock',0o600)
  with self.assertRaisesRegex(o.Refused,'local_lock_custody'):j.acquire_lock()
 def test_transport_preserves_foreign_output_name(self):
  j=self.job();p=j.state/'same-000000000000.stdout';o.exclusive(p,b'FOREIGN')
  with patch.object(o.os,'urandom',return_value=b'\0'*6):
   with self.assertRaises(FileExistsError):j.remote('Tarragon','check','same')
  self.assertEqual(p.read_bytes(),b'FOREIGN')
 def test_output_bound_retains_private_partial(self):
  j=self.job();j.fake.transform=lambda c,r:b'x'*11
  with self.assertRaisesRegex(o.Refused,'transport_file_custody'):j.remote('Tarragon','check','bounded',cap=10)
  p=next(j.state.glob('*.stdout'));self.assertEqual(p.read_bytes(),b'x'*11);self.assertEqual(stat.S_IMODE(p.stat().st_mode),0o600)
 def test_deadline_prevents_command_and_reserves_cleanup(self):
  j=self.job();j.deadline=o.time.monotonic()+24
  with self.assertRaisesRegex(o.Refused,'whole_step_cleanup_reserve_required'):j.remote('Tarragon','check','too-late')
  self.assertEqual(j.calls,[]);j.deadline=o.time.monotonic()+30;j.remote('Tarragon','check','clamped');self.assertTrue(0<j.calls[-1]['kw']['timeout']<=5)
 def test_constructor_and_hash_work_use_whole_invocation_deadline(self):
  with self.assertRaisesRegex(o.Refused,'whole_step_deadline_exhausted'):self.job(deadline=o.time.monotonic()-1)
  j=self.job();r=j.put(j.state/'input',b'PUBLIC');j.deadline=o.time.monotonic()-1
  with self.assertRaisesRegex(o.Refused,'whole_step_deadline_exhausted'):j.read_record(r,65536)
 def test_late_command_never_becomes_completed_step(self):
  j=self.job()
  def late(c):
   if c['role']=='Tarragon':j.deadline=o.time.monotonic()-1
  j.fake.after=late
  with self.assertRaisesRegex(o.Refused,'whole_step_deadline_exhausted'):j.run_step('stage-tarragon')
  self.assertFalse((j.state/'stage-tarragon.complete.json').exists())
 def test_real_common_bounded_stderr_with_synthetic_local_helper_only(self):
  j=self.job();script="import os; os.write(2,b'x'*(3*1024**2)); os.write(1,b'{\"status\":\"passed\"}')"
  j.common.command=lambda work,args,label,**kw:j.real_command(work,[sys.executable,'-B','-c',script],label,**kw);r=j.remote('Tarragon','check','synthetic-helper');self.assertEqual(j.require_pass(r),{'status':'passed'});v=json.loads(next(j.state.glob('command-*/metadata.json')).read_text());self.assertTrue(v['streams']['stderr']['truncated']);self.assertEqual(v['streams']['stderr']['stored_bytes'],2*1024**2);self.assertTrue(v['owned_command_reaped'])
 def test_cli_execute_and_explicit_overlay_step_gate_precede_constructor(self):
  args=['orchestrator','--bundle-manifest','/missing','--manifest-sha256','0'*64,'--operation-id',self.id,'--state','/missing','--managed-health-overlay',self.overlay,'--expected-head-sha256','none','--private-result',str(self.root/'private-result.json'),'--step','stage-tarragon']
  with patch.object(sys,'argv',args),patch.object(o,'Orchestrator',side_effect=AssertionError('probe before gate')):
   with self.assertRaisesRegex(o.Refused,'explicit_execute_required'):o.main()
 def test_no_aggregate_cli_or_health_fallback(self):
  self.assertNotIn("add_argument('--phase'",Path(o.__file__).read_text());self.assertIn('Bridge(Path(q[',o.BROKER);self.assertNotIn('health=False',o.BROKER);self.assertNotIn('.admit(',o.BROKER);self.assertIn('600-second',o.__doc__)

 def test_outer_ssh_has_strict_batch_and_no_connection_sharing_once(self):
  j=self.job();j.remote('Tarragon','check','ssh-options');args=j.calls[0]['args'];self.assertEqual(ssh_option_lists(args),{key:[value] for key,value in SSH_REQUIRED.items()});self.assertEqual(args[0],'ssh');self.assertNotIn('shell',j.calls[0]['kw'])
 def test_nested_ssh_preserves_pinned_identity_knownhosts_proxy_guards_and_no_sharing(self):
  tree=ast.parse(o.BROKER);node=next(n for n in ast.walk(tree) if isinstance(n,ast.Assign) and any(isinstance(t,ast.Name) and t.id=='args' for t in n.targets) and isinstance(n.value,ast.List) and isinstance(n.value.elts[0],ast.Constant) and n.value.elts[0].value=='ssh');parts=[n.value if isinstance(n,ast.Constant) and isinstance(n.value,str) else None for n in node.value.elts];self.assertEqual(parts[:4],['ssh','-F','/dev/null','-T']);self.assertEqual(ssh_option_lists(parts),{key:[value] for key,value in SSH_REQUIRED.items()})
  required=['IdentitiesOnly=yes','IdentityAgent=none','ForwardAgent=no','ClearAllForwardings=yes','ProxyCommand=none','ProxyJump=none','PermitLocalCommand=no','PreferredAuthentications=publickey','GSSAPIAuthentication=no','HostbasedAuthentication=no','PasswordAuthentication=no','KbdInteractiveAuthentication=no','GlobalKnownHostsFile=/dev/null']
  for option in required:self.assertEqual(parts.count(option),1,option)
  rendered=ast.unparse(node.value);self.assertIn('guest-known-hosts',rendered);self.assertIn('UserKnownHostsFile=',rendered);self.assertIn('guest-client',rendered)
 def test_ssh_G_uses_only_synthetic_hostile_config_and_cli_controls_win(self):
  j=self.job();j.remote('Tarragon','check','ssh-effective-options');args=j.calls[0]['args'];config=self.root/'synthetic-hostile-ssh.conf';master=self.root/'never-open-this-master'
  config.write_text('Host *\n    HostName 127.0.0.1\n    CanonicalizeHostname no\n    BatchMode no\n    StrictHostKeyChecking no\n    ControlMaster auto\n    ControlPath '+str(master)+'\n    ControlPersist 600\n    UserKnownHostsFile /dev/null\n    GlobalKnownHostsFile /dev/null\n    ProxyCommand none\n    ProxyJump none\n    PermitLocalCommand no\n');config.chmod(0o600);ssh=shutil.which('ssh');self.assertIsNotNone(ssh,'existing local OpenSSH client required for config-only fixture')
  command=[ssh,'-G','-F',str(config),*args[1:-2],'synthetic-nebula.invalid'];result=subprocess.run(command,stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=5,env={'PATH':'/usr/bin:/bin','HOME':str(self.root),'LANG':'C','LC_ALL':'C'});self.assertEqual(result.returncode,0,'config-only synthetic ssh -G failed');selected={}
  for line in result.stdout.decode().splitlines():
   key,separator,value=line.partition(' ')
   if key in SSH_REQUIRED:self.assertNotIn(key,selected);selected[key]=value.strip()
  # OpenSSH omits ControlPath when the explicit CLI value none resolves to NULL.
  self.assertNotIn(str(master),result.stdout.decode());self.assertIn(set(selected),[set(SSH_REQUIRED),set(SSH_REQUIRED)-{'controlpath'}]);selected.setdefault('controlpath','none')
  self.assertIn(selected['batchmode'],['yes','true']);self.assertIn(selected['stricthostkeychecking'],['yes','true']);self.assertIn(selected['controlmaster'],['no','false']);self.assertEqual(selected['controlpath'],'none');self.assertIn(selected['controlpersist'],['no','false','0']);self.assertFalse(master.exists());print('synthetic_ssh_effective_options '+json.dumps(selected,sort_keys=True))
 def test_expected_head_is_external_full_record_checkpoint_and_advances_only_after_success(self):
  j=self.job();self.assertIsNone(j.head_record());self.assertEqual(j.head_sha256(),'none');self.assertEqual(self.expected_head,'none');j.run_step('stage-tarragon');head=j.head_record();self.assertEqual(head['name'],'stage-tarragon.complete.json');self.assertEqual(self.expected_head,o.sha(o.bytes_json(head)));self.assertEqual(j.expected_head_sha256,self.expected_head);self.assertNotEqual(self.expected_head,o.sha((j.state/head['name']).read_bytes()));j.close();j=self.job();self.assertEqual(j.head_record(),head);self.assertEqual(j.head_sha256(),self.expected_head)
 def test_identical_byte_latest_completion_inode_replacement_is_refused_before_remote(self):
  j=self.prepare('stage-slipstream');trusted=self.expected_head;path=j.state/'stage-tarragon.complete.json';raw=path.read_bytes();old_inode=path.stat().st_ino;j.close();replacement=self.state/'tip-replacement';o.exclusive(replacement,raw);os.replace(replacement,path);self.assertNotEqual(path.stat().st_ino,old_inode);count=len(self.history)
  with self.assertRaisesRegex(o.Refused,'head'):self.job()
  self.assertEqual(self.expected_head,trusted);self.assertEqual(path.read_bytes(),raw);self.assertEqual(len(self.history),count)
 def test_coherent_latest_completion_and_fabricated_result_substitution_is_refused(self):
  j=self.prepare('stage-slipstream');trusted=self.expected_head;path=j.state/'stage-tarragon.complete.json';ledger=json.loads(path.read_text());j.close();fabricated=self.state/'forged-status.stdout';raw=o.bytes_json({'status':'passed','fabricated':True});o.exclusive(fabricated,raw);record={'name':fabricated.name,'identity':o.meta(fabricated.stat()),'sha256':o.sha(raw),'limit':512*1024};old_result=ledger['result'];ledger['files']=[record if value==old_result else value for value in ledger['files']];ledger['result']=record;replacement=self.state/'tip-replacement';o.exclusive(replacement,o.bytes_json(ledger));os.replace(replacement,path);count=len(self.history)
  with self.assertRaisesRegex(o.Refused,'head'):self.job()
  self.assertEqual(self.expected_head,trusted);self.assertEqual(fabricated.read_bytes(),raw);self.assertEqual(len(self.history),count)
 def test_expected_head_format_rejected_before_source_reads(self):
  for value in [None,'','none ','NONE','A'*64,'f'*63,'f'*65,7,b'none',{}]:
   with self.subTest(value=value),patch.object(o,'local_read',side_effect=AssertionError('source read before head gate')):
    with self.assertRaises(o.Refused):self.job(expected_head=value)
 def test_expected_head_constructor_argument_is_required_before_reads(self):
  with patch.object(o,'local_read',side_effect=AssertionError('source read before required argument')):
   with self.assertRaises(TypeError):o.Orchestrator(self.manifest,o.sha(self.manifest.read_bytes()),self.id,self.state,self.overlay)
 def test_wrong_checkpoint_cannot_describe_initial_empty_head(self):
  with self.assertRaisesRegex(o.Refused,'head'):self.job(expected_head='f'*64)
  self.assertEqual(self.history,[])
 def test_none_and_stale_valid_head_cannot_rebind_noninitial_operation(self):
  j=self.job();j.run_step('stage-tarragon');first=self.expected_head;j.close();j=self.job();j.run_step('stage-slipstream');latest=self.expected_head;j.close();count=len(self.history)
  for value in ['none',first,'f'*64]:
   with self.subTest(value=value):
    with self.assertRaisesRegex(o.Refused,'head'):self.job(expected_head=value)
  self.assertEqual(self.expected_head,latest);self.assertEqual(len(self.history),count)
 def test_pending_attempt_refuses_even_readonly_check_without_adoption(self):
  j=self.job()
  def fail(call):
   if call['phase']=='stage':raise o.Refused('synthetic_failure')
  j.fake.before=fail
  with self.assertRaises(o.Refused):j.run_step('stage-tarragon')
  self.assertEqual(self.expected_head,'none');j.close();count=len(self.history)
  with self.assertRaisesRegex(o.Refused,'unknown_partial_requires_review'):self.job()
  self.assertEqual(len(self.history),count)
 def test_readonly_check_revalidates_head_after_return_before_success(self):
  j=self.prepare('stage-slipstream');trusted=self.expected_head;original=j.head_sha256;drift=[False];j.head_sha256=lambda:'f'*64 if drift[0] else original()
  def after(call):
   if len(j.calls)==3:drift[0]=True
  j.fake.after=after
  with self.assertRaisesRegex(o.Refused,'head'):j.run_step('check-tarragon')
  self.assertEqual(len(j.calls),3);self.assertEqual(self.expected_head,trusted)
 def test_new_process_never_derives_expected_head_from_current_tip(self):
  j=self.job();j.run_step('stage-tarragon');trusted=self.expected_head;j.close()
  # Holding the caller checkpoint unchanged is essential: replacing the tip with
  # an otherwise valid private file cannot refresh this out-of-state expected pin.
  path=self.state/'stage-tarragon.complete.json';replacement=self.state/'same-bytes-new-inode';o.exclusive(replacement,path.read_bytes());os.replace(replacement,path)
  with self.assertRaises(o.Refused):self.job(expected_head=trusted)
  self.assertEqual(self.expected_head,trusted)

class ManagedBridgeTests(unittest.TestCase):
 def setUp(self):
  import types
  self.temp=tempfile.TemporaryDirectory(prefix='nebula-bridge-fixture-',dir='/root');self.root=Path(self.temp.name);self.root.chmod(0o700);self.work=self.root/'plan-synthetic';self.seen=[];self.guards=[];self.external=0;self.failure=None
  owner=self
  class Job:
   plan_path=owner.work/'plan.json'
   def guard(self,health=True):
    owner.guards.append(health);self.external_guard()
    if owner.failure:raise RuntimeError(owner.failure)
  self.job=Job()
  class Bridge:
   def __init__(self,path):owner.seen.append(path);self.o={'lifecycle_path':'/root/nebula-alpha-lifecycle-7c93lt9w/lifecycle-6b4ae6.py','preflight_path':'/root/nebula-alpha-prep-u0i7dxy9/preflight.py'}
   def lifecycle(self,runner=None):owner.assertIsNone(runner);return owner.job
  self.Bridge=Bridge;self.env={'Path':Path,'q':{'managed_health_overlay':'/root/synthetic-admitted-overlay.json'},'managed_bridge':lambda:types.SimpleNamespace(Bridge=self.Bridge),'need':lambda v,c:None if v else (_ for _ in ()).throw(RuntimeError(c))};n=next(n for n in ast.parse(o.BROKER).body if isinstance(n,ast.FunctionDef) and n.name=='managed_lifecycle');exec(compile(ast.Module(body=[n],type_ignores=[]),'managed-lifecycle-fixture','exec'),self.env)
 def tearDown(self):self.temp.cleanup()
 def external_guard(self):self.external+=1
 def test_explicit_overlay_default_health_and_external_lock_guard_preserved(self):
  result=self.env['managed_lifecycle'](self.work,self.external_guard);self.assertIs(result,self.job);self.assertEqual(self.seen,[Path('/root/synthetic-admitted-overlay.json')]);self.assertEqual(self.guards,[True]);self.assertEqual(self.external,1)
 def test_stale_or_missing_managed_proof_never_falls_back(self):
  self.failure='stale_managed_proof'
  with self.assertRaisesRegex(RuntimeError,'stale_managed_proof'):self.env['managed_lifecycle'](self.work,self.external_guard)
  self.assertEqual(self.guards,[True]);self.assertEqual(len(self.seen),1)
 def test_wrong_admitted_original_plan_path_is_refused(self):
  self.job.plan_path=self.root/'foreign-plan.json'
  with self.assertRaisesRegex(RuntimeError,'admitted_original_plan_path_required'):self.env['managed_lifecycle'](self.work,self.external_guard)
  self.assertEqual(self.guards,[])
 def public_loader(self):
  import types
  path=self.root/'bridge.py';path.write_bytes(Path('/tmp/nebula-managed-v3-consumers-rkss039w/references/alpha-managed-health-bridge.py').read_bytes());path.chmod(0o644);env={'Path':lambda fixed:path,'os':os,'stat':stat,'hashlib':hashlib,'types':types,'identity':lambda st:tuple(o.meta(st)),'need':lambda v,c:None if v else (_ for _ in ()).throw(RuntimeError(c))};n=next(n for n in ast.parse(o.BROKER).body if isinstance(n,ast.FunctionDef) and n.name=='managed_bridge');exec(compile(ast.Module(body=[n],type_ignores=[]),'public-loader-fixture','exec'),env);return path,env['managed_bridge']
 def test_public_bridge0644_and0555_are_hash_pinned_without_private_loader_weakening(self):
  path,load=self.public_loader();self.assertTrue(callable(load().Bridge));path.chmod(0o555);self.assertTrue(callable(load().Bridge));self.assertIn('stat.S_IMODE(s.st_mode)==0o600',o.BROKER)
 def test_public_bridge_source_drift_refused_before_execution(self):
  path,load=self.public_loader();path.write_bytes(b'raise AssertionError("MUST NOT EXECUTE")\n')
  with self.assertRaisesRegex(RuntimeError,'managed_bridge_source_pin'):load()
 def test_public_bridge_unsafe_mode_and_links_refused(self):
  path,load=self.public_loader();path.chmod(0o666)
  with self.assertRaisesRegex(RuntimeError,'managed_bridge_source_custody'):load()
  path.chmod(0o644);os.link(path,self.root/'hardlink')
  with self.assertRaisesRegex(RuntimeError,'managed_bridge_source_custody'):load()

class RelayTests(unittest.TestCase):
 def setUp(self):
  import types
  self.temp=tempfile.TemporaryDirectory(prefix='nebula-relay-fixture-',dir='/root');self.work=Path(self.temp.name);self.work.chmod(0o700);self.output=io.BytesIO();self.fds=[];self.guards=0;self.raise_at=None;self.behavior='pass';self.mod=types.ModuleType('relay-fixture')
  tree=ast.parse(o.BROKER);functions=[n for n in tree.body if isinstance(n,ast.FunctionDef) and n.name in ['need','identity','relay']]
  env={'Path':Path,'os':os,'stat':stat,'tempfile':tempfile,'sys':types.SimpleNamespace(stdout=types.SimpleNamespace(buffer=self.output))};exec(compile(ast.Module(body=functions,type_ignores=[]),'relay-fixture','exec'),env);self.relay=env['relay'];self.transport=types.SimpleNamespace(command=self.command)
 def tearDown(self):self.temp.cleanup()
 def guard(self):
  self.guards+=1
  if self.guards==self.raise_at:raise RuntimeError('synthetic_guard_refusal')
 def command(self,work,args,label,**kw):
  self.assertEqual(args,['FAKE-SSH-NEVER-EXECUTED']);self.assertEqual(kw['input_bytes'],b'PUBLIC-INPUT');self.assertNotIn('local_controller',kw);fd=kw['stdout_fd'];self.fds.append(fd);st=os.fstat(fd);self.assertTrue(stat.S_ISREG(st.st_mode));self.assertEqual(stat.S_IMODE(st.st_mode),0o600);self.assertEqual(st.st_uid,0);self.assertEqual(st.st_gid,0);self.assertEqual(st.st_nlink,1);os.write(fd,b'PUBLIC-OUTPUT')
  if self.behavior=='fail':raise RuntimeError('synthetic_transport_failure')
  if self.behavior=='replace':
   foreign=work/'foreign';o.exclusive(foreign,b'FOREIGN-PRESERVE');os.replace(foreign,work/'stdout')
 def run_relay(self):return self.relay(self.transport,self.work,['FAKE-SSH-NEVER-EXECUTED'],b'PUBLIC-INPUT',512*1024,self.guard)
 def assert_closed(self):
  self.assertEqual(len(self.fds),1)
  with self.assertRaises(OSError):os.fstat(self.fds[0])
 def test_success_forwards_same_held_spool_only_after_guards(self):
  self.run_relay();self.assertEqual(self.output.getvalue(),b'PUBLIC-OUTPUT');self.assertEqual(self.guards,3);self.assert_closed()
 def test_failed_command_never_forwards_partial(self):
  self.behavior='fail'
  with self.assertRaisesRegex(RuntimeError,'synthetic_transport_failure'):self.run_relay()
  self.assertEqual(self.output.getvalue(),b'');self.assert_closed()
 def test_failed_post_command_guard_never_forwards_partial(self):
  self.raise_at=2
  with self.assertRaisesRegex(RuntimeError,'synthetic_guard_refusal'):self.run_relay()
  self.assertEqual(self.output.getvalue(),b'');self.assert_closed()
 def test_replaced_spool_preserves_foreign_and_never_forwards(self):
  self.behavior='replace'
  with self.assertRaisesRegex(RuntimeError,'guest_transport_postimage_changed'):self.run_relay()
  self.assertEqual(self.output.getvalue(),b'');self.assertEqual(next(self.work.glob('backup-transport-*/stdout')).read_bytes(),b'FOREIGN-PRESERVE');self.assert_closed()

class StageTests(unittest.TestCase):
 def setUp(self):
  self.temp=tempfile.TemporaryDirectory(prefix='nebula-inert-stage-test-',dir='/root');self.root=Path(self.temp.name);self.root.chmod(0o700)
 def tearDown(self):self.temp.cleanup()
 def helpers(self):
  import ast,types
  tree=ast.parse(o.BROKER);chosen=[n for n in tree.body if isinstance(n,ast.FunctionDef)]
  mod=types.ModuleType('inert-stage');code=ast.Module(body=chosen,type_ignores=[]);exec(compile(code,'inert-stage','exec'),mod.__dict__)
  for name,value in {'Path':Path,'os':os,'stat':stat,'hashlib':hashlib,'json':json,'types':types}.items():setattr(mod,name,value)
  def need(v,c):
   if not v:raise o.Refused(c)
  mod.need=need;mod.identity=lambda st:(st.st_dev,st.st_ino,st.st_mode,st.st_uid,st.st_gid,st.st_nlink,st.st_size,st.st_mtime_ns,st.st_ctime_ns)
  raw={n:('# synthetic '+n+'\n').encode() for n in o.NAMES};mod.q={'files':{n:hashlib.sha256(v).hexdigest() for n,v in raw.items()}}
  import base64
  return mod,{n:base64.b64encode(v).decode() for n,v in raw.items()}
 def test_inert_stage_only_public_code_expected_files(self):
  h,payload=self.helpers();directory=self.root/'operation';h.stage_bundle(directory,'nebula-backup-target.py',payload)
  self.assertEqual({p.name for p in directory.iterdir()},{'nebula-backup-common.py','nebula-backup-envelope-policy.py','nebula-backup-target.py','source-manifest.json'})
  self.assertTrue(all(stat.S_IMODE(p.stat().st_mode)==0o600 for p in directory.iterdir()))
 def test_existing_foreign_source_directory_preserved(self):
  h,payload=self.helpers();directory=self.root/'operation';directory.mkdir(mode=0o700);foreign=directory/'foreign';foreign.write_text('preserve')
  with self.assertRaises(o.Refused):h.stage_bundle(directory,'nebula-backup-target.py',payload)
  self.assertEqual(foreign.read_text(),'preserve')
 def test_bad_public_digest_no_directory_creation(self):
  h,payload=self.helpers();payload['nebula-backup-common.py']='eD0yCg==';directory=self.root/'operation'
  with self.assertRaises(o.Refused):h.stage_bundle(directory,'nebula-backup-target.py',payload)
  self.assertFalse(directory.exists())
 def test_guest_rejects_wrong_privilege_before_any_write(self):
  x={'uuid':'not-a-real-uuid','operation_id':'1'*32,'phase':'stage','run_id':'a'*12,'address':'192.0.2.1','files':{},'public_input':'{}'}
  with patch.object(os,'geteuid',return_value=1000):
   with self.assertRaises(RuntimeError):exec(compile(o.GUEST_RECEIVER,'guest-stage','exec'),{'x':x})
class PrivateResultTests(unittest.TestCase):
 def setUp(self):
  self.temp=tempfile.TemporaryDirectory(prefix='nebula-private-result-fixture-',dir='/root');self.root=Path(self.temp.name);self.root.chmod(0o700);self.state=self.root/'operation-state';self.state.mkdir(mode=0o700);self.parent=self.root/'results';self.parent.mkdir(mode=0o700);self.path=self.parent/'success.json';self.value={'status':'passed','step':'stage-tarragon','head_record':{'name':'synthetic.complete.json','identity':[1,2,33152,0,0,1,3,4,5],'sha256':'b'*64,'limit':3},'head_sha256':'c'*64}
 def tearDown(self):self.temp.cleanup()
 def test_private_success_result_is_exclusive0600_and_exact(self):
  result=o.PrivateResult(self.path,self.state)
  try:result.write(self.value)
  finally:result.close()
  self.assertEqual(json.loads(self.path.read_text()),self.value);st=self.path.stat();self.assertEqual(stat.S_IMODE(st.st_mode),0o600);self.assertEqual(st.st_uid,os.geteuid());self.assertEqual(st.st_gid,os.getegid());self.assertEqual(st.st_nlink,1);before=o.meta(st)
  with self.assertRaises((o.Refused,FileExistsError)):o.PrivateResult(self.path,self.state)
  self.assertEqual(o.meta(self.path.stat()),before)
 def test_result_path_inside_operation_state_refused(self):
  child=self.state/'child';child.mkdir(mode=0o700)
  for path in [self.state/'success.json',child/'success.json']:
   with self.subTest(path=path):
    with self.assertRaises(o.Refused):o.PrivateResult(path,self.state)
    self.assertFalse(path.exists())
 def test_result_missing_or_public_parent_refused_without_creation(self):
  missing=self.root/'missing'/'result.json'
  with self.assertRaises((o.Refused,FileNotFoundError)):o.PrivateResult(missing,self.state)
  self.assertFalse(missing.parent.exists());self.parent.chmod(0o755)
  with self.assertRaises(o.Refused):o.PrivateResult(self.path,self.state)
  self.assertFalse(self.path.exists())
 def test_result_symlink_and_symlink_ancestor_refused_preserving_target(self):
  target=self.parent/'foreign';o.exclusive(target,b'FOREIGN-PRESERVE');os.symlink(target,self.path)
  with self.assertRaises(o.Refused):o.PrivateResult(self.path,self.state)
  self.assertEqual(target.read_bytes(),b'FOREIGN-PRESERVE');self.path.unlink();link=self.root/'linked-results';os.symlink(self.parent,link)
  with self.assertRaises(o.Refused):o.PrivateResult(link/'other.json',self.state)
  self.assertFalse((self.parent/'other.json').exists())
 def test_held_result_parent_replacement_refused_preserving_foreign(self):
  result=o.PrivateResult(self.path,self.state);held=self.root/'held-results';os.rename(self.parent,held);self.parent.mkdir(mode=0o700);marker=self.parent/'foreign';o.exclusive(marker,b'FOREIGN-PRESERVE')
  try:
   with self.assertRaises((o.Refused,FileNotFoundError)):result.write(self.value)
  finally:result.close()
  self.assertEqual(marker.read_bytes(),b'FOREIGN-PRESERVE');self.assertFalse(self.path.exists())
 def cli_args(self):return ['orchestrator','--bundle-manifest','/synthetic/manifest.json','--manifest-sha256','a'*64,'--operation-id','1'*32,'--state',str(self.state),'--managed-health-overlay','/root/synthetic-admitted-overlay.json','--expected-head-sha256','none','--private-result',str(self.path),'--step','stage-tarragon','--execute']
 def fake_job(self):
  owner=self
  class FakeJob:
   def __init__(self,*args,**kwargs):self.state=args[3];owner.assertEqual(args[5],'none');self.expected_head_sha256=args[5];self.closed=False;self.steps=[];self.verified=0;owner.instance=self
   def acquire_lock(self):pass
   def run_step(self,step):self.steps.append(step);o.exclusive(self.state/'synthetic-complete',b'COMPLETED-PRESERVE');self.expected_head_sha256=owner.value['head_sha256']
   def guard_local(self):pass
   def verify_expected_head(self):owner.assertEqual(self.expected_head_sha256,owner.value['head_sha256'] if self.steps else 'none');self.verified+=1
   def head_record(self):return owner.value['head_record']
   def head_sha256(self):return owner.value['head_sha256']
   def close(self):self.closed=True
  return FakeJob
 def test_cli_requires_checkpoint_and_private_result_before_constructor(self):
  for flag in ['--expected-head-sha256','--private-result']:
   args=self.cli_args();index=args.index(flag);del args[index:index+2]
   with self.subTest(flag=flag),patch.object(sys,'argv',args),patch.object(o,'Orchestrator',side_effect=AssertionError('constructor before required argument')),contextlib.redirect_stderr(io.StringIO()):
    with self.assertRaises(SystemExit) as raised:o.main()
    self.assertEqual(raised.exception.code,2)
 def test_cli_success_head_goes_only_to_private_result_not_stdout(self):
  stdout=io.StringIO()
  with patch.object(sys,'argv',self.cli_args()),patch.object(o,'Orchestrator',self.fake_job()),contextlib.redirect_stdout(stdout):o.main()
  public=json.loads(stdout.getvalue());self.assertEqual(public['status'],'passed');self.assertEqual(public['step'],'stage-tarragon');self.assertIn(str(self.path),public.values());self.assertLessEqual(len(public),3);self.assertNotIn('head_record',public);self.assertNotIn('head_sha256',public);self.assertNotIn(self.value['head_sha256'],stdout.getvalue());private=json.loads(self.path.read_text());self.assertEqual(private['head_record'],self.value['head_record']);self.assertEqual(private['head_sha256'],self.value['head_sha256']);self.assertTrue(self.instance.closed)
 def test_lost_private_receipt_does_not_retry_or_remove_completed_state(self):
  stdout=io.StringIO()
  with patch.object(sys,'argv',self.cli_args()),patch.object(o,'Orchestrator',self.fake_job()),patch.object(o.PrivateResult,'write',side_effect=OSError('synthetic private output failure')),contextlib.redirect_stdout(stdout):
   with self.assertRaisesRegex(o.Refused,'private_success_result_failed_manual_review_required'):o.main()
  self.assertEqual((self.state/'synthetic-complete').read_bytes(),b'COMPLETED-PRESERVE');self.assertEqual(self.instance.steps,['stage-tarragon']);self.assertTrue(self.instance.closed);self.assertFalse(self.path.exists());self.assertNotIn(self.value['head_sha256'],stdout.getvalue());self.assertEqual(stdout.getvalue(),'')

if __name__=='__main__':unittest.main(verbosity=2)

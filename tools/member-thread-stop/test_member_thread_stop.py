#!/usr/bin/env python3
"""OWN inert C tasks only. Preserves all fixture receipts, including failures.
No network/fabric/profile/remote target or PID arguments are accepted.
"""
import ctypes,fcntl,hashlib,json,os,select,shutil,signal,struct,subprocess,tempfile,time,unittest
from pathlib import Path
SOURCE=Path(__file__).with_name('nebula-member-thread-stop.c')
HELPER=Path(__file__).with_name('build')/'nebula-member-thread-stop-disposable'
TARGET=Path(__file__).with_name('build')/'nebula-member-thread-fixture-target'
LAUNCH=Path(__file__).with_name('build')/'nebula-member-thread-fixture-launch'
EVENT=struct.Struct('@cii')
ALL=[]
def process_start(pid):return int(Path('/proc/'+str(pid)+'/stat').read_text().rsplit(') ',1)[1].split()[19])
def proc_status(pid):
 return dict(line.split(':',1)for line in Path('/proc/'+str(pid)+'/status').read_text().splitlines()if ':'in line)
class Fixture:
 def __init__(self,mode='multi'):
  self.base=Path(tempfile.mkdtemp(prefix='nebula-member-thread-test-',dir='/run'));self.base.chmod(0o700);ALL.append(str(self.base));self.events=[];self.buffer=b'';self.extra={};self.helpers=[]
  shutil.copyfile(TARGET,self.base/'nucleus');(self.base/'nucleus').chmod(0o555)
  cr,self.command=os.pipe();self.event,ew=os.pipe();self.child=subprocess.Popen([str(self.base/'nucleus'),mode,str(cr),str(ew)],stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,pass_fds=(cr,ew),start_new_session=True);os.close(cr);os.close(ew);self.pidfd=os.pidfd_open(self.child.pid);self.start=process_start(self.child.pid);self.wait_event('R')
  self.home=self.base/'native-home';self.home.mkdir(mode=0o700);self.state=self.home/'state.json';self.state.write_bytes(b'{"synthetic_fixture_only":true}\n');self.state.chmod(0o600);(self.home/'state.lock').write_bytes(b'');(self.home/'state.lock').chmod(0o600)
  self.receipt=self.base/('thread-stop-'+'a'*16);self.receipt.mkdir(mode=0o700);shutil.copyfile(self.base/'nucleus',self.receipt/'binary.before');(self.receipt/'binary.before').chmod(0o555);shutil.copyfile(self.state,self.receipt/'state.before');(self.receipt/'state.before').chmod(0o600)
  ex=os.stat('/proc/'+str(self.child.pid)+'/exe');self.values={'schema':2,'pid':self.child.pid,'start':self.start,'uid':0,'gid':0,'exe_dev':ex.st_dev,'exe_ino':ex.st_ino,'exe_size':ex.st_size,'checked_at':int(time.time()),'valid_until':int(time.time())+120,'native_load_preflight':1,'state':str(self.state)};self.request=self.receipt/'stop.request';self.save()
 def save(self):self.request.write_text(''.join(str(k)+'='+str(v)+'\n'for k,v in self.values.items()));self.request.chmod(0o600)
 def pump(self,timeout=0):
  if not select.select([self.event],[],[],timeout)[0]:return
  b=os.read(self.event,65536)
  if not b:return
  self.buffer+=b
  while len(self.buffer)>=EVENT.size:
   code,pid,tid=EVENT.unpack(self.buffer[:EVENT.size]);self.buffer=self.buffer[EVENT.size:];code=code.decode();self.events.append((code,pid,tid))
   if code in ['B','O']:
    try:
     st=proc_status(tid)
     if int(st['Tgid'])==tid and tid!=self.child.pid and tid not in self.extra:
      actual=os.stat('/proc/'+str(tid)+'/exe');known=(self.base/'nucleus').stat();assert(actual.st_dev,actual.st_ino)==(known.st_dev,known.st_ino);self.extra[tid]=os.pidfd_open(tid)
    except FileNotFoundError:pass
 def wait_event(self,code,timeout=2):
  end=time.monotonic()+timeout
  while time.monotonic()<end:
   self.pump(.01)
   for event in self.events:
    if event[0]==code:return event
  raise AssertionError('Own fixture marker missing: '+code)
 def command_byte(self,c):os.write(self.command,c.encode())
 def run(self,mode='--probe',action=None,launcher=None,blocked_stdout=False):
  go_r,go=os.pipe();notice,notice_w=os.pipe();env={**os.environ,'NEBULA_TEST_IN':str(go_r),'NEBULA_TEST_OUT':str(notice_w)}
  argv=[str(HELPER),mode,str(self.request)]
  if launcher:argv=[str(LAUNCH),launcher,*argv]
  blocked_read=None;blocked_write=None;filled=0
  if blocked_stdout:
   blocked_read,blocked_write=os.pipe();flags=fcntl.fcntl(blocked_write,fcntl.F_GETFL);fcntl.fcntl(blocked_write,fcntl.F_SETFL,flags|os.O_NONBLOCK)
   try:
    while True:filled+=os.write(blocked_write,b'F'*4096)
   except BlockingIOError:pass
   fcntl.fcntl(blocked_write,fcntl.F_SETFL,flags)
  p=subprocess.Popen(argv,stdin=subprocess.DEVNULL,stdout=blocked_write if blocked_stdout else subprocess.PIPE,stderr=subprocess.PIPE,pass_fds=(go_r,notice_w),env=env);
  if blocked_write is not None:os.close(blocked_write)
  pfd=os.pidfd_open(p.pid);self.helpers.append((p,pfd));os.close(go_r);os.close(notice_w);buf=b'';seen=[];end=time.monotonic()+10
  try:
   while time.monotonic()<end:
    if select.select([notice],[],[],.01)[0]:
     block=os.read(notice,4096)
     if not block:break
     buf+=block
     while b'\n'in buf:
      raw,buf=buf.split(b'\n',1);stage=raw.decode();seen.append(stage)
      if action:action(stage,p)
      try:os.write(go,b'G')
      except BrokenPipeError:pass
    if p.poll()is not None:break
   out,err=p.communicate(timeout=3);self.pump(.01)
   if blocked_read is not None:
    raw=b''
    while True:
     chunk=os.read(blocked_read,65536)
     if not chunk:break
     raw+=chunk
    assert raw.startswith(b'F'*filled);out=raw[filled:];(self.base/'prefilled-stdout-count.json').write_text(json.dumps({'bytes':filled,'remaining_bytes':len(out)})+'\n')
   out=out or b''
   stem=self.base/('helper-'+str(len(self.helpers)));Path(str(stem)+'.stdout').write_bytes(out);Path(str(stem)+'.stderr').write_bytes(err);Path(str(stem)+'.stages.json').write_text(json.dumps(seen)+'\n')
   assert not err,err
   if out:value=json.loads(out)
   elif p.returncode==124:
    known=False if mode=='--probe'else(True if'after-queue'in seen else(False if'after-final'not in seen else None));value={'status':'refused','reason':'watchdog_exit124_no_helper_json','sigterm_queued':known,'fixture_driver_observation_only':True}
   else:raise AssertionError('Missing helper report without watchdog refusal')
   Path(str(stem)+'.result.json').write_text(json.dumps(value,sort_keys=True)+'\n');return p.returncode,value
  finally:
   os.close(go);os.close(notice)
   if blocked_read is not None:os.close(blocked_read)
 def alive_untraced(self):
  assert self.child.poll()is None
  for tid in Path('/proc/'+str(self.child.pid)+'/task').iterdir():
   try:s=proc_status(int(tid.name))
   except FileNotFoundError:continue
   assert int(s['TracerPid'])==0 and s['State'].strip()[0]!='t'
 def close(self):
  # Only pre-held fixture pidfds; no numeric/group termination fallback.
  for p,fd in self.helpers:
   if p.poll()is None:signal.pidfd_send_signal(fd,signal.SIGKILL)
   p.wait(timeout=3);os.close(fd)
  self.pump(.05)
  for fd in [*self.extra.values(),self.pidfd]:
   try:signal.pidfd_send_signal(fd,signal.SIGKILL)
   except ProcessLookupError:pass
  self.child.wait(timeout=3)
  (self.base/'events.json').write_text(json.dumps(self.events)+'\n')
  for pid,fd in self.extra.items():
   try:os.waitpid(pid,0x40000000)
   except ChildProcessError:pass
   os.close(fd)
  os.close(self.pidfd);os.close(self.command);os.close(self.event)
  # All files intentionally retained; nothing is recursively deleted.
class Tests(unittest.TestCase):
 def fixture(self,mode='multi'):
  f=Fixture(mode);self.addCleanup(f.close);return f
 def test_multithread_probe_all_held_and_released(self):
  f=self.fixture();observed=[]
  def check(stage,p):
   if stage=='after-acquire':
    rows=[proc_status(int(t.name))for t in Path('/proc/'+str(f.child.pid)+'/task').iterdir()];self.assertGreaterEqual(len(rows),2);self.assertTrue(all(int(x['TracerPid'])==p.pid and x['State'].strip()[0]=='t'for x in rows));observed.append(True)
  c,r=f.run(action=check);self.assertEqual((c,r['status']),(0,'probe-detached'));self.assertTrue(observed);self.assertTrue(r['target_group_closed']);self.assertFalse(r['sigterm_queued']);f.alive_untraced()
 def test_one_term_to_positive_own_tgid(self):
  f=self.fixture();c,r=f.run('--terminate');self.assertTrue(r['sigterm_queued']);self.assertTrue(r['target_group_closed']);self.assertEqual(f.child.wait(timeout=2),-signal.SIGTERM);self.assertIn(r['status'],['termination-requested','termination-requested-partial-cleanup'])
 def test_pending_term_survives_detach_zero(self):
  f=self.fixture('term-handler');proof=[]
  def check(stage,p):
   if stage=='after-queue':
    rows=[proc_status(int(t.name))for t in Path('/proc/'+str(f.child.pid)+'/task').iterdir()];self.assertTrue(any((int(x['SigPnd'],16)|int(x['ShdPnd'],16))&(1<<(signal.SIGTERM-1))for x in rows));proof.append(True)
  c,r=f.run('--terminate',check);self.assertTrue(proof);self.assertTrue(r['sigterm_queued']);f.wait_event('T');self.assertEqual(f.child.wait(timeout=2),0)
 def test_old_schema_refuses(self):
  f=self.fixture();f.values['schema']=1;f.save();c,r=f.run('--terminate');self.assertEqual(c,1);self.assertFalse(r['sigterm_queued']);f.alive_untraced()
 def test_missing_native_load_prerequisite_refuses(self):
  f=self.fixture();f.values['native_load_preflight']=0;f.save();c,r=f.run('--terminate');self.assertEqual(r['reason'],'private_schema2_request_invalid');self.assertFalse(r['sigterm_queued']);f.alive_untraced()
 def test_old_namespace_refuses(self):
  f=self.fixture();original=f.request;f.request=f.base/'stop.request';f.request.write_bytes(original.read_bytes());f.request.chmod(0o600);c,r=f.run('--terminate');self.assertEqual(r['reason'],'thread_stop_namespace_required');f.alive_untraced()
 def test_wrong_start_or_binary_or_state_refuses(self):
  for what in ['start','binary','state']:
   f=self.fixture()
   if what=='start':f.values['start']+=1;f.save()
   elif what=='binary':f.values['exe_ino']+=1;f.save()
   else:f.state.write_bytes(b'FOREIGN')
   c,r=f.run('--terminate');self.assertEqual(c,1);self.assertFalse(r['sigterm_queued']);f.alive_untraced()
 def test_mutated_state_while_all_held_preserved(self):
  f=self.fixture()
  def change(stage,p):
   if stage=='after-acquire':f.state.write_bytes(b'UNKNOWN PRESERVED')
  c,r=f.run('--terminate',change);self.assertEqual(c,1);self.assertFalse(r['sigterm_queued']);self.assertEqual(f.state.read_bytes(),b'UNKNOWN PRESERVED');f.alive_untraced()
 def test_cancel_while_all_held(self):
  f=self.fixture()
  def change(stage,p):
   if stage=='after-acquire':os.kill(p.pid,signal.SIGTERM)
  c,r=f.run('--terminate',change);self.assertEqual(c,1);self.assertFalse(r['sigterm_queued']);f.alive_untraced()
 def test_unexpected_usr1_delivery_preserved_once_on_abort(self):
  f=self.fixture();once=[]
  def change(stage,p):
   if stage=='leader-seized'and not once:
    signal.pidfd_send_signal(f.pidfd,signal.SIGUSR1);time.sleep(.03);once.append(True)
  c,r=f.run('--terminate',change);self.assertEqual(c,1);self.assertFalse(r['sigterm_queued']);f.wait_event('U');f.pump(.05);self.assertEqual(sum(x[0]=='U'for x in f.events),1);f.alive_untraced()
 def test_preexisting_group_stop_not_resumed(self):
  f=self.fixture();signal.pidfd_send_signal(f.pidfd,signal.SIGSTOP);end=time.monotonic()+1
  while time.monotonic()<end and proc_status(f.child.pid)['State'].strip()[0]!='T':time.sleep(.001)
  c,r=f.run('--terminate');self.assertEqual(c,1);self.assertFalse(r['sigterm_queued']);self.assertEqual(proc_status(f.child.pid)['State'].strip()[0],'T');signal.pidfd_send_signal(f.pidfd,signal.SIGCONT);f.alive_untraced()
 def test_fatal_before_final_prevents_queue(self):
  f=self.fixture()
  def change(stage,p):
   if stage=='after-acquire':signal.pidfd_send_signal(f.pidfd,signal.SIGKILL);time.sleep(.02)
  c,r=f.run('--terminate',change);self.assertEqual(c,1);self.assertFalse(r['sigterm_queued']);self.assertEqual(f.child.wait(timeout=2),-signal.SIGKILL)
 def test_group_stop_during_trace_preserved_on_tracer_exit(self):
  f=self.fixture();done=[]
  def change(stage,p):
   if stage=='leader-seized'and not done:signal.pidfd_send_signal(f.pidfd,signal.SIGSTOP);time.sleep(.03);done.append(True)
  c,r=f.run('--terminate',change);self.assertEqual(c,1);self.assertFalse(r['sigterm_queued']);end=time.monotonic()+1
  while time.monotonic()<end and proc_status(f.child.pid)['State'].strip()[0]!='T':time.sleep(.001)
  self.assertEqual(proc_status(f.child.pid)['State'].strip()[0],'T');self.assertEqual(int(proc_status(f.child.pid)['TracerPid']),0);signal.pidfd_send_signal(f.pidfd,signal.SIGCONT);f.alive_untraced()
 def test_terminal_race_after_kernel_stop_query_aborts(self):
  f=self.fixture();done=[]
  def change(stage,p):
   if stage=='after-stop-query'and not done:signal.pidfd_send_signal(f.pidfd,signal.SIGKILL);time.sleep(.02);done.append(True)
  c,r=f.run('--terminate',change);self.assertEqual(c,1);self.assertFalse(r['sigterm_queued']);self.assertEqual(f.child.wait(timeout=2),-signal.SIGKILL)
 def test_fatal_after_final_has_no_reap_or_fallback(self):
  f=self.fixture()
  def change(stage,p):
   if stage=='after-final':signal.pidfd_send_signal(f.pidfd,signal.SIGKILL);time.sleep(.02)
  c,r=f.run('--terminate',change);self.assertTrue(r['target_group_closed']);self.assertFalse(r['explicit_outside_signal_sent']);self.assertEqual(f.child.wait(timeout=2),-signal.SIGKILL)
 def test_same_binary_nonleader_exec_during_acquisition_refuses(self):
  f=self.fixture();once=[]
  def change(stage,p):
   if stage=='leader-seized'and not once:
    f.command_byte('E');time.sleep(.02);once.append(True)
  c,r=f.run('--terminate',change);self.assertIn(c,[1,124]);self.assertFalse(r['sigterm_queued']);f.wait_event('E');self.assertEqual(process_start(f.child.pid),f.start);f.alive_untraced()
 def test_same_binary_exec_cannot_run_while_all_held(self):
  f=self.fixture();proof=[]
  def change(stage,p):
   if stage=='after-acquire':f.command_byte('E');f.pump(.03);self.assertFalse(any(x[0]=='E'for x in f.events));proof.append(True)
  c,r=f.run(action=change);self.assertEqual(c,0);self.assertTrue(proof);f.wait_event('E');f.alive_untraced()
 def test_raw_untraced_same_group_thread_is_counted(self):
  f=self.fixture();f.command_byte('I');f.wait_event('I');c,r=f.run();self.assertEqual(c,0);self.assertGreaterEqual(r['retained_task_count'],3);self.assertTrue(r['target_group_closed']);f.alive_untraced()
 def test_pthread_churn_never_silently_drops_exit(self):
  for _ in range(4):
   f=self.fixture('churn');c,r=f.run();self.assertFalse(r['sigterm_queued']);self.assertTrue((c==0 and r['target_group_closed'])or(c==1 and r['status']=='refused'));f.alive_untraced()
 def test_raw_untraced_thread_churn_never_misses_running_producer(self):
  for _ in range(4):
   f=self.fixture('untraced-churn');c,r=f.run();self.assertFalse(r['sigterm_queued']);self.assertTrue((c==0 and r['target_group_closed'])or(c==1 and r['status']=='refused'));f.alive_untraced()
 def test_outside_clone_event_refuses_no_outside_signal(self):
  f=self.fixture();once=[]
  def change(stage,p):
   if stage=='thread-seized'and not once:f.command_byte('C');time.sleep(.02);once.append(True)
  c,r=f.run('--terminate',change);self.assertEqual(c,1);self.assertFalse(r['sigterm_queued']);self.assertTrue(r['observed_outside_relation_caused_refusal']);self.assertFalse(r['explicit_outside_signal_sent']);f.wait_event('O');f.alive_untraced()
 def test_hidden_ptrace_untraced_outside_relation_honestly_unobserved(self):
  f=self.fixture();once=[]
  def change(stage,p):
   if stage=='thread-seized'and not once:f.command_byte('H');time.sleep(.03);once.append(True)
  c,r=f.run('--probe',change);self.assertEqual(c,0);self.assertFalse(r['sigterm_queued']);self.assertFalse(r['observed_outside_relation_caused_refusal']);self.assertFalse(r['outside_relationship_inventory_exhaustive']);f.wait_event('O');f.alive_untraced()
  for pid in f.extra:self.assertEqual(int(proc_status(pid)['TracerPid']),0)
 def test_hidden_outside_autochild_survives_only_positive_target_term(self):
  f=self.fixture();once=[]
  def change(stage,p):
   if stage=='thread-seized'and not once:f.command_byte('H');time.sleep(.03);once.append(True)
  c,r=f.run('--terminate',change);self.assertTrue(r['sigterm_queued']);self.assertFalse(r['explicit_outside_signal_sent']);self.assertFalse(r['outside_relationship_inventory_exhaustive']);f.wait_event('O');self.assertEqual(f.child.wait(timeout=2),-signal.SIGTERM);self.assertTrue(f.extra)
  for pid in f.extra:self.assertEqual(int(proc_status(pid)['TracerPid']),0);self.assertNotIn(proc_status(pid)['State'].strip()[0],['Z','X'])
 def test_futex_sleep_requires_actual_event(self):
  f=self.fixture('futex');event=f.wait_event('W');end=time.monotonic()+1
  while time.monotonic()<end:
   raw=Path('/proc/'+str(event[2])+'/syscall').read_text().split()
   if raw and raw[0]=='202':break
   time.sleep(.001)
  self.assertTrue(raw and raw[0]=='202');c,r=f.run();self.assertEqual(c,0);self.assertGreaterEqual(r['acquisition_event_count'],3);f.alive_untraced()
 def test_vfork_wait_is_not_accepted_as_stop(self):
  f=self.fixture();f.command_byte('V');f.wait_event('O');started=time.monotonic();c,r=f.run('--terminate');elapsed=time.monotonic()-started;self.assertIn(c,[1,124]);self.assertFalse(r['sigterm_queued']);self.assertLess(elapsed,5);f.command_byte('Q');f.wait_event('B');f.alive_untraced()
 def test_inherited_sigchld_ignore_nocldwait_is_reset(self):
  f=self.fixture();c,r=f.run(launcher='ignored');self.assertEqual(c,0);self.assertTrue(r['target_group_closed']);f.alive_untraced()
 def test_self_restricted_fixture_policy_refuses_no_relaxation(self):
  f=self.fixture();c,r=f.run('--terminate',launcher='deny');self.assertEqual(c,1);self.assertEqual(r['reason'],'seize_refused_no_policy_change');self.assertFalse(r['sigterm_queued']);f.alive_untraced()
 def test_task_limit_refuses_before_group_control(self):
  f=self.fixture('many');c,r=f.run('--terminate');self.assertEqual(c,1);self.assertFalse(r['sigterm_queued']);self.assertEqual(r['retained_task_count'],0);f.alive_untraced()
 def test_request_duplicates_nuls_extra_and_expiry_refuse(self):
  for suffix in [b'\0ignored',b'foreign=1\n',b'\n']:
   f=self.fixture();f.request.write_bytes(f.request.read_bytes()+suffix);c,r=f.run('--terminate');self.assertEqual(c,1);self.assertFalse(r['sigterm_queued']);f.alive_untraced()
  f=self.fixture();f.values['checked_at']-=121;f.values['valid_until']-=121;f.save();c,r=f.run('--terminate');self.assertEqual(c,1);self.assertFalse(r['sigterm_queued']);f.alive_untraced()
 def test_hidden_outside_relation_unobserved_cleanup_without_parent_event(self):
  p=subprocess.run([str(Path(__file__).with_name('build')/'nebula-member-hidden-relation-fixture')],stdin=subprocess.DEVNULL,capture_output=True,timeout=12);self.assertEqual(p.returncode,0,p.stderr);r=json.loads(p.stdout);self.assertEqual(r['status'],'passed');self.assertTrue(r['parent_clone_event_absent']);self.assertTrue(r['outside_auto_relationship_never_waited_or_detached']);self.assertTrue(r['kernel_tracer_exit_unlinked_both']);self.assertTrue(r['both_inert_children_exited_normally']);self.assertFalse(r['numeric_sigterm_sent']);self.assertFalse(r['zero_wait_implies_unscheduled_claimed'])
 def test_full_stdout_cannot_block_normal_cleanup_unknown_relation(self):
  f=self.fixture();once=[]
  def change(stage,p):
   if stage=='thread-seized'and not once:f.command_byte('H');time.sleep(.02);once.append(True)
  before=time.monotonic();c,r=f.run('--probe',change,blocked_stdout=True);self.assertEqual(c,124);self.assertLess(time.monotonic()-before,2.5);self.assertTrue(r['fixture_driver_observation_only']);f.wait_event('O');f.alive_untraced()
  for pid in f.extra:self.assertEqual(int(proc_status(pid)['TracerPid']),0)
 def test_full_stdout_cannot_block_acquisition_watchdog_exit(self):
  f=self.fixture();once=[]
  def change(stage,p):
   if stage=='leader-seized'and not once:f.command_byte('E');time.sleep(.02);once.append(True)
  before=time.monotonic();c,r=f.run('--terminate',change,blocked_stdout=True);self.assertEqual(c,124);self.assertLess(time.monotonic()-before,4.5);self.assertFalse(r['sigterm_queued']);f.wait_event('E');f.alive_untraced()
 def test_full_stdout_inherited_ignored_alarm_early_refusal_is_bounded(self):
  f=self.fixture();before=time.monotonic();c,r=f.run('--unsupported',launcher='ignored-alarm',blocked_stdout=True);self.assertEqual(c,124);self.assertLess(time.monotonic()-before,2.5);self.assertFalse(r['sigterm_queued']);f.alive_untraced()
 def test_full_stdout_inherited_blocked_alarm_still_cleans_unknown(self):
  f=self.fixture();once=[]
  def change(stage,p):
   if stage=='thread-seized'and not once:f.command_byte('H');time.sleep(.02);once.append(True)
  before=time.monotonic();c,r=f.run('--probe',change,launcher='blocked-alarm',blocked_stdout=True);self.assertEqual(c,124);self.assertLess(time.monotonic()-before,2.5);self.assertFalse(r['sigterm_queued']);f.wait_event('O');f.alive_untraced()
  for pid in f.extra:self.assertEqual(int(proc_status(pid)['TracerPid']),0)
 def test_symlink_or_writable_request_preserved(self):
  for kind in ['symlink','writable']:
   f=self.fixture()
   if kind=='symlink':f.request.rename(f.receipt/'retained');f.request.symlink_to(f.receipt/'retained')
   else:f.request.chmod(0o620)
   c,r=f.run('--terminate');self.assertEqual(c,1);self.assertFalse(r['sigterm_queued']);f.alive_untraced()
if __name__=='__main__':
 assert os.geteuid()==0
 subprocess.run(['gcc','-std=c11','-Wall','-Wextra','-Werror','-O2','-DNEBULA_THREAD_STOP_FIXTURE','-o',str(HELPER),str(SOURCE)],check=True)
 lib=ctypes.CDLL(None,use_errno=True);old=ctypes.c_int();assert lib.prctl(37,ctypes.byref(old),0,0,0)==0;assert lib.prctl(36,1,0,0,0)==0
 try:program=unittest.main(exit=False)
 finally:
  assert lib.prctl(36,old.value,0,0,0)==0
  (Path(__file__).with_name('build')/'fixture-runs.json').write_text(json.dumps({'fixture_directories':ALL,'all_targets_fresh_inert_own_c_tasks':True,'no_remote_or_fabric_or_production_targets':True,'files_retained_for_review':True},indent=2)+'\n')

 raise SystemExit(0 if program.result.wasSuccessful() else 1)

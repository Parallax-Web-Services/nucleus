#!/usr/bin/env python3
import importlib.util,json,os,stat,sys,tempfile,unittest
from pathlib import Path
from unittest.mock import patch
spec=importlib.util.spec_from_file_location('backup_common','/tmp/nebula-backup-common.py');m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
class CommonTests(unittest.TestCase):
 def setUp(self):
  self.temp=tempfile.TemporaryDirectory(prefix='nebula-backup-unit-',dir='/root');self.base=Path(self.temp.name);os.chmod(self.base,0o700)
 def tearDown(self):self.temp.cleanup()
 def test_exclusive_never_overwrites(self):
  p=self.base/'file';m.exclusive(p,b'owned')
  with self.assertRaises(FileExistsError):m.exclusive(p,b'foreign')
  self.assertEqual(p.read_bytes(),b'owned')
 def test_private_read_refuses_permissions_and_links(self):
  p=self.base/'file';p.write_bytes(b'fixture');os.chmod(p,0o644)
  with self.assertRaises(m.Refused):m.read(p)
  link=self.base/'link';link.symlink_to(p)
  with self.assertRaises(m.Refused):m.read(link,private=False)
 def test_same_inode_changed_file_is_not_adopted(self):
  p=self.base/'file';m.exclusive(p,b'first');old=m.read(p)
  p.write_bytes(b'other');self.assertNotEqual(m.read(p),old)
 def test_pinned_fd_detects_replacement(self):
  p=self.base/'file';m.exclusive(p,b'original')
  with self.assertRaises(m.Refused):
   with m.pinned(p,100,True):
    q=self.base/'new';m.exclusive(q,b'original');q.replace(p)
 def test_new_dir_requires_absent(self):
  p=self.base/'new';m.new_dir(p)
  with self.assertRaises(m.Refused):m.new_dir(p)
 def test_parent_world_write_rejected(self):
  p=self.base/'unsafe';p.mkdir(mode=0o777);os.chmod(p,0o777)
  with self.assertRaises(m.Refused):m.new_dir(p/'child')
 def test_journal_survives_owned_receipt_subdirectory(self):
  j=m.Journal(self.base,['state-a.json','state-b.json']);j.append('state-a.json',{'value':1})
  m.new_dir(self.base/'command-private');j.guard();j.append('state-b.json',{'value':2})
  self.assertEqual(j.get('state-a.json')['value'],1)
 def test_journal_unknown_control_preserved(self):
  j=m.Journal(self.base,['state-a.json']);m.exclusive(self.base/'state-foreign.json',b'foreign')
  with self.assertRaises(m.Refused):j.append('state-a.json',{'v':1})
  self.assertEqual((self.base/'state-foreign.json').read_bytes(),b'foreign')
 def test_journal_changed_control_preserved(self):
  j=m.Journal(self.base,['state-a.json','state-b.json']);j.append('state-a.json',{'v':1})
  path=self.base/'state-a.json';path.write_bytes(b'foreign')
  with self.assertRaises(m.Refused):j.append('state-b.json',{'v':2})
  self.assertEqual(path.read_bytes(),b'foreign');self.assertFalse((self.base/'state-b.json').exists())
 def test_journal_reserved_field_rejected(self):
  j=m.Journal(self.base,['state-a.json'])
  with self.assertRaises(m.Refused):j.append('state-a.json',{'journal_directory':'foreign'})
 def test_postwrite_replacement_not_adopted(self):
  j=m.Journal(self.base,['state-a.json']);original=m.exclusive
  def replace(path,raw,*args):
   expected=original(path,raw,*args);p=self.base/'replacement';original(p,raw);p.replace(path);return expected
  with patch.object(m,'exclusive',side_effect=replace):
   with self.assertRaises(m.Refused):j.append('state-a.json',{'v':1})
  self.assertNotIn('state-a.json',j.records)
 def test_command_output_stays_private(self):
  out=m.command(self.base,[sys.executable,'-c','print("synthetic-sensitive-fixture")'],'synthetic-output')
  self.assertEqual(out,b'synthetic-sensitive-fixture\n')
  dirs=list(self.base.glob('command-*'));self.assertEqual(len(dirs),1)
  for p in dirs[0].iterdir():self.assertEqual(stat.S_IMODE(p.stat().st_mode),0o600)
  self.assertEqual((dirs[0]/'stdout').read_bytes(),out)
 def test_child_output_file_limit_enforced(self):
  p=self.base/'bounded-output';fd=m.new_output(p)
  try:
   try:m.command(self.base,[sys.executable,'-c','import os;os.write(1,b"x"*8192)'],'synthetic-bound',stdout_fd=fd,file_limit=1024)
   except m.Refused:pass
  finally:os.close(fd)
  self.assertLessEqual(p.stat().st_size,1024)
 def test_timeout_retains_private_receipt(self):
  with self.assertRaisesRegex(m.Refused,'command_timeout_private_receipt'):m.command(self.base,[sys.executable,'-c','import time;time.sleep(10)'],'synthetic-timeout',timeout=0.1)
  receipt=next(self.base.glob('command-*'));meta=json.loads((receipt/'metadata.json').read_bytes());self.assertTrue(meta['timed_out'])
 def test_policy_hash_is_fixed(self):
  p=self.base/'nebula-backup-envelope-policy.py';m.exclusive(p,Path('/tmp/nebula-backup-envelope-policy.py').read_bytes())
  with patch.object(m,'__file__',str(self.base/'nebula-backup-common.py')):self.assertEqual(m.policy().TARGETS,('Tarragon','Slipstream'))
 def test_mismatched_public_source_not_executed(self):
  p=self.base/'module.py';m.exclusive(p,b'raise RuntimeError("must-not-run")')
  with self.assertRaisesRegex(m.Refused,'public_source_pin'):m.load_module(p,'must_not_load','0'*64)

class StreamingCaptureTests(unittest.TestCase):
 setUp=CommonTests.setUp
 tearDown=CommonTests.tearDown
 def test_hostile_output_is_bounded_head_tail_and_small_return_refused(self):
  code='import os;os.write(1,b"H"+b"x"*(5*1024*1024)+b"T");os.write(2,b"A"+b"y"*(5*1024*1024)+b"Z")'
  with self.assertRaisesRegex(m.Refused,'command_stdout_return_bound'):m.command(self.base,[sys.executable,'-c',code],'hostile-output')
  receipt=next(self.base.glob('command-*'));v=json.loads((receipt/'metadata.json').read_bytes())
  for name,head,tail in [('stdout',b'H',b'T'),('stderr',b'A',b'Z')]:
   raw=(receipt/name).read_bytes();self.assertEqual(len(raw),2*1024**2);self.assertTrue(raw.startswith(head));self.assertTrue(raw.endswith(tail));self.assertTrue(v['streams'][name]['truncated'])
  self.assertTrue(v['owned_command_reaped'])
 def test_stderr_can_be_drained_without_unbounded_parent_return(self):
  code='import os;os.write(2,b"x"*(5*1024*1024));os.write(1,b"small")'
  out=m.command(self.base,[sys.executable,'-c',code],'large-stderr');self.assertEqual(out,b'small')
  receipt=next(self.base.glob('command-*'));self.assertEqual((receipt/'stderr').stat().st_size,2*1024**2)
 def test_ignored_term_timeout_kills_and_reaps_exact_child(self):
  code='import signal,time;signal.signal(signal.SIGTERM,signal.SIG_IGN);print("ready",flush=True);time.sleep(20)'
  with self.assertRaisesRegex(m.Refused,'command_timeout_private_receipt'):m.command(self.base,[sys.executable,'-c',code],'ignored-term',timeout=0.2)
  receipt=next(self.base.glob('command-*'));v=json.loads((receipt/'metadata.json').read_bytes());self.assertTrue(v['owned_command_reaped']);self.assertLess(v['returncode'],0);self.assertTrue(v['timed_out'])
 def test_capture_exception_also_reaps_owned_child(self):
  import time
  process=[];original=m.subprocess.Popen;original_select=m.selectors.DefaultSelector
  def spawn(*a,**k):v=original(*a,**k);process.append(v);return v
  class Broken:
   def __init__(self):self.inner=original_select()
   def __getattr__(self,n):return getattr(self.inner,n)
   def select(self,*a,**k):time.sleep(0.15);raise RuntimeError('synthetic_capture_failure')
  code='import signal,time;signal.signal(signal.SIGTERM,signal.SIG_IGN);time.sleep(20)'
  with patch.object(m.subprocess,'Popen',side_effect=spawn),patch.object(m.selectors,'DefaultSelector',Broken):
   with self.assertRaisesRegex(RuntimeError,'synthetic_capture_failure'):m.command(self.base,[sys.executable,'-c',code],'capture-error',timeout=10)
  self.assertIsNotNone(process[0].returncode);receipt=next(self.base.glob('command-*'));self.assertTrue(json.loads((receipt/'metadata.json').read_bytes())['owned_command_reaped'])

class OwnedGroupAndRestoreProfileTests(unittest.TestCase):
 setUp=CommonTests.setUp
 tearDown=CommonTests.tearDown
 def test_exited_leader_forked_writer_is_cleaned_before_reap(self):
  code='import os,signal,time\np=os.fork()\nif p:\n os._exit(0)\nsignal.signal(signal.SIGTERM,signal.SIG_IGN)\nwhile True:\n os.write(1,b"x"*4096)\n time.sleep(0.01)\n'
  with self.assertRaisesRegex(m.Refused,'command_timeout_private_receipt'):m.command(self.base,[sys.executable,'-c',code],'forked-pipe-writer',timeout=0.2)
  receipt=next(self.base.glob('command-*'));v=json.loads((receipt/'metadata.json').read_bytes());self.assertTrue(v['owned_command_reaped']);self.assertTrue(v['timed_out']);self.assertLess(v['duration_seconds'],12)
 def test_non_utf8_owned_process_name_does_not_break_cleanup(self):
  code='import ctypes;ctypes.CDLL(None).prctl(15,b"\\xffowned-fixture",0,0,0);print("ready")'
  self.assertEqual(m.command(self.base,[sys.executable,'-c',code],'non-utf8-child'),b'ready\n')
 def test_restore_profile_file_map_and_private_data_bound(self):
  import textwrap
  p=self.base/'tiny-readonly-file';m.exclusive(p,b'\0'*4096)
  code=textwrap.dedent('''
   import ctypes,errno,os,resource,sys
   lib=ctypes.CDLL(None,use_errno=True);lib.mmap.restype=ctypes.c_void_p
   lib.mmap.argtypes=[ctypes.c_void_p,ctypes.c_size_t,ctypes.c_int,ctypes.c_int,ctypes.c_int,ctypes.c_long]
   lib.munmap.argtypes=[ctypes.c_void_p,ctypes.c_size_t]
   invalid=ctypes.c_void_p(-1).value
   assert resource.getrlimit(resource.RLIMIT_AS)==(16*1024**3,16*1024**3)
   assert resource.getrlimit(resource.RLIMIT_DATA)==(2*1024**3,2*1024**3)
   assert os.environ.get('GOMEMLIMIT')=='1GiB'
   a=lib.mmap(None,10*1024**3,1,1,int(sys.argv[1]),0)
   assert a!=invalid
   assert lib.munmap(a,10*1024**3)==0
   b=lib.mmap(None,3*1024**3,3,2|32,-1,0)
   assert b==invalid and ctypes.get_errno()==errno.ENOMEM
   print('bounded-profile-probe-passed')
  ''')
  with m.pinned(p,4096,True) as (fd,meta):
   out=m.command(self.base,[sys.executable,'-c',code,str(fd)],'restore-resource-probe',pass_fds=(fd,),address_limit=16*1024**3,execution_profile='etcd-restore')
  self.assertEqual(out,b'bounded-profile-probe-passed\n');self.assertEqual(p.stat().st_size,4096)
 def test_restore_profile_cannot_be_arbitrary_numeric_limit(self):
  for limit in [4*1024**3,32*1024**3]:
   with self.assertRaises(m.Refused):m.command(self.base,[sys.executable,'-c','pass'],'bad-profile',execution_profile='etcd-restore',address_limit=limit)
 def test_restore_profile_memory_admission_refuses_before_process(self):
  original=Path.read_text
  def text(path,*a,**k):return 'MemAvailable: 1024 kB\n' if str(path)=='/proc/meminfo' else original(path,*a,**k)
  with patch.object(Path,'read_text',text),patch.object(m.subprocess,'Popen',side_effect=AssertionError('must-not-spawn')):
   with self.assertRaisesRegex(m.Refused,'restore_memory_admission_failed'):m.command(self.base,[sys.executable,'-c','pass'],'low-memory',execution_profile='etcd-restore',address_limit=16*1024**3)


class HeldInputAndControllerTests(unittest.TestCase):
 setUp=CommonTests.setUp
 tearDown=CommonTests.tearDown
 def test_held_private_stdin_not_buffered_or_closed_by_runner(self):
  path=self.base/'input';m.exclusive(path,b'synthetic-input')
  with m.pinned(path,100,True) as (fd,meta):
   out=m.command(self.base,[sys.executable,'-c','import sys;sys.stdout.buffer.write(sys.stdin.buffer.read())'],'held-input',stdin_fd=fd)
   self.assertEqual(out,b'synthetic-input');self.assertEqual(m.ident(os.fstat(fd)),meta)
 def test_stdin_bytes_and_fd_mutually_exclusive(self):
  p=self.base/'input';m.exclusive(p,b'x')
  with m.pinned(p,10,True) as (fd,_):
   with self.assertRaises(m.Refused):m.command(self.base,[sys.executable,'-c','pass'],'bad-input',stdin_fd=fd,input_bytes=b'x')
 def test_binary_stdout_requires_owned_regular_not_pipe(self):
  r,w=os.pipe()
  try:
   with self.assertRaisesRegex(m.Refused,'exclusive_regular_stdout_fd_required'):m.command(self.base,[sys.executable,'-c','pass'],'bad-output',stdout_fd=w)
  finally:os.close(r);os.close(w)
 def test_producer_starts_only_after_child_exec_owned_identity(self):
  import threading
  r,w=os.pipe2(os.O_CLOEXEC);threads=[];process=[];original=m.subprocess.Popen
  def spawn(*a,**k):p=original(*a,**k);process.append(p);return p
  def start():
   self.assertTrue(hasattr(process[0],'_backup_start_ticks'))
   self.assertTrue((Path('/proc')/str(process[0].pid)/'exe').exists())
   def produce():
    try:os.write(w,b'pipe-fixture')
    finally:os.close(w)
   t=threading.Thread(target=produce);threads.append(t);t.start()
  try:
   with patch.object(m.subprocess,'Popen',side_effect=spawn):
    out=m.command(self.base,[sys.executable,'-c','import sys;sys.stdout.buffer.write(sys.stdin.buffer.read())'],'post-exec-producer',stdin_fd=r,on_start=start)
   self.assertEqual(out,b'pipe-fixture')
  finally:
   os.close(r)
   for t in threads:t.join(timeout=2);self.assertFalse(t.is_alive())
 def test_explicit_local_controller_receipts_owned_by_current_user(self):
  code=r'''
import importlib.util,os,tempfile
from pathlib import Path
s=importlib.util.spec_from_file_location('c','/tmp/nebula-backup-common.py');m=importlib.util.module_from_spec(s);s.loader.exec_module(m)
with tempfile.TemporaryDirectory(prefix='nebula-user-command-') as d:
 p=Path(d);p.chmod(0o700)
 try:m.command(p,['/usr/bin/true'],'root-default')
 except m.Refused:pass
 else:raise AssertionError('root default unexpectedly accepted user path')
 result=m.command(p,['/usr/bin/printf','controller-ok'],'user-command',local_controller=True)
 assert result==b'controller-ok'
 for path in p.glob('command-*/*'):assert path.stat().st_uid==os.getuid() and path.stat().st_mode&0o777==0o600
 print('passed')
'''
  import subprocess
  r=subprocess.run([sys.executable,'-c',code],stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=10,preexec_fn=lambda:(os.setgid(1000),os.setuid(1000)))
  self.assertEqual(r.returncode,0);self.assertEqual(r.stdout,b'passed\n')

if __name__=='__main__':unittest.main()


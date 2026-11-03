#!/usr/bin/env python3
"""Shared source-only NEBULA initial-backup primitives. No standalone operations."""
from __future__ import annotations
import contextlib,hashlib,json,os,re,resource,selectors,signal,stat,subprocess,tempfile,time,types,sys
from pathlib import Path
ENV={'PATH':'/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin','LANG':'C.UTF-8','LC_ALL':'C.UTF-8'}
POLICY_SHA='c34deff89a5ddac75f1a01ae84e114fa004bc54edeee97d23d8f722990884ee7'
class Refused(RuntimeError):pass
def need(ok,code):
 if not ok:raise Refused(code)
def sha(raw):return hashlib.sha256(raw).hexdigest()
def ident(s):return [s.st_dev,s.st_ino,s.st_mode,s.st_uid,s.st_gid,s.st_nlink,s.st_size,s.st_mtime_ns,s.st_ctime_ns]
def canonical(path):
 need(path.is_absolute() and path.resolve()==path,'canonical_path_required');return path
def parent_safe(path):
 canonical(path)
 for p in [path,*path.parents]:
  s=p.lstat();need(stat.S_ISDIR(s.st_mode) and s.st_uid==0 and stat.S_IMODE(s.st_mode)&0o022==0,'unsafe_directory_ancestor')
def private_dir(path):
 canonical(path);s=path.lstat();need(stat.S_ISDIR(s.st_mode) and s.st_uid==0 and s.st_gid==0 and stat.S_IMODE(s.st_mode)==0o700,'private_directory_required')
def new_dir(path):
 parent_safe(path.parent);need(not os.path.lexists(path),'exclusive_directory_required');path.mkdir(mode=0o700);private_dir(path);return ident(path.lstat())[:5]
def regular_fd(path,limit,private=False):
 canonical(path);fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC);s=os.fstat(fd)
 try:
  need(stat.S_ISREG(s.st_mode) and s.st_uid==0 and s.st_gid==0 and s.st_nlink==1 and s.st_size<=limit and stat.S_IMODE(s.st_mode)&0o022==0,'unsafe_regular_file')
  if private:need(stat.S_IMODE(s.st_mode)==0o600,'private_file_required')
  need(ident(path.lstat())==ident(s),'input_identity_changed');return fd,ident(s)
 except BaseException:os.close(fd);raise
@contextlib.contextmanager
def pinned(path,limit,private=False):
 fd,before=regular_fd(path,limit,private)
 try:
  yield fd,before
  need(ident(os.fstat(fd))==before==ident(path.lstat()),'input_changed')
 finally:os.close(fd)
def read(path,limit=2*1024**2,private=True):
 with pinned(path,limit,private) as (fd,meta):
  raw=b''
  while True:
   b=os.read(fd,65536)
   if not b:break
   raw+=b;need(len(raw)<=limit,'input_size_bound')
  return raw,{'identity':meta,'sha256':sha(raw)}
def exclusive(path,raw,mode=0o600):
 need(type(raw) is bytes,'byte_payload_required');canonical(path.parent);private_dir(path.parent)
 fd=os.open(path,os.O_CREAT|os.O_EXCL|os.O_WRONLY|os.O_NOFOLLOW|os.O_CLOEXEC,mode)
 try:
  view=memoryview(raw)
  while view:
   n=os.write(fd,view);need(n>0,'short_file_write');view=view[n:]
  os.fsync(fd);expected=ident(os.fstat(fd));need(expected==ident(path.lstat()) and expected[6]==len(raw),'exclusive_postimage_changed');return expected
 finally:os.close(fd)
def new_output(path,mode=0o600):
 private_dir(path.parent);return os.open(path,os.O_CREAT|os.O_EXCL|os.O_RDWR|os.O_NOFOLLOW|os.O_CLOEXEC,mode)
def load_module(path,name,pin):
 raw,_=read(path,2*1024**2,private=False);need(sha(raw)==pin,'public_source_pin')
 m=types.ModuleType(name);m.__file__=str(path);sys.modules[name]=m
 try:exec(compile(raw,str(path),'exec'),m.__dict__)
 except BaseException:sys.modules.pop(name,None);raise
 return m
def policy():
 return load_module(Path(__file__).with_name('nebula-backup-envelope-policy.py'),'_backup_envelope_policy',POLICY_SHA)
def operation_id(value):
 need(type(value) is str and re.fullmatch('[a-f0-9]{32}',value),'operation_id_required');return value
def json_bytes(value):return (json.dumps(value,sort_keys=True,separators=(',',':'))+'\n').encode()
class Journal:
 def __init__(self,work,allowed):
  private_dir(work);self.work=work;self.directory=ident(work.lstat())[:5];self.allowed=set(allowed);self.records={}
  names={p.name for p in work.glob('state-*.json')};need(names<=self.allowed,'unknown_state_record')
  for name in sorted(names):
   raw,meta=read(work/name);v=json.loads(raw);need(v.get('journal_directory')==self.directory,'journal_directory_changed');self.records[name]=(raw,meta,v)
 def guard(self):
  private_dir(self.work);need(ident(self.work.lstat())[:5]==self.directory,'journal_directory_changed')
  need({p.name for p in self.work.glob('state-*.json')}==set(self.records),'journal_inventory_changed')
  for n,(raw,meta,_) in self.records.items():need(read(self.work/n)==(raw,meta),'journal_record_changed')
 def append(self,name,value):
  self.guard();need(name in self.allowed and name not in self.records,'state_append_only')
  need('journal_directory' not in value,'reserved_journal_field');v={**value,'journal_directory':self.directory};raw=json_bytes(v);expected=exclusive(self.work/name,raw);actual,meta=read(self.work/name)
  need(actual==raw and meta['identity']==expected,'state_postimage_changed');self.records[name]=(raw,meta,v);self.guard();return v
 def get(self,name):self.guard();need(name in self.records,'required_state_missing');return self.records[name][2]
def _command_directory(path,uid,gid):
 canonical(path);s=path.lstat()
 need(stat.S_ISDIR(s.st_mode) and s.st_uid==uid and s.st_gid==gid and stat.S_IMODE(s.st_mode)==0o700,'private_command_directory_required')
def _command_file(path,raw,uid,gid):
 _command_directory(path.parent,uid,gid);fd=os.open(path,os.O_CREAT|os.O_EXCL|os.O_WRONLY|os.O_NOFOLLOW|os.O_CLOEXEC,0o600)
 try:
  view=memoryview(raw)
  while view:
   n=os.write(fd,view);need(n>0,'short_command_receipt_write');view=view[n:]
  os.fsync(fd);s=os.fstat(fd);need(s.st_uid==uid and s.st_gid==gid and ident(s)==ident(path.lstat()) and s.st_size==len(raw),'command_receipt_postimage_changed')
 finally:os.close(fd)
class _Capture:
 def __init__(self,limit=2*1024**2):self.limit=limit;self.head=bytearray();self.tail=bytearray();self.total=0
 def feed(self,raw):
  self.total+=len(raw);room=self.limit//2-len(self.head);self.head.extend(raw[:room]);rest=raw[room:]
  if rest:self.tail=(self.tail+rest)[-self.limit//2:]
 def value(self):return bytes(self.head+self.tail)
 def metadata(self):return {'original_bytes':self.total,'stored_bytes':len(self.head)+len(self.tail),'truncated':self.total>self.limit,'format':'head-tail' if self.total>self.limit else 'whole'}
def _child_identity(process):
 raw=(Path('/proc')/str(process.pid)/'stat').read_bytes().rsplit(b') ',1)[1].split()
 need(raw[2]==str(process.pid).encode() and raw[3]==str(process.pid).encode(),'owned_session_identity_changed')
 return raw[19].decode('ascii')
def _observe_owned(process):
 """Observe without reaping: reserve leader PID/session ID until its group is cleaned."""
 need(process.returncode is None,'owned_leader_reaped_before_group_cleanup')
 try:result=os.waitid(os.P_PID,process.pid,os.WEXITED|os.WNOHANG|os.WNOWAIT)
 except ChildProcessError:raise Refused('owned_child_waitability_lost') from None
 need(_child_identity(process)==process._backup_start_ticks,'owned_child_identity_changed')
 return result is not None
def _living_group(process):
 # The unreaped leader reserves this PID/group ID; unrelated sessions cannot reuse it.
 _observe_owned(process);result=[]
 for entry in Path('/proc').iterdir():
  if not entry.name.isdecimal():continue
  try:
   fields=(entry/'stat').read_bytes().rsplit(b') ',1)[1].split()
   if fields[2]==str(process.pid).encode() and fields[3]==str(process.pid).encode() and fields[0] not in [b'Z',b'X']:result.append(int(entry.name))
  except (FileNotFoundError,ProcessLookupError,PermissionError):pass
 return result
def _stop_owned(process):
 """Clean only the new session/group WHILE its leader is still waitable, then reap."""
 if process is None or getattr(process,'_backup_cleanup_complete',False):return
 _observe_owned(process)
 try:os.killpg(process.pid,signal.SIGTERM)
 except ProcessLookupError:pass
 deadline=time.monotonic()+5
 while _living_group(process) and time.monotonic()<deadline:time.sleep(0.05)
 if _living_group(process):
  try:os.killpg(process.pid,signal.SIGKILL)
  except ProcessLookupError:pass
  deadline=time.monotonic()+5
  while _living_group(process) and time.monotonic()<deadline:time.sleep(0.05)
 need(not _living_group(process),'owned_group_cleanup_timeout')
 process.wait(timeout=5);process._backup_cleanup_complete=True
def command(work,args,label,timeout=60,input_bytes=None,stdout_fd=None,pass_fds=(),file_limit=1024**3,address_limit=2*1024**3,execution_profile='ordinary',stdin_fd=None,local_controller=False,on_start=None):
 """Bounded head/tail capture; small stdout return only. Binary output uses held stdout_fd."""
 need(on_start is None or callable(on_start),'trusted_start_callback_required')
 need(type(local_controller) is bool,'typed_local_controller_flag')
 owner_uid=os.geteuid() if local_controller else 0;owner_gid=os.getegid() if local_controller else 0
 need(stdin_fd is None or type(stdin_fd) is int and stdin_fd>=3 and input_bytes is None,'held_stdin_fd_required')
 if stdin_fd is not None:
  f=os.fstat(stdin_fd);need((stat.S_ISREG(f.st_mode) or stat.S_ISFIFO(f.st_mode)) and f.st_uid==owner_uid and f.st_gid==owner_gid and stat.S_IMODE(f.st_mode)&0o077==0,'stdin_fd_custody')
 if stdout_fd is not None:
  f=os.fstat(stdout_fd);need(stat.S_ISREG(f.st_mode) and f.st_uid==owner_uid and f.st_gid==owner_gid and f.st_nlink==1 and stat.S_IMODE(f.st_mode)&0o022==0 and f.st_size==0,'exclusive_regular_stdout_fd_required')
 need(execution_profile in ['ordinary','etcd-restore'],'reviewed_execution_profile_required')
 if execution_profile=='etcd-restore':
  need(address_limit==16*1024**3,'fixed_restore_virtual_budget_required')
  memory=next((int(line.split()[1])*1024 for line in Path('/proc/meminfo').read_text().splitlines() if line.startswith('MemAvailable:')),0)
  need(memory>=6*1024**3,'restore_memory_admission_failed')
 else:need(address_limit in [768*1024**2,2*1024**3],'reviewed_child_address_limit_required')
 need(type(timeout) in [int,float] and 0<timeout<=600 and type(file_limit) is int and 0<file_limit<=2*1024**3,'finite_command_limits_required')
 need(input_bytes is None or type(input_bytes) is bytes and len(input_bytes)<=2*1024**2,'bounded_command_input_required')
 _command_directory(work,owner_uid,owner_gid);need(re.fullmatch('[a-z0-9-]{1,64}',label),'command_label')
 receipt=Path(tempfile.mkdtemp(prefix='command-'+label+'-',dir=work));receipt.chmod(0o700);_command_directory(receipt,owner_uid,owner_gid)
 env={**ENV,'HOME':str(work)}
 if execution_profile=='etcd-restore':env['GOMEMLIMIT']='1GiB' # soft Go target; NOT a hard RSS claim
 def limits():
  resource.setrlimit(resource.RLIMIT_CORE,(0,0));resource.setrlimit(resource.RLIMIT_FSIZE,(file_limit,file_limit));resource.setrlimit(resource.RLIMIT_AS,(address_limit,address_limit))
  if execution_profile=='etcd-restore':resource.setrlimit(resource.RLIMIT_DATA,(2*1024**3,2*1024**3))
 started=time.monotonic();deadline=started+timeout;process=None;timed=False;error=None;capture={'stdout':_Capture(),'stderr':_Capture()};sel=selectors.DefaultSelector()
 try:
  process=subprocess.Popen(args,env=env,stdin=stdin_fd if stdin_fd is not None else subprocess.PIPE if input_bytes is not None else subprocess.DEVNULL,stdout=subprocess.PIPE if stdout_fd is None else stdout_fd,stderr=subprocess.PIPE,pass_fds=pass_fds,preexec_fn=limits,start_new_session=True)
  process._backup_start_ticks=_child_identity(process)
  if on_start is not None:on_start()
  for name in ['stdout','stderr']:
   stream=getattr(process,name)
   if stream is not None:os.set_blocking(stream.fileno(),False);sel.register(stream,selectors.EVENT_READ,name)
  pending=memoryview(input_bytes or b'')
  if process.stdin is not None:
   if pending:os.set_blocking(process.stdin.fileno(),False);sel.register(process.stdin,selectors.EVENT_WRITE,'stdin')
   else:process.stdin.close()
  while sel.get_map() or not _observe_owned(process):
   if time.monotonic()>=deadline:
    timed=True;_stop_owned(process)
    # Drain only already produced bytes after the exact owned child was reaped.
    drain_deadline=time.monotonic()+1
    while sel.get_map() and time.monotonic()<drain_deadline:
     ready=sel.select(0)
     if not ready:break
     for key,_ in ready:
      if key.data=='stdin':sel.unregister(key.fileobj);key.fileobj.close();continue
      try:raw=os.read(key.fileobj.fileno(),65536)
      except BlockingIOError:continue
      if raw:capture[key.data].feed(raw)
      else:sel.unregister(key.fileobj);key.fileobj.close()
    break
   for key,_ in sel.select(min(0.1,max(0,deadline-time.monotonic()))):
    if key.data=='stdin':
     try:n=os.write(key.fileobj.fileno(),pending)
     except BlockingIOError:continue
     except BrokenPipeError:n=0;pending=memoryview(b'')
     if n:pending=pending[n:]
     if not pending:sel.unregister(key.fileobj);key.fileobj.close()
    else:
     try:raw=os.read(key.fileobj.fileno(),65536)
     except BlockingIOError:continue
     if raw:capture[key.data].feed(raw)
     else:sel.unregister(key.fileobj);key.fileobj.close()
 except BaseException as exc:
  error=exc
 finally:
  cleanup_error=None
  try:_stop_owned(process)
  except BaseException as exc:cleanup_error=exc
  for key in list(sel.get_map().values()):
   try:sel.unregister(key.fileobj);key.fileobj.close()
   except OSError:pass
  sel.close()
  if process is not None:
   for name in ['stdin','stdout','stderr']:
    stream=getattr(process,name)
    if stream is not None and not stream.closed:stream.close()
  for name,item in capture.items():_command_file(receipt/name,item.value(),owner_uid,owner_gid)
  metadata={'label':label,'returncode':process.returncode if process is not None else None,'timed_out':timed,'duration_seconds':round(time.monotonic()-started,3),'stdout_redirected_to_private_fd':stdout_fd is not None,'execution_profile':execution_profile,'address_limit_bytes':address_limit,'data_limit_bytes':2*1024**3 if execution_profile=='etcd-restore' else None,'go_memory_target_is_soft':execution_profile=='etcd-restore','streams':{k:v.metadata() for k,v in capture.items()},'owned_command_reaped':process is not None and process.returncode is not None}
  _command_file(receipt/'metadata.json',json_bytes(metadata),owner_uid,owner_gid)
  if cleanup_error is not None:raise Refused('owned_command_cleanup_failed_private_receipt') from None
 if error is not None:raise error
 need(not timed,'command_timeout_private_receipt');need(process.returncode==0,'command_failed_private_receipt')
 need(capture['stdout'].total<=capture['stdout'].limit,'command_stdout_return_bound_private_receipt')
 return capture['stdout'].value()
def require_free(parent,required):
 s=os.statvfs(parent);need(s.f_bavail*s.f_frsize>=required,'combined_capacity_gate_failed')
def safe_cli(fn):
 os.umask(0o077)
 try:fn()
 except Exception as e:
  print(json.dumps({'status':'refused','reason':str(e) if isinstance(e,Refused) and re.fullmatch('[a-z0-9_]+',str(e)) else type(e).__name__}),file=sys.stderr);raise SystemExit(1)

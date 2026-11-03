#!/usr/bin/env python3
"""SOURCE ONLY: two-target initial encrypted backup custody and offline restore.
Every mutating phase requires --execute. No service/listener or live data path is used.
Command outputs and all recovered data remain root-private. Partial attempts are retained.
"""
from __future__ import annotations
import argparse,base64,contextlib,copy,fcntl,hashlib,ipaddress,json,os,re,socket,stat,sys,tarfile,time,types,uuid
from pathlib import Path,PurePosixPath
COMMON_SHA='cd5fc702868af2e74965aa13677c691bd3eb872cdb20d5db45e0f0efe6855322'
CLUSTER_SHA='7fe61c84b6e5167be8658e66c70063463f52baa7cc0de401f9bb83257242612c'
NAMESPACES={'Tarragon':('/backup/parallax-nebula',40*1024**3),'Slipstream':('/var/lib/parallax-nebula-backups',12*1024**3)}
STATES=['state-plan.json','state-key-intent.json','state-keys.json','state-tool-intent.json','state-tool.json','state-config-intent.json','state-config.json','state-receive-intent.json','state-received.json','state-restore-intent.json','state-restored.json']
PLAIN_BOUND=656*1024**2
CRITICAL_FILES=frozenset(['snapshot.db',
 'etc/kubernetes/nebula/encryption.json','etc/kubernetes/nebula/audit-policy.json','etc/kubernetes/nebula/admission.json',
 'etc/kubernetes/manifests/etcd.yaml','etc/kubernetes/manifests/kube-apiserver.yaml','etc/kubernetes/manifests/kube-controller-manager.yaml','etc/kubernetes/manifests/kube-scheduler.yaml',
 'etc/kubernetes/admin.conf','etc/kubernetes/super-admin.conf','etc/kubernetes/kubelet.conf','var/lib/kubelet/config.yaml',
 'restore-inputs/kubeadm-config-restore.json','restore-inputs/kubelet-config-restore.json','restore-inputs/kubelet-embedded-restore.json',
 'restore-inputs/control-plane-images.lock.json','restore-inputs/calico-image-pins.json','restore-inputs/calico-3.33.0-nebula.yaml',
 'etc/kubernetes/pki/sa.key','etc/kubernetes/pki/sa.pub']+
 ['etc/kubernetes/pki/'+name+'.'+suffix for name in ['ca','apiserver','apiserver-kubelet-client','apiserver-etcd-client','front-proxy-ca','front-proxy-client'] for suffix in ['crt','key']]+
 ['etc/kubernetes/pki/etcd/'+name+'.'+suffix for name in ['ca','server','peer','healthcheck-client'] for suffix in ['crt','key']])

PROFILE_PROBE = r"""
import ctypes,errno,json,os,resource,sys
from pathlib import Path
assert sys.platform=='linux' and ctypes.sizeof(ctypes.c_void_p)==8
assert resource.getrlimit(resource.RLIMIT_AS)==(16*1024**3,16*1024**3)
assert resource.getrlimit(resource.RLIMIT_DATA)==(2*1024**3,2*1024**3)
assert os.environ.get('GOMEMLIMIT')=='1GiB'
fd=int(sys.argv[1]);st=os.fstat(fd)
assert st.st_uid==st.st_gid==0 and st.st_size==4096 and st.st_nlink==1
libc=ctypes.CDLL(None,use_errno=True)
libc.mmap.argtypes=[ctypes.c_void_p,ctypes.c_size_t,ctypes.c_int,ctypes.c_int,ctypes.c_int,ctypes.c_longlong]
libc.mmap.restype=ctypes.c_void_p
libc.munmap.argtypes=[ctypes.c_void_p,ctypes.c_size_t];libc.munmap.restype=ctypes.c_int
bad=ctypes.c_void_p(-1).value
# Reserve only virtual address space. Never dereference either mapping.
filemap=libc.mmap(None,10*1024**3,1,1,fd,0)
assert filemap!=bad
assert libc.munmap(filemap,10*1024**3)==0
ctypes.set_errno(0)
anon=libc.mmap(None,3*1024**3,3,2|32,-1,0)
if anon!=bad:
 libc.munmap(anon,3*1024**3)
 raise RuntimeError('anonymous_mapping_limit_not_enforced')
assert ctypes.get_errno()==errno.ENOMEM
print(json.dumps({'schema_version':1,'readonly_file_mapping_verified':True,'anonymous_mapping_cap_verified':True},sort_keys=True,separators=(',',':')))
"""

def memory_available(raw,m):
 m.need(type(raw) is bytes and len(raw)<=65536,'memory_metadata_bound')
 lines=[line for line in raw.splitlines() if line.startswith(b'MemAvailable:')]
 m.need(len(lines)==1 and re.fullmatch(rb'MemAvailable:\s+[0-9]+ kB',lines[0]) is not None,'memory_metadata_required')
 m.need(int(lines[0].split()[1])*1024>=6*1024**3,'restore_memory_headroom_required');return True

def load_common():
 p=Path(__file__).with_name('nebula-backup-common.py');fd=os.open(p,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC)
 try:
  s=os.fstat(fd);raw=os.read(fd,262144)
  if not(stat.S_ISREG(s.st_mode) and s.st_uid==s.st_gid==0 and s.st_nlink==1 and stat.S_IMODE(s.st_mode)&0o022==0 and len(raw)==s.st_size and hashlib.sha256(raw).hexdigest()==COMMON_SHA):raise RuntimeError('common_source_pin')
  fields=lambda z:(z.st_dev,z.st_ino,z.st_mode,z.st_uid,z.st_gid,z.st_nlink,z.st_size,z.st_mtime_ns,z.st_ctime_ns)
  if fields(s)!=fields(os.fstat(fd)) or fields(s)!=fields(p.lstat()):raise RuntimeError('common_source_changed')
 finally:os.close(fd)
 m=types.ModuleType('_nebula_target_common');m.__file__=str(p);sys.modules[m.__name__]=m;exec(compile(raw,str(p),'exec'),m.__dict__);return m

def bounded_json(raw,limit,m,code):
 m.need(type(raw) is bytes and 0<len(raw)<=limit,code)
 def pairs(items):
  result={}
  for k,v in items:
   m.need(k not in result,'duplicate_json_key');result[k]=v
  return result
 try:return json.loads(raw,object_pairs_hook=pairs,parse_constant=lambda _:m.need(False,'nonfinite_json'))
 except (ValueError,UnicodeError):raise m.Refused(code) from None

def hash_fd(fd,limit,m):
 before=m.ident(os.fstat(fd));h=hashlib.sha256();size=0;offset=0
 while True:
  chunk=os.pread(fd,min(1024**2,limit+1-size),offset)
  if not chunk:break
  size+=len(chunk);m.need(size<=limit,'bounded_input_exceeded');offset+=len(chunk);h.update(chunk)
 m.need(m.ident(os.fstat(fd))==before,'held_file_changed');return h.hexdigest(),size

def write_all(fd,raw,m):
 view=memoryview(raw)
 while view:
  n=os.write(fd,view);m.need(n>0,'short_file_write');view=view[n:]

def stream_exclusive(path,stream,limit,m,exact=None):
 fd=m.new_output(path);size=0;h=hashlib.sha256()
 try:
  while True:
   chunk=stream.read(min(1024**2,limit+1-size));m.need(type(chunk) is bytes,'binary_input_required')
   if not chunk:break
   size+=len(chunk);m.need(size<=limit,'bounded_input_exceeded');write_all(fd,chunk,m);h.update(chunk)
  m.need(exact is None or size==exact,'input_length_mismatch');os.fsync(fd);record={'identity':m.ident(os.fstat(fd)),'sha256':h.hexdigest()}
  m.need(record['identity']==m.ident(path.lstat()),'output_postimage_changed');return record
 finally:os.close(fd)

def strict_tar(fd,total,outer,m):
 """Walk raw headers first: hidden PAX/GNU metadata, duplicates and links never pass."""
 m.need(total%512==0 and 1024<=total<=((1024**3+65536) if outer else PLAIN_BOUND),'tar_size_bound')
 result=[];names=set();pos=0
 while pos+512<=total:
  raw=os.pread(fd,512,pos);m.need(len(raw)==512,'short_tar_header')
  if raw==b'\0'*512:
   m.need(os.pread(fd,512,pos+512)==b'\0'*512,'tar_end_blocks_required')
   remain=total-pos;m.need(remain<=10240,'tar_padding_bound')
   m.need(os.pread(fd,remain,pos)==b'\0'*remain,'tar_trailing_payload');break
  m.need(len(result)<(3 if outer else 4096),'tar_member_bound')
  m.need(raw[156:157] in [b'0',b'\0'] and raw[257:263]==b'ustar\0' and raw[263:265]==b'00','regular_ustar_only')
  m.need(raw[345:500].strip(b'\0')==b'' and raw[157:257].strip(b'\0')==b'','tar_link_or_prefix_refused')
  try:item=tarfile.TarInfo.frombuf(raw,'utf-8','strict')
  except (tarfile.TarError,UnicodeError,ValueError):raise m.Refused('invalid_tar_header') from None
  name=item.name;m.need(name.isascii() and all(32<ord(c)<127 for c in name),'tar_control_or_nonascii_path');m.need(name not in names and name and '\x00' not in name and '\\' not in name and str(PurePosixPath(name))==name and not name.startswith('/') and '..' not in PurePosixPath(name).parts,'tar_path_or_duplicate')
  m.need(item.type in [tarfile.REGTYPE,tarfile.AREGTYPE] and not item.pax_headers and not item.sparse,'regular_tar_member_required')
  if outer:
   limits={'backup.tar.gpg':1024**3,'manifest.json':8192,'manifest.sig':64};m.need(name in limits and 0<item.size<=limits.get(name,0),'outer_member_size_or_name')
   if name=='manifest.sig':m.need(item.size==64,'signature_length_required')
  else:m.need(item.size>=0,'inner_member_size')
  end=pos+512+item.size;padded=(end+511)//512*512;m.need(padded+1024<=total,'truncated_tar_member')
  pad=padded-end;m.need(os.pread(fd,pad,end)==b'\0'*pad,'nonzero_tar_member_padding')
  result.append({'name':name,'kind':'regular','size':item.size,'offset':pos+512});names.add(name);pos=padded
 else:raise m.Refused('tar_end_missing')
 if outer:m.need(names=={'backup.tar.gpg','manifest.json','manifest.sig'},'exact_outer_members_required')
 return result

def extract_member(fd,item,path,m):
 out=m.new_output(path);h=hashlib.sha256();offset=item['offset'];left=item['size']
 try:
  while left:
   b=os.pread(fd,min(left,1024**2),offset);m.need(bool(b),'truncated_member');write_all(out,b,m);h.update(b);offset+=len(b);left-=len(b)
  os.fsync(out);record={'identity':m.ident(os.fstat(out)),'sha256':h.hexdigest()};m.need(record['identity']==m.ident(path.lstat()),'extracted_postimage_changed');return record
 finally:os.close(out)

def ed25519_public(raw,m):
 m.need(type(raw) is str and len(raw)<=4096,'signer_public_required')
 lines=raw.splitlines();m.need(len(lines)==3 and lines[0]=='-----BEGIN PUBLIC KEY-----' and lines[-1]=='-----END PUBLIC KEY-----','signer_spki_required')
 try:der=base64.b64decode(lines[1],validate=True)
 except ValueError:raise m.Refused('signer_spki_required') from None
 m.need(len(der)==44 and der[:12]==bytes.fromhex('302a300506032b6570032100'),'ed25519_signer_required');return raw.encode()

class Target:
 def __init__(self,plan_path,phase,m,runner=None):
  self.m=m;self.p=m.policy();self.run=runner or m.command;self.plan_path=plan_path;self.raw,self.plan_record=m.read(plan_path);p=bounded_json(self.raw,8192,m,'target_plan_schema');self.plan=p
  m.need(type(p) is dict and set(p)=={'schema_version','operation_id','target','namespace','minimum_free_bytes'} and type(p['schema_version']) is int and p['schema_version']==1,'target_plan_schema')
  self.id=m.operation_id(p['operation_id']);m.need(p['target'] in NAMESPACES,'target_not_owned');self.target=p['target'];fixed,minimum=NAMESPACES[self.target]
  m.need(p['namespace']==fixed and type(p['minimum_free_bytes']) is int and p['minimum_free_bytes']==minimum,'fixed_target_namespace_required')
  m.need(socket.gethostname().split('.')[0].lower()==self.target.lower(),'target_hostname_mismatch')
  self.namespace=Path(fixed);self.work=self.namespace/self.id;self.phase=phase;self.journal=None;self.lockfd=None;self.nsmeta=None;self.nsrecord=None;self.lockmeta=None;self.pending_credit={};self.credit_fds={}
  if phase=='init-keys':self.require_memory()
  self._namespace_check()
  if phase=='init-keys' or (phase=='check' and not os.path.lexists(self.work)):self._capacity()
  if phase=='init-keys':
   if not os.path.lexists(self.namespace):
    self.nsmeta=m.new_dir(self.namespace);marker=m.json_bytes({'schema_version':1,'target':self.target,'namespace':fixed});expected=m.exclusive(self.namespace/'namespace.json',marker);self.nsrecord={'identity':expected,'sha256':m.sha(marker)}
   self._namespace_check();m.new_dir(self.work);self.lockfd=m.new_output(self.work/'operation.lock');os.fsync(self.lockfd);self.lockmeta=m.ident(os.fstat(self.lockfd));fcntl.flock(self.lockfd,fcntl.LOCK_EX|fcntl.LOCK_NB)
   self.journal=m.Journal(self.work,STATES);self.journal.append('state-plan.json',{'schema_version':1,'plan':p,'plan_record':self.plan_record,'lock':self.lockmeta})
  elif phase=='check' and not os.path.lexists(self.work):pass
  else:
   m.private_dir(self.work);self.journal=m.Journal(self.work,STATES);initial=self.journal.get('state-plan.json');m.need(initial['plan']==p and initial['plan_record']==self.plan_record,'target_plan_binding_changed')
   self.lockfd=os.open(self.work/'operation.lock',os.O_RDWR|os.O_NOFOLLOW|os.O_CLOEXEC);self.lockmeta=initial['lock'];m.need(m.ident(os.fstat(self.lockfd))==self.lockmeta,'operation_lock_changed');fcntl.flock(self.lockfd,fcntl.LOCK_EX|fcntl.LOCK_NB)
  self.guard()
 def close(self):
  if self.lockfd is not None:os.close(self.lockfd);self.lockfd=None
 def _namespace_check(self):
  m=self.m;m.parent_safe(self.namespace.parent)
  if os.path.lexists(self.namespace):
   m.private_dir(self.namespace);raw,record=m.read(self.namespace/'namespace.json');expected={'schema_version':1,'target':self.target,'namespace':str(self.namespace)}
   m.need(bounded_json(raw,8192,m,'namespace_marker_required')==expected,'namespace_not_owned')
   if self.nsrecord is not None:m.need(record==self.nsrecord and m.ident(self.namespace.lstat())[:5]==self.nsmeta,'namespace_changed')
   else:self.nsrecord=record;self.nsmeta=m.ident(self.namespace.lstat())[:5]
 def track(self,path,record):
  self.m.need(path.is_relative_to(self.work),'credit_path_outside_operation');self.pending_credit[path]=copy.deepcopy(record);return record
 def _capacity(self):
  # Credit only immutable post-states of THIS operation, never foreign files or future budgets.
  m=self.m;records=dict(self.pending_credit)
  if self.journal:
   def add(path,record):
    if record is not None:records[path]=record
   for name,(_,meta,value) in self.journal.records.items():add(self.work/name,meta)
   values={name:value for name,(_,_,value) in self.journal.records.items()}
   key=values.get('state-keys.json')
   if key:
    add(self.work/'recovery-public.asc',key['public_record']);add(self.work/'keyinit-memory-probe.bin',key['memory_probe_record'])
    for name,identity in key['private_key_records']['files'].items():
     m.need(re.fullmatch('[a-fA-F0-9]{40}\.key',name) is not None,'credit_private_key_path');add(self.work/'gnupg'/'private-keys-v1.d'/name,{'identity':identity})
   stage=values.get('state-tool.json')
   if stage:add(self.work/'etcdutl',stage['record'])
   config=values.get('state-config.json')
   if config:
    for path,keyname in [('trusted.json','trusted_record'),('signer-public.pem','signer_record'),('tools/etcdutl','tool_record')]:add(self.work/path,config[keyname])
   received=values.get('state-received.json')
   if received:
    add(self.work/'received'/'envelope.tar',received['outer_record'])
    for name in ['backup.tar.gpg','manifest.json','manifest.sig']:add(self.work/'received'/name,received['records'][name])
   restored=values.get('state-restored.json')
   if restored:
    add(self.work/'plaintext.tar',restored['plaintext_record']);add(self.work/'gpg-status',restored['gpg_status_record']);add(self.work/'restore-memory-probe.bin',restored['memory_probe_record'])
    for name,record in restored['recovered_records'].items():self.p.archive_member(name,'regular',record['identity'][6]);add(self.work/'recovered'/name,record)
    for name,record in restored['restored_inventory'].items():
     m.need(re.fullmatch(r'member/(snap/(db|[a-f0-9]{16}-[a-f0-9]{16}\.snap)|wal/[a-f0-9]{16}-[a-f0-9]{16}\.wal)',name) is not None,'credit_restored_path');add(self.work/'offline-restore'/name,record)
  credit=0;seen=set();m.need(len(records)<=24576,'owned_credit_inventory_bound')
  for path,record in records.items():
   m.need(path.is_relative_to(self.work),'credit_path_outside_operation');expected=record['identity']
   with m.pinned(path,max(expected[6],1),False) as (fd,identity):
    m.need(identity==expected and stat.S_IMODE(identity[2]) in [0o600,0o500],'owned_allocation_changed');key=tuple(identity[:2]);m.need(key not in seen,'duplicate_allocation_credit');seen.add(key);credit+=os.fstat(fd).st_blocks*512
  for fd,(path,before,limit) in self.credit_fds.items():
   now=m.ident(os.fstat(fd));m.need(now[:6]==before[:6] and now==m.ident(path.lstat()) and now[6]<=limit,'exclusive_output_credit_changed');key=tuple(now[:2]);m.need(key not in seen,'duplicate_allocation_credit');seen.add(key);credit+=os.fstat(fd).st_blocks*512
  m.need(credit<=8*1024**3,'owned_allocation_credit_bound');required=self.plan['minimum_free_bytes'];floor=min(required,(10 if self.target=='Tarragon' else 2)*1024**3)
  m.require_free(self.namespace if self.namespace.exists() else self.namespace.parent,max(floor,required-credit))

 def guard(self):
  m=self.m;m.need(m.read(self.plan_path)==(self.raw,self.plan_record),'target_plan_changed');self._namespace_check()
  if self.journal:self.journal.guard()
  self._capacity()
  if self.lockfd is not None:m.need(m.ident(os.fstat(self.lockfd))==self.lockmeta==m.ident((self.work/'operation.lock').lstat()),'operation_lock_changed')
 def cmd(self,args,label,capture=None,**kw):
  self.guard();out=self.run(self.work,args,label,**kw)
  if capture:capture()
  self.guard();return out
 def state(self,name):return copy.deepcopy(self.journal.get(name))
 def record(self,path,limit=2*1024**2):
  with self.m.pinned(path,limit,True) as (fd,meta):return {'identity':meta,'sha256':hash_fd(fd,limit,self.m)[0]}
 def exclusive_control(self,path,raw):
  expected=self.m.exclusive(path,raw);record={'identity':expected,'sha256':self.m.sha(raw)};self.verify_record(path,record,len(raw));return self.track(path,record)
 def verify_record(self,path,record,limit):
  m=self.m
  with m.pinned(path,limit,True) as (fd,meta):m.need(meta==record['identity'] and hash_fd(fd,limit,m)==(record['sha256'],meta[6]),'immutable_input_changed')
 def require_memory(self):return memory_available(Path('/proc/meminfo').read_bytes(),self.m)
 def probe_restore_profile(self,cohort):
  m=self.m;m.need(cohort in ['keyinit','restore'],'fixed_memory_probe_cohort');self.require_memory();path=self.work/(cohort+'-memory-probe.bin');record=self.exclusive_control(path,b'\0'*4096)
  with m.pinned(path,4096,True) as (fd,meta):
   m.need(meta==record['identity'],'memory_probe_changed');raw=self.cmd(['/usr/bin/python3','-c',PROFILE_PROBE,str(fd)],cohort+'-memory-profile',pass_fds=(fd,),timeout=30,address_limit=16*1024**3,execution_profile='etcd-restore')
  result=bounded_json(raw,1024,m,'memory_profile_probe_result');m.need(type(result) is dict and type(result.get('schema_version')) is int and result=={'schema_version':1,'readonly_file_mapping_verified':True,'anonymous_mapping_cap_verified':True} and all(type(result[k]) is bool for k in ['readonly_file_mapping_verified','anonymous_mapping_cap_verified']),'memory_profile_not_verified');return record
 def check(self):
  self.guard();self.require_memory()
  for path in ['/usr/bin/gpg','/usr/bin/openssl']:
   with self.m.pinned(Path(path),64*1024**2,False):pass
  return {'status':'passed','target':self.target,'namespace_owned_or_absent':True,'capacity_gate':True,'tools_present':True,'memory_headroom':True,'no_mutation':True}
 def gpg_version(self):
  out=self.cmd(['/usr/bin/gpg','--no-options','--version'],'gpg-version',address_limit=768*1024**2)
  self.m.need(out.splitlines()[0]==b'gpg (GnuPG) 2.4.4','gpg_2_4_4_required')
 def key_metadata(self):
  out=self.cmd(self.p.gpg_prefix(str(self.work/'gnupg'))+['--with-colons','--with-fingerprint','--with-subkey-fingerprint','--list-keys'],'public-key-metadata',address_limit=768*1024**2)
  self.m.need(len(out)<=65536,'public_key_metadata_bound');return out.decode('ascii')
 def validate_key(self,text,expected=None):
  m=self.m;rows=[r.split(':') for r in text.splitlines() if r];fprs={};kind=None
  for r in rows:
   if r[0] in ['pub','sub']:
    kind=r[0];m.need(len(r)>16,'key_curve_metadata_required');m.need(r[16]==('ed25519' if kind=='pub' else 'cv25519'),'exact_recovery_curve_required')
    caps=''.join(c for c in r[11] if c.islower());m.need(caps==('c' if kind=='pub' else 'e'),'exact_recovery_capabilities_required')
    m.need(r[5].isdecimal() and r[6].isdecimal() and 364*86400<=int(r[6])-int(r[5])<=366*86400,'one_year_recovery_key_required')
   elif r[0]=='fpr' and kind is not None:
    m.need(kind not in fprs and len(r)>9,'recovery_fingerprint_count');fprs[kind]=r[9];kind=None
  m.need(set(fprs)=={'pub','sub'},'recovery_fingerprint_count');pins={'primary_fingerprint':fprs['pub'],'encryption_subkey_fingerprint':fprs['sub']}
  if expected is not None:m.need(pins==expected,'own_recipient_pin_changed')
  self.p.parsed_key(text,pins,int(time.time()));return pins
 def init_keys(self):
  m=self.m;self.guard();self.journal.append('state-key-intent.json',{'schema_version':1,'one_use':True});profile_record=self.probe_restore_profile('keyinit');self.gpg_version();m.new_dir(self.work/'gnupg')
  prefix=self.p.gpg_prefix(str(self.work/'gnupg'))+['--pinentry-mode','loopback','--passphrase','']
  uid='NEBULA '+self.target+' Recovery '+self.id
  self.cmd(prefix+['--quick-generate-key',uid,'ed25519','cert','365d'],'generate-primary',timeout=120,address_limit=768*1024**2)
  text=self.key_metadata();rows=[r.split(':') for r in text.splitlines()];primary=next((r[9] for r in rows if r[0]=='fpr' and len(r)>9),None);self.p.fingerprint(primary)
  self.cmd(prefix+['--quick-add-key',primary,'cv25519','encr','365d'],'generate-subkey',timeout=120,address_limit=768*1024**2)
  pins=self.validate_key(self.key_metadata());private_keys=self.private_key_custody();raw=self.cmd(self.p.gpg_prefix(str(self.work/'gnupg'))+['--armor','--export',pins['primary_fingerprint']],'export-public',address_limit=768*1024**2);self.p.public_key_file(raw)
  public_record=self.exclusive_control(self.work/'recovery-public.asc',raw);self.journal.append('state-keys.json',{'schema_version':1,**pins,'public_record':public_record,'private_key_records':private_keys,'memory_probe_record':profile_record})
  return {'status':'passed','target':self.target,'recovery_keys_initialized':True,'private_keys_exported':False}
 def private_key_custody(self,expected=None):
  m=self.m;home=self.work/'gnupg';m.private_dir(home);keys=home/'private-keys-v1.d';m.private_dir(keys);names=set();records={}
  for path in keys.iterdir():
   m.need(re.fullmatch('[A-Fa-f0-9]{40}\.key',path.name) is not None,'private_key_inventory');names.add(path.name)
   with m.pinned(path,1024**2,True) as (_,meta):records[path.name]=meta
  m.need(len(names)==2,'two_private_recovery_keys_required');result={'directory':m.ident(keys.lstat())[:5],'files':records}
  if expected is not None:m.need(result==expected,'private_recovery_key_changed')
  return result
 def export_public(self):
  s=self.state('state-keys.json');self.private_key_custody(s['private_key_records']);self.verify_record(self.work/'recovery-public.asc',s['public_record'],65536);raw,_=self.m.read(self.work/'recovery-public.asc',65536)
  return {'schema_version':1,'operation_id':self.id,'target':self.target,'public_key_armored':raw.decode('ascii'),'primary_fingerprint':s['primary_fingerprint'],'encryption_subkey_fingerprint':s['encryption_subkey_fingerprint']}
 def stage_etcdutl(self,stream,digest,size):
  m=self.m;self.state('state-keys.json');m.need(type(digest) is str and re.fullmatch('[a-f0-9]{64}',digest) is not None and type(size) is int and 0<size<=64*1024**2,'public_artifact_pin_required');self.journal.append('state-tool-intent.json',{'schema_version':1,'sha256':digest,'bytes':size})
  record=stream_exclusive(self.work/'etcdutl',stream,size,m,exact=size);self.track(self.work/'etcdutl',record);m.need(record['sha256']==digest,'public_artifact_digest_mismatch');self.journal.append('state-tool.json',{'schema_version':1,'record':record,'bytes':size,'sha256':digest})
  return {'status':'passed','target':self.target,'public_tool_staged':True}
 def configure(self,raw):
  m=self.m;key=self.state('state-keys.json');staged=self.state('state-tool.json');v=bounded_json(raw,131072,m,'trusted_configuration_required')
  fields={'schema_version','operation_id','recipients','signer_public_pem','signer_public_sha256','etcd_version','etcdutl_sha256','etcdutl_bytes'}
  m.need(type(v) is dict and set(v)==fields and type(v['schema_version']) is int and v['schema_version']==1 and v['operation_id']==self.id and v['etcd_version']=='3.7.0','trusted_configuration_schema')
  self.private_key_custody(key['private_key_records']);pins=self.p.pins(v['recipients']);m.need(pins[self.target]=={k:key[k] for k in ['primary_fingerprint','encryption_subkey_fingerprint']},'own_recipient_pin_mismatch');signer=ed25519_public(v['signer_public_pem'],m);m.need(m.sha(signer)==v['signer_public_sha256'],'signer_public_digest_mismatch')
  m.need(type(v['etcdutl_bytes']) is int and v['etcdutl_bytes']==staged['bytes'] and v['etcdutl_sha256']==staged['sha256'],'staged_tool_pin_mismatch')
  self.verify_record(self.work/'etcdutl',staged['record'],64*1024**2);self.validate_key(self.key_metadata(),pins[self.target]);self.journal.append('state-config-intent.json',{'schema_version':1,'one_use':True})
  trusted_record=self.exclusive_control(self.work/'trusted.json',m.json_bytes(v));signer_record=self.exclusive_control(self.work/'signer-public.pem',signer);m.new_dir(self.work/'tools')
  with m.pinned(self.work/'etcdutl',64*1024**2,True) as (fd,_):
   with os.fdopen(os.dup(fd),'rb') as stream:record=stream_exclusive(self.work/'tools'/'etcdutl',stream,staged['bytes'],m,exact=staged['bytes'])
  path=self.work/'tools'/'etcdutl';fd,meta=m.regular_fd(path,64*1024**2,True)
  try:
   m.need(meta==record['identity'] and hash_fd(fd,64*1024**2,m)==(staged['sha256'],staged['bytes']),'public_tool_postimage_changed');os.fchmod(fd,0o500);os.fsync(fd);expected=m.ident(os.fstat(fd));m.need(expected==m.ident(path.lstat()),'public_tool_postimage_changed');record={'identity':expected,'sha256':staged['sha256'],'bytes':staged['bytes']}
  finally:os.close(fd)
  self.track(path,record)
  with self.tool_fd(record) as fd:
   out=self.cmd(['/proc/self/fd/'+str(fd),'version'],'etcdutl-version',pass_fds=(fd,),address_limit=2*1024**3)
  m.need(re.search(rb'(?m)^etcdutl version: 3\.7\.0\s*$',out) is not None,'etcdutl_3_7_0_required')
  self.verify_record(self.work/'trusted.json',trusted_record,131072);self.verify_record(self.work/'signer-public.pem',signer_record,4096);self.journal.append('state-config.json',{'schema_version':1,'trusted_record':trusted_record,'signer_record':signer_record,'tool_record':record})
  return {'status':'passed','target':self.target,'trusted_configuration_bound':True}
 def tool_record(self):
  m=self.m;path=self.work/'tools'/'etcdutl'
  with m.pinned(path,64*1024**2,False) as (fd,meta):m.need(stat.S_IMODE(meta[2])==0o500,'private_executable_mode');digest,size=hash_fd(fd,64*1024**2,m);return {'identity':meta,'sha256':digest,'bytes':size}
 @contextlib.contextmanager
 def tool_fd(self,expected):
  m=self.m;path=self.work/'tools'/'etcdutl'
  with m.pinned(path,64*1024**2,False) as (fd,meta):
   m.need(meta==expected['identity'] and stat.S_IMODE(meta[2])==0o500 and hash_fd(fd,64*1024**2,m)==(expected['sha256'],expected['bytes']),'verified_tool_changed');yield fd
 def trusted(self):
  s=self.state('state-config.json');self.verify_record(self.work/'trusted.json',s['trusted_record'],131072);self.verify_record(self.work/'signer-public.pem',s['signer_record'],4096);v=bounded_json(self.m.read(self.work/'trusted.json',131072)[0],131072,self.m,'trusted_configuration_required');return v,s
 def verify_envelope(self,directory,records):
  m=self.m;v,cfg=self.trusted()
  with contextlib.ExitStack() as stack:
   handles={}
   for name,limit in [('backup.tar.gpg',self.p.MAX_CIPHERTEXT),('manifest.json',8192),('manifest.sig',64)]:
    fd,meta=stack.enter_context(m.pinned(directory/name,limit,True));m.need(meta==records[name]['identity'] and hash_fd(fd,limit,m)==(records[name]['sha256'],meta[6]),'received_envelope_changed');handles[name]=fd
   raw=os.pread(handles['manifest.json'],8193,0);manifest=self.p.validate_received_manifest(raw,v['recipients'],v['signer_public_sha256'],self.id)
   m.need(hash_fd(handles['backup.tar.gpg'],self.p.MAX_CIPHERTEXT,m)==(manifest['ciphertext']['sha256'],manifest['ciphertext']['bytes']),'ciphertext_digest_or_length_mismatch')
   key,keymeta=stack.enter_context(m.pinned(self.work/'signer-public.pem',4096,True));m.need(keymeta==cfg['signer_record']['identity'],'signer_file_changed')
   self.cmd(['/usr/bin/openssl','pkeyutl','-verify','-pubin','-inkey','/proc/self/fd/'+str(key),'-rawin','-in','/proc/self/fd/'+str(handles['manifest.json']),'-sigfile','/proc/self/fd/'+str(handles['manifest.sig'])],'verify-envelope-signature',pass_fds=(key,handles['manifest.json'],handles['manifest.sig']))
   yield handles,manifest,v,cfg
 @contextlib.contextmanager
 def authenticated_envelope(self,directory,records):
  yield from self.verify_envelope(directory,records)
 def receive(self,stream):
  m=self.m;self.trusted();self.journal.append('state-receive-intent.json',{'schema_version':1,'one_use':True});m.new_dir(self.work/'received')
  envelope=self.work/'received'/'envelope.tar';outer=stream_exclusive(envelope,stream,self.p.MAX_CIPHERTEXT+65536,m);self.track(envelope,outer)
  with m.pinned(envelope,self.p.MAX_CIPHERTEXT+65536,True) as (fd,meta):
   m.need(meta==outer['identity'],'envelope_changed');items=strict_tar(fd,meta[6],True,m);records={i['name']:self.track(self.work/'received'/i['name'],extract_member(fd,i,self.work/'received'/i['name'],m)) for i in items}
  with self.authenticated_envelope(self.work/'received',records):pass
  self.journal.append('state-received.json',{'schema_version':1,'outer_record':outer,'records':records})
  return {'status':'passed','target':self.target,'signed_envelope_received':True,'decrypted':False}
 def gpg_status(self,raw,own):
  m=self.m;m.need(len(raw)<=65536,'gpg_status_bound');lines=raw.decode('ascii').splitlines();rows=[]
  for line in lines:m.need(line.startswith('[GNUPG:] '),'gpg_status_prefix');rows.append(line[9:].split())
  names=[r[0] for r in rows if r];m.need('DECRYPTION_OKAY' in names and not(set(names)&{'ERROR','FAILURE','BADMDC','ERRMDC','NODATA','NO_SECKEY','DECRYPTION_FAILED','BADARMOR','BAD_PASSPHRASE','MISSING_PASSPHRASE'}),'gpg_authenticated_decryption_required')
  keys=[r for r in rows if r and r[0]=='DECRYPTION_KEY'];m.need(len(keys)==1 and len(keys[0])>=3 and keys[0][1:3]==[own['encryption_subkey_fingerprint'],own['primary_fingerprint']],'own_full_decryption_key_required')
  infos=[r for r in rows if r and r[0]=='DECRYPTION_INFO'];m.need(len(infos)==1 and len(infos[0])>=3 and infos[0][2]=='9','aes256_decryption_required')
  # GnuPG reports MDC method in field1; legacy no-integrity ciphertext is never accepted.
  m.need(infos[0][1] in ['1','2'] and 'GOODMDC' in names,'authenticated_mdc_required')
 def restore_manifest(self,raw,items):
  m=self.m;v=bounded_json(raw,2*1024**2,m,'restore_manifest_required');fields={'schema_version','operation_id','expected_uuid','run_id','api_address','etcd_version','snapshot_status','source_cluster_sha256','archive_members'}
  m.need(type(v) is dict and set(v)==fields and type(v['schema_version']) is int and v['schema_version']==1 and v['operation_id']==self.id and v['etcd_version']=='3.7.0' and v['source_cluster_sha256']==CLUSTER_SHA,'restore_manifest_schema')
  try:valid_uuid=str(uuid.UUID(v['expected_uuid']))==v['expected_uuid'];address=ipaddress.IPv4Address(v['api_address'])
  except (ValueError,AttributeError,TypeError):raise m.Refused('restore_source_identity') from None
  m.need(valid_uuid and type(v['run_id']) is str and re.fullmatch('[a-f0-9]{12}',v['run_id']) is not None and address.is_private and not(address.is_loopback or address.is_link_local or address.is_unspecified or address.is_multicast),'restore_source_identity')
  actual=[{k:i[k] for k in ['name','kind','size']} for i in items if i['name']!='restore-manifest.json'];listed=v['archive_members'];sizes={i['name']:i['size'] for i in actual};m.need(CRITICAL_FILES<=set(sizes) and all(sizes[n]>0 for n in CRITICAL_FILES),'critical_recovery_material_missing')
  m.need(type(listed) is list and len(listed)==len(actual) and all(type(i) is dict and set(i)=={'name','kind','size'} and type(i['name']) is str and i['kind']=='regular' and type(i['size']) is int and i['size']>=0 for i in listed),'restore_inventory_schema')
  m.need(sorted(listed,key=lambda i:i['name'])==sorted(actual,key=lambda i:i['name']),'restore_inventory_mismatch');status=v['snapshot_status'];m.need(type(status) is dict and {'hash','revision','totalKey','totalSize'}<=set(status) and set(status)<={'hash','revision','totalKey','totalSize','version'} and all(type(status[k]) is int for k in ['hash','revision','totalKey','totalSize']) and 0<=status['hash']<=0xffffffff and 0<status['revision']<=2**63-1-1000000000 and status['totalKey']>0 and 0<status['totalSize']<=self.p.MAX_SNAPSHOT and ('version' not in status or (type(status['version']) is str and len(status['version'])<=32)),'snapshot_status_schema');return v
 def private_parents(self,base,name):
  current=base
  for part in PurePosixPath(name).parts[:-1]:
   current=current/part
   if not os.path.lexists(current):self.m.new_dir(current)
   self.m.private_dir(current)
 def verify_restore(self):
  m=self.m;s=self.state('state-received.json');self.verify_record(self.work/'received'/'envelope.tar',s['outer_record'],self.p.MAX_CIPHERTEXT+65536);v,cfg=self.trusted();own=v['recipients'][self.target];self.private_key_custody(self.state('state-keys.json')['private_key_records']);self.gpg_version();self.validate_key(self.key_metadata(),own);self.journal.append('state-restore-intent.json',{'schema_version':1,'one_use':True});profile_record=self.probe_restore_profile('restore')
  plain=self.work/'plaintext.tar';status=self.work/'gpg-status';out=m.new_output(plain);statusfd=m.new_output(status);self.credit_fds[out]=(plain,m.ident(os.fstat(out)),PLAIN_BOUND);self.credit_fds[statusfd]=(status,m.ident(os.fstat(statusfd)),65536)
  try:
   with self.authenticated_envelope(self.work/'received',s['records']) as (handles,_,_,_):
    cipher=handles['backup.tar.gpg'];args=self.p.decrypt_args(str(self.work/'gnupg'),out,PLAIN_BOUND)+['--yes','--status-fd',str(statusfd),'/proc/self/fd/'+str(cipher)]
    self.cmd(args,'decrypt-private-envelope',timeout=300,pass_fds=(out,statusfd,cipher),file_limit=PLAIN_BOUND,address_limit=768*1024**2);os.fsync(out);os.fsync(statusfd)
   m.need(m.ident(os.fstat(out))==m.ident(plain.lstat()) and m.ident(os.fstat(statusfd))==m.ident(status.lstat()),'decryption_output_replaced');self.gpg_status(os.pread(statusfd,65537,0),own)
   items=strict_tar(out,os.fstat(out).st_size,False,m);self.p.archive_inventory([{k:i[k] for k in ['name','kind','size']} for i in items]);manifest=next(i for i in items if i['name']=='restore-manifest.json');m.need(manifest['size']<=2*1024**2,'restore_manifest_bound');source=self.restore_manifest(os.pread(out,manifest['size'],manifest['offset']),items)
   recovered=self.work/'recovered';m.new_dir(recovered);records={}
   for item in items:self.private_parents(recovered,item['name']);records[item['name']]=self.track(recovered/item['name'],extract_member(out,item,recovered/item['name'],m))
   plain_record={'identity':m.ident(os.fstat(out)),'sha256':hash_fd(out,PLAIN_BOUND,m)[0]};gpg_status_record={'identity':m.ident(os.fstat(statusfd)),'sha256':hash_fd(statusfd,65536,m)[0]}
  finally:
   self.credit_fds.pop(out,None);self.credit_fds.pop(statusfd,None);os.close(out);os.close(statusfd)
  self.track(plain,plain_record);self.track(status,gpg_status_record)
  snapshot=recovered/'snapshot.db';restore=self.work/'offline-restore';m.need(not os.path.lexists(restore),'restore_destination_must_be_new');restore_identity=m.new_dir(restore)
  with contextlib.ExitStack() as stack:
   restorefd=os.open(restore,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC);stack.callback(os.close,restorefd)
   m.need(m.ident(os.fstat(restorefd))[:5]==restore_identity==m.ident(restore.lstat())[:5] and not os.listdir(restorefd),'restore_directory_changed')
   tool=stack.enter_context(self.tool_fd(cfg['tool_record']));snap,meta=stack.enter_context(m.pinned(snapshot,self.p.MAX_SNAPSHOT,True))
   m.need(meta==records['snapshot.db']['identity'] and hash_fd(snap,self.p.MAX_SNAPSHOT,m)==(records['snapshot.db']['sha256'],meta[6]),'snapshot_changed');toolpath='/proc/self/fd/'+str(tool);snappath='/proc/self/fd/'+str(snap)
   raw=self.cmd([toolpath,'snapshot','status',snappath,'--write-out=json'],'independent-snapshot-status',pass_fds=(tool,snap),timeout=120,address_limit=2*1024**3);independent=bounded_json(raw,65536,m,'independent_snapshot_status');m.need(independent==source['snapshot_status'],'independent_snapshot_status_mismatch')
   m.need(m.ident(os.fstat(restorefd))[:5]==restore_identity==m.ident(restore.lstat())[:5] and not os.listdir(restorefd),'restore_directory_changed')
   name='nebula-restore-'+self.target.lower()+'-'+self.id;token=name
   # The tool writes through our held exclusive directory FD, never a replaced pathname.
   args=[toolpath,'snapshot','restore',snappath,'--data-dir','/proc/self/fd/'+str(restorefd),'--name',name,'--initial-cluster',name+'=http://127.0.0.1:2380','--initial-advertise-peer-urls','http://127.0.0.1:2380','--initial-cluster-token',token,'--bump-revision','1000000000','--mark-compacted']
   def capture_restore():
    m.need(m.ident(os.fstat(restorefd))[:5]==restore_identity==m.ident(restore.lstat())[:5],'restore_directory_changed')
    for name,record in self.restored_tree(restore).items():self.track(restore/name,record)
   self.cmd(args,'offline-etcd-restore',capture=capture_restore,pass_fds=(tool,snap,restorefd),timeout=300,file_limit=2*1024**3,address_limit=16*1024**3,execution_profile='etcd-restore')
   m.need(m.ident(os.fstat(restorefd))[:5]==restore_identity==m.ident(restore.lstat())[:5],'restore_directory_changed')
  inventory=self.restored_tree(restore);m.need('member/snap/db' in inventory,'restored_database_missing')
  with self.tool_fd(cfg['tool_record']) as tool, m.pinned(restore/'member'/'snap'/'db',2*1024**3,True) as (db,meta):
   m.need(meta==inventory['member/snap/db']['identity'],'restored_database_changed');raw=self.cmd(['/proc/self/fd/'+str(tool),'snapshot','status','/proc/self/fd/'+str(db),'--write-out=json'],'restored-database-status',pass_fds=(tool,db),timeout=120,address_limit=2*1024**3);restored_status=bounded_json(raw,65536,m,'restored_database_status')
   m.need(type(restored_status) is dict and type(restored_status.get('revision')) is int and restored_status['revision']==independent['revision']+1000000000 and restored_status.get('version')==independent.get('version'),'restored_revision_bump_unverified')
  m.need(self.restored_tree(restore)==inventory,'restored_tree_changed')
  self.verify_record(plain,plain_record,PLAIN_BOUND);self.journal.append('state-restored.json',{'schema_version':1,'target':self.target,'independent_snapshot_status':independent,'restored_snapshot_status':restored_status,'plaintext_record':plain_record,'gpg_status_record':gpg_status_record,'memory_probe_record':profile_record,'recovered_records':records,'restored_inventory':inventory,'restore_directory':m.ident(restore.lstat())[:5],'offline_only':True,'revision_bump':1000000000,'mark_compacted':True})
  return {'status':'passed','target':self.target,'signature_verified':True,'own_recovery_key_verified':True,'independent_snapshot_status_verified':True,'offline_restore_verified':True,'authenticated_decryption_verified':True,'isolated_restore_verified':True,'no_listener_started':True,'critical_recovery_material_verified':True,'revision_bump':1000000000,'mark_compacted':True,'listeners_started':False,'private_data_exported':False}
 def restored_tree(self,base):
  m=self.m;result={};m.private_dir(base);count=0;total=0
  for root,dirs,files in os.walk(base,followlinks=False):
   for name in dirs+files:
    path=Path(root)/name;s=path.lstat();count+=1;m.need(count<=16384 and s.st_uid==s.st_gid==0 and not stat.S_ISLNK(s.st_mode),'restored_tree_custody')
    if stat.S_ISDIR(s.st_mode):m.need(stat.S_IMODE(s.st_mode)==0o700 and path.relative_to(base).as_posix() in ['member','member/snap','member/wal'],'restored_directory_allowlist')
    else:
     rel=path.relative_to(base).as_posix();m.need(stat.S_ISREG(s.st_mode) and s.st_nlink==1 and stat.S_IMODE(s.st_mode)==0o600 and re.fullmatch(r'member/(snap/(db|[a-f0-9]{16}-[a-f0-9]{16}\.snap)|wal/[a-f0-9]{16}-[a-f0-9]{16}\.wal)',rel) is not None,'restored_file_allowlist');total+=s.st_size;m.need(total<=4*1024**3,'restored_tree_size_bound');result[rel]=self.record(path,2*1024**3)
  return result

def main():
 parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--plan',type=Path,required=True);parser.add_argument('--phase',choices=['check','init-keys','export-public','stage-etcdutl','configure','receive','verify-restore'],required=True);parser.add_argument('--execute',action='store_true');parser.add_argument('--artifact-sha256');parser.add_argument('--artifact-bytes',type=int);a=parser.parse_args()
 # Gate precedes plan reads, module imports and probes; missing opt-in cannot mutate.
 if a.phase not in ['check','export-public'] and not a.execute:parser.error('mutating phase requires --execute')
 m=load_common()
 def perform():
  m.need(os.geteuid()==0,'root_required');m.need(a.phase=='stage-etcdutl' or (a.artifact_sha256 is None and a.artifact_bytes is None),'artifact_arguments_only_for_stage');target=None
  try:
   target=Target(a.plan,a.phase,m)
   if a.phase=='stage-etcdutl':result=target.stage_etcdutl(sys.stdin.buffer,a.artifact_sha256,a.artifact_bytes)
   elif a.phase=='configure':result=target.configure(sys.stdin.buffer.read(131073))
   elif a.phase=='receive':result=target.receive(sys.stdin.buffer)
   else:result=getattr(target,a.phase.replace('-','_'))()
   target.guard();print(json.dumps(result,sort_keys=True))
  finally:
   if target:target.close()
 m.safe_cli(perform)
if __name__=='__main__':main()

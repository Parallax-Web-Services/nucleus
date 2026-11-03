#!/usr/bin/env python3
"""SOURCE-ONLY initial backup orchestrator. Existing owned SSH only; ciphertext/public data only.
Requires inert reviewed code and private per-role plans already staged at the fixed locations.
No shell, private key, CA, kubeconfig or plaintext snapshot is transported to this controller.
ROOT RUNTIME GATE: after owner admission, root must launch and verify a fresh accepted
600-second managed-health publisher for EACH invocation, invoke ONE step immediately,
then stop only that owned publisher. The whole invocation has a 510s monotonic acceptance deadline; remote timeouts are
clamped to its remaining time with 25s reserved for owned cleanup. Guard/action
maxima are 45/420s. Late results fail closed; root must inspect any partial attempt.
Every invocation requires the caller's independently retained expected completion-head
pin. Success heads are written only to a new private result outside the operation state;
consume that result only after exit zero. Failure or lost capture requires explicit review.
Never reconstruct the expected head from current operation files.
No publisher admission, start, extension, fallback or runtime acceptance is implemented here.
"""
from __future__ import annotations
import argparse,base64,contextlib,fcntl,hashlib,json,os,re,shlex,stat,sys,time,types
from collections import namedtuple
from pathlib import Path,PurePosixPath
ROOT=Path('/mnt/wsl/projects/workspace/parallax/nucleus')
RUN_ID='8b593520afd7'
COMMON_SHA='cd5fc702868af2e74965aa13677c691bd3eb872cdb20d5db45e0f0efe6855322'
BRIDGE_SHA='b8e05a5557ded628307f387879b2ef63297f8162790a54177ce7d8edd628b095'
STEPS=('stage-tarragon','stage-slipstream','stage-guest','init-tarragon','init-slipstream','init-guest','public-tarragon','public-slipstream','public-guest','export-tool','configure-guest','stage-tool-tarragon','configure-tarragon','stage-tool-slipstream','configure-slipstream','snapshot-seal','export-envelope','receive-tarragon','receive-slipstream','restore-tarragon','restore-slipstream')
CHECK_STEPS=('check-guest','check-tarragon','check-slipstream')
STEP_REMOTE={**{prefix+'-'+role.lower():(role,phase) for prefix,phase in [('stage','stage'),('init','init-keys'),('public','export-public'),('receive','receive'),('restore','verify-restore'),('check','check')] for role in ['Tarragon','Slipstream']},'stage-guest':('Guest','stage'),'init-guest':('Guest','prepare'),'public-guest':('Guest','export-public'),'check-guest':('Guest','check'),'export-tool':('Guest','export-etcdutl'),'configure-guest':('Guest','configure'),'stage-tool-tarragon':('Tarragon','stage-etcdutl'),'configure-tarragon':('Tarragon','configure'),'stage-tool-slipstream':('Slipstream','stage-etcdutl'),'configure-slipstream':('Slipstream','configure'),'snapshot-seal':('Guest','snapshot-seal'),'export-envelope':('Guest','export-envelope')}
NAMES={'nebula-backup-common.py','nebula-backup-envelope-policy.py','nebula-backup-guest.py','nebula-backup-target.py'}
ROLE_PHASES={'Guest':{'stage','check','prepare','configure','snapshot-seal','export-public','export-etcdutl','export-envelope'},'Tarragon':{'stage','check','init-keys','export-public','stage-etcdutl','configure','receive','verify-restore'},'Slipstream':{'stage','check','init-keys','export-public','stage-etcdutl','configure','receive','verify-restore'}}
class Refused(RuntimeError):pass
def need(ok,code):
 if not ok:raise Refused(code)
def sha(raw):return hashlib.sha256(raw).hexdigest()
def meta(s):return [s.st_dev,s.st_ino,s.st_mode,s.st_uid,s.st_gid,s.st_nlink,s.st_size,s.st_mtime_ns,s.st_ctime_ns]
def local_read(path,limit,private=True):
 need(path.is_absolute() and path.resolve()==path,'canonical_local_path');fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
 try:
  before=os.fstat(fd);need(stat.S_ISREG(before.st_mode) and before.st_uid==os.geteuid() and before.st_gid==os.getegid() and before.st_nlink==1 and before.st_size<=limit and stat.S_IMODE(before.st_mode)&0o022==0,'local_input_custody')
  if private:need(stat.S_IMODE(before.st_mode)==0o600,'local_private_input_required')
  raw=b''
  while True:
   b=os.read(fd,65536)
   if not b:break
   raw+=b;need(len(raw)<=limit,'local_input_bound')
  need(meta(before)==meta(os.fstat(fd))==meta(path.lstat()),'local_input_changed');return raw,meta(before)
 finally:os.close(fd)
def write_all(fd,raw):
 view=memoryview(raw)
 while view:
  n=os.write(fd,view)
  if n<=0:raise RuntimeError('short_file_write')
  view=view[n:]
def exclusive(path,raw):
 fd=os.open(path,os.O_CREAT|os.O_EXCL|os.O_WRONLY|os.O_NOFOLLOW,0o600)
 try:
  with os.fdopen(os.dup(fd),'wb') as out:out.write(raw);out.flush();os.fsync(out.fileno())
  need(meta(os.fstat(fd))==meta(path.lstat()) and os.fstat(fd).st_size==len(raw),'local_postimage_changed');return tuple(meta(os.fstat(fd)))
 finally:os.close(fd)
def bytes_json(v):return (json.dumps(v,sort_keys=True,separators=(',',':'))+'\n').encode()
def decode(raw):
 def pairs(items):
  out={}
  for key,value in items:need(key not in out,'duplicate_json_key');out[key]=value
  return out
 return json.loads(raw,object_pairs_hook=pairs,parse_constant=lambda _:need(False,'nonfinite_json'))
def overlay_path(value):
 need(type(value) is str and 1<len(value)<=1024 and value.isascii() and all(32<ord(c)<127 for c in value) and '\\' not in value,'explicit_managed_overlay_required');path=PurePosixPath(value);need(path.is_absolute() and str(path)==value and '..' not in path.parts,'canonical_remote_overlay_required');return value
BROKER='\nimport contextlib,fcntl,hashlib,ipaddress,json,os,re,shlex,stat,subprocess,sys,tempfile,types\nfrom pathlib import Path\nos.umask(0o077)\ndef need(v,c):\n if not v:raise RuntimeError(c)\ndef identity(s):return(s.st_dev,s.st_ino,s.st_mode,s.st_uid,s.st_gid,s.st_nlink,s.st_size,s.st_mtime_ns,s.st_ctime_ns)\ndef public_source(path,pin):\n fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)\n try:\n  s=os.fstat(fd);need(stat.S_ISREG(s.st_mode) and s.st_uid==0 and s.st_gid==0 and s.st_nlink==1 and stat.S_IMODE(s.st_mode)==0o600 and s.st_size<262144,\'source_custody\')\n  raw=os.read(fd,262144);need(identity(s)==identity(os.fstat(fd))==identity(path.lstat()) and hashlib.sha256(raw).hexdigest()==pin,\'source_pin\');return raw\n finally:os.close(fd)\ndef module(path,pin,name):\n raw=public_source(path,pin);m=types.ModuleType(name);m.__file__=str(path);sys.modules[name]=m;exec(compile(raw,str(path),\'exec\'),m.__dict__);return m\ndef managed_bridge():\n path=Path(\'/usr/local/lib/parallax-nebula-managed-v3/alpha-managed-health-bridge.py\');fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)\n try:\n  st=os.fstat(fd);need(path.resolve()==path and stat.S_ISREG(st.st_mode) and st.st_uid==st.st_gid==0 and st.st_nlink==1 and stat.S_IMODE(st.st_mode)&0o022==0 and st.st_size<262144,\'managed_bridge_source_custody\');raw=os.read(fd,262144);need(len(raw)==st.st_size and identity(st)==identity(os.fstat(fd))==identity(path.lstat()) and hashlib.sha256(raw).hexdigest()==\'b8e05a5557ded628307f387879b2ef63297f8162790a54177ce7d8edd628b095\',\'managed_bridge_source_pin\')\n finally:os.close(fd)\n result=types.ModuleType(\'_accepted_managed_health_bridge\');result.__file__=str(path);exec(compile(raw,str(path),\'exec\'),result.__dict__);return result\ndef managed_lifecycle(work,external_guard):\n bridge=managed_bridge().Bridge(Path(q[\'managed_health_overlay\']));need(bridge.o[\'lifecycle_path\']==\'/root/nebula-alpha-lifecycle-7c93lt9w/lifecycle-6b4ae6.py\' and bridge.o[\'preflight_path\']==\'/root/nebula-alpha-prep-u0i7dxy9/preflight.py\',\'admitted_original_source_paths_required\');job=bridge.lifecycle(runner=None);need(job.plan_path==work/\'plan.json\',\'admitted_original_plan_path_required\');job.external_guard=external_guard;job.guard();return job\n\ndef verify_bundle(directory,entry):\n need(directory.resolve()==directory,\'source_directory_canonical\');s=directory.lstat();need(s.st_uid==0 and s.st_gid==0 and stat.S_IMODE(s.st_mode)==0o700,\'source_directory_custody\')\n for name in [\'nebula-backup-common.py\',\'nebula-backup-envelope-policy.py\',entry]:public_source(directory/name,q[\'files\'][name])\n return module(directory/entry,q[\'files\'][entry],\'_approved_backup_entry\')\n\ndef private_directory(p,create=False):\n need(p.is_absolute() and p.resolve()==p,\'stage_directory_canonical\')\n if not os.path.lexists(p):\n  need(create,\'stage_parent_missing\');parent=p.parent.lstat();need(stat.S_ISDIR(parent.st_mode) and parent.st_uid==0 and stat.S_IMODE(parent.st_mode)&0o022==0,\'stage_parent_custody\');p.mkdir(mode=0o700)\n s=p.lstat();need(stat.S_ISDIR(s.st_mode) and s.st_uid==0 and s.st_gid==0 and stat.S_IMODE(s.st_mode)==0o700,\'stage_private_directory\')\ndef put(p,raw):\n fd=os.open(p,os.O_CREAT|os.O_EXCL|os.O_WRONLY|os.O_NOFOLLOW,0o600)\n try:\n  with os.fdopen(os.dup(fd),\'wb\') as out:out.write(raw);out.flush();os.fsync(out.fileno())\n  a=os.fstat(fd);b=p.lstat();need(identity(a)==identity(b) and a.st_size==len(raw),\'stage_file_postimage\')\n finally:os.close(fd)\ndef stage_bundle(directory,entry,payloads):\n required=[\'nebula-backup-common.py\',\'nebula-backup-envelope-policy.py\',entry];raws={}\n need(set(payloads)==set(q[\'files\']),\'stage_public_inventory\')\n for name in required:\n  raw=__import__(\'base64\').b64decode(payloads[name],validate=True);need(len(raw)<262144 and hashlib.sha256(raw).hexdigest()==q[\'files\'][name],\'stage_public_source_pin\');compile(raw,name,\'exec\');raws[name]=raw\n private_directory(directory.parent,True);need(not os.path.lexists(directory),\'stage_new_operation_directory\');directory.mkdir(mode=0o700);private_directory(directory)\n for name,raw in raws.items():put(directory/name,raw)\n put(directory/\'source-manifest.json\',(json.dumps({\'schema_version\':1,\'files\':q[\'files\']},sort_keys=True)+\'\\n\').encode())\n\ndef relay(transport,work,args,payload,cap,guard):\n receipt=Path(tempfile.mkdtemp(prefix=\'backup-transport-\',dir=work));receipt.chmod(0o700)\n output=receipt/\'stdout\';outfd=os.open(output,os.O_RDWR|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_CLOEXEC,0o600)\n try:\n  guard();transport.command(receipt,args,\'guest-relay\',input_bytes=payload,stdout_fd=outfd,timeout=360,file_limit=cap)\n  os.fsync(outfd);held=identity(os.fstat(outfd));need(held==identity(output.lstat()) and stat.S_ISREG(held[2]) and held[3:6]==(0,0,1) and stat.S_IMODE(held[2])==0o600 and held[6]<=cap,\'guest_transport_postimage_changed\');guard();offset=0\n  while offset<held[6]:\n   raw=os.pread(outfd,min(1048576,held[6]-offset),offset);need(bool(raw),\'guest_transport_short_read\');sys.stdout.buffer.write(raw);offset+=len(raw)\n  sys.stdout.buffer.flush();need(held==identity(os.fstat(outfd))==identity(output.lstat()),\'guest_transport_postimage_changed\');guard()\n finally:os.close(outfd)\n\n\ntry:\n need(os.geteuid()==0 and re.fullmatch(\'[a-f0-9]{32}\',q[\'operation_id\']),\'root_operation_binding\')\n role=q[\'role\'];phase=q[\'phase\']\n allowed={\'Guard\':{\'check\'},\'Guest\':{\'stage\',\'check\',\'prepare\',\'configure\',\'snapshot-seal\',\'export-public\',\'export-etcdutl\',\'export-envelope\'},\'Tarragon\':{\'stage\',\'check\',\'init-keys\',\'export-public\',\'stage-etcdutl\',\'configure\',\'receive\',\'verify-restore\'},\'Slipstream\':{\'stage\',\'check\',\'init-keys\',\'export-public\',\'stage-etcdutl\',\'configure\',\'receive\',\'verify-restore\'}}\n need(role in allowed and phase in allowed[role],\'typed_phase_required\')\n if role in [\'Guard\',\'Guest\']:\n  life=module(Path(\'/root/nebula-alpha-lifecycle-7c93lt9w/lifecycle-6b4ae6.py\'),\'6b4ae6d7be5ed6a21db251c8da6e103c251da803819fa820e788cdb7abfcad90\',\'_approved_backup_alpha\')\n  lock=Path(\'/var/lock/nebula-alpha-bootstrap.lock\');lfd=os.open(lock,os.O_RDWR|os.O_NOFOLLOW);held=identity(os.fstat(lfd));need(held[3:7]==(0,0,1,0) and stat.S_IMODE(held[2])==0o600,\'alpha_lock_custody\');fcntl.flock(lfd,fcntl.LOCK_EX|fcntl.LOCK_NB)\n  try:\n   work=Path(\'/var/lib/parallax-nebula-bootstrap/plan-\'+q[\'run_id\']);j=managed_lifecycle(work,lambda:need(identity(os.fstat(lfd))==identity(lock.lstat())==held,\'alpha_lock_changed\'))\n   if role==\'Guard\':print(json.dumps({\'status\':\'passed\',\'alpha_fleet_relay_guards\':True,\'managed_owner_health_checked\':True}));raise SystemExit(0)\n   known=life.read(work/\'guest-known-hosts\',private=True).decode().splitlines();need(len(known)==1 and len(known[0].split())==3,\'guest_knownhost_binding\');address=known[0].split()[0]\n   need(ipaddress.ip_address(address) in ipaddress.ip_network(j.plan[\'network\'][\'subnet\']),\'guest_address_scope\')\n   receiver=GUEST_RECEIVER\n   public_input=sys.stdin.buffer.read(1048577) if phase in [\'configure\',\'stage\'] else b\'\';need(len(public_input)<=1048576,\'public_input_bound\')\n   x={\'operation_id\':q[\'operation_id\'],\'phase\':phase,\'files\':q[\'files\'],\'uuid\':j.plan[\'new_domain_uuid\'],\'run_id\':q[\'run_id\'],\'address\':address,\'public_input\':public_input.decode() if public_input else None}\n   code="import json,sys\\nx=json.loads(sys.stdin.buffer.read(2097153))\\n"+receiver\n   args=[\'ssh\',\'-F\',\'/dev/null\',\'-T\',\'-i\',str(work/\'guest-client\'),\'-o\',\'BatchMode=yes\',\'-o\',\'ControlMaster=no\',\'-o\',\'ControlPath=none\',\'-o\',\'ControlPersist=no\',\'-o\',\'IdentitiesOnly=yes\',\'-o\',\'IdentityAgent=none\',\'-o\',\'ForwardAgent=no\',\'-o\',\'ClearAllForwardings=yes\',\'-o\',\'ProxyCommand=none\',\'-o\',\'ProxyJump=none\',\'-o\',\'PermitLocalCommand=no\',\'-o\',\'PreferredAuthentications=publickey\',\'-o\',\'GSSAPIAuthentication=no\',\'-o\',\'HostbasedAuthentication=no\',\'-o\',\'PasswordAuthentication=no\',\'-o\',\'KbdInteractiveAuthentication=no\',\'-o\',\'StrictHostKeyChecking=yes\',\'-o\',\'UserKnownHostsFile=\'+str(work/\'guest-known-hosts\'),\'-o\',\'GlobalKnownHostsFile=/dev/null\',\'-o\',\'ConnectTimeout=8\',\'nebula@\'+address,shlex.join([\'sudo\',\'-n\',\'python3\',\'-I\',\'-c\',code])]\n   common_directory=Path(\'/root/nebula-backup-sources\')/q[\'operation_id\']\n   if phase==\'stage\':stage_bundle(common_directory,\'nebula-backup-common.py\',json.loads(public_input))\n   transport=verify_bundle(common_directory,\'nebula-backup-common.py\')\n   cap=1024**3+65536 if phase==\'export-envelope\' else 64*1024**2 if phase==\'export-etcdutl\' else 512*1024\n   relay(transport,work,args,json.dumps(x).encode(),cap,j.guard)\n  finally:os.close(lfd)\n else:\n  directory=Path(\'/root/nebula-backup-sources\')/q[\'operation_id\']\n  if phase==\'stage\':\n   need(__import__(\'socket\').gethostname().split(\'.\')[0].lower()==role.lower(),\'target_hostname_binding\');body=sys.stdin.buffer.read(1048577);need(len(body)<=1048576,\'stage_input_bound\');payload=json.loads(body);stage_bundle(directory,\'nebula-backup-target.py\',payload)\n   fixed=\'/backup/parallax-nebula\' if role==\'Tarragon\' else \'/var/lib/parallax-nebula-backups\'\n   put(directory/\'target-plan.json\',(json.dumps({\'schema_version\':1,\'operation_id\':q[\'operation_id\'],\'target\':role,\'namespace\':fixed,\'minimum_free_bytes\':(40 if role==\'Tarragon\' else 12)*1024**3},sort_keys=True)+\'\\n\').encode())\n   print(json.dumps({\'status\':\'passed\',\'phase\':\'stage\',\'inert_sources_and_private_plan_only\':True}));raise SystemExit(0)\n  m=verify_bundle(directory,\'nebula-backup-target.py\')\n  plan=directory/\'target-plan.json\';fd=os.open(plan,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)\n  try:\n   s=os.fstat(fd);need(stat.S_ISREG(s.st_mode) and s.st_uid==0 and s.st_gid==0 and s.st_nlink==1 and stat.S_IMODE(s.st_mode)==0o600 and s.st_size<8192,\'target_plan_custody\');v=json.loads(os.read(fd,8192));need(v.get(\'operation_id\')==q[\'operation_id\'] and v.get(\'target\')==role,\'target_plan_binding\')\n  finally:os.close(fd)\n  sys.argv=[str(directory/\'nebula-backup-target.py\'),\'--plan\',str(plan),\'--phase\',phase]\n  if phase not in [\'check\',\'export-public\']:sys.argv.append(\'--execute\')\n  if phase==\'stage-etcdutl\':sys.argv+=[\'--artifact-sha256\',q[\'artifact_sha256\'],\'--artifact-bytes\',str(q[\'artifact_bytes\'])]\n  m.main()\nexcept SystemExit:raise\nexcept Exception:\n print(json.dumps({\'status\':\'refused\',\'reason\':\'remote_typed_phase_failed_private_receipts\'}),file=sys.stderr);raise SystemExit(1)\n'
GUEST_RECEIVER="\nimport hashlib,json,os,socket,stat,sys,types\nfrom pathlib import Path\nos.umask(0o077)\ndef need(v,c='guest_stage_guard'):\n if not v:raise RuntimeError(c)\ndef identity(s):return(s.st_dev,s.st_ino,s.st_mode,s.st_uid,s.st_gid,s.st_nlink,s.st_size,s.st_mtime_ns,s.st_ctime_ns)\nq=x\n\ndef private_directory(p,create=False):\n need(p.is_absolute() and p.resolve()==p,'stage_directory_canonical')\n if not os.path.lexists(p):\n  need(create,'stage_parent_missing');parent=p.parent.lstat();need(stat.S_ISDIR(parent.st_mode) and parent.st_uid==0 and stat.S_IMODE(parent.st_mode)&0o022==0,'stage_parent_custody');p.mkdir(mode=0o700)\n s=p.lstat();need(stat.S_ISDIR(s.st_mode) and s.st_uid==0 and s.st_gid==0 and stat.S_IMODE(s.st_mode)==0o700,'stage_private_directory')\ndef put(p,raw):\n fd=os.open(p,os.O_CREAT|os.O_EXCL|os.O_WRONLY|os.O_NOFOLLOW,0o600)\n try:\n  with os.fdopen(os.dup(fd),'wb') as out:out.write(raw);out.flush();os.fsync(out.fileno())\n  a=os.fstat(fd);b=p.lstat();need(identity(a)==identity(b) and a.st_size==len(raw),'stage_file_postimage')\n finally:os.close(fd)\ndef stage_bundle(directory,entry,payloads):\n required=['nebula-backup-common.py','nebula-backup-envelope-policy.py',entry];raws={}\n need(set(payloads)==set(q['files']),'stage_public_inventory')\n for name in required:\n  raw=__import__('base64').b64decode(payloads[name],validate=True);need(len(raw)<262144 and hashlib.sha256(raw).hexdigest()==q['files'][name],'stage_public_source_pin');compile(raw,name,'exec');raws[name]=raw\n private_directory(directory.parent,True);need(not os.path.lexists(directory),'stage_new_operation_directory');directory.mkdir(mode=0o700);private_directory(directory)\n for name,raw in raws.items():put(directory/name,raw)\n put(directory/'source-manifest.json',(json.dumps({'schema_version':1,'files':q['files']},sort_keys=True)+'\\n').encode())\n\nneed(os.geteuid()==0 and Path('/sys/class/dmi/id/product_uuid').read_text().strip().lower()==x['uuid'] and socket.gethostname()=='nebula-control-'+x['run_id'])\ndirectory=Path('/var/lib/parallax-nebula-backup-sources')/x['operation_id']\nif x['phase']=='stage':\n payload=json.loads(x['public_input']);stage_bundle(directory,'nebula-backup-guest.py',payload)\n parent=Path('/var/lib/parallax-nebula-backup-plans');private_directory(parent,True)\n put(parent/(x['operation_id']+'.json'),(json.dumps({'schema_version':1,'operation_id':x['operation_id'],'run_id':x['run_id'],'expected_uuid':x['uuid'],'api_address':x['address']},sort_keys=True)+'\\n').encode())\n print(json.dumps({'status':'passed','phase':'stage','inert_sources_and_private_plan_only':True}));raise SystemExit(0)\ns=directory.lstat();need(directory.resolve()==directory and s.st_uid==0 and s.st_gid==0 and stat.S_IMODE(s.st_mode)==0o700)\nraws={}\nfor name in ['nebula-backup-common.py','nebula-backup-envelope-policy.py','nebula-backup-guest.py']:\n p=directory/name;fd=os.open(p,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)\n try:\n  s=os.fstat(fd);raw=os.read(fd,262144);need(stat.S_ISREG(s.st_mode) and s.st_uid==0 and s.st_gid==0 and s.st_nlink==1 and stat.S_IMODE(s.st_mode)==0o600 and s.st_size==len(raw) and hashlib.sha256(raw).hexdigest()==x['files'][name]);raws[name]=raw\n finally:os.close(fd)\nplan=Path('/var/lib/parallax-nebula-backup-plans')/(x['operation_id']+'.json');fd=os.open(plan,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)\ntry:\n s=os.fstat(fd);need(stat.S_ISREG(s.st_mode) and s.st_uid==0 and s.st_gid==0 and s.st_nlink==1 and stat.S_IMODE(s.st_mode)==0o600 and s.st_size<8192);v=json.loads(os.read(fd,8192));need(v=={'schema_version':1,'operation_id':x['operation_id'],'run_id':x['run_id'],'expected_uuid':x['uuid'],'api_address':x['address']})\nfinally:os.close(fd)\nm=types.ModuleType('_approved_backup_guest');m.__file__=str(directory/'nebula-backup-guest.py');sys.modules[m.__name__]=m;exec(compile(raws['nebula-backup-guest.py'],m.__file__,'exec'),m.__dict__)\nsys.argv=[m.__file__,'--plan',str(plan),'--phase',x['phase']]\nif x['phase'] not in ['check','export-public','export-etcdutl','export-envelope']:sys.argv.append('--execute')\nif x['phase']=='configure':\n p=directory/'public-recipients.json';raw=x['public_input'].encode();need(len(raw)<=262144);fd=os.open(p,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)\n try:\n  with os.fdopen(os.dup(fd),'wb') as out:out.write(raw);out.flush();os.fsync(out.fileno())\n  need(os.fstat(fd).st_ino==p.lstat().st_ino and os.fstat(fd).st_size==len(raw))\n finally:os.close(fd)\n sys.argv+=['--input',str(p)]\nm.main()\n"
FileRecord=namedtuple('FileRecord','path identity sha256 limit')

class PrivateResult:
 def __init__(self,path,state):
  self.path=path;self.fd=None
  need(path.is_absolute() and path.parent.resolve()==path.parent and path.name not in ['', '.', '..'],'canonical_private_result_path')
  need(state.is_absolute() and state.parent.resolve()==state.parent and path!=state and state not in path.parents,'private_result_outside_operation_state')
  need(not os.path.lexists(path),'private_result_must_be_new')
  fd=os.open(path.parent,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC)
  try:
   st=os.fstat(fd);need(stat.S_ISDIR(st.st_mode) and st.st_uid==os.geteuid() and st.st_gid==os.getegid() and stat.S_IMODE(st.st_mode)==0o700,'private_result_parent_custody')
   self.parent_identity=tuple(meta(st)[:5]);self.fd=fd;self.guard()
  except BaseException:self.fd=None;os.close(fd);raise
 def guard(self,absent=True):
  need(self.fd is not None and self.path.parent.resolve()==self.path.parent,'private_result_parent_changed')
  need(tuple(meta(os.fstat(self.fd))[:5])==self.parent_identity==tuple(meta(self.path.parent.lstat())[:5]),'private_result_parent_changed')
  if absent:need(not os.path.lexists(self.path),'private_result_must_be_new')
 def write(self,value):
  self.guard();raw=bytes_json(value);need(len(raw)<=65536,'private_result_bound')
  fd=os.open(self.path.name,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_CLOEXEC,0o600,dir_fd=self.fd)
  try:
   os.fchmod(fd,0o600);write_all(fd,raw);os.fsync(fd);known=tuple(meta(os.fstat(fd)));need(known[5]==1 and known[6]==len(raw),'private_result_postimage_changed')
   self.guard(False);body,current=local_read(self.path,65536);need(tuple(current)==known and body==raw,'private_result_postimage_changed');os.fsync(self.fd);self.guard(False);need(known==tuple(meta(os.fstat(fd)))==tuple(meta(self.path.lstat())),'private_result_postimage_changed')
   return FileRecord(self.path,known,sha(raw),len(raw))
  finally:os.close(fd)
 def close(self):
  if self.fd is not None:os.close(self.fd);self.fd=None

class Orchestrator:
 def __init__(self,manifest_path,manifest_sha,operation_id,state,managed_health_overlay,expected_head_sha256,deadline=None):
  self.deadline=time.monotonic()+510 if deadline is None else deadline;self.budget_guard();need(type(expected_head_sha256) is str and (expected_head_sha256=='none' or re.fullmatch('[a-f0-9]{64}',expected_head_sha256)),'expected_head_argument_required');self.expected_head_sha256=expected_head_sha256
  need(re.fullmatch('[a-f0-9]{32}',operation_id),'operation_id_required');self.id=operation_id;raw,self.manifest_meta=local_read(manifest_path,8192);need(sha(raw)==manifest_sha,'bundle_manifest_pin')
  self.manifest=decode(raw);self.manifest_sha256=manifest_sha;self.managed_health_overlay=overlay_path(managed_health_overlay);self.bundle_root=manifest_path.parent;need(set(self.manifest)=={'schema_version','files'} and type(self.manifest['schema_version']) is int and self.manifest['schema_version']==1 and set(self.manifest['files'])==NAMES,'bundle_manifest_schema')
  need(self.manifest['files']['nebula-backup-common.py']==COMMON_SHA,'accepted_common_pin_required');self.source_records={manifest_path:tuple(self.manifest_meta)};sources={}
  for name,pin in self.manifest['files'].items():
   need(re.fullmatch('[a-f0-9]{64}',pin),'source_digest_required');source,identity=local_read(manifest_path.parent/name,262144,False);need(sha(source)==pin,'local_source_pin');self.source_records[manifest_path.parent/name]=tuple(identity);sources[name]=source
  common_path=self.bundle_root/'nebula-backup-common.py';self.common=types.ModuleType('_backup_controller_common');self.common.__file__=str(common_path);exec(compile(sources[common_path.name],str(common_path),'exec'),self.common.__dict__)
  self.state=state;need(state.is_absolute() and state.parent.resolve()==state.parent and state.name=='nebula-backup-orchestrator-'+operation_id,'fixed_local_state_namespace')
  if not os.path.lexists(state):state.mkdir(mode=0o700)
  st=state.lstat();need(stat.S_ISDIR(st.st_mode) and st.st_uid==os.geteuid() and st.st_gid==os.getegid() and stat.S_IMODE(st.st_mode)==0o700,'private_local_state')
  self.state_meta=meta(st)[:5];self.records={};self.lockfd=None;self.lock_meta=None;self.results={};self.completed=[];self.pending=None;self.operation_record=None;self.dispatched=False
  self.targets={'Slipstream':'slipstream.host'}
  for label,session,host in [('Guest','rollout-alpha','alpha.wphyperdrive.com'),('Guard','rollout-alpha','alpha.wphyperdrive.com'),('Tarragon','rollout-tarragon','tarragon.app')]:
   data,_=local_read(ROOT/'.runtime'/session/'session.json',2*1024**2)
   value=json.loads(data)['ssh_target'];need(type(value) is str and not value.startswith('-') and not any(c.isspace() for c in value) and value.split('@')[-1]==host,'existing_owned_ssh_pin');self.targets[label]=value
 def acquire_lock(self):
  need(self.lockfd is None,'operation_lock_already_held');path=self.state/'operation.lock';fd=os.open(path,os.O_CREAT|os.O_RDWR|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC,0o600)
  try:
   st=os.fstat(fd);need(stat.S_ISREG(st.st_mode) and st.st_uid==os.geteuid() and st.st_gid==os.getegid() and st.st_size==0 and st.st_nlink==1 and stat.S_IMODE(st.st_mode)==0o600,'local_lock_custody');fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB);self.lockfd=fd;self.lock_meta=meta(st);self.guard_local();self.load_ledger()
  except BaseException:self.lockfd=None;os.close(fd);raise
 def close(self):
  if self.lockfd is not None:os.close(self.lockfd);self.lockfd=None
 def budget_guard(self):need(time.monotonic()<self.deadline,'whole_step_deadline_exhausted')
 def guard_local(self):
  self.budget_guard();need(meta(self.state.lstat())[:5]==self.state_meta,'local_state_changed');need(self.lockfd is not None,'operation_lock_required')
  need(meta(os.fstat(self.lockfd))==self.lock_meta==meta((self.state/'operation.lock').lstat()),'local_lock_changed')
  for path,identity in self.source_records.items():need(tuple(meta(path.lstat()))==identity,'local_source_changed')
  for path,record in self.records.items():need(tuple(meta(path.lstat()))==record.identity,'owned_file_changed')
 def _record_fd(self,path,fd,limit,expected=None):
  self.budget_guard();before=os.fstat(fd);identity=tuple(meta(before));need(stat.S_ISREG(before.st_mode) and before.st_uid==os.geteuid() and before.st_gid==os.getegid() and before.st_nlink==1 and stat.S_IMODE(before.st_mode)==0o600 and 0<=before.st_size<=limit,'transport_file_custody')
  if expected is not None:need(identity==expected,'owned_file_changed')
  h=hashlib.sha256();offset=0
  while offset<before.st_size:
   self.budget_guard();raw=os.pread(fd,min(1048576,before.st_size-offset),offset);need(bool(raw),'transport_file_short_read');h.update(raw);offset+=len(raw)
  need(identity==tuple(meta(os.fstat(fd)))==tuple(meta(path.lstat())),'transport_postimage_changed');return FileRecord(path,identity,h.hexdigest(),limit)
 def _known(self,record):
  need(type(record) is FileRecord and self.records.get(record.path)==record,'verified_transport_record_required');return record
 @contextlib.contextmanager
 def held_input(self,record):
  self.guard_local();record=self._known(record);fd=os.open(record.path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC)
  try:
   need(self._record_fd(record.path,fd,record.limit,record.identity)==record,'owned_file_changed');os.lseek(fd,0,os.SEEK_SET);yield fd
   need(self._record_fd(record.path,fd,record.limit,record.identity)==record,'transfer_input_changed');self.guard_local()
  finally:os.close(fd)
 def put(self,path,raw):
  self.guard_local();identity=exclusive(path,raw);fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC)
  try:record=self._record_fd(path,fd,len(raw),identity);need(record.sha256==sha(raw),'local_postimage_changed');self.records[path]=record;self.guard_local();return record
  finally:os.close(fd)
 def remote(self,role,phase,label,input_path=None,cap=512*1024,artifact=None):
  self.guard_local();need(role=='Guard' or role in ROLE_PHASES,'typed_role_required');allowed={'check'} if role=='Guard' else ROLE_PHASES[role];need(phase in allowed,'typed_phase_required');need(type(cap) is int and 0<cap<=1024**3+65536,'transport_output_limit')
  q={'operation_id':self.id,'run_id':RUN_ID,'role':role,'phase':phase,'files':self.manifest['files'],'allowed_phases':sorted(allowed),'managed_health_overlay':self.managed_health_overlay}
  if artifact:q.update(artifact)
  code="import json,base64\nq=json.loads(base64.b64decode("+repr(base64.b64encode(bytes_json(q)).decode())+"))\nGUEST_RECEIVER="+repr(GUEST_RECEIVER)+"\n"+BROKER
  cmd=['ssh','-o','BatchMode=yes','-o','StrictHostKeyChecking=yes','-o','ControlMaster=no','-o','ControlPath=none','-o','ControlPersist=no','-o','ConnectTimeout=8','-o','ForwardAgent=no','-o','ClearAllForwardings=yes','-o','PermitLocalCommand=no','-T',self.targets[role],shlex.join(['python3','-I','-c',code])]
  label=label+'-'+os.urandom(6).hex();output=self.state/(label+'.stdout');ofd=os.open(output,os.O_CREAT|os.O_EXCL|os.O_RDWR|os.O_NOFOLLOW|os.O_CLOEXEC,0o600)
  try:
   with self.held_input(input_path) if input_path is not None else contextlib.nullcontext(None) as ifd:
    self.guard_local();timeout=min(45 if role=='Guard' else 420,self.deadline-time.monotonic()-25);need(timeout>0,'whole_step_cleanup_reserve_required');self.common.command(self.state,cmd,label,stdin_fd=ifd,stdout_fd=ofd,timeout=timeout,file_limit=cap,local_controller=True);os.fsync(ofd);record=self._record_fd(output,ofd,cap);self.records[output]=record;self.guard_local();return record
  finally:os.close(ofd)
 def read_record(self,record,limit):
  record=self._known(record);need(record.identity[6]<=limit,'result_size_bound')
  with self.held_input(record) as fd:
   raw=os.pread(fd,limit+1,0);need(len(raw)==record.identity[6] and sha(raw)==record.sha256,'owned_file_changed');return raw
 def result(self,record):
  raw=self.read_record(record,512*1024);v=decode(raw);need(type(v) is dict,'safe_json_result_required');return v
 def require_pass(self,record):
  v=self.result(record);need(v.get('status')=='passed','remote_safe_result_refused');return v
 def outer_guard(self,label):self.require_pass(self.remote('Guard','check',label))
 def mark(self,name,value):return self.put(self.state/name,bytes_json(value))
 def binding(self):return {'schema_version':2,'controller_profile':'managed-single-step-v1','operation_id':self.id,'manifest_sha256':self.manifest_sha256,'managed_health_overlay':self.managed_health_overlay,'managed_bridge_sha256':BRIDGE_SHA,'common_sha256':COMMON_SHA}
 def encode_record(self,record):
  record=self._known(record);need(record.path.parent==self.state,'ledger_record_outside_state');return {'name':record.path.name,'identity':list(record.identity),'sha256':record.sha256,'limit':record.limit}
 def load_record(self,value):
  need(type(value) is dict and set(value)=={'name','identity','sha256','limit'},'file_ledger_schema');name=value['name'];identity=value['identity'];limit=value['limit'];need(type(name) is str and re.fullmatch('[a-z0-9.-]{1,128}',name) and name not in ['.','..','operation.lock'],'file_ledger_name');need(type(identity) is list and len(identity)==9 and all(type(v) is int for v in identity) and type(limit) is int and 0<limit<=1024**3+65536 and type(value['sha256']) is str and re.fullmatch('[a-f0-9]{64}',value['sha256']),'file_ledger_values');record=FileRecord(self.state/name,tuple(identity),value['sha256'],limit)
  fd=os.open(record.path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC)
  try:need(self._record_fd(record.path,fd,limit,record.identity)==record,'ledger_file_changed')
  finally:os.close(fd)
  known=self.records.get(record.path);need(known is None or known==record,'ledger_file_conflict');self.records[record.path]=record;return record
 def load_ledger(self):
  self.guard_local();path=self.state/'operation.json';binding=self.binding()
  if not os.path.lexists(path):
   need(self.expected_head_sha256=='none','expected_head_changed');need({p.name for p in self.state.iterdir()}=={'operation.lock'},'new_operation_ledger_required');self.operation_record=self.put(path,bytes_json(binding));self.verify_expected_head();return
  raw,identity=local_read(path,8192);need(decode(raw)==binding,'operation_binding_changed');self.operation_record=FileRecord(path,tuple(identity),sha(raw),len(raw));self.records[path]=self.operation_record
  expected={step+suffix for step in STEPS for suffix in ['.started.json','.complete.json']};actual={p.name for p in self.state.iterdir() if '.started' in p.name or '.complete' in p.name};need(actual<=expected,'unknown_or_legacy_step_ledger');previous=None;gap=False
  for step in STEPS:
   started=self.state/(step+'.started.json');complete=self.state/(step+'.complete.json');has_start=os.path.lexists(started);has_complete=os.path.lexists(complete);need(not has_complete or has_start,'completion_without_attempt');need(not gap or not has_start,'step_order_differs')
   if not has_start:gap=True;continue
   raw,start_meta=local_read(started,16384);v=decode(raw);expected_start={**binding,'step':step,'status':'started','operation_record':self.encode_record(self.operation_record),'predecessor':self.encode_record(previous) if previous else None};need(v==expected_start,'step_attempt_binding_changed');start_record=FileRecord(started,tuple(start_meta),sha(raw),len(raw));self.records[started]=start_record
   if not has_complete:self.pending=step;gap=True;continue
   raw,complete_meta=local_read(complete,65536);v=decode(raw);need(type(v) is dict and set(v)==set(binding)|{'step','status','operation_record','predecessor','attempt_record','files','result'},'step_completion_schema');need(all(v[k]==val for k,val in binding.items()) and v['step']==step and v['status']=='passed' and v['operation_record']==self.encode_record(self.operation_record) and v['predecessor']==(self.encode_record(previous) if previous else None) and v['attempt_record']==self.encode_record(start_record),'step_completion_binding_changed');need(type(v['files']) is list and 1<=len(v['files'])<=16,'step_file_inventory_bound');files=[self.load_record(item) for item in v['files']];need(len({r.path for r in files})==len(files),'duplicate_step_file');result=self.load_record(v['result']);need(result in files,'step_result_not_in_inventory');self.results[step]=result;record=FileRecord(complete,tuple(complete_meta),sha(raw),len(raw));self.records[complete]=record;self.completed.append(step);previous=record
  self.guard_local();self.verify_expected_head()
 def previous(self):return self.records[self.state/(self.completed[-1]+'.complete.json')] if self.completed else None
 def head_record(self):
  previous=self.previous();return self.encode_record(previous) if previous else None
 def head_sha256(self):
  record=self.head_record();return sha(bytes_json(record)) if record is not None else 'none'
 def verify_expected_head(self,pending_step=None):
  self.guard_local();need(self.pending is None or (pending_step is not None and self.pending==pending_step),'unknown_partial_requires_review');need(self.head_sha256()==self.expected_head_sha256,'expected_head_changed')
 def public_configuration(self):
  exports={role:self.result(self.results['public-'+role.lower()]) for role in ['Tarragon','Slipstream']};recipients={};keys={}
  for role,v in exports.items():
   need(type(v.get('schema_version')) is int and v['schema_version']==1 and v.get('operation_id')==self.id and v.get('target')==role,'public_recovery_export_binding')
   for key in ['primary_fingerprint','encryption_subkey_fingerprint']:need(type(v.get(key)) is str and re.fullmatch('[A-F0-9]{40}',v[key]),'exact_public_recipient_pin')
   recipients[role]={k:v[k] for k in ['primary_fingerprint','encryption_subkey_fingerprint']};keys[role]=v['public_key_armored'];need(type(keys[role]) is str and len(keys[role])<=65536 and 'PRIVATE KEY' not in keys[role] and 'SECRET KEY' not in keys[role],'public_key_only')
  primary={v['primary_fingerprint'] for v in recipients.values()};sub={v['encryption_subkey_fingerprint'] for v in recipients.values()};need(len(primary)==len(sub)==2 and primary.isdisjoint(sub),'independent_recipients_required');source=self.result(self.results['public-guest']);need(type(source.get('schema_version')) is int and source['schema_version']==1 and source.get('operation_id')==self.id and source.get('etcd_version')=='3.7.0','source_public_export_binding');need(type(source.get('signer_public_pem')) is str and source['signer_public_pem'].startswith('-----BEGIN PUBLIC KEY-----') and sha(source['signer_public_pem'].encode())==source.get('signer_public_sha256'),'pinned_signer_public');n=source.get('etcdutl_bytes');pin=source.get('etcdutl_sha256');need(type(n) is int and 0<n<=64*1024**2 and type(pin) is str and re.fullmatch('[a-f0-9]{64}',pin),'public_tool_metadata');return recipients,keys,source
 def dispatch(self,step):
  role,phase=STEP_REMOTE[step];input_file=None;artifact=None;cap=512*1024
  if step.startswith('stage-') and not step.startswith('stage-tool-'):input_file=self.put(self.state/(step+'-public-sources.json'),bytes_json({name:base64.b64encode(local_read(self.bundle_root/name,262144,False)[0]).decode() for name in sorted(NAMES)}))
  elif step in ['configure-guest','configure-tarragon','configure-slipstream']:
   recipients,keys,source=self.public_configuration();value={'schema_version':1,'operation_id':self.id,'recipients':recipients}
   if role=='Guest':value['public_keys']=keys
   else:value.update({k:source[k] for k in ['signer_public_pem','signer_public_sha256','etcd_version','etcdutl_sha256','etcdutl_bytes']})
   input_file=self.put(self.state/(step+'-public-input.json'),bytes_json(value))
  elif step in ['stage-tool-tarragon','stage-tool-slipstream']:
   _,_,source=self.public_configuration();input_file=self.results['export-tool'];artifact={'artifact_sha256':source['etcdutl_sha256'],'artifact_bytes':source['etcdutl_bytes']}
  elif step in ['receive-tarragon','receive-slipstream']:input_file=self.results['export-envelope']
  elif step=='export-tool':_,_,source=self.public_configuration();cap=source['etcdutl_bytes']
  elif step=='export-envelope':cap=1024**3+65536
  result=self.remote(role,phase,step,input_path=input_file,cap=cap,artifact=artifact)
  if phase=='export-public':self.result(result)
  elif step=='export-tool':raw=self.read_record(result,cap);need(len(raw)==cap and sha(raw)==source['etcdutl_sha256'],'public_etcdutl_transport_digest')
  elif step!='export-envelope':
   v=self.require_pass(result)
   if phase=='verify-restore':need(v.get('target')==role and all(v.get(k) is True for k in ['signature_verified','own_recovery_key_verified','independent_snapshot_status_verified','offline_restore_verified','authenticated_decryption_verified','isolated_restore_verified','no_listener_started','critical_recovery_material_verified','mark_compacted']) and v.get('listeners_started') is False and v.get('private_data_exported') is False and type(v.get('revision_bump')) is int and v['revision_bump']==1000000000,'each_target_restore_acceptance_required')
  return result
 def run_step(self,step):
  need(step in STEPS+CHECK_STEPS,'typed_step_required');need(not self.dispatched,'one_step_per_invocation');self.dispatched=True;self.guard_local();self.verify_expected_head();mutating=step in STEPS;previous=self.previous();before=set(self.records)
  if mutating:
   need(self.pending is None,'unknown_partial_requires_review');need(len(self.completed)<len(STEPS) and step==STEPS[len(self.completed)],'next_exact_step_required');attempt=self.put(self.state/(step+'.started.json'),bytes_json({**self.binding(),'step':step,'status':'started','operation_record':self.encode_record(self.operation_record),'predecessor':self.encode_record(previous) if previous else None}));self.pending=step
  self.outer_guard(step+'-before');self.verify_expected_head(step if mutating else None);result=self.dispatch(step);self.outer_guard(step+'-after');self.verify_expected_head(step if mutating else None)
  if mutating:
   files=[record for path,record in self.records.items() if path not in before and record!=attempt];complete=self.put(self.state/(step+'.complete.json'),bytes_json({**self.binding(),'step':step,'status':'passed','operation_record':self.encode_record(self.operation_record),'predecessor':self.encode_record(previous) if previous else None,'attempt_record':self.encode_record(attempt),'files':[self.encode_record(record) for record in files],'result':self.encode_record(result)}));self.pending=None;self.completed.append(step);self.results[step]=result;self.expected_head_sha256=sha(bytes_json(self.encode_record(complete)));self.verify_expected_head()
  return result
def main():
 os.umask(0o077);p=argparse.ArgumentParser(description=__doc__);p.add_argument('--bundle-manifest',type=Path,required=True);p.add_argument('--manifest-sha256',required=True);p.add_argument('--operation-id',required=True);p.add_argument('--state',type=Path,required=True);p.add_argument('--managed-health-overlay',required=True);p.add_argument('--expected-head-sha256',required=True);p.add_argument('--private-result',type=Path,required=True);p.add_argument('--step',choices=STEPS+CHECK_STEPS,required=True);p.add_argument('--execute',action='store_true');a=p.parse_args();need(a.step in CHECK_STEPS or a.execute,'explicit_execute_required')
 deadline=time.monotonic()+510;capture=PrivateResult(a.private_result,a.state);j=None
 try:
  j=Orchestrator(a.bundle_manifest,a.manifest_sha256,a.operation_id,a.state,a.managed_health_overlay,a.expected_head_sha256,deadline=deadline)
  j.acquire_lock();j.run_step(a.step);j.guard_local();j.verify_expected_head()
  result={'status':'passed','step':a.step,'ciphertext_and_public_data_only':True,'source_private_material_exposed':False,'one_bounded_remote_step':True,'publisher_lifecycle_managed_externally':True,'no_scheduling_or_retention_cleanup':True,'head_record':j.head_record(),'head_sha256':j.head_sha256()}
  try:capture.write(result);j.guard_local();j.verify_expected_head()
  except BaseException:raise Refused('private_success_result_failed_manual_review_required')from None
  print(json.dumps({'status':'passed','step':a.step,'private_result':str(a.private_result)}))
 finally:
  if j is not None:j.close()
  capture.close()
if __name__=='__main__':
 try:main()
 except Exception as e:
  print(json.dumps({'status':'refused','reason':str(e) if isinstance(e,Refused) else type(e).__name__,'unknown_partial_preserved':True}),file=sys.stderr);raise SystemExit(1)

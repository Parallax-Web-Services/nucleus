#!/usr/bin/env python3
"""SOURCE ONLY: scoped retirement after managed owner acceptance.
SIGKILL only the four already-paused source-bound Python parents. Preserve
three original exclusive SSH children plus desktop/shared hub; no claim of
member engine/tunnel durability. No live authorization follows from this file.
"""
import argparse,fcntl,hashlib,json,os,pwd,re,signal,stat,subprocess,time,types
from pathlib import Path
QUIESCENCE_SHA='20da87c572d57971bffc9d27cbbc7261d49240db3bffa4a99000fb576482d59c'
EVIDENCE_SHA='ac5baf54f319e76168d967adb5e7a31444b3d355babb9fee7273b00f591276a0'
HEALTH_SHA='487a8c4af222935ec819e37d35f10fa34873b02949e3a45639f66d5d8582d497'
REMOTE_HEALTH=Path('/usr/local/lib/parallax-nebula-managed-v3/managed-health-overlay.py')
REMOTE_OVERLAY=Path('/etc/parallax/nebula-health/managed-owner.json')
class Refused(RuntimeError):pass
def need(ok,label):
 if not ok:raise Refused(label)
def load_quiescence(path):
 fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW)
 try:
  s=os.fstat(fd);need(path.resolve()==path and stat.S_ISREG(s.st_mode)and s.st_uid==s.st_gid==0 and stat.S_IMODE(s.st_mode)==0o600 and s.st_nlink==1 and s.st_size<=1024*1024,'quiescence_source_metadata_differs');data=os.read(fd,1024*1024+1);keys=['st_dev','st_ino','st_mode','st_uid','st_gid','st_nlink','st_size','st_mtime_ns','st_ctime_ns'];need(all(getattr(s,k)==getattr(os.fstat(fd),k)==getattr(path.lstat(),k)for k in keys)and hashlib.sha256(data).hexdigest()==QUIESCENCE_SHA,'quiescence_source_changed')
 finally:os.close(fd)
 m=types.ModuleType('accepted_quiescence');m.__file__=str(path);exec(compile(data,str(path),'exec'),m.__dict__);return m

def remote_health(q,job,overlay_id):
 # One administrative WSL action only. Use the existing user's authenticated
 # SSH alias in its own home; never copy its key into any remote account.
 uids={r['parent']['uid'][0]for r in job.data['controllers'].values()};need(len(uids)==1,'auditor_account_scope_differs');account=pwd.getpwuid(next(iter(uids)));need(account.pw_uid>0 and re.fullmatch('[a-z_][a-z0-9_-]*',account.pw_name),'auditor_account_unreviewed');nonce=job.data['quiescence_id']
 code="""from pathlib import Path
import hashlib,json,os,stat,types
p=Path(PATH);fd=os.open(p,os.O_RDONLY|os.O_NOFOLLOW)
try:
 s=os.fstat(fd);assert p.resolve()==p and stat.S_ISREG(s.st_mode)and s.st_uid==s.st_gid==0 and stat.S_IMODE(s.st_mode)==0o600 and s.st_nlink==1 and s.st_size<=1048576
 data=os.read(fd,1048577);keys=['st_dev','st_ino','st_mode','st_uid','st_gid','st_nlink','st_size','st_mtime_ns','st_ctime_ns'];assert all(getattr(s,k)==getattr(os.fstat(fd),k)==getattr(p.lstat(),k)for k in keys)and hashlib.sha256(data).hexdigest()==SHA
finally:os.close(fd)
m=types.ModuleType('accepted_health');m.__file__=str(p);exec(compile(data,str(p),'exec'),m.__dict__)
o=Path(OVERLAY);raw,r=m.read(o,65536);v=m.decode(raw);assert v['overlay_id']==OVERLAY_ID and v['quiescence_id']==NONCE
out=m.check(o);assert m.read(o,65536)[1]==r
print(json.dumps(out))
"""
 for token,value in{'PATH':str(REMOTE_HEALTH),'SHA':HEALTH_SHA,'OVERLAY_ID':overlay_id,'OVERLAY':str(REMOTE_OVERLAY),'NONCE':nonce}.items():code=code.replace(token,repr(value))
 p=subprocess.run(['/usr/sbin/runuser','-u',account.pw_name,'--','/usr/bin/ssh','-o','BatchMode=yes','-o','ConnectTimeout=5','-o','StrictHostKeyChecking=yes','-o','ForwardAgent=no','-o','ClearAllForwardings=yes','-o','PermitLocalCommand=no','slipstream.host','python3','-'],input=code.encode(),stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,timeout=15)
 need(p.returncode==0 and len(p.stdout)<=4096,'managed_health_unavailable');v=json.loads(p.stdout);expected={'schema_version','overlay_id','checked_at_unix','managed_owner_matches','cutover_receipt_unchanged','registered_node_count','required_server_count','required_server_online_count','same_fabric','required_server_resources_fresh'};need(set(v)==expected and type(v['schema_version'])is int and v['schema_version']==2 and v['overlay_id']==overlay_id,'managed_health_scope_differs');need(type(v['checked_at_unix'])is int and -5<=time.time()-v['checked_at_unix']<=5,'managed_health_not_fresh');need(all(v[k]is True for k in['managed_owner_matches','cutover_receipt_unchanged','same_fabric','required_server_resources_fresh'])and all(type(v[k])is int and v[k]==x for k,x in[('registered_node_count',5),('required_server_count',4),('required_server_online_count',4)]),'managed_health_not_ready');return v

def paused_signals(record):
 pid=record['parent']['pid'];lines=(Path('/proc')/str(pid)/'status').read_text().splitlines();fields={x.split(':',1)[0]:x.split(':',1)[1].strip()for x in lines if x.startswith(('SigPnd:','ShdPnd:','TracerPid:'))};need(set(fields)=={'SigPnd','ShdPnd','TracerPid'}and int(fields['TracerPid'])==0,'paused_parent_traced_or_signal_shape_differs');allowed=(1<<(signal.SIGCHLD-1))if record['role']=='owner'else 0;need(all(int(fields[k],16)&~allowed==0 for k in['SigPnd','ShdPnd']),'paused_parent_unreviewed_pending_signal')

def dead(pid,start):
 try:v=(Path('/proc')/str(pid)/'stat').read_text().split(') ',1)[1].split()
 except FileNotFoundError:return True
 return int(v[19])!=start or v[0]in['Z','X']
def survivors(q,record):
 pid=record['parent']['pid'];ids=(Path('/proc')/str(pid)/'task'/str(pid)/'children').read_text().split();live={}
 for child_pid in ids:
  need(child_pid in record['children'],'unexpected_controller_child');before=record['children'][child_pid]
  if dead(int(child_pid),before['process']['start']):continue
  need(q.child(int(child_pid))==before,'original_child_changed');live[child_pid]=before
 expected=set(record['protected_children'])if record['role']=='owner'else set(record['children']);need(set(live)==expected,'retirement_remaining_child_scope_differs');return live

def surviving_after(q,record,children):
 need(q.stable(q.process(record['outer']['pid']))==record['outer'],'outer_executor_changed')
 for pid,before in children.items():
  need(not dead(int(pid),before['process']['start']),'preserved_child_did_not_survive');after=q.child(int(pid));a=dict(after['process']);b=dict(before['process']);need(a.pop('ppid')==record['outer']['pid'],'child_not_reparented_to_proved_outer');b.pop('ppid');need(a==b and after['stdio']==before['stdio'],'reparented_child_context_changed')
 return True

class Retirement:
 def __init__(self,q,request,receipt):self.q=q;self.request=request;self.receipt=receipt;self.data=None;self.control=None;self.job=None
 def save(self):self.control=self.q.write(self.receipt/'control.json',(json.dumps(self.data,sort_keys=True,indent=2)+'\n').encode(),self.control)
 def load(self):
  self.control=self.q.private(self.receipt/'control.json');self.data=json.loads(self.q.raw(self.control));need(self.q.private(self.request)==self.data['request'],'retirement_request_changed');self.attach()
 def attach(self):
  c=self.data['config'];self.job=self.q.Quiescence(Path(c['quiescence_request']),Path(c['quiescence_receipt']));self.job.load();need(self.job.control==self.data['quiescence_control'],'quiescence_control_changed')
 def guard(self):need(self.q.private(self.receipt/'control.json')==self.control and self.q.private(self.request)==self.data['request'],'retirement_control_changed');self.job.guard()
 def remaining(self):
  self.guard()
  for pid,r in self.job.data['controllers'].items():
   if pid in self.data['retired']:
    need(dead(int(pid),r['parent']['start']),'retired_parent_reappeared');surviving_after(self.q,r,self.data['children'][pid]);continue
   p=self.q.process(int(pid));need(p['state']in['T','t']and self.q.stable(p)==r['parent']and self.q.sources(p)==r['sources'],'paused_parent_context_changed');paused_signals(r);need(self.q.stable(self.q.process(r['outer']['pid']))==r['outer']and {str(n):self.q.fd_record(int(pid),n)for n in range(3)}==r['stdio'],'parent_outer_or_stdio_changed');need(survivors(self.q,r)==self.data['children'][pid],'remaining_children_changed')
 def plan(self):
  request=self.q.private(self.request);c=json.loads(self.q.raw(request));need(set(c)=={'schema_version','quiescence_request','quiescence_receipt','evidence_report','health_overlay_id','acknowledge_foundation_quiescent'}and c['schema_version']==1 and c['acknowledge_foundation_quiescent']is True and re.fullmatch('[a-f0-9]{32}',c['health_overlay_id']),'retirement_request_scope_differs');report=self.q.private(Path(c['evidence_report']));need(hashlib.sha256(self.q.raw(report)).hexdigest()==EVIDENCE_SHA,'accepted_survival_evidence_changed');self.data={'schema_version':1,'phase':'planned','request':request,'config':c,'checked_at_unix':int(time.time()),'retired':[],'pending_retirement':None,'evidence_report':report};self.job=self.q.Quiescence(Path(c['quiescence_request']),Path(c['quiescence_receipt']));self.job.load();status=self.job.status();need(self.job.data.get('gate_ever_exported')is True,'managed_handoff_gate_missing');need(status['all_controllers_stopped']is True,'all_controllers_not_stopped');self.data['quiescence_control']=self.job.control;self.data['children']={pid:survivors(self.q,r)for pid,r in self.job.data['controllers'].items()};health=remote_health(self.q,self.job,c['health_overlay_id']);self.data['health_before']=health;self.save();self.remaining();return {'status':'retirement-planned','controller_count':4,'preserved_ssh_children':3,'shared_hub_and_desktop_preserved':True,'managed_owner_and_four_servers_fresh':True,'engine_or_tunnel_durability_claimed':False,'signals_performed':False}
 def resume_plan(self):
  self.load();need(self.data['phase']=='retiring','retirement_resume_phase_differs');self.guard();pending=self.data.get('pending_retirement')
  if pending is not None:
   need(pending in self.job.data['controllers']and pending not in self.data['retired'],'pending_retirement_scope_differs');r=self.job.data['controllers'][pending]
   if dead(int(pending),r['parent']['start']):surviving_after(self.q,r,self.data['children'][pending]);remote_health(self.q,self.job,self.data['config']['health_overlay_id']);self.data['retired'].append(pending)
   else:paused_signals(r)
   self.data['pending_retirement']=None
  self.remaining();remote_health(self.q,self.job,self.data['config']['health_overlay_id']);self.data['phase']='resume-planned';self.data['checked_at_unix']=int(time.time());self.save();return {'status':'retirement-resume-planned','retired_parent_count':len(self.data['retired']),'remaining_parent_count':4-len(self.data['retired']),'signals_performed':False,'unknown_state_preserved':True}
 def retire(self,acknowledge=False):
  need(acknowledge is True,'explicit_irreversible_retirement_required');self.load();need(self.data['phase']in['planned','resume-planned']and 0<=time.time()-self.data['checked_at_unix']<=120,'retirement_plan_expired_or_phase_differs');need(self.q.private(Path(self.data['config']['evidence_report']))==self.data['evidence_report'],'accepted_evidence_changed');self.remaining();fds={}
  try:
   for pid,r in self.job.data['controllers'].items():
    if pid not in self.data['retired']:fds[pid]=os.pidfd_open(int(pid),0)
   for pid,r in self.job.data['controllers'].items():
    if pid in self.data['retired']:continue
    self.remaining();remote_health(self.q,self.job,self.data['config']['health_overlay_id']);self.data['phase']='retiring';self.data['pending_retirement']=pid;self.save();self.remaining();signal.pidfd_send_signal(fds[pid],signal.SIGKILL,None,0);end=time.monotonic()+2
    while time.monotonic()<end:
     if dead(int(pid),r['parent']['start']):break
     time.sleep(.01)
    need(dead(int(pid),r['parent']['start']),'exact_parent_did_not_exit');surviving_after(self.q,r,self.data['children'][pid]);remote_health(self.q,self.job,self.data['config']['health_overlay_id']);self.data['retired'].append(pid);self.data['pending_retirement']=None;self.save();self.remaining()
   self.data['phase']='retired';self.save();return {'status':'retired','controller_count':4,'preserved_ssh_children':3,'shared_hub_and_desktop_preserved':True,'managed_owner_and_four_servers_fresh':True,'engine_or_tunnel_durability_claimed':False,'native_or_ssh_children_signaled':False,'no_term_int_group_or_relay_signals':True}
  finally:
   for fd in fds.values():os.close(fd)

def main():
 os.umask(0o077);need(os.geteuid()==0,'root_only');p=argparse.ArgumentParser(description=__doc__);p.add_argument('mode',choices=['plan','resume-plan','retire']);p.add_argument('--quiescence-source',type=Path,required=True);p.add_argument('--request',type=Path,required=True);p.add_argument('--receipt',type=Path,required=True);p.add_argument('--acknowledge-irreversible-parent-retirement',action='store_true');a=p.parse_args();q=load_quiescence(a.quiescence_source);need(re.fullmatch('nebula-controller-retirement-[a-f0-9]{16}',a.receipt.name)and a.receipt.is_absolute(),'explicit_retirement_receipt_required')
 if a.mode=='plan':need(not os.path.lexists(a.receipt),'retirement_receipt_collision');a.receipt.mkdir(mode=0o700)
 s=a.receipt.lstat();need(a.receipt.resolve()==a.receipt and stat.S_ISDIR(s.st_mode)and s.st_uid==s.st_gid==0 and stat.S_IMODE(s.st_mode)==0o700,'retirement_receipt_metadata_differs');request=json.loads(q.raw(q.private(a.request)));control_parent=Path(request['quiescence_receipt']);fd=os.open(control_parent/'operation.lock',os.O_RDWR|os.O_NOFOLLOW)
 try:
  st=os.fstat(fd);need(stat.S_ISREG(st.st_mode)and st.st_uid==st.st_gid==0 and stat.S_IMODE(st.st_mode)==0o600 and st.st_nlink==1 and st.st_size==0,'quiescence_lock_differs');fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB);need(q.ident(st)==q.ident((control_parent/'operation.lock').lstat()),'quiescence_lock_replaced');job=Retirement(q,a.request,a.receipt)
  try:result=job.plan()if a.mode=='plan'else job.resume_plan()if a.mode=='resume-plan'else job.retire(a.acknowledge_irreversible_parent_retirement)
  except Exception as e:
   result={'status':'refused','reason':str(e)if isinstance(e,(Refused,q.Refused))else type(e).__name__,'remaining_parents_not_resumed':True,'unknown_state_preserved':True,'no_automatic_recovery_or_cleanup':True};q.write(a.receipt/('failure-'+str(time.time_ns())+'.json'),(json.dumps(result)+'\n').encode())
  print(json.dumps(result));return 1 if result['status']=='refused'else 0
 finally:os.close(fd)
if __name__=='__main__':
 try:raise SystemExit(main())
 except Exception as e:print(json.dumps({'status':'refused','reason':str(e)if isinstance(e,Refused)else type(e).__name__,'no_automatic_recovery_or_cleanup':True}));raise SystemExit(1)

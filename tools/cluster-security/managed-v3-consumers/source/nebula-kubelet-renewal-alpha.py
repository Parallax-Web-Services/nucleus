#!/usr/bin/env python3
"""SOURCE ONLY. One explicit guest renewal phase under already-admitted managed health.
Requires pre-staged reviewed public sources/tools and an identical private enrollment plan.
Does not stage, admit health, start a writer, modify Alpha or alter original ledgers.
"""
from __future__ import annotations
import argparse,base64,contextlib,fcntl,hashlib,json,os,re,stat,sys,time,types
from pathlib import Path
READONLY_SHA='be39063281364f97ea72d19df3c57f97df7da0dd1e06e617d34a188c5d0f070b'
BRIDGE_SHA='b8e05a5557ded628307f387879b2ef63297f8162790a54177ce7d8edd628b095'
COMMON_SHA='cd5fc702868af2e74965aa13677c691bd3eb872cdb20d5db45e0f0efe6855322'
DURABILITY_SHA='0883835c069808543115f102ffa42fffca7e6a716bef1badb532f1a6b1f5e926'
GUEST_SHA='8dad25eb92f59616cb211cfba493aac06bc424feb34f550148a96967e046dc3b'
BRIDGE_PATH=Path('/usr/local/lib/parallax-nebula-managed-v3/alpha-managed-health-bridge.py')
PHASES=('check','capture','enable-renewal','complete-renewal','prepare-proof','submit-proof','verify-proof','cleanup-proof','complete-cleanup')
def need(ok,reason):
 if not ok:raise RuntimeError(reason)
@contextlib.contextmanager
def load_root_source(path,pin):
 need(path.is_absolute() and path.resolve()==path,'canonical_readonly_source_required')
 for parent in path.parents:
  s=parent.lstat();need(stat.S_ISDIR(s.st_mode) and s.st_uid==s.st_gid==0 and stat.S_IMODE(s.st_mode)&0o022==0,'readonly_source_parent_custody')
 fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC)
 try:
  s=os.fstat(fd);fields=lambda x:(x.st_dev,x.st_ino,x.st_mode,x.st_uid,x.st_gid,x.st_nlink,x.st_size,x.st_mtime_ns,x.st_ctime_ns)
  need(stat.S_ISREG(s.st_mode) and s.st_uid==s.st_gid==0 and s.st_nlink==1 and stat.S_IMODE(s.st_mode)==0o600 and 0<s.st_size<=262144,'private_readonly_source_required')
  raw=os.read(fd,262145);need(len(raw)==s.st_size and hashlib.sha256(raw).hexdigest()==pin and fields(s)==fields(os.fstat(fd))==fields(path.lstat()),'readonly_source_pin_or_identity')
  m=types.ModuleType('_renewal_readonly_composition');m.__file__=str(path);sys.modules[m.__name__]=m;exec(compile(raw,str(path),'exec'),m.__dict__);yield m
  need(fields(s)==fields(os.fstat(fd))==fields(path.lstat()),'readonly_source_changed_after_phase')
 finally:os.close(fd)
class PhaseRunner:
 def __init__(self,common,receipt):self.common=common;self.receipt=receipt;self.deadline=time.monotonic()+100;self.calls=0
 def __call__(self,args,label,timeout=40,input_bytes=None,pass_fds=()):
  left=self.deadline-time.monotonic()-5;need(left>0,'alpha_phase_cleanup_reserve');self.calls+=1;need(self.calls<=384,'alpha_phase_command_bound')
  return self.common.command(self.receipt,args,label,timeout=min(timeout,left),input_bytes=input_bytes,pass_fds=pass_fds)

RECEIVER=r"""
import base64,hashlib,json,os,re,socket,stat,sys,types
from pathlib import Path
os.umask(0o077)
def need(ok,reason):
 if not ok:raise RuntimeError(reason)
def fields(s):return(s.st_dev,s.st_ino,s.st_mode,s.st_uid,s.st_gid,s.st_nlink,s.st_size,s.st_mtime_ns,s.st_ctime_ns)
def read(path,limit):
 need(path.is_absolute() and path.resolve()==path,'canonical_guest_input')
 for parent in path.parents:
  s=parent.lstat();need(stat.S_ISDIR(s.st_mode) and s.st_uid==s.st_gid==0 and stat.S_IMODE(s.st_mode)&0o022==0,'guest_input_parent_custody')
 fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC)
 try:
  s=os.fstat(fd);need(stat.S_ISREG(s.st_mode) and s.st_uid==s.st_gid==0 and s.st_nlink==1 and stat.S_IMODE(s.st_mode)==0o600 and 0<s.st_size<=limit,'private_guest_input')
  raw=os.read(fd,limit+1);need(len(raw)==s.st_size and fields(s)==fields(os.fstat(fd))==fields(path.lstat()),'guest_input_changed');return raw
 finally:os.close(fd)
try:
 x=json.loads(sys.stdin.buffer.read(16385))
 need(set(x)=={'uuid','hostname','address','run_id'} and os.geteuid()==0,'root_guest_scope')
 plan_raw=base64.b64decode(q['plan_base64'],validate=True);plan=json.loads(plan_raw);op=plan['operation_id']
 need(type(op) is str and re.fullmatch('[a-f0-9]{32}',op) is not None,'fixed_guest_operation_namespace')
 need(Path('/sys/class/dmi/id/product_uuid').read_text().strip().lower()==x['uuid']==plan['expected_uuid'] and socket.gethostname()==x['hostname']==plan['enrollment']['node_name'] and x['run_id']==plan['run_id'] and x['address']==plan['api_address'],'exact_enrolled_guest_identity')
 directory=Path('/var/lib/parallax-nebula-tls-sources')/op
 planpath=Path('/var/lib/parallax-nebula-tls-plans')/(op+'.json')
 need(read(planpath,16384)==plan_raw,'same_pre_staged_private_enrollment_plan')
 raw=read(directory/'nebula-kubelet-client-renewal.py',262144)
 need(hashlib.sha256(raw).hexdigest()==q['source_sha256'],'guest_public_source_pin')
 common=read(directory/'nebula-backup-common.py',262144)
 need(hashlib.sha256(common).hexdigest()==q['common_sha256'],'guest_common_source_pin')
 m=types.ModuleType('_approved_client_renewal');m.__file__=str(directory/'nebula-kubelet-client-renewal.py');sys.modules[m.__name__]=m;exec(compile(raw,m.__file__,'exec'),m.__dict__)
 need(tuple(m.PHASES)==tuple(q['allowed_phases']) and q['phase'] in m.PHASES,'exact_typed_phase_contract')
 sys.argv=[m.__file__,'--plan',str(planpath),'--phase',q['phase']]
 if q['phase'] in m.MUTATIONS:sys.argv.append('--execute')
 m.main()
except Exception:
 print(json.dumps({'status':'refused','reason':'guest_renewal_phase_failed_private_receipts'}));raise SystemExit(2)
"""
def guest_script(plan_raw,phase):
 need(type(plan_raw) is bytes and 0<len(plan_raw)<=16384 and phase in PHASES,'typed_private_plan_and_phase')
 q={'plan_base64':base64.b64encode(plan_raw).decode(),'phase':phase,'source_sha256':GUEST_SHA,'common_sha256':COMMON_SHA,'allowed_phases':list(PHASES)}
 return 'q='+repr(q)+'\n'+RECEIVER
def one_phase(w,bridge,d,common,plan_raw,phase,runner,fd,lockpath,lockrecord):
 need(phase in PHASES,'typed_renewal_phase_required')
 job=bridge.lifecycle(runner=runner);job.external_guard=lambda:d.require_lock(fd,lockpath,lockrecord);job.guard()
 adapter=w.readonly_adapter(d,job,bridge.m)
 need(set(adapter.records)==w.COMPLETED_DURABILITY_RECORDS,'existing_completed_ledger_required')
 adapter.journal_guard()
 # Retain THIS constructor's exact records over both independent RO proofs.
 w.check_composition(bridge,d,runner,fd,lockpath,lockrecord);adapter.journal_guard()
 plan=json.loads(plan_raw)
 need(plan.get('run_id')==job.plan['run_id'] and plan.get('expected_uuid')==job.plan['new_domain_uuid'] and plan.get('api_address')==adapter.address and plan.get('enrollment',{}).get('node_name')==job.plan['proposed_name'] and plan.get('enrollment',{}).get('authority')=='verified-libvirt-reservation','alpha_plan_and_enrollment_binding')
 answer=adapter.guest_execute(guest_script(plan_raw,phase));adapter.journal_guard()
 need(type(answer) is dict and answer.get('status') in ['passed','pending'] and answer.get('phase') in [phase,{'complete-renewal':'enable-renewal','complete-cleanup':'cleanup-proof'}.get(phase,phase)],'guest_phase_result_binding')
 need(answer['status']=='passed' or (phase=='verify-proof' and answer.get('native_issuance_pending') is True),'only_native_issuance_may_be_pending')
 w.check_composition(bridge,d,runner,fd,lockpath,lockrecord);adapter.journal_guard()
 return {'status':answer['status'],'phase':phase,'guest_result':answer,'fresh_admitted_managed_health_checked':True,'original_alpha_local_guard_preserved':True,'original_plan_and_durability_ledger_not_written':True,'original_13_flags_ready_node_and_nine_system_pods_verified':True,'health_writer_started':False,'serving_or_api_trust_changed':False}
def run(overlay,plan_path,phase,readonly_source,durability_source,common_source,receipt):
 need(os.geteuid()==0 and phase in PHASES,'root_typed_phase_only')
 need(re.fullmatch(r'/var/lib/parallax-nebula-bootstrap/plan-[a-f0-9]{12}/managed-health-bridge\.json',str(overlay)) is not None,'explicit_admitted_managed_overlay')
 need(receipt.parent==Path('/root') and re.fullmatch(r'nebula-tls-alpha-phase-[a-f0-9]{16}',receipt.name) is not None,'new_private_phase_receipt')
 with load_root_source(readonly_source,READONLY_SHA) as w,w.pinned_source(BRIDGE_PATH,BRIDGE_SHA,'_renewal_managed_bridge') as b,w.pinned_source(durability_source,DURABILITY_SHA,'_renewal_durability') as d,w.pinned_source(common_source,COMMON_SHA,'_renewal_alpha_common') as common:
  common.parent_safe(plan_path.parent);raw,record=common.read(plan_path,16384)
  common.new_dir(receipt);runner=PhaseRunner(common,receipt);fd=os.open(w.BOOTSTRAP_LOCK,os.O_RDWR|os.O_NOFOLLOW|os.O_CLOEXEC)
  try:
   held=os.fstat(fd);need(stat.S_ISREG(held.st_mode) and held.st_uid==held.st_gid==0 and stat.S_IMODE(held.st_mode)==0o600 and held.st_nlink==1 and held.st_size==0,'existing_private_bootstrap_lock')
   fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB);need(w.identity(held)==w.identity(w.BOOTSTRAP_LOCK.lstat()),'bootstrap_lock_changed')
   result=one_phase(w,b.Bridge(overlay),d,common,raw,phase,runner,fd,w.BOOTSTRAP_LOCK,d.identity(held))
   need(common.read(plan_path,16384)==(raw,record),'private_phase_plan_changed')
  finally:os.close(fd)
 common.exclusive(receipt/'result.json',common.json_bytes(result))
 return result
def main():
 os.umask(0o077);p=argparse.ArgumentParser(description=__doc__)
 p.add_argument('--overlay',type=Path,required=True);p.add_argument('--plan',type=Path,required=True);p.add_argument('--phase',choices=PHASES,required=True)
 p.add_argument('--readonly-source',type=Path,required=True);p.add_argument('--durability-source',type=Path,required=True);p.add_argument('--common-source',type=Path,required=True);p.add_argument('--receipt',type=Path,required=True);p.add_argument('--execute',action='store_true');a=p.parse_args()
 need(a.execute==(a.phase!='check'),'explicit_typed_execution_flag')
 print(json.dumps(run(a.overlay,a.plan,a.phase,a.readonly_source,a.durability_source,a.common_source,a.receipt),sort_keys=True))
if __name__=='__main__':
 try:main()
 except Exception as error:
  print(json.dumps({'status':'refused','reason':str(error) if re.fullmatch('[a-z0-9_]+',str(error)) else type(error).__name__,'no_automatic_retry_admission_or_writer':True}));raise SystemExit(2)

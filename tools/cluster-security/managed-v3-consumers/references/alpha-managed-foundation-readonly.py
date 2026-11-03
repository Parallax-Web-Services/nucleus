#!/usr/bin/env python3
"""SOURCE ONLY. Bounded read-only foundation check through an ALREADY admitted bridge.
Never admits health, changes a plan/ledger/VM/cluster, or starts a proof writer.
Only new root-private command receipts are written. No credentials/paths are emitted.
"""
from __future__ import annotations
import argparse,contextlib,fcntl,hashlib,json,os,re,stat,sys,time,types
from pathlib import Path

BRIDGE_SOURCE=Path('/usr/local/lib/parallax-nebula-managed-v3/alpha-managed-health-bridge.py')
BRIDGE_SHA='b8e05a5557ded628307f387879b2ef63297f8162790a54177ce7d8edd628b095'
DURABILITY_SHA='0883835c069808543115f102ffa42fffca7e6a716bef1badb532f1a6b1f5e926'
COMMON_SHA='cd5fc702868af2e74965aa13677c691bd3eb872cdb20d5db45e0f0efe6855322'
BOOTSTRAP_LOCK=Path('/var/lock/nebula-alpha-bootstrap.lock')
MAX_SECONDS=90
COMPLETED_DURABILITY_RECORDS={'baseline.json','reservation-applied.json','autostart-applied.json','verified.json','cluster-postcheck.json'}
EXPECTED={'accepted_cluster_source_matches':True,'accepted_phase_and_13_flags_unchanged':True,'private_api_ready':True,'ready_node_count':1,'ready_system_pod_count':9,'customer_or_unrelated_pod_count':0,'owned_validation_namespace_absent':True,'ten_image_pins_unchanged':True,'no_smoke_init_cni_or_cluster_mutation':True}

class Refused(RuntimeError):pass
def need(ok,reason):
 if not ok:raise Refused(reason)
def identity(s):
 return (s.st_dev,s.st_ino,s.st_mode,s.st_uid,s.st_gid,s.st_nlink,s.st_size,s.st_mtime_ns,s.st_ctime_ns)

@contextlib.contextmanager
def pinned_source(path,pin,name):
 need(path.is_absolute() and path.resolve()==path,'canonical_source_required')
 for parent in path.parents:
  st=parent.lstat();need(stat.S_ISDIR(st.st_mode) and st.st_uid==st.st_gid==0 and stat.S_IMODE(st.st_mode)&0o022==0,'source_parent_custody')
 fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC)
 try:
  before=os.fstat(fd);need(stat.S_ISREG(before.st_mode) and before.st_uid==before.st_gid==0 and stat.S_IMODE(before.st_mode)==0o600 and before.st_nlink==1 and 0<before.st_size<=262144,'private_frozen_source_required')
  raw=os.read(fd,262145);need(len(raw)==before.st_size and hashlib.sha256(raw).hexdigest()==pin and identity(before)==identity(os.fstat(fd))==identity(path.lstat()),'frozen_source_changed')
  module=types.ModuleType(name);module.__file__=str(path);sys.modules[name]=module
  exec(compile(raw,str(path),'exec'),module.__dict__)
  yield module
  need(identity(before)==identity(os.fstat(fd))==identity(path.lstat()),'frozen_source_changed_after_check')
 finally:os.close(fd)

def readonly_adapter(d,job,lifecycle_module):
 # Exact088 constructor, EXCEPT the explicit verified6b module binding.
 # Dynamic Bridge classes belong to the bridge module, which lacks6b's read helpers.
 # Frozen guest_execute/journal_guard are inherited unchanged. No record()/phase is invoked.
 class ReadOnlyManagedDurability(d.Durability):
  def __init__(self,job,work):
   self.j=job;self.m=lifecycle_module;self.work=work
   d.need(work==job.work/'durability','fixed_durability_state_location')
   if os.path.lexists(work):self.m.private_dir(work)
   self.records={}
   if work.exists():
    actual={p.name for p in work.iterdir()};d.need(actual<=set(d.RECORDS),'unknown_durability_record')
    for name in d.RECORDS:
     if name in actual:
      state,raw=d.regular(work/name,True);value=json.loads(raw);d.need(value.get('schema_version')==1 and value.get('run_id')==job.plan['run_id'] and value.get('journal_directory')==d.identity(work.lstat())[:6],'record_binding')
      self.records[name]=(state,raw,value)
   self.uuid=job.plan['new_domain_uuid'];self.network=job.plan['network']['uuid'];self.name=job.plan['proposed_name'];self.mac=job.state['mac'].lower()
   self.address=d.known_address(self.m.read(job.work/'guest-known-hosts',private=True),job.plan['network']['subnet'])
   self.domain_config=Path('/etc/libvirt/qemu')/(self.name+'.xml');self.autolink=self.domain_config.parent/'autostart'/self.domain_config.name
   self.network_config=Path('/etc/libvirt/qemu/networks')/(job.plan['network']['name']+'.xml')
 return ReadOnlyManagedDurability(job,job.work/'durability')

class BoundedRunner:
 def __init__(self,common,receipt):
  self.common=common;self.receipt=receipt;self.deadline=time.monotonic()+MAX_SECONDS;self.calls=0
 def __call__(self,args,label,timeout=60,input_bytes=None,pass_fds=()):
  remaining=self.deadline-time.monotonic();need(remaining>0,'readonly_check_budget_expired')
  self.calls+=1;need(self.calls<=128,'readonly_command_count_bound')
  return self.common.command(self.receipt,args,label,timeout=min(timeout,remaining),input_bytes=input_bytes,pass_fds=pass_fds)

def check_composition(bridge,d,runner,lockfd,lockpath,lock_identity):
 job=bridge.lifecycle(runner=runner)
 # Both bridge.binding and the original6b guard retain this exact held-lock callback.
 job.external_guard=lambda:d.require_lock(lockfd,lockpath,lock_identity)
 job.guard()
 work=job.work/'durability'
 need(os.path.lexists(work) and work.resolve()==work and work.is_dir(),'existing_completed_durability_required')
 adapter=readonly_adapter(d,job,bridge.m)
 need(set(adapter.records)==COMPLETED_DURABILITY_RECORDS,'completed_durability_record_set_required')
 retained=adapter.records['cluster-postcheck.json'][2]
 need({k:v for k,v in retained.items()if k not in ['schema_version','run_id','journal_directory']}==EXPECTED,'historical_accepted_postcheck_required')
 adapter.journal_guard()
 answer=adapter.guest_execute(d.CLUSTER_POSTCHECK)
 need(answer==EXPECTED,'accepted_readonly_postcheck_failed')
 job.guard();adapter.journal_guard()
 return {'status':'passed',**answer,'original_alpha_local_engine_guard_preserved':True,'original_plan_and_helpers_unchanged':True,'admitted_managed_health_only':True,'durability_ledger_not_written':True,'proof_writer_started':False,'guest_commands_readonly':True}

def run(overlay,durability_source,common_source,receipt,bridge_source=BRIDGE_SOURCE):
 need(os.geteuid()==0,'alpha_root_only')
 need(re.fullmatch(r'/var/lib/parallax-nebula-bootstrap/plan-[a-f0-9]{12}/managed-health-bridge\.json',str(overlay)) is not None,'explicit_admitted_overlay_required')
 need(receipt.is_absolute() and receipt.parent==Path('/root') and re.fullmatch(r'nebula-managed-foundation-check-[a-f0-9]{16}',receipt.name) is not None,'exclusive_readonly_receipt_required')
 with pinned_source(bridge_source,BRIDGE_SHA,'_reviewed_managed_bridge') as bridge_module,pinned_source(durability_source,DURABILITY_SHA,'_reviewed_managed_durability') as d,pinned_source(common_source,COMMON_SHA,'_reviewed_readonly_common') as common:
  # The admitted bridge is read, never created or repaired. Its constructor pins the
  # original plan, LOCAL assertions,6b/f7 and proof source; lifecycle asserts Alpha.
  bridge=bridge_module.Bridge(overlay)
  common.new_dir(receipt);runner=BoundedRunner(common,receipt)
  fd=os.open(BOOTSTRAP_LOCK,os.O_RDWR|os.O_NOFOLLOW|os.O_CLOEXEC)
  try:
   held=os.fstat(fd);need(stat.S_ISREG(held.st_mode) and held.st_uid==held.st_gid==0 and stat.S_IMODE(held.st_mode)==0o600 and held.st_nlink==1 and held.st_size==0,'existing_private_bootstrap_lock_required')
   fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB);need(identity(held)==identity(BOOTSTRAP_LOCK.lstat()),'bootstrap_lock_changed')
   result=check_composition(bridge,d,runner,fd,BOOTSTRAP_LOCK,d.identity(held))
  finally:os.close(fd)
 # Only persist success AFTER every held public-source context passed its postcheck.
 common.exclusive(receipt/'result.json',common.json_bytes(result))
 return result

def main():
 os.umask(0o077);parser=argparse.ArgumentParser(description=__doc__)
 parser.add_argument('--overlay',required=True,type=Path);parser.add_argument('--durability-source',required=True,type=Path);parser.add_argument('--common-source',required=True,type=Path);parser.add_argument('--receipt',required=True,type=Path);args=parser.parse_args()
 print(json.dumps(run(args.overlay,args.durability_source,args.common_source,args.receipt),sort_keys=True))
if __name__=='__main__':
 try:main()
 except Exception as error:
  print(json.dumps({'status':'refused','reason':str(error) if re.fullmatch('[a-z0-9_]+',str(error)) else type(error).__name__,'no_plan_ledger_or_cluster_repair':True}));raise SystemExit(1)

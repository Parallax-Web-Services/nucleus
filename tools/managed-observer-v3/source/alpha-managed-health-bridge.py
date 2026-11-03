#!/usr/bin/env python3
"""SOURCE ONLY: Alpha health-only managed-owner bridge.
Original6b/f7 files, immutable plan and every local protected-process assertion
stay unchanged. Changed observation basis is explicit; no legacy two-view claim.
"""
import argparse,hashlib,json,os,re,stat,tempfile,time,types
from pathlib import Path
LIFECYCLE_SHA='6b4ae6d7be5ed6a21db251c8da6e103c251da803819fa820e788cdb7abfcad90'
PREFLIGHT_SHA='f7d216b1aa1e803e9386b227f2954604c6746dddb1c63847c662b7f04c9f33f4'
REDUCER_SHA='e519baaf5daf066ab1ff603e953800c6bda8b77df8f7af47071a282e66ed402d'
FIELDS=('st_dev','st_ino','st_mode','st_uid','st_gid','st_nlink','st_size','st_mtime_ns','st_ctime_ns')
class Refused(RuntimeError):pass
def need(ok,label):
 if not ok:raise Refused(label)
def identity(s):return {k:getattr(s,k)for k in FIELDS}
def read(path,limit=1048576):
 need(path.is_absolute()and path.resolve()==path,'canonical_private_path_required');fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
 try:
  s=os.fstat(fd);need(stat.S_ISREG(s.st_mode)and s.st_uid==s.st_gid==0 and stat.S_IMODE(s.st_mode)==0o600 and s.st_nlink==1 and s.st_size<=limit,'private_file_metadata_differs');data=bytearray()
  while True:
   chunk=os.read(fd,min(65536,limit+1-len(data)))
   if not chunk:break
   data.extend(chunk);need(len(data)<=limit,'private_file_size_bound')
  need(identity(s)==identity(os.fstat(fd))==identity(path.lstat()),'private_file_changed');return bytes(data),{'identity':identity(s),'sha256':hashlib.sha256(data).hexdigest()}
 finally:os.close(fd)
def unique(pairs):
 out={}
 for k,v in pairs:need(k not in out,'duplicate_json_key');out[k]=v
 return out
def decode(data):return json.loads(data,object_pairs_hook=unique,parse_constant=lambda _:(_ for _ in()).throw(Refused('nonfinite_json')))
def load_source(path,pin):
 data,record=read(path);need(record['sha256']==pin,'public_source_pin_differs');m=types.ModuleType('accepted_alpha_'+pin[:8]);m.__file__=str(path);exec(compile(data,str(path),'exec'),m.__dict__);return m,record

def health(envelope,overlay_id,now=None,require_ready=True,expected_plan_record=None):
 now=time.time()if now is None else now;need(set(envelope)=={'schema_version','transport','reducer_sha256','original_plan_record','health'}and type(envelope['schema_version'])is int and envelope['schema_version']==1 and envelope['transport']=='authenticated-administrative-ssh'and envelope['reducer_sha256']==REDUCER_SHA,'managed_health_transport_envelope_differs');context=envelope['original_plan_record'];need(isinstance(context,dict)and set(context)=={'identity','sha256'}and isinstance(context['identity'],dict)and set(context['identity'])==set(FIELDS)and isinstance(context['sha256'],str)and re.fullmatch('[a-f0-9]{64}',context['sha256'])is not None,'original_plan_context_shape_differs');need(expected_plan_record is None or context==expected_plan_record,'original_plan_context_mismatch');p=envelope['health'];expected={'schema_version','observation_basis','overlay_id','checked_at_unix','managed_owner_matches','cutover_receipt_unchanged','origin_plan_context_matches','registered_node_count','required_server_count','required_server_online_count','same_fabric','required_server_resources_fresh','owner_view_online_count','owner_view_last_seen_fresh_count','owner_view_resource_fresh_count','all_five_samples_valid_until_unix_ms','managed_relay_binary_matches','managed_relay_process_unchanged'};need(isinstance(p,dict)and set(p)==expected and type(p['schema_version'])is int and p['schema_version']==2 and p['observation_basis']=='managed-owner-view'and p['overlay_id']==overlay_id,'managed_owner_health_schema_or_binding_differs');need(type(p['checked_at_unix'])is int and 0<=now-p['checked_at_unix']<=15,'managed_health_proof_not_fresh');counts={'registered_node_count':5,'required_server_count':4,'required_server_online_count':4,'owner_view_online_count':5,'owner_view_last_seen_fresh_count':5,'owner_view_resource_fresh_count':5};booleans=['managed_owner_matches','cutover_receipt_unchanged','origin_plan_context_matches','same_fabric','required_server_resources_fresh','managed_relay_binary_matches','managed_relay_process_unchanged'];need(all(type(p[k])is int and 0<=p[k]<=limit for k,limit in counts.items())and all(type(p[k])is bool for k in booleans),'managed_health_count_or_bool_type_differs');deadline=p['all_five_samples_valid_until_unix_ms'];need(type(deadline)is int and 0<=deadline<=p['checked_at_unix']*1000+15000,'all_five_deadline_invalid')
 if require_ready:
  need(all(p[k]==v for k,v in counts.items()),'all_five_managed_owner_observations_required');need(all(p[k]is True for k in booleans),'managed_owner_or_relay_proof_failed');need(now*1000<=deadline,'all_five_samples_expired')
 return p

def new_private(path,data):
 parent=path.parent;s=parent.lstat();need(parent.resolve()==parent and stat.S_ISDIR(s.st_mode)and s.st_uid==s.st_gid==0 and stat.S_IMODE(s.st_mode)==0o700 and not os.path.lexists(path),'new_private_overlay_required');fd,name=tempfile.mkstemp(prefix='.alpha-bridge-',dir=parent);temp=Path(name);held=os.fstat(fd)
 try:
  with os.fdopen(fd,'wb')as f:f.write(data);f.flush();os.fchmod(f.fileno(),0o600);os.fsync(f.fileno());staged=identity(os.fstat(f.fileno()))
  need(identity(temp.lstat())==staged and read(temp)[0]==data and not os.path.lexists(path),'overlay_temp_or_target_changed');os.link(temp,path,follow_symlinks=False);need((temp.lstat().st_dev,temp.lstat().st_ino)==(held.st_dev,held.st_ino),'overlay_temp_replaced');temp.unlink();after,record=read(path);need((record['identity']['st_dev'],record['identity']['st_ino'])==(held.st_dev,held.st_ino)and after==data,'overlay_postimage_unknown');return record
 finally:
  try:
   s=temp.lstat()
   if(s.st_dev,s.st_ino)==(held.st_dev,held.st_ino):temp.unlink()
  except FileNotFoundError:pass

def admit(plan_path,lifecycle_path,preflight_path,proof_path,overlay_path,overlay_id):
 need(re.fullmatch('[a-f0-9]{32}',overlay_id)is not None,'managed_overlay_id_required');raw,plan_record=read(plan_path);plan=decode(raw);need(plan.get('schema_version')==1 and isinstance(plan.get('protected_nucleus_processes'),list),'original_alpha_plan_shape_differs');m,lifecycle_record=load_source(lifecycle_path,LIFECYCLE_SHA);pf,preflight_record=load_source(preflight_path,PREFLIGHT_SHA);original=m.Lifecycle(plan_path,pf);original.guard(health=False);need(original.plan_raw==raw and original.plan['protected_nucleus_processes']==plan['protected_nucleus_processes'],'original_lifecycle_admission_binding_differs');data,proof_record=read(proof_path,8192);health(decode(data),overlay_id,expected_plan_record=plan_record);value={'schema_version':1,'mode':'health-only','observation_basis':'managed-owner-view','managed_overlay_id':overlay_id,'original_plan_path':str(plan_path),'original_plan_record':plan_record,'local_process_assertions':plan['protected_nucleus_processes'],'lifecycle_path':str(lifecycle_path),'lifecycle_record':lifecycle_record,'preflight_path':str(preflight_path),'preflight_record':preflight_record,'health_path':str(proof_path),'reducer_sha256':REDUCER_SHA};need(read(plan_path)[1]==plan_record and read(lifecycle_path)[1]==lifecycle_record and read(preflight_path)[1]==preflight_record and read(proof_path,8192)[1]==proof_record,'admission_inputs_changed');new_private(overlay_path,(json.dumps(value,sort_keys=True,indent=2)+'\n').encode());return {'status':'admitted','mode':'health-only','original_plan_and_helper_bytes_preserved':True,'all_local_process_assertions_preserved':True,'credential_bytes_emitted':False}

def lifecycle_class(base,bridge):
 class ManagedHealthLifecycle(base.Lifecycle):
  def guard(self,health=True,volume_exception=None):
   bridge.binding(self);super().guard(health=health,volume_exception=volume_exception);bridge.binding(self)
  def external_health(self):bridge.external_health(self)
 return ManagedHealthLifecycle
class Bridge:
 def __init__(self,overlay_path):
  self.path=overlay_path;data,self.record=read(overlay_path);self.o=decode(data);o=self.o;need(o.get('schema_version')==1 and o.get('mode')=='health-only'and o.get('observation_basis')=='managed-owner-view'and o.get('reducer_sha256')==REDUCER_SHA,'alpha_bridge_mode_differs');self.m,lifecycle_record=load_source(Path(o['lifecycle_path']),LIFECYCLE_SHA);self.pf,preflight_record=load_source(Path(o['preflight_path']),PREFLIGHT_SHA);need(lifecycle_record==o['lifecycle_record']and preflight_record==o['preflight_record'],'alpha_original_sources_changed');self.plan_raw,record=read(Path(o['original_plan_path']));self.plan=decode(self.plan_raw);need(record==o['original_plan_record']and self.plan['protected_nucleus_processes']==o['local_process_assertions'],'alpha_original_plan_or_local_assertions_changed');self.cls=lifecycle_class(self.m,self)
 def binding(self,job):
  o=self.o;need(read(self.path)[1]==self.record and read(Path(o['original_plan_path']))[1]==o['original_plan_record'],'alpha_plan_or_overlay_changed');need(job.plan_path==Path(o['original_plan_path'])and job.plan_raw==self.plan_raw and job.plan['protected_nucleus_processes']==o['local_process_assertions'],'alpha_job_binding_changed');need(read(Path(o['lifecycle_path']))[1]==o['lifecycle_record']and read(Path(o['preflight_path']))[1]==o['preflight_record'],'alpha_original_sources_changed')
 def external_health(self,job):
  self.binding(job);data,_=read(Path(self.o['health_path']),8192);health(decode(data),self.o['managed_overlay_id'],expected_plan_record=self.o['original_plan_record']);self.binding(job)
 def lifecycle(self,runner=None):
  job=self.cls(Path(self.o['original_plan_path']),self.pf,runner);self.binding(job);return job

def main():
 os.umask(0o077);need(os.geteuid()==0,'alpha_root_only');p=argparse.ArgumentParser(description=__doc__);p.add_argument('mode',choices=['admit','check']);p.add_argument('--overlay',type=Path,required=True);p.add_argument('--plan',type=Path);p.add_argument('--lifecycle',type=Path);p.add_argument('--preflight',type=Path);p.add_argument('--health-proof',type=Path);p.add_argument('--managed-overlay-id');a=p.parse_args()
 if a.mode=='admit':need(all([a.plan,a.lifecycle,a.preflight,a.health_proof,a.managed_overlay_id]),'admission_arguments_required');result=admit(a.plan,a.lifecycle,a.preflight,a.health_proof,a.overlay,a.managed_overlay_id)
 else:need(not any([a.plan,a.lifecycle,a.preflight,a.health_proof,a.managed_overlay_id]),'check_uses_only_admitted_overlay');bridge=Bridge(a.overlay);bridge.lifecycle().guard();result={'status':'passed','mode':'health-only','all_original_lifecycle_guards_executed':True,'all_local_process_assertions_preserved':True,'no_original_plan_or_helper_changes':True}
 print(json.dumps(result))
if __name__=='__main__':
 try:main()
 except Exception as e:print(json.dumps({'status':'refused','reason':str(e)if isinstance(e,Refused)else type(e).__name__,'no_automatic_state_adoption':True}));raise SystemExit(1)

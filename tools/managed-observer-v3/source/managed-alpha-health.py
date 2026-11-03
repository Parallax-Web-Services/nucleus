#!/usr/bin/env python3
"""SOURCE ONLY: explicit managed-owner-view Alpha health, no legacy two-view claim.
Loads accepted read-only ManagedSource and overlay admission chain. No plan,
identity/CA, rawview, bearer or private receipt leaves the coordinator server.
"""
import argparse,hashlib,json,os,re,stat,subprocess,time,types
from pathlib import Path
OVERLAY_SOURCE_SHA='487a8c4af222935ec819e37d35f10fa34873b02949e3a45639f66d5d8582d497'
RELAY_SHA='8dfddeecc99527b530c959d2a4a778d9b9debbfa1dcf7a62a70e08bcd48ee4b1'
RELAY_BINARY=Path('/opt/parallax/nebula/releases')/RELAY_SHA/'nucleus'
RELAY_RECEIPT=Path('/var/lib/parallax-nebula-deploy/managed-issuer-ready.json')
FIELDS=('st_dev','st_ino','st_mode','st_uid','st_gid','st_nlink','st_size','st_mtime_ns','st_ctime_ns')
class Refused(RuntimeError):pass
def need(ok,label):
 if not ok:raise Refused(label)
def identity(s):return {k:getattr(s,k)for k in FIELDS}
def load_overlay_source(path):
 fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW)
 try:
  s=os.fstat(fd);need(path.resolve()==path and stat.S_ISREG(s.st_mode)and s.st_uid==s.st_gid==0 and stat.S_IMODE(s.st_mode)==0o600 and s.st_nlink==1 and s.st_size<=1048576,'overlay_source_metadata_differs');data=os.read(fd,1048577);need(identity(s)==identity(os.fstat(fd))==identity(path.lstat())and hashlib.sha256(data).hexdigest()==OVERLAY_SOURCE_SHA,'overlay_source_changed')
 finally:os.close(fd)
 h=types.ModuleType('accepted_health_overlay');h.__file__=str(path);exec(compile(data,str(path),'exec'),h.__dict__);return h

def relay_proof(h):
 result={'managed_relay_binary_matches':False,'managed_relay_process_unchanged':False}
 try:
  data,receipt=h.read(RELAY_RECEIPT,131072);proof=h.decode(data);need(proof.get('status')=='passed','relay_receipt_not_passed');r=subprocess.run(['/usr/bin/systemctl','show','nebula-relay.service','--property=MainPID','--value'],stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,env={'PATH':'/usr/bin:/bin','LC_ALL':'C'},timeout=3);need(r.returncode==0 and re.fullmatch(rb'[1-9][0-9]{0,9}\n',r.stdout)is not None,'relay_pid_query_failed');pid=int(r.stdout);need(pid>1,'relay_not_running');proc=Path('/proc')/str(pid);start=(proc/'stat').read_text().rsplit(') ',1)[1].split()[19];need(os.readlink(proc/'exe')==str(RELAY_BINARY),'relay_executable_path_differs');fd=os.open(RELAY_BINARY,os.O_RDONLY|os.O_NOFOLLOW)
  try:
   s=os.fstat(fd);need(RELAY_BINARY.resolve()==RELAY_BINARY and stat.S_ISREG(s.st_mode)and s.st_uid==s.st_gid==0 and not s.st_mode&0o022 and s.st_nlink==1 and s.st_size<=64*1024*1024,'relay_binary_metadata_differs');exe=(proc/'exe').stat();need((exe.st_dev,exe.st_ino)==(s.st_dev,s.st_ino),'relay_held_executable_differs');digest=hashlib.sha256();total=0
   while True:
    chunk=os.read(fd,65536)
    if not chunk:break
    total+=len(chunk);need(total<=64*1024*1024,'relay_binary_size_bound');digest.update(chunk)
   need(identity(s)==identity(os.fstat(fd))==identity(RELAY_BINARY.lstat())and digest.hexdigest()==RELAY_SHA,'relay_binary_changed')
  finally:os.close(fd)
  need((proc/'stat').read_text().rsplit(') ',1)[1].split()[19]==start and h.read(RELAY_RECEIPT,131072)[1]==receipt,'relay_invocation_or_receipt_changed');result['managed_relay_binary_matches']=True;result['managed_relay_process_unchanged']=type(proof['relay_process']['pid'])is int and pid==proof['relay_process']['pid']and start==str(proof['relay_process']['start_ticks'])
 except Exception:pass
 return result

def counts(normalized,now):
 hosts=normalized['hosts'];fresh=lambda value:type(value)is int and -5000<=now-value<=10000
 timestamps=[normalized['view_collected_at_ms']]+[n[k]for n in hosts for k in['last_seen_at_ms','resource_collected_at_ms']];deadline=min(timestamps)+10000 if all(type(x)is int for x in timestamps)else 0
 return {'owner_view_online_count':sum(n['status']=='online'for n in hosts),'owner_view_last_seen_fresh_count':sum(fresh(n['last_seen_at_ms'])for n in hosts),'owner_view_resource_fresh_count':sum(fresh(n['resource_collected_at_ms'])for n in hosts),'all_five_samples_valid_until_unix_ms':deadline}
def check(overlay_path,source_path,expected_origin_record):
 h=load_overlay_source(source_path);data,overlay_record=h.read(overlay_path,65536);o=h.decode(data);need(o.get('schema_version')==2 and re.fullmatch('[a-f0-9]{32}',o.get('overlay_id','')),'overlay_shape_differs');need(isinstance(expected_origin_record,dict)and expected_origin_record==o['original_plan_record'],'original_plan_context_mismatch');m,producer_record=h.load_producer(Path(o['producer_path']));need(producer_record==o['producer_record'],'admitted_producer_changed');need(h.read(Path(o['origin_binding_path']),16384)[1]==o['origin_binding_record'],'origin_context_changed');h.metadata_unchanged(Path(o['cutover_path']),o['cutover_record']);c,config_record=m.load_config(Path(o['config_path']));need(config_record==o['config_record'],'managed_config_changed');view=m.fetch(c);now=int(time.time()*1000);required=h.reduce_health(view,c,o['expected_members'],o['required_server_ids'],now,m);normalized=m.normalize(view,c,now);extra=counts(normalized,now);relay=relay_proof(h);need(h.read(overlay_path,65536)[1]==overlay_record and m.record(Path(o['config_path']),8192)==config_record,'health_inputs_changed');h.metadata_unchanged(Path(o['cutover_path']),o['cutover_record']);return {'schema_version':2,'observation_basis':'managed-owner-view','overlay_id':o['overlay_id'],'checked_at_unix':int(time.time()),'managed_owner_matches':True,'cutover_receipt_unchanged':True,'origin_plan_context_matches':True,**required,**extra,**relay}
def main():
 os.umask(0o077);need(os.geteuid()==0,'root_only');p=argparse.ArgumentParser(description=__doc__);p.add_argument('--overlay',type=Path,required=True);p.add_argument('--overlay-source',type=Path,required=True);p.add_argument('--expected-origin-record',type=Path,required=True);a=p.parse_args();h=load_overlay_source(a.overlay_source);expected=h.decode(h.read(a.expected_origin_record,16384)[0]);print(json.dumps(check(a.overlay,a.overlay_source,expected)))
if __name__=='__main__':
 try:main()
 except Exception as e:print(json.dumps({'status':'refused','reason':str(e)if isinstance(e,Refused)else type(e).__name__,'credential_bytes_emitted':False}));raise SystemExit(1)

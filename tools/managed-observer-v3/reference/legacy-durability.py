#!/usr/bin/env python3
"""Owned Alpha VM autostart + exact DHCP reservation candidate. NO live execution authorized."""
from __future__ import annotations
import argparse,copy,fcntl,hashlib,ipaddress,json,os,re,shlex,stat,sys,types,xml.etree.ElementTree as E
from pathlib import Path
LIFECYCLE_SHA='6b4ae6d7be5ed6a21db251c8da6e103c251da803819fa820e788cdb7abfcad90'
FAILED_EXECUTION_SOURCE_SHA='a5d7efab776e22cdcf16e3df0ab6d1234bb1993a5ce2ed1b3d7e7cd7db5c93ac'
FAILED_EXECUTION_RECEIPT_SHA='f989f262603108bc9cfe8982c76864395344232a89cbd4bff888ee0817a49a60'
RECORDS=['baseline.json','reservation-applied.json','autostart-applied.json','verified.json','cluster-postcheck.json','autostart-reverted.json','reservation-reverted.json','rolled-back.json']
class Refused(RuntimeError):pass
def need(ok,code):
 if not ok:raise Refused(code)
def digest(raw):return hashlib.sha256(raw).hexdigest()
def canonical(raw):
 root=E.fromstring(raw)
 for x in root.iter():
  x.attrib=dict(sorted(x.attrib.items()))
  if x.text is not None and not x.text.strip():x.text=None
  if x.tail is not None and not x.tail.strip():x.tail=None
 return E.tostring(root,encoding='unicode')
def identity(s):return [s.st_dev,s.st_ino,s.st_mode,s.st_uid,s.st_gid,s.st_nlink,s.st_size,s.st_mtime_ns,s.st_ctime_ns]
def require_lock(fd,path,expected):
 need(identity(os.fstat(fd))==expected and identity(path.lstat())==expected,'lifecycle_lock_changed')
def regular(path,private=False):
 need(path.is_absolute() and path.resolve()==path,'noncanonical_input_path')
 fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
 try:
  before=os.fstat(fd);need(stat.S_ISREG(before.st_mode) and before.st_nlink==1 and before.st_size<=2*1024**2,'unsafe_regular_input')
  need(before.st_uid==0 and stat.S_IMODE(before.st_mode)&0o022==0,'unsafe_input_custody')
  if private:need(stat.S_IMODE(before.st_mode)==0o600,'private_input_required')
  raw=b''
  while True:
   b=os.read(fd,65536)
   if not b:break
   raw+=b;need(len(raw)<=2*1024**2,'input_bound')
  need(identity(before)==identity(os.fstat(fd))==identity(path.lstat()),'input_changed')
  return {'identity':identity(before),'sha256':digest(raw)},raw
 finally:os.close(fd)
def link_state(path,target):
 if not os.path.lexists(path):return None
 before=path.lstat();need(stat.S_ISLNK(before.st_mode) and before.st_uid==0 and before.st_gid==0 and before.st_nlink==1,'unsafe_autostart_link')
 value=os.readlink(path);need(path.resolve()==target and target.resolve()==target,'unexpected_autostart_target')
 need(identity(before)==identity(path.lstat()) and os.readlink(path)==value,'autostart_link_changed')
 return {'identity':identity(before),'target':value}
def add_reservation(raw,network_uuid,subnet,gateway,address,mac,hostname):
 root=E.fromstring(raw);need(root.findtext('uuid')==network_uuid,'network_uuid_changed')
 matching=[]
 for i,p in enumerate(root.findall('ip')):
  try:n=ipaddress.ip_network(p.get('address','')+'/'+str(p.get('netmask') or p.get('prefix')),strict=False)
  except ValueError:continue
  if str(n)==subnet and p.get('address')==gateway:matching.append((i,p))
 need(len(matching)==1,'network_ip_parent_ambiguous');index,parent=matching[0]
 dhcp=parent.find('dhcp');need(dhcp is not None,'existing_dhcp_required')
 addr=ipaddress.ip_address(address);need(addr in ipaddress.ip_network(subnet) and address!=gateway,'address_outside_owned_network')
 need(any(ipaddress.ip_address(r.get('start'))<=addr<=ipaddress.ip_address(r.get('end')) for r in dhcp.findall('range')),'current_address_outside_dhcp_range')
 for h in root.findall('ip/dhcp/host'):
  need(h.get('mac','').lower()!=mac and h.get('ip')!=address and h.get('name','').lower()!=hostname.lower(),'reservation_collision')
 host=E.Element('host',{'mac':mac,'name':hostname,'ip':address});dhcp.append(host)
 return canonical(E.tostring(root)),index,E.tostring(host,encoding='unicode')
def known_counter_only_partial(current,baseline):
 expected=E.fromstring(baseline['expected_network_live'])
 before=E.fromstring(baseline['before']['network_live'])
 need(expected.get('connections')==before.get('connections')=='1','only_observed_single_live_counter_may_normalize')
 del expected.attrib['connections']
 need(current['network_live']==canonical(E.tostring(expected)),'live_difference_not_exact_counter_removal')
 need(current['network_persistent']==baseline['expected_network_persistent'],'persistent_reservation_not_exact')
 need(all(current[k]==baseline['before'][k] for k in ['domain_file','autostart','autostart_link']),'partial_unrelated_domain_changed')
 need(current['autostart'] is False and current['autostart_link'] is None,'autostart_must_not_have_run')
 need(current['network_file']['identity'][2:6]==baseline['before']['network_file']['identity'][2:6],'network_file_custody_changed')
 return current
def lease_matches(raw,mac,address):
 rows=[]
 for line in raw.decode().splitlines():
  f=line.split()
  for i,v in enumerate(f):
   if re.fullmatch(r'(?:[0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}',v) and i+2<len(f) and f[i+1]=='ipv4':
    try:ip=ipaddress.ip_interface(f[i+2]).ip
    except ValueError:raise Refused('unexpected_lease_address') from None
    rows.append((v.lower(),str(ip)))
 need(sum(m==mac and a==address for m,a in rows)==1,'unique_current_owned_lease_required')
 need(all((m==mac)==(a==address) for m,a in rows if m==mac or a==address),'lease_identity_collision')
 return True
def known_address(raw,subnet):
 lines=raw.decode().splitlines();need(len(lines)==1 and len(lines[0].split())==3,'single_pinned_guest_hostkey_required')
 address=lines[0].split()[0];need(ipaddress.ip_address(address) in ipaddress.ip_network(subnet),'pinned_address_outside_network')
 need(lines[0].split()[1]=='ssh-ed25519','pinned_guest_ed25519_required');return address
GUEST_PROOF=r"""
import json,os,socket,subprocess,sys
from pathlib import Path
x=json.loads(sys.stdin.buffer.read(8192))
def need(v):
 if not v:raise SystemExit(1)
need(os.geteuid()==0)
need(Path('/sys/class/dmi/id/product_uuid').read_text().strip().lower()==x['uuid'])
need(socket.gethostname()==x['hostname'])
for args in [['systemctl','is-active','ssh.socket'],['systemctl','is-enabled','ssh.socket'],['systemctl','is-active','ssh.service']]:
 r=subprocess.run(args,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=8);need(r.returncode==0)
r=subprocess.run(['ip','-j','address','show'],stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=8);need(r.returncode==0)
need(sum(v.get('local')==x['address'] for i in json.loads(r.stdout) for v in i.get('addr_info',[]) if v.get('family')=='inet')==1)
print(json.dumps({'guest_identity_matches':True,'pinned_address_present':True,'ssh_socket_active_and_enabled':True,'ssh_service_active':True}))
"""
CLUSTER_POSTCHECK="\nimport fcntl,hashlib,json,os,stat,sys,types\nfrom pathlib import Path\nx=json.loads(sys.stdin.buffer.read(8192))\ndef need(v):\n if not v:raise SystemExit(1)\nbase=Path('/var/lib/parallax-nebula-guest-bootstrap')/('plan-'+x['run_id']);path=base/'cluster-init.py'\nfd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW);before=os.fstat(fd)\ntry:\n need(stat.S_ISREG(before.st_mode) and before.st_uid==0 and stat.S_IMODE(before.st_mode)==0o600 and before.st_nlink==1)\n raw=os.read(fd,262144);need(os.read(fd,1)==b'')\n ident=lambda z:(z.st_dev,z.st_ino,z.st_mode,z.st_uid,z.st_gid,z.st_nlink,z.st_size,z.st_mtime_ns,z.st_ctime_ns)\n need(ident(os.fstat(fd))==ident(path.lstat())==ident(before))\n need(hashlib.sha256(raw).hexdigest()=='7fe61c84b6e5167be8658e66c70063463f52baa7cc0de401f9bb83257242612c')\nfinally:os.close(fd)\nm=types.ModuleType('_accepted_cluster_readonly');m.__file__=str(path);sys.modules[m.__name__]=m;exec(compile(raw,str(path),'exec'),m.__dict__)\nlock=base/'cluster-operation.lock';lfd=os.open(lock,os.O_RDWR|os.O_NOFOLLOW);held=os.fstat(lfd)\ntry:\n need(stat.S_ISREG(held.st_mode) and held.st_uid==0 and held.st_gid==0 and stat.S_IMODE(held.st_mode)==0o600 and held.st_nlink==1 and held.st_size==0)\n fcntl.flock(lfd,fcntl.LOCK_EX|fcntl.LOCK_NB)\n j=m.Cluster(x['uuid'],x['run_id'],x['address'],'check')\n j.external_guard=lambda:need(ident(lock.lstat())==ident(os.fstat(lfd))==ident(held))\n j.guard();j.verify_images()\n flags=['private_single_node_api','node_ready','locked_control_plane_and_addons','calico_ready','pod_to_service_network','cluster_dns','network_policy_deny_and_scoped_allow','restricted_pod_security','secretbox_encryption_at_rest','metadata_audit_active','control_plane_taint_retained','no_bootstrap_join_token','validation_namespace_cleaned']\n need(j.state['phase']=='accepted' and j.state.get('acceptance')==dict.fromkeys(flags,True))\n ready=j.kubectl(['get','--raw','/readyz']).stdout;need(ready.strip()==b'ok')\n nodes=json.loads(j.kubectl(['get','nodes','-o','json'],sensitive=True).stdout)['items']\n need(len(nodes)==1 and nodes[0]['status']['nodeInfo']['systemUUID'].lower()==x['uuid'])\n need(any(v.get('type')=='Ready' and v.get('status')=='True' for v in nodes[0]['status'].get('conditions',[])))\n need(any(v.get('key')=='node-role.kubernetes.io/control-plane' and v.get('effect')=='NoSchedule' for v in nodes[0]['spec'].get('taints',[])))\n pods=json.loads(j.kubectl(['get','pods','-A','-o','json'],sensitive=True).stdout)['items']\n need(len(pods)==9 and all(v['metadata']['namespace']=='kube-system' and v['status']['phase']=='Running' and any(c.get('type')=='Ready' and c.get('status')=='True' for c in v['status'].get('conditions',[])) for v in pods))\n need(not j.kubectl(['get','namespace','nebula-validate-'+x['run_id'],'--ignore-not-found','-o','json'],sensitive=True).stdout.strip())\n j.api_security_checks();j.guard()\n print(json.dumps({'accepted_cluster_source_matches':True,'accepted_phase_and_13_flags_unchanged':True,'private_api_ready':True,'ready_node_count':1,'ready_system_pod_count':9,'customer_or_unrelated_pod_count':0,'owned_validation_namespace_absent':True,'ten_image_pins_unchanged':True,'no_smoke_init_cni_or_cluster_mutation':True}))\nfinally:os.close(lfd)\n"
class Durability:
 def __init__(self,job,work):
  self.j=job;self.m=sys.modules[job.__class__.__module__];self.work=work
  need(work==job.work/'durability','fixed_durability_state_location')
  if os.path.lexists(work):self.m.private_dir(work)
  self.records={}
  if work.exists():
   actual={p.name for p in work.iterdir()};need(actual<=set(RECORDS),'unknown_durability_record')
   for name in RECORDS:
    if name in actual:
     state,raw=regular(work/name,True);value=json.loads(raw);need(value.get('schema_version')==1 and value.get('run_id')==job.plan['run_id'] and value.get('journal_directory')==identity(work.lstat())[:6],'record_binding')
     self.records[name]=(state,raw,value)
  self.uuid=job.plan['new_domain_uuid'];self.network=job.plan['network']['uuid'];self.name=job.plan['proposed_name'];self.mac=job.state['mac'].lower()
  self.address=known_address(self.m.read(job.work/'guest-known-hosts',private=True),job.plan['network']['subnet'])
  self.domain_config=Path('/etc/libvirt/qemu')/(self.name+'.xml');self.autolink=self.domain_config.parent/'autostart'/self.domain_config.name
  self.network_config=Path('/etc/libvirt/qemu/networks')/(job.plan['network']['name']+'.xml')
 def journal_guard(self):
  if not self.work.exists():need(not self.records,'durability_state_missing');return
  self.m.private_dir(self.work);need({p.name for p in self.work.iterdir()}==set(self.records),'durability_record_inventory_changed')
  for name,(before,raw,_) in self.records.items():
   current,value=regular(self.work/name,True);need(current==before and value==raw,'durability_record_changed')
 def record(self,name,value):
  self.journal_guard();need(name in RECORDS and name not in self.records,'record_already_exists')
  value={'schema_version':1,'run_id':self.j.plan['run_id'],**value};raw=(json.dumps(value,sort_keys=True,indent=2)+'\n').encode()
  if not self.work.exists():
   need(not self.records,'record_parent_missing');self.work.mkdir(mode=0o700);self.m.private_dir(self.work)
  value['journal_directory']=identity(self.work.lstat())[:6];raw=(json.dumps(value,sort_keys=True,indent=2)+'\n').encode()
  self.journal_guard();path=self.work/name;fd=os.open(path,os.O_CREAT|os.O_EXCL|os.O_WRONLY|os.O_NOFOLLOW,0o600)
  try:
   with os.fdopen(os.dup(fd),'wb') as out:out.write(raw);out.flush();os.fsync(out.fileno())
   owned=identity(os.fstat(fd));current,actual=regular(path,True)
   need(actual==raw and current['identity']==owned,'record_postimage_changed')
   self.records[name]=(current,raw,value);self.journal_guard()
  finally:os.close(fd)
 def query(self,*args):
  return self.j.runner(['/usr/bin/virsh','--readonly','--connect','qemu:///system',*args],'durability-read-'+os.urandom(4).hex(),15)
 def mutate(self,*args):
  self.journal_guard()
  return self.j.runner(['/usr/bin/virsh','--connect','qemu:///system',*args],'durability-write-'+os.urandom(4).hex(),20)
 def snapshot(self):
  self.j.guard();need(self.j.state['status']=='guest_os_authenticated','only_authenticated_owned_guest')
  info=self.j.pf.info(self.query('dominfo',self.uuid));need(info.get('Persistent')=='yes' and info.get('State')=='running','running_persistent_guest_required')
  auto=info.get('Autostart');need(auto in ['disable','disabled','enable','enabled','yes','no'],'unknown_autostart_value')
  enabled=auto in ['enable','enabled','yes'];link=link_state(self.autolink,self.domain_config);need(enabled==(link is not None),'autostart_link_flag_mismatch')
  domainfile,_=regular(self.domain_config);networkfile,nraw=regular(self.network_config)
  live=canonical(self.query('net-dumpxml',self.network));persistent=canonical(self.query('net-dumpxml',self.network,'--inactive'))
  need(canonical(nraw)==persistent,'persistent_network_file_mismatch')
  ni=self.j.pf.info(self.query('net-info',self.network));need(ni.get('Active')=='yes' and ni.get('Persistent')=='yes' and ni.get('Autostart')=='yes','network_boot_state_changed')
  lease_matches(self.query('net-dhcp-leases',self.network),self.mac,self.address)
  self.j.guard();self.journal_guard()
  return {'network_live':live,'network_persistent':persistent,'network_file':networkfile,'domain_file':domainfile,'autostart':enabled,'autostart_link':link}
 def guest_execute(self,script):
  self.j.guard();self.journal_guard()
  ssh=['ssh','-F','/dev/null','-T','-i',str(self.j.work/'guest-client'),'-o','BatchMode=yes','-o','IdentitiesOnly=yes','-o','IdentityAgent=none','-o','ForwardAgent=no','-o','ClearAllForwardings=yes','-o','ProxyCommand=none','-o','ProxyJump=none','-o','PermitLocalCommand=no','-o','PreferredAuthentications=publickey','-o','GSSAPIAuthentication=no','-o','HostbasedAuthentication=no','-o','PasswordAuthentication=no','-o','KbdInteractiveAuthentication=no','-o','StrictHostKeyChecking=yes','-o','UserKnownHostsFile='+str(self.j.work/'guest-known-hosts'),'-o','GlobalKnownHostsFile=/dev/null','-o','ConnectTimeout=8','nebula@'+self.address,shlex.join(['sudo','-n','python3','-c',script])]
  result=json.loads(self.j.runner(ssh,'durability-guest-proof-'+os.urandom(4).hex(),40,input_bytes=json.dumps({'uuid':self.uuid,'hostname':self.name,'address':self.address,'run_id':self.j.plan['run_id']}).encode()))
  self.j.guard();return result
 def guest_proof(self):
  result=self.guest_execute(GUEST_PROOF)
  need(result=={'guest_identity_matches':True,'pinned_address_present':True,'ssh_socket_active_and_enabled':True,'ssh_service_active':True},'guest_identity_address_or_ssh_boot_proof_failed')
  return result
 def verify_cluster(self):
  need('verified.json' in self.records and 'cluster-postcheck.json' not in self.records and 'autostart-reverted.json' not in self.records,'durability_apply_required')
  expected=self.current_expected();self.require_exact(expected)
  result=self.guest_execute(CLUSTER_POSTCHECK)
  need(result=={'accepted_cluster_source_matches':True,'accepted_phase_and_13_flags_unchanged':True,'private_api_ready':True,'ready_node_count':1,'ready_system_pod_count':9,'customer_or_unrelated_pod_count':0,'owned_validation_namespace_absent':True,'ten_image_pins_unchanged':True,'no_smoke_init_cni_or_cluster_mutation':True},'accepted_cluster_postcheck_failed')
  self.require_exact(expected);self.record('cluster-postcheck.json',result)
 def baseline(self):need('baseline.json' in self.records,'capture_required');return self.records['baseline.json'][2]
 def capture(self):
  need(not self.records,'durability_already_captured');before=self.snapshot();need(before['autostart'] is False,'expected_autostart_disabled')
  live,i,host=add_reservation(before['network_live'],self.network,self.j.plan['network']['subnet'],self.j.plan['network']['gateway'],self.address,self.mac,self.name)
  persistent,k,same=add_reservation(before['network_persistent'],self.network,self.j.plan['network']['subnet'],self.j.plan['network']['gateway'],self.address,self.mac,self.name)
  need(i==k and host==same,'network_live_config_parent_mismatch');proof=self.guest_proof();need(self.snapshot()==before,'capture_state_changed')
  self.record('baseline.json',{'before':before,'expected_network_live':live,'expected_network_persistent':persistent,'host_xml':host,'parent_index':i,'guest_proof':proof})
 def current_expected(self):
  expected=copy.deepcopy(self.baseline()['before'])
  for n in ['reservation-applied.json','autostart-applied.json','autostart-reverted.json','reservation-reverted.json']:
   if n in self.records:expected=copy.deepcopy(self.records[n][2]['after'])
  return expected
 def require_exact(self,expected):
  current=self.snapshot();need(current==expected,'known_state_changed_manual_recovery');return current
 def network_custody(self,current,original):
  need(current['network_file']['identity'][2:6]==original['network_file']['identity'][2:6],'network_file_custody_changed')
 def retained_original_command(self):
  paths=sorted(self.j.work.glob('durability-write-*'))
  need(len(paths)==2,'exact_original_write_receipt_pair_required');records={};labels=[];streams=[]
  for path in paths:
   match=re.fullmatch(r'durability-write-([a-f0-9]{8})-[a-f0-9]{8}\.(stdout|stderr)',path.name)
   need(match is not None,'unexpected_original_write_receipt_name')
   record,_=regular(path,True);need(record['identity'][8]>=self.records['baseline.json'][0]['identity'][8],'write_receipt_predates_baseline')
   records[path.name]=record;labels.append(match[1]);streams.append(match[2])
  need(len(set(labels))==1 and set(streams)=={'stdout','stderr'},'exact_original_write_receipt_pair_required')
  return records
 def check_completion(self,evidence,failure_evidence):
  need(set(self.records)=={'baseline.json'},'only_exact_unrecorded_reservation_partial')
  need(evidence.parent==self.j.work and re.fullmatch(r'durability-readonly-diagnostic-[a-f0-9]{12}\.json',evidence.name),'owned_readonly_evidence_required')
  failure_record,failure_raw=regular(failure_evidence,True)
  need(failure_record['sha256']==FAILED_EXECUTION_RECEIPT_SHA,'actual_failed_execution_receipt_pin')
  need(json.loads(failure_raw)=={'completed_phases':[],'phase':'apply','reason':'reservation_postimage_unknown','status':'refused','unknown_state_preserved':True},'wrong_failed_execution_path')
  evidence_record,evidence_raw=regular(evidence,True);proof=json.loads(evidence_raw);baseline=self.baseline()
  need(proof['private_baseline']==baseline,'original_baseline_evidence_changed')
  need(proof['safe_result']['xml_difference_fieldpaths']=={'live':[{'path':'network/@connections','kind':'attribute_removed'}],'persistent':[]},'wrong_observed_xml_difference')
  need(proof['safe_result']['reservation_postimage_not_adopted'] is True and proof['safe_result']['autostart_step_record_absent'] is True,'completion_evidence_not_initial_partial')
  command_receipts=self.retained_original_command()
  current=self.snapshot();need(current==proof['private_actual'],'retained_partial_identity_changed')
  known_counter_only_partial(current,baseline)
  live=self.j.domain_xml()
  self.m.validate_xml(live,self.j.plan,self.j.disk,self.j.seed,self.mac,live=True)
  self.m.live_devices_owned_by_new_qemu(live,self.j.plan)
  self.guest_proof();self.require_exact(current)
  need(regular(evidence,True)==(evidence_record,evidence_raw) and regular(failure_evidence,True)==(failure_record,failure_raw),'completion_evidence_changed')
  need(self.retained_original_command()==command_receipts,'original_write_receipts_changed')
  # The pinned a5 apply reaches this exact refusal only AFTER command() requires returncode0.
  # Original stdout/stderr are retained by that command; there was no separate exit-code metadata.
  return current,evidence_record,failure_record,command_receipts
 def complete_reservation(self,evidence,failure_evidence):
  current,evidence_record,failure_record,command_receipts=self.check_completion(evidence,failure_evidence)
  self.record('reservation-applied.json',{'after':current,'completion_evidence':evidence_record,'failed_execution_receipt':failure_record,'executed_source_sha256':FAILED_EXECUTION_SOURCE_SHA,'successful_command_return_proved_by_pinned_refusal_path':True,'original_write_receipts':command_receipts,'reservation_readded':False})
 def enable_autostart(self):
  need(set(self.records)=={'baseline.json','reservation-applied.json'},'only_recorded_reservation_can_continue')
  after=self.current_expected();self.require_exact(after);self.guest_proof();self.require_exact(after)
  self.mutate('autostart',self.uuid)
  enabled=self.snapshot();need(enabled['autostart'] is True and enabled['autostart_link'] is not None,'autostart_not_enabled')
  need(all(enabled[k]==after[k] for k in ['network_live','network_persistent','network_file','domain_file']),'unrelated_state_changed_during_autostart')
  self.require_exact(enabled);self.record('autostart-applied.json',{'after':enabled})
  proof=self.guest_proof();self.require_exact(enabled);self.record('verified.json',{'guest_proof':proof,'new_vm_autostart_enabled':True,'persistent_and_live_address_reservation':True,'no_reboot':True})
 def apply(self):
  b=self.baseline();need(set(self.records)=={'baseline.json'},'apply_once_only')
  self.require_exact(b['before']);self.guest_proof();self.require_exact(b['before'])
  self.mutate('net-update',self.network,'add-last','ip-dhcp-host',b['host_xml'],'--parent-index',str(b['parent_index']),'--live','--config')
  after=self.snapshot();self.network_custody(after,b['before'])
  need(after['network_live']==b['expected_network_live'] and after['network_persistent']==b['expected_network_persistent'],'reservation_postimage_unknown')
  need(all(after[k]==b['before'][k] for k in ['domain_file','autostart','autostart_link']),'unrelated_domain_state_changed')
  self.require_exact(after);self.record('reservation-applied.json',{'after':after})
  self.require_exact(after);self.mutate('autostart',self.uuid)
  enabled=self.snapshot();need(enabled['autostart'] is True and enabled['autostart_link'] is not None,'autostart_not_enabled')
  need(all(enabled[k]==after[k] for k in ['network_live','network_persistent','network_file','domain_file']),'unrelated_state_changed_during_autostart')
  self.require_exact(enabled);self.record('autostart-applied.json',{'after':enabled})
  proof=self.guest_proof();self.require_exact(enabled);self.record('verified.json',{'guest_proof':proof,'new_vm_autostart_enabled':True,'persistent_and_live_address_reservation':True,'no_reboot':True})
 def check(self):
  need('rolled-back.json' not in self.records,'already_rolled_back')
  if self.records:self.require_exact(self.current_expected())
  else:self.snapshot()
  return self.guest_proof()
 def rollback(self):
  b=self.baseline();need('reservation-applied.json' in self.records and not any(n in self.records for n in ['autostart-reverted.json','reservation-reverted.json','rolled-back.json']),'only_known_applied_state_can_rollback')
  # Combined preflight BEFORE any restore. Unknown/concurrent state preserves ALL targets.
  known=self.current_expected();self.require_exact(known);self.guest_proof();self.require_exact(known)
  if 'autostart-applied.json' in self.records:
   self.require_exact(known);self.mutate('autostart',self.uuid,'--disable')
   reverted=self.snapshot();need(reverted['autostart'] is False and reverted['autostart_link'] is None,'autostart_rollback_postimage_unknown')
   need(all(reverted[k]==known[k] for k in ['network_live','network_persistent','network_file','domain_file']),'rollback_unrelated_state_changed')
   self.require_exact(reverted);self.record('autostart-reverted.json',{'after':reverted});known=reverted
  self.require_exact(known);self.mutate('net-update',self.network,'delete','ip-dhcp-host',b['host_xml'],'--parent-index',str(b['parent_index']),'--live','--config')
  after=self.snapshot();self.network_custody(after,b['before']);need(after['network_live']==b['before']['network_live'] and after['network_persistent']==b['before']['network_persistent'],'reservation_rollback_postimage_unknown')
  need(after['domain_file']==b['before']['domain_file'] and after['autostart'] is False and after['autostart_link'] is None,'rollback_domain_state_unknown')
  self.require_exact(after);self.record('reservation-reverted.json',{'after':after})
  proof=self.guest_proof();self.require_exact(after);self.record('rolled-back.json',{'original_network_semantics_and_vm_boot_flag_restored':True,'guest_proof':proof,'no_reboot':True})
def load_lifecycle(path):
 raw=regular(path)[1];need(digest(raw)==LIFECYCLE_SHA,'lifecycle_source_pin')
 m=types.ModuleType('_reviewed_durability_lifecycle');m.__file__=str(path);sys.modules[m.__name__]=m;exec(compile(raw,str(path),'exec'),m.__dict__);return m
def main():
 os.umask(0o077);p=argparse.ArgumentParser(description=__doc__)
 p.add_argument('--plan',type=Path,required=True);p.add_argument('--preflight',type=Path,required=True);p.add_argument('--lifecycle',type=Path,required=True)
 p.add_argument('--phase',choices=['capture','check','apply','complete-reservation','enable-autostart','verify-cluster','rollback'],required=True);p.add_argument('--execute',action='store_true');p.add_argument('--completion-evidence',type=Path);p.add_argument('--failure-evidence',type=Path);a=p.parse_args()
 need(os.geteuid()==0,'root_required');need(a.phase in ['check','verify-cluster'] or a.execute,'explicit_execute_required')
 lock=Path('/var/lock/nebula-alpha-bootstrap.lock');fd=os.open(lock,os.O_RDWR|os.O_NOFOLLOW);s=os.fstat(fd)
 try:
  need(stat.S_ISREG(s.st_mode) and s.st_uid==0 and s.st_gid==0 and s.st_size==0 and s.st_nlink==1 and stat.S_IMODE(s.st_mode)==0o600,'unsafe_existing_lock');fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
  m=load_lifecycle(a.lifecycle);j=m.Lifecycle(a.plan,m.load_preflight(a.preflight))
  j.external_guard=lambda:require_lock(fd,lock,identity(s))
  j.guard();job=Durability(j,j.work/'durability')
  try:
   if a.phase=='complete-reservation':
    need(a.completion_evidence is not None and a.failure_evidence is not None,'explicit_completion_evidence_required');job.complete_reservation(a.completion_evidence,a.failure_evidence)
   elif a.phase=='check' and (a.completion_evidence is not None or a.failure_evidence is not None):
    need(a.completion_evidence is not None and a.failure_evidence is not None,'explicit_completion_evidence_required');job.check_completion(a.completion_evidence,a.failure_evidence)
   else:getattr(job,{'verify-cluster':'verify_cluster','enable-autostart':'enable_autostart'}.get(a.phase,a.phase))()
  except BaseException:
   path=j.work/('durability-manual-recovery-'+os.urandom(6).hex()+'.json')
   m.write(path,json.dumps({'schema_version':1,'status':'manual_review_required','phase':a.phase,'automatic_rollback':False,'unknown_state_preserved':True}).encode());raise
  j.guard();print(json.dumps({'status':'passed','phase':a.phase,'only_owned_vm_and_exact_reservation_in_scope':True,'old_fleet_and_relay_guards_passed':True,'no_reboot':True,'accepted_cluster_postcheck_required':a.phase in ['apply','enable-autostart'],'durability_complete':'cluster-postcheck.json' in job.records and 'rolled-back.json' not in job.records}))
 finally:os.close(fd)
if __name__=='__main__':
 try:main()
 except Exception as e:
  print(json.dumps({'status':'refused','reason':str(e) if isinstance(e,Refused) else type(e).__name__}),file=sys.stderr);raise SystemExit(1)

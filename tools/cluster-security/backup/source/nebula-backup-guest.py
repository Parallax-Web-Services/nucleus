#!/usr/bin/env python3
"""SOURCE-ONLY initial backup guest executor. Mutating phases require --execute.
No plaintext, CA, kubeconfig, private key or private-derived fingerprint is exported.
"""
from __future__ import annotations
import argparse,base64,contextlib,fcntl,gzip,hashlib,io,json,os,re,stat,sys,tarfile,threading,time,types,uuid
from pathlib import Path,PurePosixPath
COMMON_SHA='cd5fc702868af2e74965aa13677c691bd3eb872cdb20d5db45e0f0efe6855322'
CLUSTER_SHA='7fe61c84b6e5167be8658e66c70063463f52baa7cc0de401f9bb83257242612c'
BASE=Path('/var/lib/parallax-nebula-backup')
REQUIRED_RECOVERY_FILES={'snapshot.db','etc/kubernetes/admin.conf','etc/kubernetes/super-admin.conf','etc/kubernetes/kubelet.conf','var/lib/kubelet/config.yaml','restore-inputs/kubeadm-config-restore.json','restore-inputs/kubelet-config-restore.json','restore-inputs/kubelet-embedded-restore.json'}
REQUIRED_RECOVERY_FILES|={'etc/kubernetes/pki/'+n for n in ['ca.crt','ca.key','apiserver.crt','apiserver.key','apiserver-etcd-client.crt','apiserver-etcd-client.key','apiserver-kubelet-client.crt','apiserver-kubelet-client.key','front-proxy-ca.crt','front-proxy-ca.key','front-proxy-client.crt','front-proxy-client.key','sa.pub','sa.key']}
REQUIRED_RECOVERY_FILES|={'etc/kubernetes/pki/etcd/'+n for n in ['ca.crt','ca.key','server.crt','server.key','peer.crt','peer.key','healthcheck-client.crt','healthcheck-client.key']}
REQUIRED_RECOVERY_FILES|={'etc/kubernetes/nebula/'+n for n in ['encryption.json','audit-policy.json','admission.json']}
REQUIRED_RECOVERY_FILES|={'restore-inputs/'+n for n in ['control-plane-images.lock.json','calico-image-pins.json','calico-3.33.0-nebula.yaml']}
REQUIRED_RECOVERY_FILES|={'etc/kubernetes/manifests/'+n for n in ['etcd.yaml','kube-apiserver.yaml','kube-controller-manager.yaml','kube-scheduler.yaml']}

def load_common():
 p=Path(__file__).with_name('nebula-backup-common.py');fd=os.open(p,os.O_RDONLY|os.O_NOFOLLOW)
 try:
  s=os.fstat(fd);raw=os.read(fd,262144);assert s.st_uid==0 and s.st_gid==0 and stat.S_ISREG(s.st_mode) and stat.S_IMODE(s.st_mode)&0o022==0 and s.st_nlink==1 and len(raw)==s.st_size and hashlib.sha256(raw).hexdigest()==COMMON_SHA
  fields=lambda z:(z.st_dev,z.st_ino,z.st_mode,z.st_uid,z.st_gid,z.st_size,z.st_mtime_ns,z.st_ctime_ns)
  assert fields(s)==fields(os.fstat(fd))==fields(p.lstat())
 finally:os.close(fd)
 m=types.ModuleType('_nebula_backup_common');m.__file__=str(p);sys.modules[m.__name__]=m;exec(compile(raw,str(p),'exec'),m.__dict__);return m
def write_all(fd,raw):
 view=memoryview(raw)
 while view:
  n=os.write(fd,view)
  if n<=0:raise RuntimeError('short_file_write')
  view=view[n:]
def hash_fd(fd,limit):
 before=os.fstat(fd);h=hashlib.sha256();size=0;os.lseek(fd,0,os.SEEK_SET)
 while True:
  b=os.read(fd,1024*1024)
  if not b:break
  size+=len(b)
  if size>limit:raise RuntimeError('bounded_file_exceeded')
  h.update(b)
 os.lseek(fd,0,os.SEEK_SET);after=os.fstat(fd)
 if (before.st_dev,before.st_ino,before.st_size,before.st_mtime_ns,before.st_ctime_ns)!=(after.st_dev,after.st_ino,after.st_size,after.st_mtime_ns,after.st_ctime_ns):raise RuntimeError('file_changed')
 return h.hexdigest(),size
@contextlib.contextmanager
def sealed_chunks(chunks,expected_sha,expected_size,limit,m,executable=False):
 """Execute/sign exactly verified public bytes, never a mutable path."""
 fd=os.memfd_create('nebula-verified-public',os.MFD_CLOEXEC|os.MFD_ALLOW_SEALING);h=hashlib.sha256();size=0
 try:
  for chunk in chunks:
   size+=len(chunk);m.need(size<=limit,'sealed_public_input_bound');write_all(fd,chunk);h.update(chunk)
  m.need(size==expected_size and h.hexdigest()==expected_sha,'sealed_public_input_digest')
  os.fchmod(fd,0o500 if executable else 0o400)
  fcntl.fcntl(fd,fcntl.F_ADD_SEALS,fcntl.F_SEAL_WRITE|fcntl.F_SEAL_GROW|fcntl.F_SEAL_SHRINK|fcntl.F_SEAL_SEAL)
  os.lseek(fd,0,os.SEEK_SET);yield fd
 finally:os.close(fd)
def tool_members(layer):
 """Only immutable regular etcd tools; reject whiteouts affecting selected paths."""
 wanted={'usr/local/bin/etcdctl','usr/local/bin/etcdutl'};found={}
 for item in layer:
  n=item.name[2:] if item.name.startswith('./') else item.name
  p=PurePosixPath(n)
  if p.is_absolute() or '..' in p.parts:raise RuntimeError('image_layer_path_escape')
  if n in ['.wh.usr','usr/.wh.local','usr/local/.wh.bin','usr/local/bin/.wh.etcdctl','usr/local/bin/.wh.etcdutl','.wh..wh..opq','usr/.wh..wh..opq','usr/local/.wh..wh..opq','usr/local/bin/.wh..wh..opq']:raise RuntimeError('unsupported_tool_whiteout')
  if n in wanted:
   if n in found or item.type!=tarfile.REGTYPE or item.pax_headers or item.sparse or not 0<item.size<=64*1024**2:raise RuntimeError('unsupported_tool_layer_member')
   found[n]=item
 return found
class Guest:
 def __init__(self,plan_path,phase,m):
  self.m=m;self.p=m.policy();self.plan_raw,self.plan_record=m.read(plan_path);self.plan_path=plan_path;self.plan=json.loads(self.plan_raw);p=self.plan
  m.need(set(p)=={'schema_version','operation_id','run_id','expected_uuid','api_address'} and p['schema_version']==1,'guest_plan_schema')
  self.id=m.operation_id(p['operation_id']);m.need(re.fullmatch('[a-f0-9]{12}',p['run_id']) is not None and str(uuid.UUID(p['expected_uuid']))==p['expected_uuid'],'guest_plan_identity')
  source=Path('/var/lib/parallax-nebula-guest-bootstrap')/('plan-'+p['run_id'])/'cluster-init.py'
  self.cluster_module=m.load_module(source,'_accepted_backup_cluster',CLUSTER_SHA)
  self.cluster=self.cluster_module.Cluster(p['expected_uuid'],p['run_id'],p['api_address'],'check')
  self.cluster_lock=self.cluster.base/'cluster-operation.lock';self.lockfd=os.open(self.cluster_lock,os.O_RDWR|os.O_NOFOLLOW);self.lockmeta=m.ident(os.fstat(self.lockfd))
  m.need(self.lockmeta[3:7]==[0,0,1,0] and stat.S_IMODE(self.lockmeta[2])==0o600,'cluster_lock_custody')
  fcntl.flock(self.lockfd,fcntl.LOCK_EX|fcntl.LOCK_NB)
  self.cluster.external_guard=lambda:m.need(m.ident(os.fstat(self.lockfd))==m.ident(self.cluster_lock.lstat())==self.lockmeta,'cluster_lock_changed')
  self.work=BASE/self.id;self.phase=phase;self.journal=None;self.guard()
  if phase=='prepare':
   if not os.path.lexists(BASE):m.new_dir(BASE)
   m.private_dir(BASE);m.new_dir(self.work)
  elif phase=='check' and not os.path.lexists(self.work):pass
  else:m.private_dir(BASE);m.private_dir(self.work)
  if self.work.exists():self.journal=m.Journal(self.work,['state-prepared.json','state-configured.json','state-seal-started.json','state-sealed.json'])
 def close(self):os.close(self.lockfd)
 def guard(self):
  m=self.m;m.need(m.read(self.plan_path)==(self.plan_raw,self.plan_record),'guest_plan_changed');self.cluster.guard();self.cluster.verify_images()
  s=self.cluster.state;flags=['private_single_node_api','node_ready','locked_control_plane_and_addons','calico_ready','pod_to_service_network','cluster_dns','network_policy_deny_and_scoped_allow','restricted_pod_security','secretbox_encryption_at_rest','metadata_audit_active','control_plane_taint_retained','no_bootstrap_join_token','validation_namespace_cleaned']
  m.need(s['phase']=='accepted' and s.get('acceptance')==dict.fromkeys(flags,True),'accepted_foundation_required')
  m.need(self.cluster.kubectl(['get','--raw','/readyz']).stdout.strip()==b'ok','live_private_api_not_ready')
  nodes=json.loads(self.cluster.kubectl(['get','nodes','-o','json'],sensitive=True).stdout)['items'];m.need(len(nodes)==1 and nodes[0]['status']['nodeInfo']['systemUUID'].lower()==self.plan['expected_uuid'] and any(c.get('type')=='Ready' and c.get('status')=='True' for c in nodes[0]['status'].get('conditions',[])),'actual_owned_node_not_ready')
  pods=json.loads(self.cluster.kubectl(['get','pods','-A','-o','json'],sensitive=True).stdout)['items']
  approved={v['immutable_image'] for v in self.cluster.images.values()}|set(self.cluster.calico.values())
  m.need(len(pods)==9 and all(p['metadata']['namespace']=='kube-system' and p['status']['phase']=='Running' and any(c.get('type')=='Ready' and c.get('status')=='True' for c in p['status'].get('conditions',[])) and all(c['image'] in approved for c in p['spec']['containers']) for p in pods),'actual_system_pods_or_images_changed')
  m.need(not self.cluster.kubectl(['get','namespace','nebula-validate-'+self.plan['run_id'],'--ignore-not-found','-o','json'],sensitive=True).stdout.strip(),'validation_namespace_must_remain_absent')
  self.cluster.api_security_checks()
  for name in REQUIRED_RECOVERY_FILES:
   if name.startswith(('snapshot.db','restore-inputs/')):continue
   path=Path('/')/name;fd,meta=m.regular_fd(path,self.p.MAX_OTHER,private=name.endswith('.key') or name=='etc/kubernetes/nebula/encryption.json')
   try:m.need(meta[6]>0,'required_recovery_file_empty')
   finally:os.close(fd)
  m.require_free(self.cluster.base,2*1024**3)
  if self.journal:self.journal.guard()
 def cmd(self,args,label,**kw):self.guard();return self.m.command(self.work,args,label,**kw)
 def public_tools(self):
  m=self.m;ref='registry.k8s.io/etcd:3.7.0-0';lock=self.cluster.images[ref]
  manifest_raw=self.cmd(['ctr','--namespace','k8s.io','content','get',lock['linux_amd64_manifest_digest']],'read-etcd-manifest')
  m.need(m.sha(manifest_raw)==lock['linux_amd64_manifest_digest'].split(':')[1],'etcd_manifest_digest')
  manifest=json.loads(manifest_raw);m.need(manifest['config']['digest']==lock['config_digest'] and [x['digest'] for x in manifest['layers']]==lock['layer_digests'],'etcd_layer_lock_mismatch')
  tools={};total=0
  for i,item in enumerate(manifest['layers']):
   m.need(item['size']<=256*1024**2 and total+item['size']<=512*1024**2,'public_layer_budget');total+=item['size'];path=self.work/('layer-'+str(i)+'.blob');fd=m.new_output(path)
   try:self.cmd(['ctr','--namespace','k8s.io','content','get',item['digest']],'copy-etcd-layer',stdout_fd=fd,file_limit=256*1024**2);os.fsync(fd)
   finally:os.close(fd)
   with m.pinned(path,256*1024**2,True) as (fd,meta):
    digest,size=hash_fd(fd,256*1024**2);m.need(digest==item['digest'].split(':')[1] and size==item['size'],'etcd_layer_digest')
    with os.fdopen(os.dup(fd),'rb') as stream:
     with tarfile.open(fileobj=stream,mode='r:*') as layer:
      members=tool_members(layer)
      for name,member in members.items():
       short=PurePosixPath(name).name;m.need(short not in tools,'duplicate_etcd_tool_layer');out=m.new_output(self.work/short,0o700)
       try:
        src=layer.extractfile(member);left=member.size
        while left:
         chunk=src.read(min(left,1024*1024));m.need(bool(chunk),'truncated_etcd_tool');write_all(out,chunk);left-=len(chunk)
        os.fsync(out);pin,n=hash_fd(out,64*1024**2);tools[short]={'sha256':pin,'bytes':n,'identity':m.ident(os.fstat(out))}
       finally:os.close(out)
  m.need(set(tools)=={'etcdctl','etcdutl'},'both_locked_etcd_tools_required')
  for tool in tools:
   with self.tool_fd(tool,tools[tool]) as fd:text=self.cmd(['/proc/self/fd/'+str(fd),'version'],'verify-'+tool+'-version',pass_fds=(fd,)).decode()
   m.need(re.search(r'(?m)^'+tool+r' version: 3\.7\.0\s*$',text) is not None,'exact_etcd_tool_version_required')
  return tools
 @contextlib.contextmanager
 def tool_fd(self,name,known):
  m=self.m;m.need(name in ['etcdctl','etcdutl'],'known_public_tool_only')
  with m.pinned(self.work/name,64*1024**2) as (source,meta):
   m.need(meta==known['identity'] and hash_fd(source,64*1024**2)==(known['sha256'],known['bytes']),'etcd_tool_changed')
   def chunks():
    os.lseek(source,0,os.SEEK_SET)
    while True:
     raw=os.read(source,65536)
     if not raw:break
     yield raw
   with sealed_chunks(chunks(),known['sha256'],known['bytes'],64*1024**2,m,True) as fd:yield fd
 def prepare(self):
  m=self.m;m.need(not self.journal.records,'new_guest_backup_operation_required')
  for tool in ['/usr/bin/gpg','/usr/bin/openssl']:m.need(Path(tool).is_file(),'guest_crypto_tool_missing')
  m.require_free(self.cluster.base,5*1024**3)
  tools=self.public_tools();home=self.work/'public-keys';m.new_dir(home)
  key=self.work/'signing-private.pem';public=self.work/'signing-public.pem';k=m.new_output(key);p=m.new_output(public)
  try:
   self.cmd(['openssl','genpkey','-algorithm','Ed25519','-out','/proc/self/fd/'+str(k)],'create-dedicated-signing-key',pass_fds=(k,))
   self.cmd(['openssl','pkey','-in','/proc/self/fd/'+str(k),'-pubout','-out','/proc/self/fd/'+str(p)],'export-signing-public',pass_fds=(k,p))
   os.fsync(k);os.fsync(p);keymeta=m.ident(os.fstat(k));pubraw,_=m.read(public);m.need(pubraw.startswith(b'-----BEGIN PUBLIC KEY-----'),'signer_public_format')
  finally:os.close(k);os.close(p)
  self.guard();self.journal.append('state-prepared.json',{'operation_id':self.id,'tools':tools,'signing_private_metadata':keymeta,'signer_public_sha256':m.sha(pubraw),'signer_public_bytes':len(pubraw)})
 def prepared(self):
  s=self.journal.get('state-prepared.json');self.m.need(s['operation_id']==self.id,'prepared_operation_binding')
  for name,known in s['tools'].items():
   with self.m.pinned(self.work/name,64*1024**2) as (fd,meta):self.m.need(meta==known['identity'] and hash_fd(fd,64*1024**2)==(known['sha256'],known['bytes']),'etcd_tool_changed')
  self.m.need(self.m.ident((self.work/'signing-private.pem').lstat())==s['signing_private_metadata'],'dedicated_signing_key_changed')
  pub,_=self.m.read(self.work/'signing-public.pem');self.m.need(self.m.sha(pub)==s['signer_public_sha256'],'signer_public_changed');return s,pub
 def export_public(self):
  self.guard();s,pub=self.prepared();return {'schema_version':1,'operation_id':self.id,'signer_public_pem':pub.decode(),'signer_public_sha256':s['signer_public_sha256'],'etcd_version':'3.7.0','etcdutl_sha256':s['tools']['etcdutl']['sha256'],'etcdutl_bytes':s['tools']['etcdutl']['bytes']}
 def configure(self,input_path):
  self.guard();self.prepared();m=self.m;m.need(set(self.journal.records)=={'state-prepared.json'},'configure_once_only')
  raw,record=m.read(input_path,256*1024);v=json.loads(raw);m.need(set(v)=={'schema_version','operation_id','recipients','public_keys'} and v['schema_version']==1 and v['operation_id']==self.id,'public_recipient_input_schema');recipients=self.p.pins(v['recipients']);m.need(set(v['public_keys'])==set(self.p.TARGETS),'exact_two_public_key_exports')
  for target in self.p.TARGETS:
   armor=v['public_keys'][target].encode();self.p.public_key_file(armor);p=self.work/(target.lower()+'-public.asc');m.exclusive(p,armor)
   meta=self.cmd(self.p.inspect_args(str(self.work/'public-keys'),str(p)),'inspect-'+target.lower()+'-public',address_limit=768*1024**2).decode()
   self.p.parsed_key(meta,recipients[target],int(time.time()))
   self.cmd(self.p.gpg_prefix(str(self.work/'public-keys'))+['--import',str(p)],'import-'+target.lower()+'-public',address_limit=768*1024**2)
  self.guard();m.need(m.read(input_path,256*1024)==(raw,record),'public_recipient_input_changed')
  self.journal.append('state-configured.json',{'operation_id':self.id,'recipients':recipients,'public_input':record})
 def archive_inputs(self,snapshot):
  m=self.m;inputs={'snapshot.db':snapshot}
  for root in [Path('/etc/kubernetes/pki'),Path('/etc/kubernetes/nebula'),Path('/etc/kubernetes/manifests')]:
   m.need(root.is_dir() and root.resolve()==root,'backup_input_directory_changed')
   for p in sorted(root.rglob('*')):
    if p.is_dir() and not p.is_symlink():continue
    m.need(not p.is_symlink() and p.is_file(),'backup_input_link_or_special_file');inputs[str(p).lstrip('/')]=p
  for name in ['/etc/kubernetes/admin.conf','/etc/kubernetes/super-admin.conf','/etc/kubernetes/kubelet.conf','/var/lib/kubelet/config.yaml']:
   inputs[name.lstrip('/')]=Path(name)
  for kind,name in [('configmap','kubeadm-config'),('configmap','kubelet-config')]:
   data=self.cluster.kubectl(['get',kind,name,'-n','kube-system','-o','json'],sensitive=True).stdout
   path=self.work/(name+'-restore.json');m.exclusive(path,data);inputs['restore-inputs/'+path.name]=path
  for name,path in [('control-plane-images.lock.json',self.cluster.input/'control-plane-images.lock.json'),('calico-image-pins.json',self.cluster.input/'calico-image-pins.json'),('calico-3.33.0-nebula.yaml',self.cluster.base/'incoming/calico-3.33.0-nebula.yaml')]:
   inputs['restore-inputs/'+name]=path
  embedded=self.cluster.run(['kubectl','--kubeconfig','/etc/kubernetes/kubelet.conf','config','view','--raw','--flatten','-o','json'],'private-kubelet-recovery-config',sensitive=True).stdout
  embedded_path=self.work/'kubelet-embedded-restore.json';m.exclusive(embedded_path,embedded);inputs['restore-inputs/'+embedded_path.name]=embedded_path
  return inputs
 def seal(self):
  self.guard();prepared,_=self.prepared();m=self.m;configured=self.journal.get('state-configured.json')
  m.need('state-seal-started.json' not in self.journal.records and 'state-sealed.json' not in self.journal.records,'seal_once_only');m.require_free(self.cluster.base,4*1024**3)
  scratch=self.work/'snapshot-scratch';m.new_dir(scratch);snapshot=scratch/'snapshot.db'
  self.journal.append('state-seal-started.json',{'operation_id':self.id,'snapshot_scratch_identity':m.ident(scratch.lstat())[:5],'one_use_snapshot_attempt_consumed':True})
  m.need(not list(scratch.iterdir()),'exclusive_snapshot_scratch_required')
  auth=['--endpoints=https://127.0.0.1:2379','--cacert=/etc/kubernetes/pki/etcd/ca.crt','--cert=/etc/kubernetes/pki/etcd/healthcheck-client.crt','--key=/etc/kubernetes/pki/etcd/healthcheck-client.key']
  with self.tool_fd('etcdctl',prepared['tools']['etcdctl']) as tool:
   self.cmd(['/proc/self/fd/'+str(tool),*auth,'snapshot','save',str(snapshot)],'snapshot-own-cluster',timeout=120,file_limit=self.p.MAX_SNAPSHOT,pass_fds=(tool,))
  with m.pinned(snapshot,self.p.MAX_SNAPSHOT,True) as (snapshot_fd,snapshot_meta):
   m.need(hash_fd(snapshot_fd,self.p.MAX_SNAPSHOT)[1]>0,'empty_snapshot')
   with self.tool_fd('etcdutl',prepared['tools']['etcdutl']) as tool:
    raw=self.cmd(['/proc/self/fd/'+str(tool),'snapshot','status','/proc/self/fd/'+str(snapshot_fd),'-w','json'],'verify-snapshot-status',pass_fds=(tool,snapshot_fd))
   status=json.loads(raw)
   m.need(type(status) is dict and set(status)=={'hash','revision','totalKey','totalSize','version'} and all(type(status[k]) is int and status[k]>=0 for k in ['hash','revision','totalKey','totalSize']) and status['revision']>0 and status['totalKey']>0 and type(status['version']) is str and len(status['version'])<=32,'snapshot_status_required')
   inputs=self.archive_inputs(snapshot);m.need(REQUIRED_RECOVERY_FILES<=set(inputs),'complete_cluster_recovery_material_required');held=[];inventory=[]
   try:
    for name,path in sorted(inputs.items()):
     limit=self.p.MAX_SNAPSHOT if name=='snapshot.db' else self.p.MAX_OTHER
     if name=='snapshot.db':fd=os.dup(snapshot_fd);meta=m.ident(os.fstat(fd));m.need(meta==snapshot_meta==m.ident(path.lstat()),'snapshot_identity_changed')
     else:fd,meta=m.regular_fd(path,limit,private=False)
     m.need(name not in REQUIRED_RECOVERY_FILES or meta[6]>0,'required_recovery_file_empty');held.append((name,path,fd,meta));inventory.append({'name':name,'kind':'regular','size':meta[6]})
    restore=m.json_bytes({'schema_version':1,'operation_id':self.id,'expected_uuid':self.plan['expected_uuid'],'run_id':self.plan['run_id'],'api_address':self.plan['api_address'],'etcd_version':'3.7.0','snapshot_status':status,'source_cluster_sha256':CLUSTER_SHA,'archive_members':inventory})
    restore_path=self.work/'restore-manifest.json';restore_identity=m.exclusive(restore_path,restore);fd,meta=m.regular_fd(restore_path,self.p.MAX_OTHER,True);m.need(meta==restore_identity,'restore_manifest_postimage_changed');held.append(('restore-manifest.json',restore_path,fd,meta));inventory.append({'name':'restore-manifest.json','kind':'regular','size':meta[6]});self.p.archive_inventory(inventory)
    cipher=self.work/'backup.tar.gpg';out=m.new_output(cipher);rfd,wfd=os.pipe2(os.O_CLOEXEC);writer_errors=[];writer_started=False
    plain_bound=self.p.MAX_SNAPSHOT+self.p.MAX_OTHER+16*1024**2
    class PipeWriter:
     def __init__(self):self.count=0
     def write(self,data):
      self.count+=len(data);m.need(self.count<=plain_bound,'archive_stream_size_bound');write_all(wfd,data);return len(data)
     def flush(self):pass
    def produce_tar():
     try:
      with tarfile.open(fileobj=PipeWriter(),mode='w|',format=tarfile.USTAR_FORMAT) as tar:
       for name,path,fd,meta in held:
        m.need(m.ident(os.fstat(fd))==meta==m.ident(path.lstat()),'backup_input_changed');os.lseek(fd,0,os.SEEK_SET)
        item=tarfile.TarInfo(name);item.size=meta[6];item.uid=item.gid=0;item.mode=0o600;item.mtime=0
        with os.fdopen(os.dup(fd),'rb') as stream:tar.addfile(item,stream)
        m.need(m.ident(os.fstat(fd))==meta==m.ident(path.lstat()),'backup_input_changed')
     except BaseException as exc:writer_errors.append(exc)
     finally:os.close(wfd)
    writer=threading.Thread(target=produce_tar,name='owned-backup-tar-producer',daemon=True)
    def start_writer():
     nonlocal writer_started
     writer.start();writer_started=True
    try:
     try:
      # Popen/exec happens BEFORE the producer thread starts: no threaded preexec fork.
      self.cmd(self.p.encrypt_args(str(self.work/'public-keys'),configured['recipients']),'encrypt-archive',timeout=240,stdout_fd=out,stdin_fd=rfd,on_start=start_writer,file_limit=self.p.MAX_CIPHERTEXT,address_limit=768*1024**2)
     finally:
      os.close(rfd)
      if writer_started:
       writer.join(timeout=5);m.need(not writer.is_alive(),'archive_writer_not_quiescent')
      else:os.close(wfd)
     m.need(not writer_errors,'archive_writer_failed_private_receipt')
     os.fsync(out);cipher_sha,n=hash_fd(out,self.p.MAX_CIPHERTEXT);cipher_identity=m.ident(os.fstat(out));m.need(n>0 and cipher_identity==m.ident(cipher.lstat()),'empty_or_replaced_ciphertext')
    finally:os.close(out)
    manifest=self.p.ciphertext_manifest(self.id,cipher_sha,n,configured['recipients'],prepared['signer_public_sha256'],int(time.time()));manifest_path=self.work/'manifest.json';manifest_identity=m.exclusive(manifest_path,manifest)
    signature=self.work/'manifest.sig';sigfd=m.new_output(signature)
    try:
     with sealed_chunks([manifest],m.sha(manifest),len(manifest),8192,m) as manifestfd:
      with m.pinned(self.work/'signing-private.pem',16384,True) as (keyfd,keymeta):
       m.need(keymeta==prepared['signing_private_metadata'],'signing_key_changed')
       self.cmd(['openssl','pkeyutl','-sign','-rawin','-inkey','/proc/self/fd/'+str(keyfd),'-in','/proc/self/fd/'+str(manifestfd),'-out','/proc/self/fd/'+str(sigfd)],'sign-ciphertext-manifest',pass_fds=(keyfd,manifestfd,sigfd))
     os.fsync(sigfd);sig_identity=m.ident(os.fstat(sigfd));sigbytes=os.pread(sigfd,65,0);m.need(len(sigbytes)==64 and sig_identity==m.ident(signature.lstat()),'ed25519_signature_postimage')
    finally:os.close(sigfd)
    expected_manifest={'identity':manifest_identity,'sha256':m.sha(manifest)};expected_signature={'identity':sig_identity,'sha256':m.sha(sigbytes)}
    m.need(m.read(manifest_path,8192)==(manifest,expected_manifest) and m.read(signature,64)==(sigbytes,expected_signature),'signed_envelope_namespace_changed')
    self.guard();self.journal.append('state-sealed.json',{'operation_id':self.id,'ciphertext_sha256':cipher_sha,'ciphertext_bytes':n,'ciphertext_identity':cipher_identity,'manifest':expected_manifest,'signature':expected_signature,'source_plaintext_exported':False})
   finally:
    for _,_,fd,_ in held:os.close(fd)
 def export_file(self,kind):
  self.guard();prepared,_=self.prepared();m=self.m
  if kind=='tool':
   with self.tool_fd('etcdutl',prepared['tools']['etcdutl']) as fd:
    while True:
     raw=os.read(fd,65536)
     if not raw:break
     sys.stdout.buffer.write(raw)
   self.guard();return
  sealed=self.journal.get('state-sealed.json');held=[]
  # Validate and retain the SAME descriptors used by the archive writer.
  with contextlib.ExitStack() as stack:
   for name,key in [('backup.tar.gpg',None),('manifest.json','manifest'),('manifest.sig','signature')]:
    limit=self.p.MAX_CIPHERTEXT if key is None else 8192 if key=='manifest' else 64
    fd,meta=stack.enter_context(m.pinned(self.work/name,limit,True))
    digest,size=hash_fd(fd,limit)
    if key is None:m.need(meta==sealed['ciphertext_identity'] and (digest,size)==(sealed['ciphertext_sha256'],sealed['ciphertext_bytes']),'sealed_ciphertext_changed')
    else:m.need({'identity':meta,'sha256':digest}==sealed[key],'sealed_envelope_changed')
    held.append((name,fd,meta))
   with tarfile.open(fileobj=sys.stdout.buffer,mode='w|',format=tarfile.USTAR_FORMAT) as out:
    for name,fd,meta in held:
     os.lseek(fd,0,os.SEEK_SET);item=tarfile.TarInfo(name);item.size=meta[6];item.mode=0o600;item.uid=item.gid=0;item.mtime=0
     with os.fdopen(os.dup(fd),'rb') as stream:out.addfile(item,stream)
  self.guard()

def main():
 os.umask(0o077);m=load_common();p=argparse.ArgumentParser(description=__doc__);p.add_argument('--plan',type=Path,required=True);p.add_argument('--phase',required=True,choices=['check','prepare','configure','snapshot-seal','export-public','export-etcdutl','export-envelope']);p.add_argument('--input',type=Path);p.add_argument('--execute',action='store_true');a=p.parse_args()
 m.need(os.geteuid()==0,'guest_root_required');m.need(a.phase in ['check','export-public','export-etcdutl','export-envelope'] or a.execute,'explicit_execute_required')
 j=Guest(a.plan,a.phase,m)
 try:
  if a.phase=='prepare':j.prepare()
  elif a.phase=='configure':m.need(a.input is not None,'public_input_required');j.configure(a.input)
  elif a.phase=='snapshot-seal':j.seal()
  elif a.phase=='export-public':print(json.dumps(j.export_public()));return
  elif a.phase in ['export-etcdutl','export-envelope']:j.export_file('tool' if a.phase=='export-etcdutl' else 'envelope');return
  else:
   j.guard()
   if j.journal is not None:j.prepared()
   else:
    for tool in ['/usr/bin/gpg','/usr/bin/openssl']:m.need(Path(tool).is_file(),'guest_crypto_tool_missing')
    m.require_free(j.cluster.base,5*1024**3)
  j.guard();print(json.dumps({'status':'passed','phase':a.phase,'source_plaintext_exported':False,'no_cluster_resources_mutated':True}))
 finally:j.close()
if __name__=='__main__':
 try:main()
 except Exception as e:
  print(json.dumps({'status':'refused','reason':str(e) if re.fullmatch('[a-z0-9_]+',str(e)) else type(e).__name__}),file=sys.stderr);raise SystemExit(1)

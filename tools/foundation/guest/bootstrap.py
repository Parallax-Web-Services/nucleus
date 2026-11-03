#!/usr/bin/env python3
"""Source API for the reviewed Noble/amd64 guest profile; not a public installer.
No kubeadm init, CNI apply, external image pulls, host package changes or reset.
"""
from __future__ import annotations
import argparse,contextlib,fcntl,hashlib,ipaddress,json,os,platform,re,socket,stat,subprocess,sys,tarfile,tempfile,time,uuid
from pathlib import Path
from foundation.framework import require_context
PINS={
 'containerd-2.3.7-linux-amd64.tar.gz':'09a1b669ac6d21e7e24c3c33a9805b48987ba5845e8d88f039c47013a0c0025c',
 'runc.amd64':'599f6f94ff8c5057241eff0d54c3c74f95c34935b6457b33fe545defc61e9488',
 'nebula-kubernetes-v1.37.1-amd64-verified.tar.gz':'a9b5f9993da58d976ae8564c2d821a347497eb3d82fda49daa8e90e608b10652',
 'calico-3.33.0-nebula.yaml':'6927c2d2c7a6de627a8df06c3097883121225d32c8bcec3f52d2ecf921dcdd1b'}
VERIFIER_SHA='1602a1f96b8187e52ca84b0562e3bb96372dabfee048c1bc4bc594e59f31162d'
# Root-verified official registry index/amd64/config chain; no separate image signature claimed.
PAUSE_IMAGE='registry.k8s.io/pause@sha256:f548e0e8e3dc1896ca956272154dde3314e8cc4fde0a57577ee9fa1c63f5baf4'
PACKAGES=[
 ('kubernetes-cni','1.9.1-1.1','4cd72d8cef4499d3dc410874287b40e8b4241e0772938c5820cbee37986c1d93'),
 ('cri-tools','1.37.0-1.1','a8eeede0deadc3d9e8f72859732441bfc86fbe60688926ef5410f01338927b71'),
 ('kubelet','1.37.1-1.1','a0692776f7f026ff17de0ede1b97f11c657300f586cc7939766c395f64c2e6d9'),
 ('kubeadm','1.37.1-1.1','b7f399d83fcb8c619927042b4dcd06ba68757fb74f9d2baabc358a0e22032f92'),
 ('kubectl','1.37.1-1.1','f2a1d6e1d2adf5c5c80d3518917a28b66a423698a553c4be4d181df8ddbdde94')]
BUNDLE_MEMBERS=set('Release.key InRelease Release Release.gpg Packages.gz Packages verified-receipt.json verify_official_packages.py GUEST-PACKAGE-PROCEDURE.md gpgv-inline-status.txt gpgv-detached-status.txt key-listing.txt fetch-receipt.json SHA256SUMS'.split())
for package,version,digest in PACKAGES:
 BUNDLE_MEMBERS.add('amd64/'+package+'_'+version+'_amd64.deb')
 for suffix in ['control.txt','contents.txt','maintainer-scripts.json']:BUNDLE_MEMBERS.add(package+'.'+suffix)
RUNTIME_MEMBERS={'bin/','bin/containerd','bin/containerd-shim-runc-v2','bin/containerd-stress','bin/ctr'}
MODULES=b'overlay\nbr_netfilter\nvxlan\n'
SYSCTL=b'net.ipv4.ip_forward = 1\nnet.bridge.bridge-nf-call-iptables = 1\nnet.bridge.bridge-nf-call-ip6tables = 1\n'
UNIT=b'''[Unit]
Description=NEBULA guest container runtime
After=network.target local-fs.target
[Service]
Type=notify
ExecStart=/usr/local/bin/containerd --config /etc/containerd/config.toml
Delegate=yes
KillMode=process
Restart=on-failure
RestartSec=5
TasksMax=infinity
LimitNOFILE=1048576
[Install]
WantedBy=multi-user.target
'''
class Refused(RuntimeError):pass
def need(ok,code):
 if not ok:raise Refused(code)
def digest(raw):return hashlib.sha256(raw).hexdigest()
def canonical(path):
 need(path.is_absolute() and path.resolve()==path,'noncanonical_path');return path
def private_dir(path):
 s=canonical(path).lstat();need(stat.S_ISDIR(s.st_mode) and s.st_uid==0 and stat.S_IMODE(s.st_mode)==0o700,'private_directory_required')
def state_identity(s):
 return(s.st_dev,s.st_ino,s.st_mode,s.st_uid,s.st_gid,s.st_nlink,s.st_size,s.st_mtime_ns,s.st_ctime_ns)
def file_snapshot(path,limit=512*1024**2,private=False):
 fd=os.open(canonical(path),os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC)
 try:
  before=os.fstat(fd);need(stat.S_ISREG(before.st_mode) and before.st_nlink==1 and before.st_uid==0 and not before.st_mode&0o022 and before.st_size<=limit,'unsafe_file')
  if private:need(stat.S_IMODE(before.st_mode)==0o600,'private_file_required')
  h=hashlib.sha256();total=0
  while True:
   raw=os.read(fd,1024*1024)
   if not raw:break
   total+=len(raw);need(total<=limit,'file_size_bound');h.update(raw)
  after=os.fstat(fd);need(state_identity(before)==state_identity(after)==state_identity(path.lstat()),'file_changed_during_read')
  return {'identity':state_identity(after),'sha256':h.hexdigest()}
 finally:os.close(fd)
def read_private(path,limit=2*1024**2):
 before=file_snapshot(path,limit,True);raw=path.read_bytes();need(file_snapshot(path,limit,True)==before,'private_control_changed');return raw,before
def write_exclusive(path,raw,mode=0o600):
 canonical(path.parent);parent=path.parent.lstat();need(stat.S_ISDIR(parent.st_mode) and parent.st_uid==0 and not parent.st_mode&0o022,'unsafe_destination_directory');need(not os.path.lexists(path),'new_path_already_exists')
 fd,temp=tempfile.mkstemp(prefix='.nebula-new-',dir=path.parent);owned=os.fstat(fd)
 try:
  with os.fdopen(fd,'wb') as out:out.write(raw);out.flush();os.fchmod(out.fileno(),mode);os.fsync(out.fileno())
  os.link(temp,path,follow_symlinks=False);os.unlink(temp)
  result=file_snapshot(path);need(result['identity'][:2]==(owned.st_dev,owned.st_ino),'new_file_postimage_unknown')
  return result
 finally:
  try:
   s=os.lstat(temp)
   if(s.st_dev,s.st_ino)==(owned.st_dev,owned.st_ino):os.unlink(temp)
  except FileNotFoundError:pass
@contextlib.contextmanager
def verified_fd(path,expected):
 expected_state=file_snapshot(path,private=True);need(expected_state['sha256']==expected,'artifact_digest_mismatch')
 fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC)
 try:
  need(state_identity(os.fstat(fd))==expected_state['identity'],'artifact_replaced_before_open')
  yield fd
  need(state_identity(os.fstat(fd))==expected_state['identity'] and file_snapshot(path,private=True)==expected_state,'artifact_changed_during_use')
 finally:os.close(fd)
def archive_members(fd,allowed):
 with os.fdopen(os.dup(fd),'rb') as source:
  source.seek(0)
  with tarfile.open(fileobj=source,mode='r:gz') as archive:
   members=archive.getmembers();names=[m.name+('/' if m.isdir() and not m.name.endswith('/') else '') for m in members]
   need(len(names)==len(set(names)) and set(names)==allowed,'archive_member_inventory')
   total=0
   for member,name in zip(members,names):
    need(not member.name.startswith('/') and '..' not in Path(member.name).parts and (member.isfile() or member.isdir()) and not member.issym() and not member.islnk(),'unsafe_archive_member')
    need(member.size<=256*1024**2,'archive_member_bound');total+=member.size
   need(total<=512*1024**2,'archive_total_bound')
   return names
def extract_selected(fd,allowed,selected,target):
 need(not os.path.lexists(target),'new_extraction_directory_exists');target.mkdir(mode=0o700);private_dir(target)
 archive_members(fd,allowed);records={}
 with os.fdopen(os.dup(fd),'rb') as source:
  source.seek(0)
  with tarfile.open(fileobj=source,mode='r:gz') as archive:
   for member in archive.getmembers():
    if member.name not in selected:continue
    need(member.isfile(),'selected_member_not_regular')
    output=target/member.name;output.parent.mkdir(mode=0o700,parents=True,exist_ok=True);canonical(output.parent)
    stream=archive.extractfile(member);need(stream is not None,'archive_member_missing')
    with stream:raw=stream.read(256*1024**2+1)
    need(len(raw)==member.size,'archive_member_truncated');records[member.name]=write_exclusive(output,raw)
 return records
def prepared_bytes(path,record):
 with verified_fd(path,record['sha256']) as fd:
  need(state_identity(os.fstat(fd))==record['identity'],'prepared_file_replaced')
  out=b''
  while True:
   raw=os.read(fd,1024*1024)
   if not raw:break
   out+=raw
  need(digest(out)==record['sha256'],'prepared_bytes_changed');return out
def routes_clear(routes):
 candidates=[ipaddress.ip_network('10.244.0.0/16'),ipaddress.ip_network('10.96.0.0/12')]
 for route in routes:
  dest=route.get('dst','default')
  if dest=='default':continue
  network=ipaddress.ip_network(dest,strict=False)
  if network.prefixlen and any(network.overlaps(x) for x in candidates):return False
 return True
def containerd_config():
 need(isinstance(PAUSE_IMAGE,str) and re.fullmatch('registry.k8s.io/pause@sha256:[a-f0-9]{64}',PAUSE_IMAGE),'pause_image_lock_pending')
 return ("""version = 3
root = "/var/lib/containerd"
state = "/run/containerd"
disabled_plugins = []
[grpc]
  address = "/run/containerd/containerd.sock"
[plugins."io.containerd.cri.v1.images".pinned_images]
  sandbox = "%s"
[plugins."io.containerd.cri.v1.runtime".containerd]
  default_runtime_name = "runc"
[plugins."io.containerd.cri.v1.runtime".containerd.runtimes.runc]
  runtime_type = "io.containerd.runc.v2"
[plugins."io.containerd.cri.v1.runtime".containerd.runtimes.runc.options]
  BinaryName = "/usr/local/sbin/runc"
  SystemdCgroup = true
"""%PAUSE_IMAGE).encode()
def guest_identity(expected_uuid,run_id,context=None):
 context=require_context(context,'guest')
 need(context.inputs['run_id']==run_id and context.inputs['expected_guest_uuid']==expected_uuid,'context_guest_identity_mismatch')
 need(os.geteuid()==0 and re.fullmatch('[a-f0-9]{12}',run_id) and str(uuid.UUID(expected_uuid))==expected_uuid,'guest_identity_arguments')
 need(Path('/sys/class/dmi/id/product_uuid').read_text().strip().lower()==expected_uuid and socket.gethostname()=='nebula-control-'+run_id,'wrong_guest_do_not_install')
 data={}
 for line in Path('/etc/os-release').read_text().splitlines():
  if '=' in line:key,value=line.split('=',1);data[key]=value.strip('"')
 need(data.get('ID')=='ubuntu' and data.get('VERSION_ID')=='24.04' and data.get('VERSION_CODENAME')=='noble' and platform.machine()=='x86_64','guest_distribution_mismatch')
 need(os.cpu_count()==2 and Path('/sys/fs/cgroup/cgroup.controllers').is_file() and len(Path('/proc/swaps').read_text().splitlines())==1,'guest_resource_cgroup_or_swap_changed')
class Bootstrap:
 def __init__(self,expected_uuid,run_id,work,context=None):
  self.context=require_context(context,'guest')
  guest_identity(expected_uuid,run_id,self.context);self.expected_uuid=expected_uuid;self.run_id=run_id
  self.work=canonical(work);need(work==self.context.path('guest_state_root')/('plan-'+run_id),'guest_work_binding')
  private_dir(work);self.incoming=work/'incoming';private_dir(self.incoming)
  need(set(x.name for x in self.incoming.iterdir())==set(PINS),'artifact_inventory')
  self.state_path=work/'install-state.json';self.expected_control=None;self.state={'schema_version':1,'run_id':run_id,'foundation_binding':self.context.binding(),'files':{},'phase':'not_started'}
 def command(self,args,label,timeout=60,pass_fds=()):
  env={'PATH':'/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin','HOME':'/root','LANG':'C.UTF-8','LC_ALL':'C.UTF-8','DEBIAN_FRONTEND':'noninteractive'}
  result=subprocess.run(args,env=env,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=timeout,pass_fds=pass_fds)
  for suffix,value in [('stdout',result.stdout),('stderr',result.stderr)]:write_exclusive(self.work/(label+'-'+os.urandom(4).hex()+'.'+suffix),value)
  need(result.returncode==0,'command_failed_private_receipt');return result.stdout
 def guard(self):
  if getattr(self,'external_guard',None):self.external_guard()
  self.context.guard();need(self.state.get('foundation_binding')==self.context.binding(),'foundation_binding_changed');guest_identity(self.expected_uuid,self.run_id,self.context);private_dir(self.work);private_dir(self.incoming)
  if self.expected_control is None:need(not os.path.lexists(self.state_path),'existing_install_state_requires_review')
  else:need(file_snapshot(self.state_path,private=True)==self.expected_control,'install_control_state_changed')
  for path,record in self.state['files'].items():need(file_snapshot(Path(path))==record,'installed_file_changed')
  need(routes_clear(json.loads(self.command(['ip','-j','-4','route','show','table','all'],'check-guest-routes'))),'candidate_cidr_route_collision')
 def persist(self):
  self.guard();raw=json.dumps(self.state,sort_keys=True,indent=2).encode()
  if self.expected_control is None:self.expected_control=write_exclusive(self.state_path,raw);return
  need(file_snapshot(self.state_path,private=True)==self.expected_control,'install_control_state_changed')
  fd,temp=tempfile.mkstemp(prefix='.install-state-',dir=self.work);owned=os.fstat(fd)
  try:
   with os.fdopen(fd,'wb') as out:out.write(raw);out.flush();os.fsync(out.fileno())
   need(file_snapshot(self.state_path,private=True)==self.expected_control,'install_control_state_changed');os.replace(temp,self.state_path)
   current=file_snapshot(self.state_path,private=True);need(current['identity'][:2]==(owned.st_dev,owned.st_ino),'install_control_postimage_unknown');self.expected_control=current
  finally:
   try:
    s=os.lstat(temp)
    if(s.st_dev,s.st_ino)==(owned.st_dev,owned.st_ino):os.unlink(temp)
   except FileNotFoundError:pass
 def preflight(self):
  self.guard()
  for executable in ['python3','gpg','gpgv','dpkg','dpkg-query','dpkg-deb','apt-mark','systemctl','modprobe','sysctl','ip']:
   need(any((Path(root)/executable).is_file() for root in ['/usr/sbin','/usr/bin','/sbin','/bin']),'guest_tool_missing')
  need(not any(os.path.lexists(x) for x in ['/etc/kubernetes','/var/lib/etcd','/etc/containerd','/var/lib/containerd','/run/containerd','/etc/systemd/system/containerd.service','/etc/modules-load.d/nebula-kubernetes.conf','/etc/sysctl.d/99-nebula-kubernetes.conf']),'existing_guest_runtime_or_cluster_state')
  for name in ['containerd','containerd-shim-runc-v2','ctr']:
   need(not os.path.lexists(Path('/usr/local/bin')/name),'runtime_binary_already_exists')
  need(not os.path.lexists('/usr/local/sbin/runc'),'runc_already_exists')
  for root in ['/etc/systemd/system','/run/systemd/system','/usr/lib/systemd/system','/lib/systemd/system']:
   for name in ['containerd.service','containerd.service.d']:need(not os.path.lexists(Path(root)/name),'foreign_containerd_unit_or_dropin')
  need(not os.path.lexists('/etc/systemd/system/multi-user.target.wants/containerd.service'),'foreign_containerd_enablement')
  for package,version,pin in PACKAGES:
   r=subprocess.run(['dpkg-query','-W','-f='+chr(36)+'{db:Status-Status}',package],stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,text=True)
   need(r.returncode==1 or r.stdout.strip()=='not-installed','selected_package_already_present')
  for package in ['libc6:amd64','mount','util-linux','iptables']:
   need(self.command(['dpkg-query','-W','-f='+chr(36)+'{db:Status-Status}',package],'check-distro-package').strip()==b'installed','distro_dependency_not_installed')
  self.command(['dpkg','--compare-versions',self.command(['dpkg-query','-W','-f='+chr(36)+'{Version}','iptables'],'check-iptables-version').decode().strip(),'ge','1.8.4'],'check-iptables-minimum')
  need(not self.command(['dpkg','--audit'],'check-dpkg-audit').strip(),'preexisting_dpkg_audit_failure')
  for name,pin in PINS.items():
   with verified_fd(self.incoming/name,pin) as fd:
    if name.startswith('containerd-'):archive_members(fd,RUNTIME_MEMBERS)
    elif name.startswith('nebula-kubernetes-'):archive_members(fd,BUNDLE_MEMBERS)
  return {'guest_identity_checked':True,'artifact_pins_checked':len(PINS),'candidate_cidrs_clear':True,'system_packages_changed':False}
 def own_file(self,path,raw,mode=0o644):
  self.guard();record=write_exclusive(path,raw,mode);self.state['files'][str(path)]=record;self.persist()
 def install(self):
  self.preflight();config=containerd_config();self.state['phase']='installation_started';self.persist()
  prepared=self.work/'prepared'
  with verified_fd(self.incoming/'nebula-kubernetes-v1.37.1-amd64-verified.tar.gz',PINS['nebula-kubernetes-v1.37.1-amd64-verified.tar.gz']) as fd:package_records=extract_selected(fd,BUNDLE_MEMBERS,BUNDLE_MEMBERS,prepared)
  verifier=prepared_bytes(prepared/'verify_official_packages.py',package_records['verify_official_packages.py']);need(digest(verifier)==VERIFIER_SHA and verifier==self.context.script_bytes('provenance/verifier'),'offline_verifier_pin')
  self.command(['python3','-c',verifier.decode(),str(prepared)],'verify-signed-official-packages',120)
  runtime=self.work/'runtime'
  with verified_fd(self.incoming/'containerd-2.3.7-linux-amd64.tar.gz',PINS['containerd-2.3.7-linux-amd64.tar.gz']) as fd:runtime_records=extract_selected(fd,RUNTIME_MEMBERS,{'bin/containerd','bin/containerd-shim-runc-v2','bin/ctr'},runtime)
  for name in ['containerd','containerd-shim-runc-v2','ctr']:self.own_file(Path('/usr/local/bin')/name,prepared_bytes(runtime/'bin'/name,runtime_records['bin/'+name]),0o755)
  with verified_fd(self.incoming/'runc.amd64',PINS['runc.amd64']) as fd:
   raw=b''
   while True:
    chunk=os.read(fd,1024*1024)
    if not chunk:break
    raw+=chunk
   self.own_file(Path('/usr/local/sbin/runc'),raw,0o755)
  need(not os.path.lexists('/etc/containerd'),'containerd_directory_race');Path('/etc/containerd').mkdir(mode=0o755)
  self.own_file(Path('/etc/containerd/config.toml'),config)
  self.own_file(Path('/etc/systemd/system/containerd.service'),UNIT)
  self.own_file(Path('/etc/modules-load.d/nebula-kubernetes.conf'),MODULES)
  self.own_file(Path('/etc/sysctl.d/99-nebula-kubernetes.conf'),SYSCTL)
  self.command(['/usr/local/bin/containerd','--config','/etc/containerd/config.toml','config','dump'],'validate-containerd-config')
  # The parent retains the verified descriptor paths while dpkg invokes its children.
  with contextlib.ExitStack() as stack:
   fds=[]
   for package,version,pin in PACKAGES:
    path=prepared/'amd64'/(package+'_'+version+'_amd64.deb');fds.append(stack.enter_context(verified_fd(path,pin)))
   paths=['/proc/'+str(os.getpid())+'/fd/'+str(fd) for fd in fds]
   self.guard();self.command(['dpkg','--no-act','--install',*paths],'dryrun-exact-five-packages',120)
   self.guard();self.command(['dpkg','--install',*paths],'install-exact-five-packages',240)
  self.command(['apt-mark','hold',*[x[0] for x in PACKAGES]],'hold-exact-five-packages')
  for package,version,pin in PACKAGES:
   actual=self.command(['dpkg-query','-W','-f='+chr(36)+'{db:Status-Status} '+chr(36)+'{Version}',package],'verify-installed-package').decode().strip()
   need(actual=='installed '+version,'installed_package_version_mismatch')
  for module in ['overlay','br_netfilter','vxlan']:self.guard();self.command(['modprobe',module],'load-guest-module')
  for key in ['net.ipv4.ip_forward','net.bridge.bridge-nf-call-iptables','net.bridge.bridge-nf-call-ip6tables']:self.guard();self.command(['sysctl','-w',key+'=1'],'set-guest-network-sysctl')
  self.guard();self.command(['systemctl','daemon-reload'],'reload-guest-systemd')
  self.command(['systemctl','enable','--now','containerd.service'],'start-only-guest-containerd',90)
  self.command(['systemctl','is-active','--quiet','containerd.service'],'verify-guest-containerd')
  info=json.loads(self.command(['crictl','--runtime-endpoint','unix:///run/containerd/containerd.sock','info'],'verify-guest-cri',30))
  need(any(x.get('type')=='RuntimeReady' and x.get('status') is True for x in info.get('status',{}).get('conditions',[])),'cri_runtime_not_ready')
  need(subprocess.run(['systemctl','is-active','--quiet','kubelet.service'],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL).returncode!=0,'unexpected_kubelet_start')
  self.state['phase']='runtime_and_packages_ready_no_cluster';self.persist();return {'status':self.state['phase'],'selected_packages':5,'runtime_ready':True,'cluster_initialized':False,'cni_applied':False}
def dispatch_phase(job,phase,execute=False):
 need(phase in ['check','install'],'unsupported_guest_phase')
 need(phase=='check' or execute is True,'explicit_execute_required')
 require_context(getattr(job,'context',None),'guest')
 return job.preflight() if phase=='check' else job.install()

def run_phase(context,expected_uuid,run_id,work,phase,execute=False):
 need(phase in ['check','install'],'unsupported_guest_phase')
 need(phase=='check' or execute is True,'explicit_execute_required')
 context=require_context(context,'guest')
 job=Bootstrap(expected_uuid,run_id,work,context=context)
 lock=job.work/'operation.lock';fd=os.open(lock,os.O_CREAT|os.O_RDWR|os.O_NOFOLLOW,0o600)
 try:
  held=os.fstat(fd);need(stat.S_ISREG(held.st_mode) and held.st_uid==0 and held.st_nlink==1 and stat.S_IMODE(held.st_mode)==0o600,'unsafe_guest_lock');fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
  fields=lambda st:tuple(getattr(st,k)for k in ['st_dev','st_ino','st_mode','st_uid','st_gid','st_nlink','st_size','st_mtime_ns','st_ctime_ns'])
  job.external_guard=lambda:need(fields(os.fstat(fd))==fields(held)==fields(lock.lstat()),'guest_lock_replaced')
  job.external_guard();return dispatch_phase(job,phase,execute)
 except BaseException:
  write_exclusive(job.work/('manual-review-'+os.urandom(5).hex()+'.json'),json.dumps({'status':'manual_review_required','automatic_reset_or_delete_attempted':False,'known_install_state':job.state}).encode());raise
 finally:os.close(fd)

def main():
 raise Refused('source_api_only_no_public_installer')
if __name__=='__main__':
 try:main()
 except Refused as e:print(json.dumps({'status':'refused','reason':str(e)}),file=sys.stderr);raise SystemExit(1)

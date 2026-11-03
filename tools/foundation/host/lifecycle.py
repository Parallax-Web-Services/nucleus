#!/usr/bin/env python3
"""Context-bound foundation lifecycle library; no operational command-line entry point."""
from __future__ import annotations
import argparse,base64,fcntl,hashlib,ipaddress,json,os,pwd,re,shutil,socket,stat,subprocess,sys,tempfile,time,types,urllib.request,uuid,xml.etree.ElementTree as E
from pathlib import Path
from foundation.framework import require_context
SIGNER='D2EB44626FDDC30B513D5BB71A5D6C4C7DB87C81'
MAX_IMAGE=2*1024**3-16*1024**2
class Refused(RuntimeError):pass
def need(ok,code):
 if not ok:raise Refused(code)
def sha(raw):return hashlib.sha256(raw).hexdigest()
def safe(p):need(p.is_absolute() and p.resolve()==p,'noncanonical_path');return p
def private_dir(p):
 safe(p);s=p.lstat();need(stat.S_ISDIR(s.st_mode) and s.st_uid==0 and stat.S_IMODE(s.st_mode)==0o700,'private_directory_permissions')
def read(p,limit=1024*1024,private=False):
 fd=os.open(safe(p),os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
 try:
  before=os.fstat(fd);need(stat.S_ISREG(before.st_mode) and before.st_nlink==1 and before.st_size<=limit,'unsafe_input_file')
  if private:need(before.st_uid==0 and stat.S_IMODE(before.st_mode)==0o600,'private_file_permissions')
  raw=b''
  while True:
   part=os.read(fd,131072)
   if not part:break
   raw+=part;need(len(raw)<=limit,'input_size_bound')
  fields=lambda s:(s.st_dev,s.st_ino,s.st_mode,s.st_uid,s.st_gid,s.st_size,s.st_mtime_ns,s.st_ctime_ns)
  need(fields(before)==fields(os.fstat(fd))==fields(p.lstat()),'input_changed_during_read');return raw
 finally:os.close(fd)
def write(p,raw,mode=0o600):
 fd=os.open(p,os.O_CREAT|os.O_EXCL|os.O_WRONLY|os.O_NOFOLLOW,mode)
 with os.fdopen(fd,'wb') as out:out.write(raw);out.flush();os.fsync(out.fileno())
def control_state(p):
 if not os.path.lexists(p):return None
 before=p.lstat();raw=read(p,private=True);after=p.lstat()
 fields=lambda s:(s.st_dev,s.st_ino,s.st_mode,s.st_uid,s.st_gid,s.st_size,s.st_mtime_ns,s.st_ctime_ns)
 need(fields(before)==fields(after),'control_state_changed_during_read')
 return {'identity':fields(after),'raw':raw}
def save(p,value,expected):
 need(control_state(p)==expected,'lifecycle_control_state_changed')
 fd,temp=tempfile.mkstemp(prefix='.state-',dir=p.parent);owned=os.fstat(fd)
 try:
  with os.fdopen(fd,'w') as out:json.dump(value,out,sort_keys=True,indent=2);out.flush();os.fsync(out.fileno())
  need(control_state(p)==expected,'lifecycle_control_state_changed')
  if expected is None:
   try:os.link(temp,p,follow_symlinks=False)
   except FileExistsError:raise Refused('lifecycle_control_state_changed') from None
   os.unlink(temp)
  else:os.replace(temp,p)
  result=control_state(p)
  need(result is not None and result['identity'][:2]==(owned.st_dev,owned.st_ino),'lifecycle_control_postimage_unknown')
  return result
 finally:
  try:
   s=os.lstat(temp)
   if(s.st_dev,s.st_ino)==(owned.st_dev,owned.st_ino):os.unlink(temp)
  except FileNotFoundError:pass
def disk_state(p):
 s=safe(p).lstat();need(stat.S_ISREG(s.st_mode) and s.st_nlink==1 and stat.S_IMODE(s.st_mode)&0o022==0,'unsafe_owned_volume')
 return {'device':s.st_dev,'inode':s.st_ino,'uid':s.st_uid,'gid':s.st_gid,'mode':s.st_mode,'size':s.st_size,'allocated':s.st_blocks*512,'mtime_ns':s.st_mtime_ns,'ctime_ns':s.st_ctime_ns}
def owned_volume_matches(current,known,started):
 if current['allocated']<current['size'] or known['allocated']<known['size']:return False
 ignored={'allocated'}|({'mtime_ns','ctime_ns'} if started else set())
 return {k:v for k,v in current.items() if k not in ignored}=={k:v for k,v in known.items() if k not in ignored}
def require_owned_volume(path,known,started,public_seed_sha=None):
 current=disk_state(path);need(owned_volume_matches(current,known,started),'owned_volume_identity_changed')
 if public_seed_sha is not None:need(file_hash(path)[0]==public_seed_sha,'readonly_seed_changed')
 return current
def file_hash(p):
 h=hashlib.sha256();total=0
 fd=os.open(safe(p),os.O_RDONLY|os.O_NOFOLLOW)
 try:
  before=os.fstat(fd);need(stat.S_ISREG(before.st_mode) and before.st_nlink==1,'unsafe_image')
  while True:
   b=os.read(fd,1024*1024)
   if not b:break
   total+=len(b);need(total<=MAX_IMAGE,'image_staging_budget');h.update(b)
  after=os.fstat(fd);need((before.st_dev,before.st_ino,before.st_size,before.st_mtime_ns)==(after.st_dev,after.st_ino,after.st_size,after.st_mtime_ns),'image_changed')
  return h.hexdigest(),total
 finally:os.close(fd)
def image_identity(fd):
 s=os.fstat(fd);need(stat.S_ISREG(s.st_mode) and s.st_nlink==1 and s.st_uid==0 and stat.S_IMODE(s.st_mode)==0o600,'unsafe_verified_image_fd')
 return (s.st_dev,s.st_ino,s.st_mode,s.st_uid,s.st_gid,s.st_nlink,s.st_size,s.st_mtime_ns,s.st_ctime_ns)
def hash_image_fd(fd):
 before=image_identity(fd);os.lseek(fd,0,os.SEEK_SET);h=hashlib.sha256();total=0
 while True:
  raw=os.read(fd,1024*1024)
  if not raw:break
  total+=len(raw);need(total<=MAX_IMAGE,'image_staging_budget');h.update(raw)
 need(image_identity(fd)==before,'verified_image_fd_changed');os.lseek(fd,0,os.SEEK_SET)
 return h.hexdigest(),total,before
def image_unchanged(fd,expected,path):
 need(image_identity(fd)==expected,'verified_image_fd_changed')
 s=path.lstat();need((s.st_dev,s.st_ino,s.st_mode,s.st_uid,s.st_gid,s.st_nlink,s.st_size,s.st_mtime_ns,s.st_ctime_ns)==expected,'verified_image_path_changed')
def pinned_primary_signature(raw):
 for line in raw.decode().splitlines():
  parts=line.split()
  if len(parts) not in [11,12] or parts[:2]!=['[GNUPG:]','VALIDSIG']:continue
  signing=parts[2];primary=parts[11] if len(parts)==12 else signing
  if re.fullmatch('[A-F0-9]{40}',signing) and primary==SIGNER:return True
 return False
def independent_qcow(raw):
 def external(value):
  if isinstance(value,dict):return any((key in ['backing-filename','full-backing-filename','data-file','data-file-raw'] and bool(item)) or external(item) for key,item in value.items())
  if isinstance(value,list):return any(external(x) for x in value)
  return False
 return raw.get('format')=='qcow2' and not external(raw)
def load_preflight(context):
 ctx=require_context(context,'host');ctx.guard();return ctx.load_module('host/preflight')
def lines(raw):return [s.strip() for s in raw.decode().splitlines() if s.strip()]
def volume_names(raw):return [s.split()[0] for s in lines(raw) if not s.startswith(('Name','---'))]

def allowed_volume_owners():
 owners={(0,0)}
 for account in ['qemu','libvirt-qemu']:
  try:u=pwd.getpwnam(account);owners.add((u.pw_uid,u.pw_gid))
  except KeyError:pass
 return owners
def repair_volume_matches(current,known,ownership_restore=False):
 if known['allocated']<known['size'] or current['allocated']<0:return False
 ignored={'allocated','mtime_ns','ctime_ns'}
 if ownership_restore:
  if (known['uid'],known['gid']) not in allowed_volume_owners() or (current['uid'],current['gid']) not in allowed_volume_owners():return False
  ignored|={'uid','gid'}
 return {k:v for k,v in current.items() if k not in ignored}=={k:v for k,v in known.items() if k not in ignored}
def canonical_xml(raw):
 root=E.fromstring(raw)
 for x in root.iter():
  x.attrib=dict(sorted(x.attrib.items()))
  if x.text is not None and not x.text.strip():x.text=None
  if x.tail is not None and not x.tail.strip():x.tail=None
 return E.tostring(root)
def repaired_xml(raw,plan,disk,seed,mac,live=False):
 validate_xml(raw,plan,disk,seed,mac,live=live)
 d=E.fromstring(raw);driver=next(x.find('driver') for x in d.findall('devices/disk') if x.get('device')=='disk')
 need(driver.attrib=={'name':'qemu','type':'raw'},'repair_original_driver_not_observed_state')
 driver.set('discard','ignore');driver.set('detect_zeroes','off')
 patched=E.tostring(d,encoding='utf-8',xml_declaration=True)
 validate_xml(patched,plan,disk,seed,mac,live=live)
 check=E.fromstring(patched);again=next(x.find('driver') for x in check.findall('devices/disk') if x.get('device')=='disk')
 del again.attrib['discard'];del again.attrib['detect_zeroes']
 need(canonical_xml(E.tostring(check))==canonical_xml(raw),'repair_would_change_other_xml')
 return patched
def reserve_owned_fd(path,expected,remaining_bytes=10*1024**3):
 fd=os.open(safe(path),os.O_RDWR|os.O_NOFOLLOW|os.O_CLOEXEC)
 try:
  def identity(s):return {'device':s.st_dev,'inode':s.st_ino,'uid':s.st_uid,'gid':s.st_gid,'mode':s.st_mode,'size':s.st_size,'allocated':s.st_blocks*512,'mtime_ns':s.st_mtime_ns,'ctime_ns':s.st_ctime_ns}
  before=identity(os.fstat(fd));need(before==expected==disk_state(path),'repair_disk_changed_before_fallocate')
  need(stat.S_ISREG(os.fstat(fd).st_mode) and os.fstat(fd).st_nlink==1,'unsafe_repair_fd')
  fs=os.fstatvfs(fd);need(fs.f_bavail*fs.f_frsize>=max(0,before['size']-before['allocated'])+remaining_bytes,'repair_free_space_admission_failed')
  os.posix_fallocate(fd,0,before['size']);os.fsync(fd)
  after=identity(os.fstat(fd));need(after==disk_state(path),'repair_disk_path_replaced')
  need(after['allocated']>=after['size'] and all(after[k]==before[k] for k in ['device','inode','uid','gid','mode','size']),'repair_disk_postimage_unknown')
  fs=os.fstatvfs(fd);need(fs.f_bavail*fs.f_frsize>=remaining_bytes,'repair_remaining_space_below_reserve')
  return after
 finally:os.close(fd)


def live_devices_owned_by_new_qemu(raw,plan,proc_root=Path('/proc'),pid_root=Path('/run/libvirt/qemu')):
 root=E.fromstring(raw);paths={y.get('path','') for x in root.findall('devices/serial')+root.findall('devices/console') for y in x.findall('source')}
 need(paths and all(re.fullmatch('/dev/pts/[0-9]+',x) for x in paths),'unexpected_live_pty_source')
 channel_paths={x.get('path','') for x in root.findall('devices/channel/source')}
 need(len(channel_paths)==1,'expected_live_agent_socket')
 pid_file=pid_root/(plan['proposed_name']+'.pid');pid_raw=read(pid_file,32)
 need(re.fullmatch(b'[0-9]+\\s*',pid_raw) is not None and int(pid_raw)>1,'owned_qemu_pid_invalid')
 proc=proc_root/str(int(pid_raw));start=read(proc/'stat',4096).rsplit(b') ',1)[1].split()[19]
 need(os.readlink(proc/'exe')=='/usr/bin/qemu-system-x86_64','owned_qemu_executable_changed')
 args=read(proc/'cmdline',128*1024).split(b'\0')
 need(sum(args[i]==b'-uuid' and args[i+1].decode()==plan['new_domain_uuid'] for i in range(len(args)-1))==1,'owned_qemu_uuid_changed')
 indices=set();socket_inodes=set();file_inodes=set();tun_names=set()
 for entry in (proc/'fd').iterdir():
  if not entry.name.isdigit():continue
  try:
   target=os.readlink(entry)
   try:st=entry.stat();file_inodes.add((st.st_dev,st.st_ino))
   except FileNotFoundError:pass
   match=re.fullmatch('socket:\\[([0-9]+)\\]',target)
   if match:socket_inodes.add(match[1])
   if target in ['/dev/ptmx','/dev/pts/ptmx','/dev/net/tun']:
    for line in read(proc/'fdinfo'/entry.name,4096).decode().splitlines():
     match=re.fullmatch('tty-index:\\s*([0-9]+)',line)
     if match and target!='/dev/net/tun':indices.add('/dev/pts/'+match[1])
     match=re.fullmatch('iff:\\s*(vnet[0-9]+)',line)
     if match and target=='/dev/net/tun':tun_names.add(match[1])
  except FileNotFoundError:continue
 need(paths<=indices,'live_pty_not_owned_by_saved_qemu')
 owned_sockets=set()
 for line in read(proc/'net/unix',2*1024*1024).decode().splitlines():
  fields=line.split()
  if len(fields)==8 and fields[6] in socket_inodes and fields[7] in channel_paths:owned_sockets.add(fields[7])
 need(channel_paths<=owned_sockets,'live_agent_socket_not_owned_by_saved_qemu')
 disk_inodes=set()
 for disk in root.findall('devices/disk'):
  st=Path(disk.find('source').get('file')).lstat();disk_inodes.add((st.st_dev,st.st_ino))
 need(len(disk_inodes)==2 and disk_inodes<=file_inodes,'live_disks_not_owned_by_saved_qemu')
 nic_names={x.get('dev','') for x in root.findall('devices/interface/target')}
 need(len(nic_names)==1 and nic_names<=tun_names,'live_nic_not_owned_by_saved_qemu')
 need(read(pid_file,32)==pid_raw and read(proc/'stat',4096).rsplit(b') ',1)[1].split()[19]==start,'owned_qemu_process_changed')
def same_running_xml(current,expected,shutting_down=False):
 if not shutting_down:return canonical_xml(current)==canonical_xml(expected)
 a=E.fromstring(current);b=E.fromstring(expected)
 for x in [a,b]:
  target=x.find('devices/channel/target')
  need(target is not None and target.get('state') in [None,'connected','disconnected'],'unexpected_shutdown_agent_state')
  target.attrib.pop('state',None)
 return canonical_xml(E.tostring(a))==canonical_xml(E.tostring(b))
def repaired_volume_postimages(raw_path,raw_after,seed_path,seed_before,seed_sha):
 need(disk_state(raw_path)==raw_after,'repair_raw_changed_before_state_adoption')
 current_seed=disk_state(seed_path)
 need(repair_volume_matches(current_seed,seed_before,True) and current_seed['allocated']>=current_seed['size'],'repair_seed_changed_before_state_adoption')
 need(file_hash(seed_path)[0]==seed_sha and disk_state(seed_path)==current_seed,'repair_seed_changed_during_state_adoption')
 need(disk_state(raw_path)==raw_after,'repair_raw_changed_during_state_adoption')
 return raw_after,current_seed

class NoRedirect(urllib.request.HTTPRedirectHandler):
 def redirect_request(self,*args,**kwargs):return None
def download(url,target,limit):
 need(url.startswith('https://cloud-images.ubuntu.com/releases/noble/release-20261017/'),'unapproved_download_origin')
 opener=urllib.request.build_opener(urllib.request.ProxyHandler({}),NoRedirect)
 fd=os.open(target,os.O_CREAT|os.O_EXCL|os.O_WRONLY|os.O_NOFOLLOW,0o600);total=0
 try:
  deadline=time.monotonic()+600
  with os.fdopen(fd,'wb') as out,opener.open(url,timeout=20) as response:
   need(response.status==200 and response.geturl()==url,'download_redirect_or_status')
   while True:
    need(time.monotonic()<=deadline,'download_deadline')
    b=response.read(1024*1024)
    if not b:break
    total+=len(b);need(total<=limit,'download_size_bound');out.write(b)
   out.flush();os.fsync(out.fileno())
 except BaseException:raise Refused('download_failed_retained_private_partial') from None
 return total
def guest_xml(plan,disk,seed,mac):
 d=E.Element('domain',{'type':'kvm'})
 def item(parent,name,text=None,attrs=None):
  e=E.SubElement(parent,name,attrs or {})
  if text is not None:e.text=str(text)
  return e
 item(d,'name',plan['proposed_name']);item(d,'uuid',plan['new_domain_uuid'])
 meta=item(d,'metadata');item(meta,'{https://parallax.link/nebula/v1}operation',plan['run_id'])
 item(d,'memory',4194304,{'unit':'KiB'});item(d,'currentMemory',4194304,{'unit':'KiB'});item(d,'vcpu',2,{'placement':'static'})
 tune=item(d,'cputune');item(tune,'period',100000);item(tune,'quota',200000)
 osx=item(d,'os');item(osx,'type','hvm',{'arch':'x86_64','machine':'pc'});item(osx,'boot',attrs={'dev':'hd'})
 features=item(d,'features');item(features,'acpi');item(features,'apic');item(d,'cpu',attrs={'mode':'host-model','check':'partial'})
 item(d,'clock',attrs={'offset':'utc'});item(d,'on_poweroff','destroy');item(d,'on_reboot','restart');item(d,'on_crash','preserve')
 dev=item(d,'devices');item(dev,'emulator','/usr/bin/qemu-system-x86_64')
 for source,kind,target,bus in [(disk,'disk','vda','virtio'),(seed,'cdrom','sda','sata')]:
  x=item(dev,'disk',attrs={'type':'file','device':kind});item(x,'driver',attrs={'name':'qemu','type':'raw',**({'discard':'ignore','detect_zeroes':'off'} if kind=='disk' else {})});item(x,'source',attrs={'file':str(source)});item(x,'target',attrs={'dev':target,'bus':bus})
  if kind=='cdrom':item(x,'readonly')
 nic=item(dev,'interface',attrs={'type':'network'});item(nic,'mac',attrs={'address':mac});item(nic,'source',attrs={'network':plan['network']['name']});item(nic,'model',attrs={'type':'virtio'})
 channel=item(dev,'channel',attrs={'type':'unix'});item(channel,'target',attrs={'type':'virtio','name':'org.qemu.guest_agent.0'})
 serial=item(dev,'serial',attrs={'type':'pty'});item(serial,'target',attrs={'port':'0'})
 console=item(dev,'console',attrs={'type':'pty'});item(console,'target',attrs={'type':'serial','port':'0'})
 return E.tostring(d,encoding='utf-8',xml_declaration=True)
def validate_xml(raw,plan,disk,seed,mac,live=False):
 d=E.fromstring(raw);need(d.tag=='domain' and d.get('type')=='kvm' and d.findtext('name')==plan['proposed_name'] and d.findtext('uuid')==plan['new_domain_uuid'],'domain_identity')
 need(d.findtext('memory')=='4194304' and d.find('memory').get('unit')=='KiB' and d.findtext('currentMemory')=='4194304' and d.find('currentMemory').get('unit')=='KiB' and d.findtext('vcpu')=='2','domain_resource_limits')
 need(d.findtext('metadata/{https://parallax.link/nebula/v1}operation')==plan['run_id'],'domain_operation_marker')
 need(all(not x.tag.startswith('{http://libvirt.org/schemas/domain/qemu/') for x in d.iter()),'qemu_extra_arguments_forbidden')
 allowed={'emulator','disk','interface','channel','serial','console','controller','input','memballoon','rng','audio'}
 top={'name','uuid','metadata','memory','currentMemory','vcpu','cputune','os','features','cpu','clock','on_poweroff','on_reboot','on_crash','devices','resource','seclabel','pm'}
 need(all(x.tag in top for x in d),'unexpected_domain_top_level')
 need(d.findtext('devices/emulator')=='/usr/bin/qemu-system-x86_64','unexpected_domain_emulator')
 need(d.findtext('cputune/period')=='100000' and d.findtext('cputune/quota')=='200000','domain_cpu_quota')
 need(all(x.tag in ['type','boot','bootmenu'] for x in d.find('os')),'unexpected_guest_loader')
 need(d.find('os/type').get('arch')=='x86_64' and d.findtext('os/type')=='hvm','unexpected_guest_arch')
 need(len(d.findall('os/boot'))==1 and d.find('os/boot').get('dev')=='hd','unexpected_guest_boot_order')
 need(all(x.get('type')=='dynamic' and x.get('model') in ['dac','selinux','apparmor'] for x in d.findall('seclabel')),'unsafe_domain_security_label')
 devices=list(d.find('devices'));need(all(x.tag in allowed for x in devices),'unexpected_domain_device')
 for x in devices:
  if x.tag in ['serial','console']:
   need(x.get('type')=='pty' and all(y.tag in ['target','alias','address']+(['source'] if live else []) for y in x),'unsafe_guest_console')
   need(len(x.findall('source'))<=1 and all(set(y.attrib)=={'path'} and re.fullmatch('/dev/pts/[0-9]+',y.get('path','')) is not None and len(y)==0 for y in x.findall('source')),'unsafe_live_guest_pty_source')
  if x.tag=='input':need(x.get('type') in ['mouse','keyboard','tablet'] and x.get('bus') in ['ps2','usb'] and x.find('source') is None,'unsafe_guest_input')
  if x.tag=='rng':need(x.get('model')=='virtio' and x.find('backend') is not None and x.find('backend').get('model')=='random' and len(x.find('backend'))==0 and x.findtext('backend') in ['/dev/urandom','/dev/random'],'unsafe_guest_rng')
  if x.tag=='audio':need(x.get('type')=='none','guest_audio_forbidden')
 disks=d.findall('devices/disk');need(len(disks)==2,'domain_disk_count')
 expected={(str(disk),'disk'),(str(seed),'cdrom')}
 actual={(x.find('source').get('file'),x.get('device')) for x in disks if x.get('type')=='file' and x.find('source') is not None}
 need(actual==expected and all(x.find('driver').get('type')=='raw' for x in disks),'domain_disk_mapping')
 for x in disks:
  need(all(y.tag in ['driver','source','target','readonly','alias','address','boot','backingStore'] for y in x),'unexpected_disk_option')
  need(x.find('backingStore') is None or len(x.find('backingStore'))==0,'disk_backing_chain_forbidden')
  need(x.find('driver').get('name')=='qemu','unexpected_disk_driver')
  if x.get('device')=='disk':need(x.find('driver').get('discard') in [None,'ignore'] and x.find('driver').get('detect_zeroes') in [None,'off'],'unsafe_disk_discard_policy')
  target=x.find('target')
  need(target is not None and ((x.get('device')=='disk' and target.get('dev')=='vda' and target.get('bus')=='virtio') or (x.get('device')=='cdrom' and target.get('dev')=='sda' and target.get('bus')=='sata')),'unexpected_disk_target')
 need(next(x for x in disks if x.get('device')=='cdrom').find('readonly') is not None,'seed_not_readonly')
 nics=d.findall('devices/interface');need(len(nics)==1 and nics[0].get('type')=='network' and nics[0].find('source').get('network')==plan['network']['name'] and nics[0].find('mac').get('address')==mac,'domain_network_mapping')
 need(all(x.tag in ['mac','source','model','target','alias','address','link','driver'] for x in nics[0]),'unsafe_interface_option')
 source=nics[0].find('source');need(set(source.attrib)<=set(['network','bridge','portid']) and source.get('bridge',plan['network']['bridge'])==plan['network']['bridge'],'unsafe_interface_source')
 target=nics[0].find('target')
 if target is not None:need(set(target.attrib)=={'dev'} and re.fullmatch('vnet[0-9]+',target.get('dev','')) is not None,'unsafe_interface_target')
 channels=d.findall('devices/channel');need(len(channels)==1 and channels[0].get('type')=='unix' and channels[0].find('target').get('name')=='org.qemu.guest_agent.0','domain_agent_channel')
 need(all(x.tag in ['source','target','alias','address'] for x in channels[0]),'unsafe_agent_channel_option')
 source=channels[0].find('source')
 if source is not None:
  path=source.get('path','')
  need(set(source.attrib)=={'mode','path'} and source.get('mode')=='bind' and '..' not in Path(path).parts and any(path.startswith(prefix) for prefix in ['/var/lib/libvirt/qemu/channel/target/','/run/libvirt/qemu/channel/target/']) and Path(path).name=='org.qemu.guest_agent.0','unexpected_guest_agent_socket')
  if live:
   match=re.fullmatch('domain-([1-9][0-9]*)-(.+)',Path(path).parent.name)
   need(match is not None and match[1]==d.get('id') and len(match[2])>=19 and plan['proposed_name'].startswith(match[2]),'unexpected_live_agent_domain_directory')
  else:need(plan['proposed_name'] in path,'unexpected_guest_agent_socket')
 need(not d.findall('devices/graphics') and not d.findall('devices/filesystem') and not d.findall('devices/hostdev'),'privileged_device_forbidden')
class Lifecycle:
 def __init__(self,plan_path,context,runner=None):
  self.context=require_context(context,'host');self.context.guard();inputs=self.context.inputs
  need(os.geteuid()==0 and socket.gethostname().lower()==inputs['host_name'].lower(),'admitted_host_root_only')
  preflight=load_preflight(self.context);self.pf=preflight;self.plan_path=safe(plan_path);private_dir(plan_path.parent);private_dir(plan_path.parent.parent)
  self.plan_raw=read(plan_path,private=True);self.plan=json.loads(self.plan_raw);p=self.plan
  need(plan_path==self.context.path('host_state_root')/('plan-'+p['run_id'])/'plan.json' and re.fullmatch('[a-f0-9]{12}',p['run_id']) and p['proposed_name']=='nebula-control-'+p['run_id'],'plan_binding')
  need(p.get('foundation_binding')==self.context.binding() and p['run_id']==inputs['run_id'] and (inputs['expected_guest_uuid'] is None or p['new_domain_uuid']==inputs['expected_guest_uuid']) and p['network']['name']==inputs['libvirt_network'] and p['pool']['name']==inputs['libvirt_pool'] and len(p['protected_domains'])==inputs['expected_protected_domain_count'],'plan_context_binding')
  need(p['schema_version']==1 and p['apply_enabled'] is False and all(p['admission'].values()),'plan_not_admitted')
  need(p['public_artifact_pins']==preflight.PUBLIC_PINS,'public_artifact_pins_changed')
  need(str(uuid.UUID(p['new_domain_uuid']))==p['new_domain_uuid'] and p['new_domain_uuid'] not in {x['uuid'] for x in p['protected_domains']} and p['proposed_name'] not in {x['name'] for x in p['protected_domains']},'new_domain_must_not_reuse_existing_identity')
  need(p['proposed_volume']==p['proposed_name']+'.raw' and p['resources']['vcpus']==2 and p['resources']['memory_bytes']==4*1024**3 and p['resources']['raw_disk_bytes']==20*1024**3,'fixed_vm_resource_contract')
  need(os.geteuid()==0 and socket.gethostname().lower()==inputs['host_name'].lower(),'admitted_host_root_only')
  self.work=plan_path.parent;self.state_path=self.work/'lifecycle.json'
  self.expected_control=control_state(self.state_path)
  self.state=json.loads(self.expected_control['raw']) if self.expected_control else {'schema_version':1,'run_id':p['run_id'],'volumes':{},'domain_defined':False,'domain_started':False,'status':'not_started'}
  need(self.state.get('run_id')==p['run_id'],'lifecycle_state_binding');self.runner=runner or self.command
  self.disk=Path(p['pool']['path'])/p['proposed_volume'];self.seed_name=p['proposed_name']+'-seed.iso';self.seed=Path(p['pool']['path'])/self.seed_name
 def persist(self):self.expected_control=save(self.state_path,self.state,self.expected_control)
 def recovery(self):
  private_dir(self.work);path=self.work/('manual-recovery-'+os.urandom(6).hex()+'.json')
  write(path,json.dumps({'status':'manual_recovery_required','run_id':self.plan['run_id'],'expected_operation_state':self.state,'foreign_control_state_overwritten':False}).encode())
  return path
 def command(self,args,label,timeout=60,input_bytes=None,pass_fds=()):
  self.context.guard()
  if hasattr(self,'external_guard'):self.external_guard()
  r=subprocess.run(args,input=input_bytes,pass_fds=pass_fds,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=timeout)
  for suffix,data in [('stdout',r.stdout),('stderr',r.stderr)]:write(self.work/(label+'-'+os.urandom(4).hex()+'.'+suffix),data)
  need(r.returncode==0,'command_failed_private_receipt');return r.stdout
 def q(self,*args):return self.pf.query(*args,context=self.context)
 def external_health(self):
  self.context.guard();members=self.context.inputs['expected_health_member_count']
  proof=json.loads(read(self.work/'external-health.json',private=True));now=time.time()
  need(proof.get('schema_version')==1 and type(proof.get('checked_at_unix')) is int and 0<=now-proof['checked_at_unix']<=60,'fresh_external_health_required')
  need(type(proof.get('registered_node_count')) is int and type(proof.get('known_online_count')) is int and proof['registered_node_count']==members and proof['known_online_count']==members and proof.get('same_fabric') is True and proof.get('managed_relay_binary_matches') is True and proof.get('managed_relay_process_unchanged') is True,'external_fleet_or_relay_changed')
 def guard(self,health=True,volume_exception=None):
  self.context.guard();inputs=self.context.inputs
  need(os.geteuid()==0 and socket.gethostname().lower()==inputs['host_name'].lower(),'admitted_host_root_only')
  need(self.plan.get('foundation_binding')==self.context.binding() and self.plan['run_id']==inputs['run_id'] and self.plan['network']['name']==inputs['libvirt_network'] and self.plan['pool']['name']==inputs['libvirt_pool'] and (inputs['expected_guest_uuid'] is None or self.plan['new_domain_uuid']==inputs['expected_guest_uuid']) and len(self.plan['protected_domains'])==inputs['expected_protected_domain_count'],'plan_context_binding')
  if hasattr(self,'external_guard'):self.external_guard()
  need(control_state(self.state_path)==self.expected_control,'lifecycle_control_state_changed')
  need(read(self.plan_path,private=True)==self.plan_raw,'private_plan_changed')
  p=self.plan
  names=set(lines(self.q('list','--all','--name')));expected={d['name'] for d in p['protected_domains']}
  if self.state['domain_defined']:expected.add(p['proposed_name'])
  need(names==expected,'unknown_domain_inventory')
  for old in p['protected_domains']:
   need(self.q('domuuid',old['name']).decode().strip()==old['uuid'] and self.q('domstate',old['name']).decode().strip()==old['state'],'protected_domain_changed')
   f=self.pf.info(self.q('dominfo',old['name']))
   need(int(f['CPU(s)'])==old['vcpus'] and int(f['Max memory'].split()[0])*1024==old['max_memory_bytes'],'protected_domain_resources_changed')
   actual_disks=[]
   for line in self.q('domblklist',old['name'],'--details').decode().splitlines():
    parts=line.split(None,3)
    if len(parts)!=4 or parts[0] in ['Type','---'] or parts[1]!='disk' or parts[3]=='-':continue
    path=Path(parts[3])
    if path.is_absolute() and os.path.lexists(path):
     entry={'source':str(path),'anchor':self.pf.anchor(path)}
     if path.is_symlink():entry['link_target']=os.readlink(path)
     actual_disks.append(entry)
   need(actual_disks==old['disks'],'protected_disk_mapping_or_identity_changed')
  ni=self.pf.info(self.q('net-info',p['network']['name']));nx=E.fromstring(self.q('net-dumpxml',p['network']['name']))
  need(self.q('net-uuid',p['network']['name']).decode().strip()==p['network']['uuid'] and ni.get('Active')=='yes' and ni.get('Persistent')=='yes','protected_network_changed')
  ip=nx.find('ip');mask=ip.get('netmask') or ip.get('prefix')
  need(nx.find('forward').get('mode')=='nat' and nx.find('bridge').get('name')==p['network']['bridge'] and ip.get('address')==p['network']['gateway'] and str(ipaddress.ip_network(ip.get('address')+'/'+str(mask),strict=False))==p['network']['subnet'],'protected_network_configuration_changed')
  px=E.fromstring(self.q('pool-dumpxml',p['pool']['name']));pi=self.pf.info(self.q('pool-info',p['pool']['name'],'--bytes'))
  need(self.q('pool-uuid',p['pool']['name']).decode().strip()==p['pool']['uuid'] and px.get('type')=='dir' and px.findtext('target/path')==p['pool']['path'] and self.pf.anchor(Path(p['pool']['path']))==p['pool']['anchor'] and pi.get('State')=='running','protected_pool_changed')
  need(set(volume_names(self.q('vol-list','--pool',p['pool']['name'])))==set(p['pool']['existing_volume_names'])|set(self.state['volumes']),'unknown_volume_inventory')
  for name,known in self.state['volumes'].items():
   path=Path(p['pool']['path'])/name
   if volume_exception is not None and name==p['proposed_volume']:volume_exception(path,known)
   elif volume_exception is not None and name==self.seed_name and getattr(self,'repair_ownership_restore',False):
    current=disk_state(path);need(repair_volume_matches(current,known,True) and current['allocated']>=current['size'] and file_hash(path)[0]==self.state['seed_sha256'],'repair_seed_identity_changed')
   else:require_owned_volume(path,known,self.state['domain_started'],self.state.get('seed_sha256') if name==self.seed_name else None)
  for old in p['protected_nucleus_processes']:
   proc=Path('/proc')/str(old['pid'])
   need(os.readlink(proc/'exe')==old['executable'] and (proc/'stat').read_text().rsplit(') ',1)[1].split()[19]==old['start_ticks'],'protected_nucleus_process_changed')
  if self.state['domain_defined']:
   own_xml=self.runner(['/usr/bin/virsh','--readonly','--connect','qemu:///system','dumpxml',p['new_domain_uuid'],'--inactive'],'inspect-new-domain');validate_xml(own_xml,p,self.disk,self.seed,self.state['mac'])
   if self.state.get('reservation_repair',{}).get('stage')=='discard_disabled_reservation_restored_stopped':
    driver=next(x.find('driver') for x in E.fromstring(own_xml).findall('devices/disk') if x.get('device')=='disk')
    need(driver.get('discard')=='ignore' and driver.get('detect_zeroes')=='off','repaired_disk_driver_changed')
  if health:self.external_health()
 def verify_image(self,keyring,retain=False):
  need(keyring.name.endswith('.gpg'),'public_image_keyring_required');r=read(keyring)
  s=keyring.stat();need(s.st_uid==0 and stat.S_IMODE(s.st_mode)&0o022==0 and len(r)<1024*1024,'image_keyring_permissions')
  read(self.work/'SHA256SUMS',private=True);read(self.work/'SHA256SUMS.gpg',limit=64*1024,private=True)
  raw=self.runner(['gpgv','--status-fd','1','--keyring',str(keyring),str(self.work/'SHA256SUMS.gpg'),str(self.work/'SHA256SUMS')],'verify-image-signature')
  need(pinned_primary_signature(raw),'image_signer_pin')
  pin=self.plan['public_artifact_pins']['ubuntu'];sums=read(self.work/'SHA256SUMS',private=True).decode().splitlines();filename=Path(pin['url']).name
  need(sum(line in [pin['sha256']+' *'+filename,pin['sha256']+'  '+filename] for line in sums)==1,'signed_image_checksum_pin')
  path=safe(self.work/filename);fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC);handed_off=False
  try:
   digest,size,identity=hash_image_fd(fd);need(digest==pin['sha256'] and size<=MAX_IMAGE,'image_integrity_or_staging_budget');image_unchanged(fd,identity,path)
   q=json.loads(self.runner(['qemu-img','info','--output=json','/proc/self/fd/'+str(fd)],'inspect-verified-image',pass_fds=(fd,)))
   image_unchanged(fd,identity,path);need(independent_qcow(q) and 0<q.get('virtual-size',0)<=self.plan['resources']['raw_disk_bytes'],'unsupported_image_layout')
   self.state['verified_image']=filename;self.state['image_bytes']=size;self.persist()
   if retain:handed_off=True;return fd,identity
  finally:
   if not handed_off:os.close(fd)
 def resume_verified_image(self,keyring):
  self.guard();self.verify_image(keyring);self.guard();self.state['status']='image_verified';self.persist()
 def fetch_image(self,keyring):
  self.guard();need(not self.state['volumes'] and not self.state['domain_defined'],'fetch_before_resources_only')
  pin=self.plan['public_artifact_pins']['ubuntu']
  for url,name,limit in [(pin['checksums_url'],'SHA256SUMS',1024*1024),(pin['signature_url'],'SHA256SUMS.gpg',64*1024),(pin['url'],Path(pin['url']).name,MAX_IMAGE)]:
   need(not os.path.lexists(self.work/name),'image_artifact_already_exists');download(url,self.work/name,limit)
  self.verify_image(keyring);self.guard();self.state['status']='image_verified';self.persist()
 def create_volume(self,name,size):
  self.guard();path=Path(self.plan['pool']['path'])/name;need(not os.path.lexists(path),'new_volume_path_exists')
  self.runner(['/usr/bin/virsh','--connect','qemu:///system','vol-create-as',self.plan['pool']['name'],name,str(size),'--allocation',str(size),'--format','raw'],'create-owned-volume',120)
  actual=self.runner(['/usr/bin/virsh','--readonly','--connect','qemu:///system','vol-path','--pool',self.plan['pool']['name'],name],'check-owned-volume-path').decode().strip()
  need(actual==str(path),'created_volume_path_unknown')
  state=disk_state(path);need(state['size']==size and state['allocated']>=size,'volume_not_fully_reserved');self.state['volumes'][name]=state;self.persist()
 def create(self,keyring):
  self.guard();need(not self.state['volumes'] and not self.state['domain_defined'],'new_resources_must_be_absent')
  fd,source_identity=self.verify_image(keyring,retain=True)
  try:self.create_from_verified_fd(fd,source_identity)
  finally:os.close(fd)
 def create_from_verified_fd(self,source_fd,source_identity):
  mem={}
  for line in Path('/proc/meminfo').read_text().splitlines():
   k,v=line.split(':',1);mem[k]=int(v.strip().split()[0])*1024
  fs=os.statvfs(self.plan['pool']['path']);need(mem['MemAvailable']>=6*1024**3 and fs.f_bavail*fs.f_frsize>=32*1024**3,'fresh_resource_admission_failed')
  key=self.work/'guest-client';need(not os.path.lexists(key) and not os.path.lexists(Path(str(key)+'.pub')),'ssh_key_already_exists')
  self.guard();self.runner(['ssh-keygen','-q','-t','ed25519','-N','','-f',str(key)],'generate-onhost-guest-key')
  k=key.lstat();need(k.st_uid==0 and stat.S_IMODE(k.st_mode)==0o600 and k.st_nlink==1,'private_guest_key_permissions')
  user,meta=self.pf.cloud_init(self.plan,read(Path(str(key)+'.pub')).decode().strip())
  data=json.loads(user.decode().split('\n',1)[1]);data['packages']=['qemu-guest-agent'];data['runcmd']=[['systemctl','enable','--now','qemu-guest-agent']]
  write(self.work/'user-data',('#cloud-config\n'+json.dumps(data,indent=2)+'\n').encode());write(self.work/'meta-data',meta)
  self.guard();self.runner(['genisoimage','-quiet','-output',str(self.work/'seed.iso'),'-volid','cidata','-joliet','-rock',str(self.work/'user-data'),str(self.work/'meta-data')],'make-public-only-seed')
  expected_seed_sha,seed_size=file_hash(self.work/'seed.iso');need(seed_size<=4*1024**2,'public_seed_size_bound')
  self.create_volume(self.plan['proposed_volume'],self.plan['resources']['raw_disk_bytes']);before=self.state['volumes'][self.plan['proposed_volume']]
  self.guard();image_unchanged(source_fd,source_identity,self.work/self.state['verified_image'])
  self.runner(['qemu-img','convert','-n','-S','0','-f','qcow2','-O','raw','/proc/self/fd/'+str(source_fd),str(self.disk)],'copy-verified-image-into-owned-raw',180,pass_fds=(source_fd,))
  image_unchanged(source_fd,source_identity,self.work/self.state['verified_image'])
  after=disk_state(self.disk);need(after['device']==before['device'] and after['inode']==before['inode'] and after['size']==20*1024**3 and after['allocated']>=20*1024**3,'raw_volume_identity_size_or_reservation_changed')
  self.state['volumes'][self.plan['proposed_volume']]=after;self.persist()
  self.create_volume(self.seed_name,seed_size);before=self.state['volumes'][self.seed_name]
  self.guard();need(file_hash(self.work/'seed.iso')[0]==expected_seed_sha,'private_seed_changed');self.runner(['qemu-img','convert','-n','-S','0','-f','raw','-O','raw',str(self.work/'seed.iso'),str(self.seed)],'copy-public-seed')
  after=disk_state(self.seed);need(after['device']==before['device'] and after['inode']==before['inode'] and after['size']==seed_size,'seed_identity_changed')
  self.state['seed_sha256']=expected_seed_sha
  need(file_hash(self.seed)[0]==self.state['seed_sha256'],'seed_copy_integrity')
  self.state['volumes'][self.seed_name]=after;self.state['mac']='52:54:00:'+':'.join(f'{x:02x}' for x in os.urandom(3));self.persist()
  raw=guest_xml(self.plan,self.disk,self.seed,self.state['mac']);validate_xml(raw,self.plan,self.disk,self.seed,self.state['mac']);write(self.work/'domain.xml',raw)
  self.guard();self.runner(['/usr/bin/virsh','--connect','qemu:///system','define','/dev/stdin'],'define-new-domain',input_bytes=raw)
  self.state['domain_defined']=True;self.persist();self.guard()
  self.start_defined()
 def admit_start(self):
  mem={}
  for line in Path('/proc/meminfo').read_text().splitlines():
   key,value=line.split(':',1);mem[key]=int(value.strip().split()[0])*1024
  fs=os.statvfs(self.plan['pool']['path'])
  existing_ram=sum(x['max_memory_bytes'] for x in self.plan['protected_domains']);existing_cpu=sum(x['vcpus'] for x in self.plan['protected_domains'])
  need(mem.get('MemAvailable',0)>=6*1024**3 and mem.get('MemTotal',0)>=existing_ram+6*1024**3 and (os.cpu_count() or 0)>=existing_cpu+4 and fs.f_bavail*fs.f_frsize>=10*1024**3,'fresh_start_resource_admission_failed')
 def start_defined(self):
  self.guard();p=self.plan
  need(self.state['domain_defined'] is True and self.state['domain_started'] is False,'defined_unstarted_owned_domain_required')
  need(set(self.state['volumes'])=={p['proposed_volume'],self.seed_name} and self.state.get('verified_image')==Path(p['public_artifact_pins']['ubuntu']['url']).name and self.state.get('seed_sha256'),'complete_owned_boot_artifacts_required')
  need(self.q('domuuid',p['proposed_name']).decode().strip()==p['new_domain_uuid'] and self.q('domstate',p['new_domain_uuid']).decode().strip()=='shut off','owned_new_domain_not_shut_off')
  self.admit_start();self.guard()
  self.runner(['/usr/bin/virsh','--connect','qemu:///system','start',self.plan['new_domain_uuid']],'start-new-domain',60)
  allowed_uids={0};allowed_gids={0}
  for account in ['qemu','libvirt-qemu']:
   try:u=pwd.getpwnam(account);allowed_uids.add(u.pw_uid);allowed_gids.add(u.pw_gid)
   except KeyError:pass
  for name,before in self.state['volumes'].items():
   current=disk_state(Path(self.plan['pool']['path'])/name)
   need(current['device']==before['device'] and current['inode']==before['inode'] and current['size']==before['size'] and current['uid'] in allowed_uids and current['gid'] in allowed_gids,'started_volume_postimage_unknown')
   self.state['volumes'][name]=current
  self.state['domain_started']=True;self.state['status']='new_vm_started_private';self.persist();self.guard()
 def domain_xml(self,inactive=False):
  args=['/usr/bin/virsh','--readonly','--connect','qemu:///system','dumpxml',self.plan['new_domain_uuid']]
  if inactive:args.append('--inactive')
  raw=self.runner(args,'inspect-owned-repair-domain')
  validate_xml(raw,self.plan,self.disk,self.seed,self.state['mac'],live=not inactive)
  if not inactive:live_devices_owned_by_new_qemu(raw,self.plan)
  return raw
 def repair_reservation(self):
  p=self.plan
  need(self.state['domain_defined'] is True and self.state['domain_started'] is True and 'reservation_repair' not in self.state,'repair_requires_original_started_owned_vm')
  need(set(self.state['volumes'])=={p['proposed_volume'],self.seed_name},'repair_requires_exact_owned_volumes')
  known=self.state['volumes'][p['proposed_volume']]
  need(known['size']==p['resources']['raw_disk_bytes']==20*1024**3,'repair_disk_size_contract')
  def repair_volume(path,previous,restore=False):
   need(path==self.disk and previous==known,'repair_exception_scope')
   need(repair_volume_matches(disk_state(path),known,restore),'repair_disk_identity_changed')
  self.guard(volume_exception=repair_volume)
  need(self.q('domuuid',p['proposed_name']).decode().strip()==p['new_domain_uuid'] and self.q('domstate',p['new_domain_uuid']).decode().strip()=='running','repair_requires_exact_running_owned_uuid')
  need(disk_state(self.disk)['allocated']<known['size'],'repair_requires_observed_allocation_deficit')
  inactive=self.domain_xml(True);running=self.domain_xml(False)
  patched=repaired_xml(inactive,p,self.disk,self.seed,self.state['mac'])
  # Both live and persistent definitions must be the observed old driver state.
  repaired_xml(running,p,self.disk,self.seed,self.state['mac'],live=True)
  def unchanged_xml(shutting_down=False):
   need(canonical_xml(self.domain_xml(True))==canonical_xml(inactive),'repair_inactive_xml_changed')
   if self.q('domstate',p['new_domain_uuid']).decode().strip()!='shut off':
    need(same_running_xml(self.domain_xml(False),running,shutting_down),'repair_running_xml_changed')
  self.state['reservation_repair']={'stage':'captured_before_graceful_shutdown','inactive_xml_sha256':sha(inactive),'running_xml_sha256':sha(running),'original_disk':known}
  self.persist();self.guard(volume_exception=repair_volume);unchanged_xml()
  self.repair_ownership_restore=True
  self.runner(['/usr/bin/virsh','--connect','qemu:///system','shutdown',p['new_domain_uuid']],'graceful-shutdown-only-owned-domain',30)
  deadline=time.monotonic()+120
  while True:
   state=self.q('domstate',p['new_domain_uuid']).decode().strip()
   need(state in ['running','in shutdown','shut off'],'unexpected_owned_domain_shutdown_state')
   # Libvirt can restore only the known root/qemu ownership while shutting down.
   def stopped_exception(path,previous):return repair_volume(path,previous,True)
   self.guard(volume_exception=stopped_exception);unchanged_xml(shutting_down=True)
   if state=='shut off':break
   need(time.monotonic()<deadline,'graceful_shutdown_timeout_no_destroy_attempted');time.sleep(2)
  need(self.q('domstate',p['new_domain_uuid']).decode().strip()=='shut off','repair_guest_must_remain_stopped')
  # The seed may receive the same expected libvirt ownership restoration.
  for name,previous in self.state['volumes'].items():
   current=disk_state(Path(p['pool']['path'])/name)
   need(repair_volume_matches(current,previous,True),'repair_stopped_volume_identity_changed')
   if name==self.seed_name:need(current['allocated']>=current['size'] and file_hash(self.seed)[0]==self.state['seed_sha256'],'repair_seed_changed')
  self.admit_start()
  before=disk_state(self.disk)
  self.guard(volume_exception=stopped_exception);unchanged_xml()
  need(self.q('domstate',p['new_domain_uuid']).decode().strip()=='shut off','repair_guest_must_remain_stopped')
  after=reserve_owned_fd(self.disk,before)
  need(self.q('domstate',p['new_domain_uuid']).decode().strip()=='shut off','repair_guest_started_during_reservation')
  self.guard(volume_exception=stopped_exception);unchanged_xml()
  raw_after,seed_after=repaired_volume_postimages(self.disk,after,self.seed,self.state['volumes'][self.seed_name],self.state['seed_sha256'])
  self.state['volumes'][p['proposed_volume']]=raw_after;self.state['volumes'][self.seed_name]=seed_after
  self.state['domain_started']=False;self.state['reservation_repair']['stage']='fully_reserved_stopped';self.persist()
  self.guard();unchanged_xml()
  write(self.work/'reservation-repaired-domain.xml',patched)
  self.guard();unchanged_xml()
  need(self.q('domstate',p['new_domain_uuid']).decode().strip()=='shut off','repair_guest_must_remain_stopped')
  self.runner(['/usr/bin/virsh','--connect','qemu:///system','define','/dev/stdin'],'update-only-owned-discard-driver',input_bytes=patched)
  need(canonical_xml(self.domain_xml(True))==canonical_xml(patched),'repair_defined_xml_postimage_unknown')
  self.state['reservation_repair']['stage']='discard_disabled_reservation_restored_stopped'
  self.state['status']='reservation_repaired_stopped';self.persist();self.guard()
 def agent(self,execute,arguments=None):
  body={'execute':execute}
  if arguments is not None:body['arguments']=arguments
  raw=self.runner(['/usr/bin/virsh','--connect','qemu:///system','qemu-agent-command',self.plan['new_domain_uuid'],json.dumps(body,separators=(',',':'))],'read-new-guest-agent',10)
  data=json.loads(raw);need('return' in data,'guest_agent_not_ready');return data['return']
 def verify_guest(self):
  self.guard();need(self.state['domain_started'],'new_domain_not_started')
  raw=self.runner(['/usr/bin/virsh','--readonly','--connect','qemu:///system','domifaddr',self.plan['new_domain_uuid'],'--source','lease'],'read-new-guest-address')
  addresses=[]
  for line in raw.decode().splitlines():
   parts=line.split()
   if len(parts)==4 and parts[1].lower()==self.state['mac'] and parts[2]=='ipv4':
    address=ipaddress.ip_interface(parts[3]).ip
    if address in ipaddress.ip_network(self.plan['network']['subnet']) and address!=ipaddress.ip_address(self.plan['network']['gateway']):addresses.append(str(address))
  need(len(addresses)==1,'unique_private_guest_address_not_ready');address=addresses[0]
  handle=self.agent('guest-file-open',{'path':'/etc/ssh/ssh_host_ed25519_key.pub','mode':'r'})
  try:
   data=self.agent('guest-file-read',{'handle':handle,'count':4096});public=base64.b64decode(data['buf-b64'],validate=True).decode().strip();public=self.pf.public_ssh_key(public)
  finally:self.agent('guest-file-close',{'handle':handle})
  known=self.work/'guest-known-hosts';expected=(address+' '+public+'\n').encode()
  if os.path.lexists(known):need(read(known,private=True)==expected,'known_hosts_changed')
  else:write(known,expected)
  self.guard();self.runner(['ssh','-F','/dev/null','-n','-T','-i',str(self.work/'guest-client'),'-o','BatchMode=yes','-o','IdentitiesOnly=yes','-o','IdentityAgent=none','-o','ForwardAgent=no','-o','ClearAllForwardings=yes','-o','ProxyCommand=none','-o','ProxyJump=none','-o','PermitLocalCommand=no','-o','PreferredAuthentications=publickey','-o','GSSAPIAuthentication=no','-o','HostbasedAuthentication=no','-o','PasswordAuthentication=no','-o','KbdInteractiveAuthentication=no','-o','StrictHostKeyChecking=yes','-o','UserKnownHostsFile='+str(known),'-o','GlobalKnownHostsFile=/dev/null','-o','ConnectTimeout=8','nebula@'+address,'true'],'verify-private-guest-ssh',15)
  self.state['status']='guest_os_authenticated';self.state['guest_ssh_hostkey_pinned']=True;self.persist();self.guard()
PHASES=frozenset(['check','fetch-image','verify-image','create','start','verify-guest','repair-reservation'])
def run_phase(context,plan_path,phase,execute=False,image_keyring=None):
 need(phase in PHASES,'supported_host_phase_required')
 need(phase=='check' or execute is True,'explicit_execute_required')
 ctx=require_context(context,'host');ctx.guard();inputs=ctx.inputs
 need(os.geteuid()==0 and socket.gethostname().lower()==inputs['host_name'].lower(),'admitted_host_root_only')
 root=ctx.path('host_state_root');private_dir(root)
 need(plan_path==root/('plan-'+inputs['run_id'])/'plan.json','plan_context_path_required')
 lockpath=root/'lifecycle.lock';fd=os.open(lockpath,os.O_CREAT|os.O_RDWR|os.O_NOFOLLOW|os.O_NONBLOCK,0o600)
 fields=('st_dev','st_ino','st_mode','st_uid','st_gid','st_nlink','st_size','st_mtime_ns','st_ctime_ns')
 identity=lambda value:tuple(getattr(value,name)for name in fields)
 try:
  held=os.fstat(fd)
  need(stat.S_ISREG(held.st_mode) and held.st_uid==held.st_gid==0 and held.st_nlink==1 and stat.S_IMODE(held.st_mode)==0o600 and held.st_size==0,'unsafe_lifecycle_lock')
  need(identity(held)==identity(lockpath.lstat()),'lifecycle_lock_replaced');fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
  def locked():
   ctx.guard();need(identity(os.fstat(fd))==identity(held)==identity(lockpath.lstat()),'lifecycle_lock_replaced')
  locked();job=Lifecycle(plan_path,ctx);job.external_guard=locked
  if phase!='repair-reservation':job.guard()
  try:
   if phase in ['fetch-image','verify-image','create']:need(image_keyring is not None,'image_public_keyring_required')
   if phase=='fetch-image':job.fetch_image(image_keyring)
   elif phase=='verify-image':job.resume_verified_image(image_keyring)
   elif phase=='create':job.create(image_keyring)
   elif phase=='start':job.start_defined()
   elif phase=='verify-guest':job.verify_guest()
   elif phase=='repair-reservation':job.repair_reservation()
   else:job.state['status']='check_passed_no_vm_changes';job.persist()
  except BaseException:
   job.state['status']='stopped_manual_review_required';job.state['automatic_delete_or_foreign_rollback']=False
   try:job.persist()
   except BaseException:job.recovery()
   raise
  locked()
  return {'status':job.state['status'],'phase':phase,'private_receipt':str(job.state_path),'existing_resources_modified':False}
 finally:os.close(fd)

if __name__=='__main__':
 raise SystemExit('Source kit only: invoke callable phases with an explicit validated host context.')

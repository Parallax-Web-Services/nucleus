#!/usr/bin/env python3
"""Explicit-context private single-control-plane source API; no public installer."""
from __future__ import annotations
import argparse,base64,contextlib,ctypes,errno,fcntl,hashlib,ipaddress,json,os,re,socket,stat,subprocess,sys,tempfile,time,types,uuid
from pathlib import Path
from foundation.framework import require_context
IMAGE_LOCK_SHA='59eaf04dd9ea8c8b3c434979073e5b2bf5db084730f1d27a50b0a5b3e8f13f1a'
CALICO_SHA='6927c2d2c7a6de627a8df06c3097883121225d32c8bcec3f52d2ecf921dcdd1b'
CALICO_PIN_SHA='1018f6097ff2dc087390c7743d7828cc78880e367af0823dbc9be74ecd80ba1c'
CRI='unix:///run/containerd/containerd.sock'
POD_CIDR='10.244.0.0/16';SERVICE_CIDR='10.96.0.0/12'
class Refused(RuntimeError):pass
def need(ok,code):
 if not ok:raise Refused(code)
def sha(raw):return hashlib.sha256(raw).hexdigest()
def load_bootstrap(context):
 return require_context(context,'guest').load_module('guest/bootstrap')

def normalize(value):return json.loads(json.dumps(value))
def dir_identity(path):
 s=path.lstat();need(stat.S_ISDIR(s.st_mode) and s.st_uid==0 and stat.S_IMODE(s.st_mode)==0o700 and path.resolve()==path,'private_owned_directory_required')
 return [s.st_dev,s.st_ino,s.st_mode,s.st_uid,s.st_gid]
def exclusive_dir(path):
 need(path.parent.resolve()==path.parent and not os.path.lexists(path),'new_directory_already_exists')
 temp=Path(tempfile.mkdtemp(prefix='.nebula-dir-',dir=path.parent));before=dir_identity(temp)
 try:
  libc=ctypes.CDLL(None,use_errno=True);rename=libc.renameat2;rename.argtypes=[ctypes.c_int,ctypes.c_char_p,ctypes.c_int,ctypes.c_char_p,ctypes.c_uint];rename.restype=ctypes.c_int
  if rename(-100,os.fsencode(temp),-100,os.fsencode(path),1)!=0:raise OSError(ctypes.get_errno(),'exclusive_directory_publish_refused')
  need(dir_identity(path)==before,'new_directory_postimage_unknown');return before
 finally:
  try:
   if dir_identity(temp)==before:temp.rmdir()
  except FileNotFoundError:pass
def audit_policy():
 return {'apiVersion':'audit.k8s.io/v1','kind':'Policy','omitStages':['RequestReceived'],'omitManagedFields':True,'rules':[{'level':'Metadata'}]}
def admission_policy():
 defaults={}
 for mode in ['enforce','audit','warn']:defaults[mode]='restricted';defaults[mode+'-version']='v1.37'
 return {'apiVersion':'apiserver.config.k8s.io/v1','kind':'AdmissionConfiguration','plugins':[{'name':'PodSecurity','configuration':{'apiVersion':'pod-security.admission.config.k8s.io/v1','kind':'PodSecurityConfiguration','defaults':defaults,'exemptions':{'usernames':[],'runtimeClasses':[],'namespaces':['kube-system']}}}]}
def encryption_policy(key):
 need(len(key)==32,'encryption_key_length')
 return {'apiVersion':'apiserver.config.k8s.io/v1','kind':'EncryptionConfiguration','resources':[{'resources':['secrets'],'providers':[{'secretbox':{'keys':[{'name':'nebula-initial','secret':base64.b64encode(key).decode()}]}},{'identity':{}}]}]}
def image_patch(image,deployment=False,expected=None):
 root='/spec/template/spec' if deployment else '/spec'
 return ([{'op':'test','path':root+'/containers/0/image','value':expected}] if expected else [])+[{'op':'replace','path':root+'/containers/0/image','value':image},{'op':'add','path':root+'/containers/0/imagePullPolicy','value':'Never'}]
def init_documents(name,address,work):
 ip=ipaddress.ip_address(address);need(ip.version==4 and not ip.is_loopback and any(ip in ipaddress.ip_network(x) for x in ['10.0.0.0/8','172.16.0.0/12','192.168.0.0/16']),'private_guest_api_address_required')
 policies=str(work/'policies');audit=str(work/'audit')
 init={'apiVersion':'kubeadm.k8s.io/v1beta4','kind':'InitConfiguration','bootstrapTokens':[],'skipPhases':['bootstrap-token','show-join-command'],'localAPIEndpoint':{'advertiseAddress':address,'bindPort':6443},'nodeRegistration':{'name':name,'criSocket':CRI,'taints':[{'key':'node-role.kubernetes.io/control-plane','effect':'NoSchedule'}],'imagePullPolicy':'Never','imagePullSerial':True,'kubeletExtraArgs':[{'name':'node-ip','value':address}]},'patches':{'directory':str(work/'patches')},'timeouts':{'controlPlaneComponentHealthCheck':'180s','kubeletHealthCheck':'180s','kubernetesAPICall':'45s','etcdAPICall':'60s','tlsBootstrap':'180s'}}
 args=[{'name':k,'value':v} for k,v in [('bind-address',address),('encryption-provider-config','/etc/kubernetes/nebula/encryption.json'),('audit-policy-file','/etc/kubernetes/nebula/audit-policy.json'),('audit-log-path','/var/log/nebula-kubernetes/audit.log'),('audit-log-maxage','7'),('audit-log-maxbackup','5'),('audit-log-maxsize','20'),('admission-control-config-file','/etc/kubernetes/nebula/admission.json'),('enable-admission-plugins','NodeRestriction,PodSecurity')]]
 cluster={'apiVersion':'kubeadm.k8s.io/v1beta4','kind':'ClusterConfiguration','kubernetesVersion':'v1.37.1','clusterName':'nebula-'+name.removeprefix('nebula-control-'),'controlPlaneEndpoint':address+':6443','networking':{'podSubnet':POD_CIDR,'serviceSubnet':SERVICE_CIDR,'dnsDomain':'cluster.local'},'apiServer':{'certSANs':[address,name],'extraArgs':args,'extraVolumes':[{'name':'nebula-policies','hostPath':policies,'mountPath':'/etc/kubernetes/nebula','readOnly':True,'pathType':'Directory'},{'name':'nebula-audit','hostPath':audit,'mountPath':'/var/log/nebula-kubernetes','readOnly':False,'pathType':'Directory'}]}}
 kubelet={'apiVersion':'kubelet.config.k8s.io/v1beta1','kind':'KubeletConfiguration','cgroupDriver':'systemd','readOnlyPort':0,'authentication':{'anonymous':{'enabled':False},'webhook':{'enabled':True}},'authorization':{'mode':'Webhook'},'rotateCertificates':True,'systemReserved':{'cpu':'200m','memory':'256Mi'},'kubeReserved':{'cpu':'200m','memory':'256Mi'},'evictionHard':{'memory.available':'256Mi','nodefs.available':'10%','imagefs.available':'10%'}}
 return [init,cluster,kubelet]
def lock_images(raw):
 lock=json.loads(raw);need(lock.get('schema_version')==1 and lock.get('kubernetes_version')=='v1.37.1' and lock.get('architecture')=='amd64' and lock.get('status')=='official_https_digest_chain_verified' and len(lock.get('images',[]))==7,'image_lock_schema')
 result={}
 for item in lock['images']:
  image=item['image'];ref=item['immutable_image']
  need(image.startswith('registry.k8s.io/') and ref==image.rsplit(':',1)[0]+'@'+item['index_digest'] and re.fullmatch('sha256:[a-f0-9]{64}',item['index_digest']) and item['linux_amd64_manifest_digest']!=item['index_digest'],'invalid_image_lock_entry')
  need(image not in result,'duplicate_image_lock_entry');result[image]=item
 need(set(result)=={'registry.k8s.io/kube-apiserver:v1.37.1','registry.k8s.io/kube-controller-manager:v1.37.1','registry.k8s.io/kube-scheduler:v1.37.1','registry.k8s.io/kube-proxy:v1.37.1','registry.k8s.io/coredns/coredns:v1.14.6','registry.k8s.io/pause:3.10.2','registry.k8s.io/etcd:3.7.0-0'},'unexpected_official_image_inventory')
 return result
def validation_objects(namespace,image):
 labels={'parallax.link/bootstrap':namespace.removeprefix('nebula-validate-')}
 corefile='.:8053 {\n  errors\n  template IN A {\n    answer "{{ .Name }} 30 IN A 192.0.2.73"\n  }\n}\n'
 result=[{'apiVersion':'v1','kind':'ConfigMap','metadata':{'name':'probe-corefile','namespace':namespace,'labels':labels},'data':{'Corefile':corefile}}]
 for role in ['client','server']:
  result.append({'apiVersion':'v1','kind':'Pod','metadata':{'name':'probe-'+role,'namespace':namespace,'labels':{**labels,'role':role}},'spec':{'automountServiceAccountToken':False,'restartPolicy':'Always','tolerations':[{'key':'node-role.kubernetes.io/control-plane','operator':'Exists','effect':'NoSchedule'}],'securityContext':{'runAsNonRoot':True,'runAsUser':65532,'runAsGroup':65532,'seccompProfile':{'type':'RuntimeDefault'}},'containers':[{'name':'dns','image':image,'imagePullPolicy':'Never','command':['/coredns','-conf','/config/Corefile'],'securityContext':{'allowPrivilegeEscalation':False,'readOnlyRootFilesystem':True,'capabilities':{'drop':['ALL'],'add':['NET_BIND_SERVICE']}},'resources':{'requests':{'cpu':'10m','memory':'24Mi'},'limits':{'cpu':'100m','memory':'64Mi'}},'ports':[{'name':'dns-udp','containerPort':8053,'protocol':'UDP'}],'volumeMounts':[{'name':'config','mountPath':'/config','readOnly':True}]}],'volumes':[{'name':'config','configMap':{'name':'probe-corefile','defaultMode':292}}]}})
 result.append({'apiVersion':'v1','kind':'Service','metadata':{'name':'probe-dns','namespace':namespace,'labels':labels},'spec':{'type':'ClusterIP','selector':{'role':'server'},'ports':[{'name':'dns-udp','port':8053,'targetPort':8053,'protocol':'UDP'}]}})
 return result
def network_policy(namespace,allow):
 obj={'apiVersion':'networking.k8s.io/v1','kind':'NetworkPolicy','metadata':{'name':'probe-allow-server' if allow else 'probe-deny-egress','namespace':namespace},'spec':{'podSelector':{'matchLabels':{'role':'client'}},'policyTypes':['Egress'],'egress':[]}}
 if allow:obj['spec']['egress']=[{'to':[{'podSelector':{'matchLabels':{'role':'server'}}}],'ports':[{'protocol':'UDP','port':8053}]}]
 return obj
def dns_client_code(address,query,answer):
 need(ipaddress.ip_address(address) in ipaddress.ip_network(SERVICE_CIDR),'dns_probe_outside_cluster_service_cidr')
 need(query in ['nebula.test','kubernetes.default.svc.cluster.local'],'bounded_dns_query_required')
 need((query=='nebula.test' and answer=='192.0.2.73') or (query=='kubernetes.default.svc.cluster.local' and ipaddress.ip_address(answer) in ipaddress.ip_network(SERVICE_CIDR)),'bounded_dns_expected_answer')
 port=8053 if query=='nebula.test' else 53
 return """import ipaddress,os,socket,struct
address=ADDRESS;query=QUERY;answer=ANSWER;port=PORT
def skipname(data,pos):
 while True:
  if pos>=len(data):raise ValueError()
  n=data[pos];pos+=1
  if n==0:return pos
  if n&192==192:
   if pos>=len(data):raise ValueError()
   return pos+1
  if n>63 or pos+n>len(data):raise ValueError()
  pos+=n
try:
 token=os.urandom(2);wire=b''.join(bytes([len(x)])+x.encode('ascii') for x in query.split('.'))+b'\\0'
 packet=token+struct.pack('!HHHHH',256,1,0,0,0)+wire+struct.pack('!HH',1,1)
 client=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);client.settimeout(1.2);client.sendto(packet,(address,port));data,_=client.recvfrom(4096);client.close()
 if data[:2]!=token or len(data)<12:raise ValueError()
 flags,questions,answers,_,_=struct.unpack('!HHHHH',data[2:12])
 if flags&15 or answers<1:raise ValueError()
 pos=12
 for _ in range(questions):pos=skipname(data,pos)+4
 matched=False
 for _ in range(answers):
  pos=skipname(data,pos)
  if pos+10>len(data):raise ValueError()
  kind,klass,ttl,length=struct.unpack('!HHIH',data[pos:pos+10]);pos+=10
  if pos+length>len(data):raise ValueError()
  if kind==1 and klass==1 and length==4 and data[pos:pos+4]==ipaddress.ip_address(answer).packed:matched=True
  pos+=length
 raise SystemExit(0 if matched else 2)
except (OSError,ValueError,struct.error):raise SystemExit(2)
""".replace('ADDRESS',repr(address)).replace('QUERY',repr(query)).replace('ANSWER',repr(answer)).replace('PORT',str(port))


def serialize_documents(documents):
 return ('\n---\n'.join(json.dumps(x,indent=2) for x in documents)+'\n').encode()
def current_modules():
 return sorted(line.split()[0] for line in Path('/proc/modules').read_text().splitlines() if line.split())
def corrected_recovery_config(raw,name,address,work):
 corrected=init_documents(name,address,work);old=json.loads(json.dumps(corrected));old[0]['skipPhases']=['bootstrap-token']
 need(raw==serialize_documents(old),'only_exact_original_configuration_may_recover')
 return serialize_documents(corrected)
def require_no_cluster_for_recovery(job):
 for path in ['/etc/kubernetes/admin.conf','/etc/kubernetes/super-admin.conf','/etc/kubernetes/kubelet.conf','/etc/kubernetes/bootstrap-kubelet.conf','/etc/kubernetes/controller-manager.conf','/etc/kubernetes/scheduler.conf','/etc/kubernetes/pki','/var/lib/etcd/member']:
  need(not os.path.lexists(path),'recovery_requires_no_live_credentials_or_etcd')
 manifests=Path('/etc/kubernetes/manifests')
 if os.path.lexists(manifests):
  need(manifests.resolve()==manifests and manifests.is_dir() and manifests.lstat().st_uid==0,'recovery_requires_no_live_manifests')
  entries=list(manifests.iterdir());need({x.name for x in entries}<={'.kubelet-keep'},'recovery_requires_no_live_manifests')
  if entries:
   # Exact zero-byte root0644 placeholder from the pinned, signed kubelet DEB.
   placeholder=job.m.file_snapshot(manifests/'.kubelet-keep');identity=placeholder['identity']
   need(stat.S_ISREG(identity[2]) and stat.S_IMODE(identity[2])==0o644 and identity[3:7]==(0,0,1,0) and placeholder['sha256']==sha(b''),'recovery_kubelet_package_placeholder_changed')
 need(job.run(['systemctl','is-active','--quiet','kubelet.service'],'recovery-check-idle-kubelet',check=False).returncode!=0,'recovery_requires_idle_kubelet')
 for verb,field in [('ps','containers'),('pods','items')]:
  r=job.run(['crictl','--runtime-endpoint',CRI,verb,'-a','-o','json'] if verb=='ps' else ['crictl','--runtime-endpoint',CRI,verb,'-o','json'],'recovery-check-empty-'+verb,sensitive=True)
  need(not json.loads(r.stdout).get(field,[]),'recovery_requires_empty_cri')
 listeners=job.run(['ss','-H','-ltnp'],'recovery-check-no-control-plane-listener',sensitive=True).stdout.decode().splitlines()
 for line in listeners:
  parts=line.split();need(len(parts)>=5,'listener_format_changed')
  need(parts[3].rsplit(':',1)[-1] not in {'6443','10250','10257','10259','2379','2380'},'recovery_requires_no_control_plane_listener')
def specified_fields_match(actual,expected):
 if isinstance(expected,dict):return isinstance(actual,dict) and all(k in actual and specified_fields_match(actual[k],v) for k,v in expected.items())
 if isinstance(expected,list):return isinstance(actual,list) and len(actual)==len(expected) and all(specified_fields_match(a,b) for a,b in zip(actual,expected))
 return actual==expected
def require_owned_probe(pod,expected,uid,node):
 need(bool(uid) and pod.get('metadata',{}).get('uid')==uid and pod['metadata'].get('name')==expected['metadata']['name'] and pod['metadata'].get('namespace')==expected['metadata']['namespace'] and pod['metadata'].get('labels')==expected['metadata']['labels'],'probe_repair_identity_changed')
 spec=pod.get('spec',{});wanted=expected['spec'].get('tolerations',[])
 defaults=[{'key':'node.kubernetes.io/not-ready','operator':'Exists','effect':'NoExecute','tolerationSeconds':300},{'key':'node.kubernetes.io/unreachable','operator':'Exists','effect':'NoExecute','tolerationSeconds':300}]
 need(spec.get('tolerations',[]) in [wanted,wanted+defaults],'probe_repair_tolerations_changed')
 normalized=dict(spec);normalized['tolerations']=wanted
 need(specified_fields_match(normalized,expected['spec']),'probe_repair_spec_changed')
 spec=pod['spec'];need(all(not spec.get(k,False) for k in ['hostNetwork','hostPID','hostIPC','shareProcessNamespace']) and spec.get('nodeName',node)==node and not spec.get('runtimeClassName'),'probe_repair_host_isolation_changed')
def upstream_kubelet_role_rules():
 return [{'apiGroups':[''],'resources':['nodes'],'verbs':['get','list','watch']},{'apiGroups':[''],'resources':['nodes'],'verbs':['proxy']},{'apiGroups':[''],'resources':['nodes/proxy','nodes/metrics','nodes/stats','nodes/log'],'verbs':['*']},{'apiGroups':[''],'resources':['nodes/pods','nodes/healthz','nodes/configz'],'verbs':['*']}]
def upstream_kubelet_binding():
 group='rbac.authorization.k8s.io'
 return {'apiVersion':group+'/v1','kind':'ClusterRoleBinding','metadata':{'name':'kubeadm:apiserver-kubelet-client'},'roleRef':{'apiGroup':group,'kind':'ClusterRole','name':'system:kubelet-api-admin'},'subjects':[{'apiGroup':group,'kind':'User','name':'kube-apiserver-kubelet-client'}]}
def require_upstream_binding(obj,expected,uid):
 need(bool(uid) and obj.get('metadata',{}).get('uid')==uid and obj['metadata'].get('name')==expected['metadata']['name'] and obj.get('apiVersion')==expected['apiVersion'] and obj.get('kind')==expected['kind'] and obj.get('roleRef')==expected['roleRef'] and obj.get('subjects')==expected['subjects'],'upstream_kubelet_binding_postimage_changed')
def kubelet_auth_config_secure(config):
 def block(top):
  found=list(re.finditer(r'^'+re.escape(top)+r':\n((?:[ \t]+[^\n]*\n|[ \t]*\n)*)',config,re.M));return found[0].group(1) if len(found)==1 else ''
 auth=block('authentication');authorization=block('authorization')
 def child(name):
  found=list(re.finditer(r'^  '+name+r':\n((?:    [^\n]*\n)*)',auth,re.M));return found[0].group(1) if len(found)==1 else ''
 return bool(re.fullmatch(r'    enabled: false\n',child('anonymous')) and len(re.findall(r'^    enabled:',child('webhook'),re.M))==1 and re.search(r'^    enabled: true$',child('webhook'),re.M) and re.fullmatch(r'    clientCAFile: /etc/kubernetes/pki/ca.crt\n',child('x509')) and len(re.findall(r'^  mode:',authorization,re.M))==1 and re.search(r'^  mode: Webhook$',authorization,re.M))
class Cluster:
 def __init__(self,expected_uuid,run_id,address,phase,context=None):
  self.context=require_context(context,'guest')
  need(self.context.inputs['run_id']==run_id and self.context.inputs['expected_guest_uuid']==expected_uuid and self.context.inputs['api_address']==address,'context_cluster_identity_mismatch')
  need(re.fullmatch('[a-f0-9]{12}',run_id) and str(uuid.UUID(expected_uuid))==expected_uuid,'cluster_identity_arguments')
  self.base=self.context.path('guest_state_root')/('plan-'+run_id);self.m=load_bootstrap(self.context);self.m.guest_identity(expected_uuid,run_id,self.context)
  self.expected_uuid=expected_uuid;self.run_id=run_id;self.address=address;self.phase=phase;self.work=self.base/'cluster';self.input=self.base/'cluster-inputs'
  self.m.private_dir(self.base);self.m.private_dir(self.input)
  need(set(x.name for x in self.input.iterdir())=={'control-plane-images.lock.json','calico-image-pins.json'},'public_cluster_input_inventory')
  lockraw=self.read_public(self.input/'control-plane-images.lock.json',IMAGE_LOCK_SHA);self.images=lock_images(lockraw)
  need(CALICO_PIN_SHA is not None,'calico_pin_manifest_pending');self.calico=json.loads(self.read_public(self.input/'calico-image-pins.json',CALICO_PIN_SHA))
  need(len(self.calico)==3 and all(k.startswith('quay.io/calico/') and re.fullmatch('quay.io/calico/[a-z0-9/-]+@sha256:[a-f0-9]{64}',v) for k,v in self.calico.items()),'calico_image_inventory')
  self.read_public(self.base/'incoming/calico-3.33.0-nebula.yaml',CALICO_SHA)
  self.bootstrap_raw,self.bootstrap_record=self.m.read_private(self.base/'install-state.json');self.bootstrap_state=json.loads(self.bootstrap_raw)
  need(self.bootstrap_state['phase']=='runtime_and_packages_ready_no_cluster','runtime_package_phase_incomplete')
  if not os.path.lexists(self.work):
   need(phase in ['stage','check'],'stage_phase_required')
   if phase=='stage':self.work_identity=exclusive_dir(self.work);self.new_work=True
   else:self.work_identity=None;self.new_work=False
  else:self.m.private_dir(self.work);self.new_work=False;self.work_identity=dir_identity(self.work)
  self.state_path=self.work/'cluster-state.json';self.expected_control=self.control()
  if self.expected_control is None:
   need(self.new_work or (phase=='check' and not os.path.lexists(self.work)),'unowned_cluster_work_requires_review');self.state={'schema_version':1,'run_id':run_id,'foundation_binding':self.context.binding(),'expected_uuid':expected_uuid,'api_address':address,'phase':'not_started','files':{},'directories':({str(self.work):self.work_identity} if self.new_work else {}),'images':{}}
  else:self.state=json.loads(self.expected_control[1])
  need(self.state.get('foundation_binding')==self.context.binding() and self.state['run_id']==run_id and self.state['expected_uuid']==expected_uuid and self.state['api_address']==address,'cluster_state_binding')
 def read_public(self,path,pin):
  with self.m.verified_fd(path,pin) as fd:
   raw=b''
   while True:
    chunk=os.read(fd,1024*1024)
    if not chunk:break
    raw+=chunk
   return raw
 def control(self):
  if not os.path.lexists(self.state_path):return None
  raw,record=self.m.read_private(self.state_path);return normalize(record),raw
 def run(self,args,label,timeout=60,input_bytes=None,sensitive=False,check=True):
  env={'PATH':'/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin','HOME':'/root','LANG':'C.UTF-8','LC_ALL':'C.UTF-8'}
  parent=self.work if self.work.exists() else self.base;self.m.private_dir(parent)
  receipt=Path(tempfile.mkdtemp(prefix='command-',dir=parent));created=receipt.lstat();self.m.private_dir(receipt)
  directory=os.open(receipt,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC);owned=os.fstat(directory)
  identity=lambda st:(st.st_dev,st.st_ino,st.st_mode,st.st_uid,st.st_gid)
  def guard_receipt():
   self.m.private_dir(parent);self.m.private_dir(receipt)
   need(identity(os.fstat(directory))==identity(receipt.lstat())==identity(owned)==identity(created),'private_command_receipt_changed')
  def write_receipt(name,payload):
   guard_receipt()
   fd=os.open(name,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_CLOEXEC,0o600,dir_fd=directory)
   try:
    before=os.fstat(fd);need(stat.S_ISREG(before.st_mode) and before.st_uid==0 and before.st_nlink==1 and stat.S_IMODE(before.st_mode)==0o600,'private_command_file_permissions')
    remaining=memoryview(payload)
    while remaining:
     count=os.write(fd,remaining);need(count>0,'private_command_write_failed');remaining=remaining[count:]
    os.fsync(fd);after=os.fstat(fd)
    need(self.m.state_identity(after)[:6]==self.m.state_identity(before)[:6] and after.st_size==len(payload),'private_command_file_changed')
    need(self.m.state_identity(os.stat(name,dir_fd=directory,follow_symlinks=False))==self.m.state_identity(after),'private_command_file_changed')
   finally:os.close(fd)
  def retain(stdout,stderr,returncode,timed_out):
   metadata={'schema_version':1,'label':label,'sensitive':bool(sensitive),'returncode':returncode,'timed_out':timed_out,'stream_limit_bytes':2*1024**2,'streams':{}}
   for name,data in [('stdout',stdout),('stderr',stderr)]:
    data=b'' if data is None else (data.encode('utf-8',errors='replace') if isinstance(data,str) else data)
    limit=2*1024**2;truncated=len(data)>limit;head=limit//2 if truncated else len(data);tail=limit-head if truncated else 0
    payload=data[:head]+(data[-tail:] if tail else b'')
    write_receipt(name,payload)
    metadata['streams'][name]={'original_bytes':len(data),'stored_bytes':len(payload),'truncated':truncated,'format':'head-tail' if truncated else 'whole','head_bytes':head,'tail_bytes':tail}
   write_receipt('metadata.json',json.dumps(metadata,sort_keys=True,indent=2).encode());os.fsync(directory);guard_receipt()
  try:
   guard_receipt()
   try:result=subprocess.run(args,env=env,input=input_bytes,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=timeout)
   except subprocess.TimeoutExpired as error:
    # Retention failure must not replace the original command timeout.
    try:retain(error.stdout,error.stderr,None,True)
    except Exception:pass
    raise
   # Retained output stays bounded and root-private, including sensitive commands.
   retain(result.stdout,result.stderr,result.returncode,False)
   if check:need(result.returncode==0,'command_failed_private_receipt')
   return result
  finally:os.close(directory)
 def kubectl(self,args,**kwargs):
  return self.run(['kubectl','--kubeconfig','/etc/kubernetes/admin.conf','--server','https://'+self.address+':6443','--request-timeout='+str(min(kwargs.get('timeout',15),600))+'s',*args],'private-cluster-api',**kwargs)
 def guard(self,routes=False):
  self.context.guard();need(self.state.get('foundation_binding')==self.context.binding(),'foundation_binding_changed')
  if hasattr(self,'external_guard'):self.external_guard()
  self.m.guest_identity(self.expected_uuid,self.run_id,self.context);need(self.control()==self.expected_control,'cluster_control_state_changed')
  need(self.m.read_private(self.base/'install-state.json')[0]==self.bootstrap_raw,'bootstrap_install_state_changed')
  for path,known in self.bootstrap_state['files'].items():need(normalize(self.m.file_snapshot(Path(path)))==known,'installed_runtime_file_changed')
  for path,known in self.state['files'].items():need(normalize(self.m.file_snapshot(Path(path),private=True))==known,'cluster_owned_file_changed')
  if 'audit_initial_identity' in self.state:
   audit=self.work/'audit/audit.log';st=audit.lstat()
   need(stat.S_ISREG(st.st_mode) and st.st_uid==0 and stat.S_IMODE(st.st_mode)==0o600 and st.st_nlink==1,'private_audit_file_metadata_changed')
   if self.state['phase'] in ['stage_started','staged','pull_started','images_ready']:
    need(list(self.m.state_identity(st))==self.state['audit_initial_identity'],'audit_file_changed_before_owned_api_start')
  for path,known in self.state.get('credentials',{}).items():need(normalize(self.m.file_snapshot(Path(path),private=True))==known,'private_cluster_credential_changed')
  for path,known in self.state['directories'].items():need(dir_identity(Path(path))==known,'cluster_owned_directory_changed')
  if self.state['phase'] not in ['not_started','stage_started']:
   expected_patches={x+'0+json.json' for x in ['kube-apiserver','kube-controller-manager','kube-scheduler','etcd','corednsdeployment','kubeproxydaemonset']}
   need(set(x.name for x in (self.work/'patches').iterdir())==expected_patches,'unexpected_patch_directory_inventory')
  for path,pin in [(self.input/'control-plane-images.lock.json',IMAGE_LOCK_SHA),(self.input/'calico-image-pins.json',CALICO_PIN_SHA)]:need(self.m.file_snapshot(path,private=True)['sha256']==pin,'cluster_public_input_changed')
  assigned=json.loads(self.run(['ip','-j','-4','addr','show'],'check-private-guest-address').stdout)
  need(any(x.get('local')==self.address and x.get('scope')=='global' for interface in assigned for x in interface.get('addr_info',[])),'api_address_not_assigned_to_guest')
  need(self.run(['systemctl','is-active','--quiet','containerd.service'],'check-owned-runtime').returncode==0,'runtime_not_active')
  if routes:need(self.m.routes_clear(json.loads(self.run(['ip','-j','-4','route','show','table','all'],'check-candidate-cidrs').stdout)),'candidate_route_collision')
 def persist(self):
  self.guard();raw=json.dumps(self.state,sort_keys=True,indent=2).encode()
  fd,temp=tempfile.mkstemp(prefix='.cluster-state-',dir=self.work);owned=os.fstat(fd)
  try:
   remaining=memoryview(raw)
   while remaining:
    written=os.write(fd,remaining);need(written>0,'cluster_control_write_failed');remaining=remaining[written:]
   os.fsync(fd);written=self.m.state_identity(os.fstat(fd));original=self.m.state_identity(owned)
   need(written[:6]==original[:6] and written[6]==len(raw) and os.pread(fd,len(raw)+1,0)==raw,'cluster_control_temporary_postimage_unknown')
   need(self.control()==self.expected_control,'cluster_control_state_changed')
   if self.expected_control is None:
    try:os.link(temp,self.state_path,follow_symlinks=False)
    except FileExistsError:raise Refused('cluster_control_state_changed') from None
    os.unlink(temp)
   else:os.replace(temp,self.state_path)
   post=self.m.state_identity(os.fstat(fd))
   # Rename/link-unlink may change ctime; every other field stays exactly ours.
   need(post[:-1]==written[:-1] and os.pread(fd,len(raw)+1,0)==raw,'cluster_control_postimage_unknown')
   retained=({'identity':list(post),'sha256':sha(raw)},raw);current=self.control()
   need(current==retained and self.control()==retained,'cluster_control_postimage_unknown')
   self.expected_control=retained
  finally:
   os.close(fd)
   try:
    st=os.lstat(temp)
    if(st.st_dev,st.st_ino)==(owned.st_dev,owned.st_ino):os.unlink(temp)
   except FileNotFoundError:pass
 def own_dir(self,path):
  if str(path) in self.state['directories']:need(dir_identity(path)==self.state['directories'][str(path)],'owned_directory_changed');return
  self.guard();record=exclusive_dir(path);self.state['directories'][str(path)]=record;self.persist()
 def own_file(self,path,producer):
  if str(path) in self.state['files']:need(normalize(self.m.file_snapshot(path,private=True))==self.state['files'][str(path)],'owned_file_changed');return
  self.guard();need(not os.path.lexists(path),'unowned_file_already_exists');record=self.m.write_exclusive(path,producer());self.state['files'][str(path)]=normalize(record);self.persist()
 def stage(self):
  need(self.state['phase'] in ['not_started','stage_started','staged'],'stage_phase_order');self.guard(routes=True)
  need(not os.path.lexists('/etc/kubernetes/admin.conf') and not os.path.lexists('/etc/kubernetes/pki') and not os.path.lexists('/var/lib/etcd/member'),'existing_cluster_requires_review')
  self.state['phase']='stage_started';self.persist()
  for name in ['policies','patches','audit']:self.own_dir(self.work/name)
  self.own_file(self.work/'policies/encryption.json',lambda:json.dumps(encryption_policy(os.urandom(32)),sort_keys=True,indent=2).encode())
  self.own_file(self.work/'policies/audit-policy.json',lambda:json.dumps(audit_policy(),sort_keys=True,indent=2).encode())
  self.own_file(self.work/'policies/admission.json',lambda:json.dumps(admission_policy(),sort_keys=True,indent=2).encode())
  audit=self.work/'audit/audit.log'
  if 'audit_initial_identity' not in self.state:
   need(not os.path.lexists(audit),'unowned_audit_file_exists');record=self.m.write_exclusive(audit,b'');self.state['audit_initial_identity']=normalize(record)['identity'];self.persist()
  s=audit.lstat();need(stat.S_ISREG(s.st_mode) and s.st_uid==0 and stat.S_IMODE(s.st_mode)==0o600 and s.st_nlink==1,'private_audit_file_required')
  for target,image in [('kube-apiserver','registry.k8s.io/kube-apiserver:v1.37.1'),('kube-controller-manager','registry.k8s.io/kube-controller-manager:v1.37.1'),('kube-scheduler','registry.k8s.io/kube-scheduler:v1.37.1'),('etcd','registry.k8s.io/etcd:3.7.0-0'),('corednsdeployment','registry.k8s.io/coredns/coredns:v1.14.6'),('kubeproxydaemonset','registry.k8s.io/kube-proxy:v1.37.1')]:
   patch=image_patch(self.images[image]['immutable_image'],target in ['corednsdeployment','kubeproxydaemonset'],image)
   self.own_file(self.work/'patches'/(target+'0+json.json'),lambda p=patch:json.dumps(p,indent=2).encode())
  documents=init_documents('nebula-control-'+self.run_id,self.address,self.work)
  self.own_file(self.work/'kubeadm.yaml',lambda:('\n---\n'.join(json.dumps(x,indent=2) for x in documents)+'\n').encode())
  self.run(['kubeadm','config','validate','--config',str(self.work/'kubeadm.yaml')],'validate-exact-kubeadm-config')
  self.state['phase']='staged';self.persist()
 def local_content(self,digest):
  need(re.fullmatch('sha256:[a-f0-9]{64}',digest),'content_digest_format')
  raw=self.run(['ctr','--namespace','k8s.io','content','get',digest],'verify-local-oci-content',sensitive=True).stdout
  need('sha256:'+sha(raw)==digest,'local_oci_content_digest_changed');return json.loads(raw)
 def verify_local_image(self,reference,expected=None):
  index_digest=reference.rsplit('@',1)[1];index=self.local_content(index_digest)
  matches=[x for x in index.get('manifests',[]) if x.get('platform',{}).get('os')=='linux' and x.get('platform',{}).get('architecture')=='amd64' and x.get('platform',{}).get('variant','') in [None,'','v1']]
  need(len(matches)==1,'one_linux_amd64_manifest_required');manifest_digest=matches[0]['digest'];manifest=self.local_content(manifest_digest);config_digest=manifest['config']['digest'];config=self.local_content(config_digest)
  need(config.get('os')=='linux' and config.get('architecture')=='amd64','local_image_platform_mismatch')
  if expected:need(manifest_digest==expected['linux_amd64_manifest_digest'] and config_digest==expected['config_digest'] and [x['digest'] for x in manifest['layers']]==expected['layer_digests'],'local_image_chain_differs_from_lock')
  need(self.alias_target(reference)==index_digest,'immutable_local_image_reference_changed')
  return {'reference':reference,'index':index_digest,'manifest':manifest_digest,'config':config_digest}
 def alias_target(self,name):
  rows=self.run(['ctr','--namespace','k8s.io','images','list','name=='+name],'check-local-image-alias').stdout.decode().splitlines()[1:]
  entries=[line.split() for line in rows if line.split() and line.split()[0]==name]
  need(len(entries)<=1,'duplicate_local_image_alias');return entries[0][2] if entries else None
 def pull(self):
  need(self.state['phase'] in ['staged','pull_started','images_ready'],'pull_phase_order');self.guard(routes=True)
  need(not os.path.lexists('/etc/kubernetes/admin.conf'),'pull_before_init_only')
  fs=os.statvfs('/');need(fs.f_bavail*fs.f_frsize>=8*1024**3,'guest_image_disk_headroom')
  self.state['phase']='pull_started';self.persist();deadline=time.monotonic()+1200
  entries=[(v['immutable_image'],v) for v in self.images.values()]+[(v,None) for v in self.calico.values()]
  for ref,lock in entries:
   self.guard();need(time.monotonic()<deadline,'image_pull_total_deadline')
   if ref not in self.state['images']:
    self.run(['crictl','--runtime-endpoint',CRI,'--image-endpoint',CRI,'pull',ref],'pull-approved-digest',120)
    self.state['images'][ref]=self.verify_local_image(ref,lock);self.persist()
   else:need(self.verify_local_image(ref,lock)==self.state['images'][ref],'owned_image_changed')
  for name,item in self.images.items():
   before=self.alias_target(name);need(before in [None,item['index_digest']],'foreign_mutable_tag_alias')
   if before is None:self.run(['ctr','--namespace','k8s.io','images','tag',item['immutable_image'],name],'create-reviewed-local-tag-alias')
   need(self.alias_target(name)==item['index_digest'],'local_tag_alias_postimage')
  self.state['phase']='images_ready';self.persist()

 def verify_images(self):
  need(len(self.state['images'])==10,'ten_approved_images_required')
  for image,item in self.images.items():
   ref=item['immutable_image'];need(self.verify_local_image(ref,item)==self.state['images'].get(ref) and self.alias_target(image)==item['index_digest'],'approved_image_or_alias_changed')
  for ref in self.calico.values():need(self.verify_local_image(ref)==self.state['images'].get(ref),'approved_calico_image_changed')
 def api_security_checks(self):
  name='nebula-control-'+self.run_id;pod=json.loads(self.kubectl(['get','pod','-n','kube-system','kube-apiserver-'+name,'-o','json'],sensitive=True).stdout)
  command=pod['spec']['containers'][0]['command'];expected=['--bind-address='+self.address,'--encryption-provider-config=/etc/kubernetes/nebula/encryption.json','--audit-policy-file=/etc/kubernetes/nebula/audit-policy.json','--audit-log-path=/var/log/nebula-kubernetes/audit.log','--admission-control-config-file=/etc/kubernetes/nebula/admission.json','--audit-log-maxage=7','--audit-log-maxbackup=5','--audit-log-maxsize=20']
  need(all(value in command for value in expected),'actual_apiserver_security_flags_changed')
  need(audit_policy()==json.loads((self.work/'policies/audit-policy.json').read_text()) and admission_policy()==json.loads((self.work/'policies/admission.json').read_text()),'security_policy_changed')
  secret=json.loads((self.work/'policies/encryption.json').read_text());providers=secret['resources'][0]['providers'];need(list(providers[0])==['secretbox'] and len(base64.b64decode(providers[0]['secretbox']['keys'][0]['secret'],validate=True))==32,'private_encryption_provider_invalid')
  audit=self.work/'audit/audit.log';s=audit.lstat();need(stat.S_ISREG(s.st_mode) and s.st_uid==0 and stat.S_IMODE(s.st_mode)==0o600 and s.st_nlink==1 and s.st_size>0,'private_metadata_audit_not_active')
 def verify_init(self):
  need(self.state['phase'] in ['init_started','init_ready','cni_started','cni_ready','smoke_started','smoke_cleanup','accepted'],'owned_init_attempt_required');self.guard()
  server=self.run(['kubectl','--kubeconfig','/etc/kubernetes/admin.conf','config','view','--minify','-o','jsonpath={.clusters[0].cluster.server}'],'verify-private-api-server',sensitive=True).stdout.decode()
  need(server=='https://'+self.address+':6443','generated_kubeconfig_server_changed')
  self.kubectl(['get','--raw','/readyz'])
  name='nebula-control-'+self.run_id;node=json.loads(self.kubectl(['get','node',name,'-o','json'],sensitive=True).stdout)
  need(node['status']['nodeInfo']['systemUUID'].lower()==self.expected_uuid and node['status']['nodeInfo']['kubeletVersion']=='v1.37.1','actual_kubernetes_node_identity')
  need(any(t.get('key')=='node-role.kubernetes.io/control-plane' and t.get('effect')=='NoSchedule' for t in node['spec'].get('taints',[])),'control_plane_taint_missing')
  for target,image in [('kube-apiserver','registry.k8s.io/kube-apiserver:v1.37.1'),('kube-controller-manager','registry.k8s.io/kube-controller-manager:v1.37.1'),('kube-scheduler','registry.k8s.io/kube-scheduler:v1.37.1'),('etcd','registry.k8s.io/etcd:3.7.0-0')]:
   pod=json.loads(self.kubectl(['get','pod','-n','kube-system',target+'-'+name,'-o','json'],sensitive=True).stdout)
   need(len(pod['spec']['containers'])==1 and pod['spec']['containers'][0]['image']==self.images[image]['immutable_image'] and pod['spec']['containers'][0]['imagePullPolicy']=='Never','static_control_plane_image_changed')
  for kind,name,image in [('deployment','coredns','registry.k8s.io/coredns/coredns:v1.14.6'),('daemonset','kube-proxy','registry.k8s.io/kube-proxy:v1.37.1')]:
   obj=json.loads(self.kubectl(['get',kind,'-n','kube-system',name,'-o','json'],sensitive=True).stdout);containers=obj['spec']['template']['spec']['containers']
   need(len(containers)==1 and containers[0]['image']==self.images[image]['immutable_image'] and containers[0]['imagePullPolicy']=='Never','system_addon_image_changed')
  names=self.kubectl(['get','secrets','-n','kube-system','--field-selector','type=bootstrap.kubernetes.io/token','-o','name'],sensitive=True).stdout
  need(not names.strip(),'bootstrap_join_token_should_not_exist');self.api_security_checks()
  for path in ['/etc/kubernetes/admin.conf','/etc/kubernetes/super-admin.conf','/etc/kubernetes/pki/ca.key']:
   p=Path(path);record=normalize(self.m.file_snapshot(p,private=True))
   if path in self.state.get('credentials',{}):need(record==self.state['credentials'][path],'private_cluster_credential_changed')
   else:self.state.setdefault('credentials',{})[path]=record
  if self.state['phase']=='init_started':self.state['phase']='init_ready'
  self.persist()
 def recover_prephase_failure(self,diagnostic,module_baseline):
  need(self.state['phase']=='init_started' and 'prephase_recovery' not in self.state,'only_one_owned_prephase_recovery')
  self.guard(routes=True);self.verify_images();require_no_cluster_for_recovery(self)
  need(diagnostic.parent==self.work and diagnostic.name.startswith('full-init-dryrun-'),'owned_diagnostic_receipt_required');self.m.private_dir(diagnostic)
  out,_=self.m.read_private(diagnostic/'stdout.private');err,_=self.m.read_private(diagnostic/'stderr.private')
  need(len(out)<=2*1024**2 and len(err)<=2*1024**2,'diagnostic_receipt_bound')
  combined=out+b'\n'+err
  need(b'unresolved dependencies:' in combined and b'missing [bootstrap-token] phase(s) needed by "show-join-command"' in combined,'exact_prephase_dependency_evidence_required')
  old_source=self.base/'cluster-init.c50bead.backup.py'
  need(self.m.file_snapshot(old_source,private=True)['sha256']=='c50bead48c56582fa61b432f7ae4950dc988058319d9fa6795dc7c8a331f1daf','original_failed_source_backup_required')
  need(module_baseline.parent==self.work and module_baseline.name.startswith('accepted-module-baseline-'),'owned_module_baseline_required')
  baseline_raw,baseline_record=self.m.read_private(module_baseline);baseline=json.loads(baseline_raw)
  need(baseline.get('schema_version')==1 and baseline.get('run_id')==self.run_id and baseline.get('expected_uuid')==self.expected_uuid and baseline.get('kernel_release')==os.uname().release and baseline.get('kernel_untainted') is True,'module_baseline_binding')
  need(baseline.get('diagnostic_module_checks')=={name:{'live':True,'untainted':True,'in_tree':True,'running_kernel_vermagic':True,'signed':True} for name in ['inet_diag','tcp_diag']},'module_identity_acceptance_required')
  need(current_modules()==baseline.get('modules') and Path('/proc/sys/kernel/tainted').read_text().strip()=='0','accepted_module_baseline_changed')
  config=self.work/'kubeadm.yaml';original,original_record=self.m.read_private(config);corrected=corrected_recovery_config(original,'nebula-control-'+self.run_id,self.address,self.work)
  self.guard(routes=True);self.verify_images();require_no_cluster_for_recovery(self)
  need(current_modules()==baseline['modules'] and self.m.read_private(module_baseline)==(baseline_raw,baseline_record),'accepted_module_baseline_changed')
  recovery=Path(tempfile.mkdtemp(prefix='prephase-recovery-',dir=self.work));self.m.private_dir(recovery);self.state['directories'][str(recovery)]=dir_identity(recovery)
  self.m.write_exclusive(recovery/'original-cluster-state.private',self.expected_control[1])
  self.m.write_exclusive(recovery/'original-kubeadm-config.private',original)
  corrected_path=recovery/'kubeadm-corrected.yaml';self.own_file(corrected_path,lambda:corrected)
  need(self.m.read_private(config)==(original,original_record),'original_configuration_changed_during_recovery')
  self.state['prephase_recovery']={'reason':'bootstrap_token_show_join_dependency','original_phase':'init_started','original_source_sha256':'c50bead48c56582fa61b432f7ae4950dc988058319d9fa6795dc7c8a331f1daf','diagnostic_receipt':str(diagnostic),'accepted_module_baseline':str(module_baseline),'private_beforeimages':str(recovery),'corrected_config':str(corrected_path),'init_retry_started':False}
  self.state['phase']='recovered_prephase_failure';self.persist()
  self.guard(routes=True);self.verify_images();require_no_cluster_for_recovery(self)
 def init(self):
  need(self.state['phase'] in ['images_ready','recovered_prephase_failure'],'init_once_images_ready_or_reviewed_recovery');self.guard(routes=True);self.verify_images()
  recovery=self.state.get('prephase_recovery');recovering=self.state['phase']=='recovered_prephase_failure'
  if recovering:need(isinstance(recovery,dict) and recovery.get('init_retry_started') is False,'recovery_retry_already_used')
  else:need(recovery is None,'recovery_state_mismatch')
  config=Path(recovery['corrected_config']) if recovering else self.work/'kubeadm.yaml'
  need(self.m.read_private(config)[0]==serialize_documents(init_documents('nebula-control-'+self.run_id,self.address,self.work)),'exact_corrected_init_configuration_required')
  need(not os.path.lexists('/etc/kubernetes/admin.conf') and not os.path.lexists('/etc/kubernetes/pki') and not os.path.lexists('/var/lib/etcd/member'),'unowned_existing_cluster_state')
  need(self.run(['systemctl','is-active','--quiet','kubelet.service'],'check-uninitialized-kubelet',check=False).returncode!=0,'kubelet_should_be_inactive')
  if recovering:
   require_no_cluster_for_recovery(self)
   recovery['init_retry_started']=True
  self.state['phase']='init_started';self.persist()
  pin=self.state['files'][str(config)]['sha256']
  with self.m.verified_fd(config,pin) as fd:
   self.run(['kubeadm','init','--config','/proc/'+str(os.getpid())+'/fd/'+str(fd),'--skip-phases','bootstrap-token,show-join-command','--skip-token-print','--skip-certificate-key-print'],'initialize-private-control-plane',timeout=600,sensitive=True)
  self.verify_init()
 def cni(self):
  need(self.state['phase'] in ['init_ready','cni_started','cni_ready'],'cni_phase_order');self.guard();self.verify_init();self.verify_images()
  self.state['phase']='cni_started';self.persist()
  manifest=self.base/'incoming/calico-3.33.0-nebula.yaml'
  with self.m.verified_fd(manifest,CALICO_SHA) as fd:
   self.kubectl(['apply','--server-side','--field-manager=nebula-bootstrap-'+self.run_id,'-f','/proc/'+str(os.getpid())+'/fd/'+str(fd)],timeout=120)
  self.kubectl(['rollout','status','daemonset/calico-node','-n','kube-system','--timeout=180s'],timeout=200)
  self.kubectl(['rollout','status','deployment/calico-kube-controllers','-n','kube-system','--timeout=180s'],timeout=200)
  self.kubectl(['rollout','status','deployment/coredns','-n','kube-system','--timeout=180s'],timeout=200)
  self.kubectl(['rollout','status','daemonset/kube-proxy','-n','kube-system','--timeout=120s'],timeout=140)
  self.kubectl(['wait','--for=condition=Ready','node/nebula-control-'+self.run_id,'--timeout=120s'],timeout=140)
  pools=json.loads(self.kubectl(['get','ippools.crd.projectcalico.org','-o','json'],sensitive=True).stdout)
  need(pools['items'] and all(x['spec']['cidr']==POD_CIDR and x['spec'].get('ipipMode')=='Never' and x['spec'].get('vxlanMode')=='Always' for x in pools['items']),'actual_calico_pool_configuration')
  self.state['phase']='cni_ready';self.persist()

 def validation_namespace(self):
  name='nebula-validate-'+self.run_id
  current=json.loads(self.kubectl(['get','namespace',name,'-o','json'],sensitive=True).stdout)
  need(current['metadata']['uid']==self.state['validation_namespace_uid'] and current['metadata'].get('labels',{}).get('parallax.link/bootstrap')==self.run_id,'validation_namespace_identity_changed');return name,current
 def create_validation(self,obj):
  key=obj['kind']+'/'+obj['metadata']['name']
  if key in self.state.get('validation_objects',{}):
   old=json.loads(self.kubectl(['get',obj['kind'],obj['metadata']['name'],'-n',obj['metadata']['namespace'],'-o','json'],sensitive=True).stdout)
   need(old['metadata']['uid']==self.state['validation_objects'][key],'validation_object_identity_changed');return old
  result=self.kubectl(['create','-f','-','-o','json'],input_bytes=json.dumps(obj).encode(),sensitive=True)
  created=json.loads(result.stdout);self.state.setdefault('validation_objects',{})[key]=created['metadata']['uid'];self.persist();return created
 def dns_probe(self,service_ip,query,answer):
  ns,_=self.validation_namespace();pod=json.loads(self.kubectl(['get','pod','probe-client','-n',ns,'-o','json'],sensitive=True).stdout)
  need(pod['metadata']['uid']==self.state['validation_objects']['Pod/probe-client'],'probe_pod_identity_changed')
  cid=pod['status']['containerStatuses'][0]['containerID'];need(re.fullmatch('containerd://[a-f0-9]{64}',cid),'probe_container_id_invalid')
  container=json.loads(self.run(['crictl','--runtime-endpoint',CRI,'inspect',cid.split('://',1)[1]],'inspect-only-owned-probe',sensitive=True).stdout)
  need(container['status']['labels'].get('io.kubernetes.pod.uid')==pod['metadata']['uid'],'probe_container_not_owned_by_pod')
  pid=int(container['info']['pid']);need(pid>1 and os.readlink('/proc/'+str(pid)+'/ns/net')!=os.readlink('/proc/1/ns/net'),'probe_requires_isolated_pod_network')
  proc=Path('/proc')/str(pid);start=(proc/'stat').read_text().rsplit(') ',1)[1].split()[19]
  code=dns_client_code(service_ip,query,answer)
  result=self.run(['nsenter','--target',str(pid),'--net','python3','-c',code],'bounded-owned-pod-network-probe',timeout=5,sensitive=True,check=False)
  need((proc/'stat').read_text().rsplit(') ',1)[1].split()[19]==start,'probe_container_process_changed')
  need(result.returncode in [0,2],'probe_failed_outside_expected_dns_timeout');return result.returncode==0
 def await_dns(self,address,query,answer,timeout=25):
  deadline=time.monotonic()+timeout
  while time.monotonic()<deadline:
   if self.dns_probe(address,query,answer):return True
   time.sleep(1)
  return False
 def complete_kubelet_authority(self):
  record=self.state.get('upstream_kubelet_authority',{})
  need(self.state['phase']=='smoke_started' and record.get('status')=='creating' and 'binding_uid' not in record,'only_exact_owned_partial_authority_may_complete')
  self.guard();self.verify_images();self.api_security_checks();self.validation_namespace()
  audit=Path(record['private_receipt']);need(audit.parent==self.work and audit.name.startswith('upstream-kubelet-authority-'),'owned_authority_receipt_required');self.m.private_dir(audit)
  created_raw,created_record=self.m.read_private(audit/'created-binding.private');created=json.loads(created_raw);expected=upstream_kubelet_binding();owned_uid=created['metadata']['uid'];require_upstream_binding(created,expected,owned_uid)
  prior=json.loads(self.m.read_private(audit/'before-cluster-state.private')[0])
  need(prior['phase']=='smoke_started' and prior.get('validation_namespace_uid')==self.state.get('validation_namespace_uid') and prior.get('validation_objects')==self.state.get('validation_objects') and prior.get('smoke_progress')==self.state.get('smoke_progress'),'original_owned_validation_state_changed')
  for path,known in prior.get('credentials',{}).items():need(normalize(self.m.file_snapshot(Path(path),private=True))==known,'original_owned_credential_changed')
  canonical=lambda rules:{json.dumps({key:sorted(value) for key,value in rule.items()},sort_keys=True) for rule in rules}
  role=json.loads(self.kubectl(['get','clusterrole','system:kubelet-api-admin','-o','json'],sensitive=True,timeout=20).stdout)
  need(role['metadata']['uid']==record['role_uid'] and not role.get('aggregationRule') and canonical(role['rules'])==canonical(upstream_kubelet_role_rules()),'original_builtin_kubelet_role_changed')
  bound=json.loads(self.kubectl(['get','clusterrolebinding',expected['metadata']['name'],'-o','json'],sensitive=True,timeout=20).stdout);require_upstream_binding(bound,expected,owned_uid)
  pod=json.loads(self.kubectl(['get','pod','kube-apiserver-nebula-control-'+self.run_id,'-n','kube-system','-o','json'],sensitive=True,timeout=20).stdout)
  need(all(flag in pod['spec']['containers'][0]['command'] for flag in ['--kubelet-client-certificate=/etc/kubernetes/pki/apiserver-kubelet-client.crt','--kubelet-client-key=/etc/kubernetes/pki/apiserver-kubelet-client.key']),'actual_apiserver_kubelet_client_flags_changed')
  certificate=Path('/etc/kubernetes/pki/apiserver-kubelet-client.crt');cert_record=self.m.file_snapshot(certificate)
  subject=self.run(['openssl','x509','-in',str(certificate),'-noout','-subject','-nameopt','RFC2253'],'fresh-completion-public-apiserver-client-subject',sensitive=True).stdout.decode().strip();need(subject=='subject=CN=kube-apiserver-kubelet-client','unexpected_apiserver_client_certificate_identity')
  self.run(['openssl','verify','-CAfile','/etc/kubernetes/pki/ca.crt',str(certificate)],'fresh-completion-public-apiserver-client-own-ca',sensitive=True)
  config=Path('/var/lib/kubelet/config.yaml');config_record=self.m.file_snapshot(config)
  with self.m.verified_fd(config,config_record['sha256']) as fd:config_raw=os.read(fd,1024*1024)
  need(len(config_raw)<1024*1024 and kubelet_auth_config_secure(config_raw.decode()),'actual_kubelet_authentication_or_authorization_changed')
  pid=int(self.run(['systemctl','show','kubelet.service','--property=MainPID','--value'],'fresh-completion-owned-kubelet-process',sensitive=True).stdout.strip());need(pid>1 and os.readlink('/proc/'+str(pid)+'/exe')=='/usr/bin/kubelet','unexpected_kubelet_process')
  process=Path('/proc')/str(pid);start=(process/'stat').read_text().rsplit(') ',1)[1].split()[19];args=[v.decode() for v in (process/'cmdline').read_bytes().split(b'\0') if v]
  need('--config=/var/lib/kubelet/config.yaml' in args and not any(a.startswith(prefix) for a in args for prefix in ['--anonymous-auth','--authorization-mode','--client-ca-file','--authentication-token-webhook']),'kubelet_authentication_flags_changed')
  access=self.kubectl(['auth','can-i','create','nodes','--subresource=proxy','--as=kube-apiserver-kubelet-client'],sensitive=True,check=False,timeout=20);need(access.returncode==0 and access.stdout.strip()==b'yes','exact_kubelet_client_proxy_authority_missing')
  fresh=json.loads(self.kubectl(['get','clusterrolebinding',expected['metadata']['name'],'-o','json'],sensitive=True,timeout=20).stdout);require_upstream_binding(fresh,expected,owned_uid)
  current_role=json.loads(self.kubectl(['get','clusterrole','system:kubelet-api-admin','-o','json'],sensitive=True,timeout=20).stdout);need(current_role['metadata']['uid']==record['role_uid'] and canonical(current_role['rules'])==canonical(role['rules']),'original_builtin_kubelet_role_changed')
  need(not self.kubectl(['get','secrets','-n','kube-system','--field-selector','type=bootstrap.kubernetes.io/token','-o','name'],sensitive=True,timeout=20).stdout.strip(),'bootstrap_tokens_should_not_exist')
  self.guard();need(self.m.read_private(audit/'created-binding.private')==(created_raw,created_record) and self.m.file_snapshot(certificate)==cert_record and self.m.file_snapshot(config)==config_record and (process/'stat').read_text().rsplit(') ',1)[1].split()[19]==start,'authority_completion_fresh_precondition_changed')
  for path,known in prior.get('credentials',{}).items():need(normalize(self.m.file_snapshot(Path(path),private=True))==known,'original_owned_credential_changed')
  proof={'fresh_secure_certificate_config_process_validated':True,'original_role_uid_and_known_credentials_retained':True,'unavailable_original_certificate_config_starttick_snapshots_compared':False,'retained_created_binding_uid_and_spec_verified':True,'exact_proxy_subresource_permission_verified':True,'no_binding_or_other_api_mutations':True}
  self.m.write_exclusive(audit/'verification-only-completion.private',json.dumps(proof,sort_keys=True,indent=2).encode())
  self.state['upstream_kubelet_authority'].update(status='ready',binding_uid=owned_uid,verification_completed_after_timeout=True,authority_probe_uses_explicit_subresource=True);self.persist()
 def restore_kubelet_authority(self):
  need(self.state['phase'] in ['init_ready','cni_ready','smoke_started'] and 'upstream_kubelet_authority' not in self.state,'only_owned_unrestored_postinit_authority')
  self.guard();self.verify_images();self.api_security_checks()
  if self.state['phase']=='smoke_started':self.validation_namespace()
  expected=upstream_kubelet_binding();role=json.loads(self.kubectl(['get','clusterrole','system:kubelet-api-admin','-o','json'],sensitive=True).stdout)
  canonical=lambda rules:{json.dumps({key:sorted(value) for key,value in rule.items()},sort_keys=True) for rule in rules}
  need(not role.get('aggregationRule') and canonical(role['rules'])==canonical(upstream_kubelet_role_rules()),'builtin_kubelet_role_changed')
  need(not self.kubectl(['get','clusterrolebinding',expected['metadata']['name'],'--ignore-not-found','-o','json'],sensitive=True).stdout.strip(),'upstream_kubelet_binding_must_be_absent')
  pod=json.loads(self.kubectl(['get','pod','kube-apiserver-nebula-control-'+self.run_id,'-n','kube-system','-o','json'],sensitive=True).stdout);command=pod['spec']['containers'][0]['command']
  need(all(flag in command for flag in ['--kubelet-client-certificate=/etc/kubernetes/pki/apiserver-kubelet-client.crt','--kubelet-client-key=/etc/kubernetes/pki/apiserver-kubelet-client.key']),'actual_apiserver_kubelet_client_flags_changed')
  certificate=Path('/etc/kubernetes/pki/apiserver-kubelet-client.crt');cert_record=self.m.file_snapshot(certificate)
  subject=self.run(['openssl','x509','-in',str(certificate),'-noout','-subject','-nameopt','RFC2253'],'verify-only-public-apiserver-client-subject',sensitive=True).stdout.decode().strip()
  need(subject=='subject=CN=kube-apiserver-kubelet-client','unexpected_apiserver_client_certificate_identity')
  self.run(['openssl','verify','-CAfile','/etc/kubernetes/pki/ca.crt',str(certificate)],'verify-public-apiserver-client-own-ca',sensitive=True)
  config=Path('/var/lib/kubelet/config.yaml');config_record=self.m.file_snapshot(config)
  with self.m.verified_fd(config,config_record['sha256']) as fd:config_raw=os.read(fd,1024*1024)
  need(len(config_raw)<1024*1024 and kubelet_auth_config_secure(config_raw.decode()),'actual_kubelet_authentication_or_authorization_changed')
  pid=int(self.run(['systemctl','show','kubelet.service','--property=MainPID','--value'],'verify-owned-kubelet-authority-process',sensitive=True).stdout.strip());need(pid>1 and os.readlink('/proc/'+str(pid)+'/exe')=='/usr/bin/kubelet','unexpected_kubelet_process')
  process=Path('/proc')/str(pid);start=(process/'stat').read_text().rsplit(') ',1)[1].split()[19];args=[v.decode() for v in (process/'cmdline').read_bytes().split(b'\0') if v]
  need('--config=/var/lib/kubelet/config.yaml' in args and not any(a.startswith(prefix) for a in args for prefix in ['--anonymous-auth','--authorization-mode','--client-ca-file','--authentication-token-webhook']),'kubelet_authentication_flags_changed')
  tokens=self.kubectl(['get','secrets','-n','kube-system','--field-selector','type=bootstrap.kubernetes.io/token','-o','name'],sensitive=True).stdout;need(not tokens.strip(),'bootstrap_tokens_should_not_exist')
  before=self.kubectl(['auth','can-i','create','nodes','--subresource=proxy','--as=kube-apiserver-kubelet-client'],sensitive=True,check=False);need(before.returncode==1 and before.stdout.strip()==b'no','unexpected_prior_kubelet_client_authority')
  self.guard();need(self.m.file_snapshot(certificate)==cert_record and self.m.file_snapshot(config)==config_record and (process/'stat').read_text().rsplit(') ',1)[1].split()[19]==start,'kubelet_authority_precondition_changed')
  audit=Path(tempfile.mkdtemp(prefix='upstream-kubelet-authority-',dir=self.work));self.m.private_dir(audit);self.state['directories'][str(audit)]=dir_identity(audit);self.m.write_exclusive(audit/'before-cluster-state.private',self.expected_control[1]);self.m.write_exclusive(audit/'verified-role.private',json.dumps(role,sort_keys=True,indent=2).encode())
  self.state['upstream_kubelet_authority']={'status':'creating','role_uid':role['metadata']['uid'],'private_receipt':str(audit)};self.persist()
  need(not self.kubectl(['get','clusterrolebinding',expected['metadata']['name'],'--ignore-not-found','-o','json'],sensitive=True).stdout.strip(),'upstream_kubelet_binding_appeared')
  created=json.loads(self.kubectl(['create','-f','-','-o','json'],input_bytes=json.dumps(expected).encode(),sensitive=True).stdout);owned_uid=created['metadata']['uid'];require_upstream_binding(created,expected,owned_uid)
  self.m.write_exclusive(audit/'created-binding.private',json.dumps(created,sort_keys=True,indent=2).encode())
  fresh=json.loads(self.kubectl(['get','clusterrolebinding',expected['metadata']['name'],'-o','json'],sensitive=True).stdout);require_upstream_binding(fresh,expected,owned_uid)
  deadline=time.monotonic()+10
  def remaining():
   left=deadline-time.monotonic();need(left>0,'restored_kubelet_client_authority_not_effective');return min(2,left)
  def retained_authority():
   bound=json.loads(self.kubectl(['get','clusterrolebinding',expected['metadata']['name'],'-o','json'],sensitive=True,timeout=remaining()).stdout);require_upstream_binding(bound,expected,owned_uid)
   retained_role=json.loads(self.kubectl(['get','clusterrole','system:kubelet-api-admin','-o','json'],sensitive=True,timeout=remaining()).stdout)
   need(retained_role['metadata']['uid']==role['metadata']['uid'] and canonical(retained_role['rules'])==canonical(role['rules']),'builtin_kubelet_role_changed')
   need(self.m.file_snapshot(certificate)==cert_record and self.m.file_snapshot(config)==config_record and (process/'stat').read_text().rsplit(') ',1)[1].split()[19]==start,'kubelet_authority_postcondition_changed')
  while True:
   retained_authority()
   after=self.kubectl(['auth','can-i','create','nodes','--subresource=proxy','--as=kube-apiserver-kubelet-client'],sensitive=True,check=False,timeout=remaining())
   if after.returncode==0 and after.stdout.strip()==b'yes':retained_authority();break
   need(after.returncode==1 and after.stdout.strip()==b'no','unexpected_kubelet_client_authorization_response')
   left=deadline-time.monotonic();need(left>0,'restored_kubelet_client_authority_not_effective');time.sleep(min(0.25,left))
  current_role=json.loads(self.kubectl(['get','clusterrole','system:kubelet-api-admin','-o','json'],sensitive=True).stdout);need(current_role['metadata']['uid']==role['metadata']['uid'] and canonical(current_role['rules'])==canonical(role['rules']),'builtin_kubelet_role_changed')
  need(not self.kubectl(['get','secrets','-n','kube-system','--field-selector','type=bootstrap.kubernetes.io/token','-o','name'],sensitive=True).stdout.strip(),'bootstrap_tokens_should_not_exist')
  self.guard();need(self.m.file_snapshot(certificate)==cert_record and self.m.file_snapshot(config)==config_record and (process/'stat').read_text().rsplit(') ',1)[1].split()[19]==start,'kubelet_authority_postcondition_changed')
  self.state['upstream_kubelet_authority'].update(status='ready',binding_uid=owned_uid);self.persist()
 def repair_probe_capabilities(self):
  need(self.state['phase']=='smoke_started' and 'probe_capability_repair' not in self.state and not self.state.get('smoke_progress') and not self.state.get('acceptance') and not self.state.get('validation_delete_requested'),'only_owned_initial_probe_failure_may_repair')
  self.guard();self.verify_images();ns,namespace=self.validation_namespace();node='nebula-control-'+self.run_id
  expected=validation_objects(ns,self.images['registry.k8s.io/coredns/coredns:v1.14.6']['immutable_image']);probes=[x for x in expected if x['kind']=='Pod'];others=[x for x in expected if x['kind']!='Pod']
  needed={x['kind']+'/'+x['metadata']['name'] for x in expected};need(set(self.state['validation_objects'])==needed,'probe_repair_object_inventory_changed')
  original_map=dict(self.state['validation_objects']);retained={}
  def preserve_others():
   self.validation_namespace()
   for obj in others:
    key=obj['kind']+'/'+obj['metadata']['name'];need(self.state['validation_objects'].get(key)==original_map[key],'probe_repair_other_object_mapping_changed')
    current=json.loads(self.kubectl(['get',obj['kind'],obj['metadata']['name'],'-n',ns,'-o','json'],sensitive=True).stdout)
    need(current['metadata']['uid']==original_map[key] and specified_fields_match(current,obj),'probe_repair_other_object_changed')
  preserve_others()
  for desired in probes:
   name=desired['metadata']['name'];key='Pod/'+name;previous=json.loads(json.dumps(desired));previous['spec']['containers'][0]['securityContext']['capabilities'].pop('add')
   pod=json.loads(self.kubectl(['get','pod',name,'-n',ns,'-o','json'],sensitive=True).stdout);require_owned_probe(pod,previous,original_map[key],node)
   statuses=pod['status'].get('containerStatuses',[]);need(len(statuses)==1 and statuses[0].get('containerID','').startswith('containerd://'),'probe_repair_container_identity_missing')
   cid=statuses[0]['containerID'].split('://',1)[1];need(re.fullmatch('[a-f0-9]{64}',cid),'probe_repair_container_id_invalid')
   cri=json.loads(self.run(['crictl','--runtime-endpoint',CRI,'inspect',cid],'only-owned-probe-repair-proof',sensitive=True).stdout)
   need(cri['status']['labels'].get('io.kubernetes.pod.uid')==pod['metadata']['uid'] and cri['status'].get('state')=='CONTAINER_EXITED' and cri['status'].get('exitCode')==255,'probe_repair_failure_identity_changed')
   caps=cri['info'].get('runtimeSpec',{}).get('process',{}).get('capabilities',{})
   need(all('CAP_NET_BIND_SERVICE' not in (v or []) and 'NET_BIND_SERVICE' not in (v or []) for v in caps.values()),'probe_repair_capability_already_present')
   logs=self.run(['crictl','--runtime-endpoint',CRI,'logs',cid],'only-owned-probe-repair-log-proof',sensitive=True);output=(logs.stdout+b'\n'+logs.stderr).lower()
   need(all(x in output for x in [b'exec',b'/coredns',b'operation not permitted']),'probe_repair_exact_exec_failure_required')
   retained[name]={'pod':pod,'previous_expected':previous,'desired':desired,'uid':original_map[key]}
  self.guard();preserve_others()
  audit=Path(tempfile.mkdtemp(prefix='probe-capability-repair-',dir=self.work));self.m.private_dir(audit);self.state['directories'][str(audit)]=dir_identity(audit)
  self.m.write_exclusive(audit/'before-cluster-state.private',self.expected_control[1]);self.m.write_exclusive(audit/'before-probe-objects.private',json.dumps(retained,sort_keys=True,indent=2).encode())
  self.state['probe_capability_repair']={'status':'started','namespace_uid':namespace['metadata']['uid'],'old_pod_uids':{k:v['uid'] for k,v in retained.items()},'new_pod_uids':{},'private_receipt':str(audit)};self.persist()
  for name,known in retained.items():
   self.guard();preserve_others();current=json.loads(self.kubectl(['get','pod',name,'-n',ns,'-o','json'],sensitive=True).stdout);require_owned_probe(current,known['previous_expected'],known['uid'],node)
   options={'apiVersion':'v1','kind':'DeleteOptions','preconditions':{'uid':known['uid'],'resourceVersion':current['metadata']['resourceVersion']},'propagationPolicy':'Foreground'}
   self.kubectl(['delete','--raw','/api/v1/namespaces/'+ns+'/pods/'+name,'-f','-'],input_bytes=json.dumps(options).encode(),sensitive=True)
   deadline=time.monotonic()+75
   while True:
    value=self.kubectl(['get','pod',name,'-n',ns,'--ignore-not-found','-o','json'],sensitive=True).stdout
    if not value.strip():break
    require_owned_probe(json.loads(value),known['previous_expected'],known['uid'],node);need(time.monotonic()<deadline,'owned_probe_deletion_pending');time.sleep(1)
   need(self.state['validation_objects']['Pod/'+name]==known['uid'],'probe_repair_old_mapping_changed');del self.state['validation_objects']['Pod/'+name];self.persist()
   created=json.loads(self.kubectl(['create','-f','-','-o','json'],input_bytes=json.dumps(known['desired']).encode(),sensitive=True).stdout);new_uid=created['metadata']['uid'];need(new_uid!=known['uid'],'probe_repair_new_uid_required');require_owned_probe(created,known['desired'],new_uid,node)
   fresh=json.loads(self.kubectl(['get','pod',name,'-n',ns,'-o','json'],sensitive=True).stdout);require_owned_probe(fresh,known['desired'],new_uid,node)
   self.m.write_exclusive(audit/(name+'-created.private'),json.dumps(created,sort_keys=True,indent=2).encode())
   self.state['validation_objects']['Pod/'+name]=new_uid;self.state['probe_capability_repair']['new_pod_uids'][name]=new_uid;self.persist();preserve_others()
  self.kubectl(['wait','--for=condition=Ready','pod/probe-client','pod/probe-server','-n',ns,'--timeout=120s'],timeout=140)
  for name,known in retained.items():
   pod=json.loads(self.kubectl(['get','pod',name,'-n',ns,'-o','json'],sensitive=True).stdout);require_owned_probe(pod,known['desired'],self.state['probe_capability_repair']['new_pod_uids'][name],node)
   need(all(v.get('ready') is True for v in pod['status'].get('containerStatuses',[])) and bool(pod['status'].get('containerStatuses')),'corrected_owned_probe_not_ready')
  self.guard();preserve_others();self.state['probe_capability_repair']['status']='ready';self.persist()
 def smoke(self):
  if self.state['phase']=='smoke_cleanup':self.cleanup_validation();return
  need(self.state['phase'] in ['cni_ready','smoke_started'],'smoke_phase_order');self.guard();self.verify_init();self.verify_images()
  name='nebula-control-'+self.run_id;self.kubectl(['wait','--for=condition=Ready','node/'+name,'--timeout=60s'],timeout=75)
  ns='nebula-validate-'+self.run_id
  if 'validation_namespace_uid' not in self.state:
   obj={'apiVersion':'v1','kind':'Namespace','metadata':{'name':ns,'labels':{'parallax.link/bootstrap':self.run_id}}}
   created=json.loads(self.kubectl(['create','-f','-','-o','json'],input_bytes=json.dumps(obj).encode(),sensitive=True).stdout)
   self.state['validation_namespace_uid']=created['metadata']['uid'];self.state['phase']='smoke_started';self.persist()
  self.validation_namespace();image=self.images['registry.k8s.io/coredns/coredns:v1.14.6']['immutable_image']
  for obj in validation_objects(ns,image):self.create_validation(obj)
  self.kubectl(['wait','--for=condition=Ready','pod/probe-client','pod/probe-server','-n',ns,'--timeout=120s'],timeout=140)
  service=json.loads(self.kubectl(['get','service','probe-dns','-n',ns,'-o','json'],sensitive=True).stdout)
  need(service['metadata']['uid']==self.state['validation_objects']['Service/probe-dns'],'probe_service_identity_changed')
  service_ip=service['spec']['clusterIP'];need(ipaddress.ip_address(service_ip) in ipaddress.ip_network(SERVICE_CIDR),'probe_service_outside_cluster_cidr')
  cluster_dns=json.loads(self.kubectl(['get','service','kube-dns','-n','kube-system','-o','json'],sensitive=True).stdout)['spec']['clusterIP']
  default_api=json.loads(self.kubectl(['get','service','kubernetes','-n','default','-o','json'],sensitive=True).stdout)['spec']['clusterIP']
  progress=self.state.setdefault('smoke_progress',{})
  if not progress.get('baseline_dns'):
   need(self.await_dns(service_ip,'nebula.test','192.0.2.73'),'pod_to_service_dns_probe_failed')
   need(self.await_dns(cluster_dns,'kubernetes.default.svc.cluster.local',default_api),'actual_cluster_dns_probe_failed')
   progress['baseline_dns']=True;self.persist()
  deny=network_policy(ns,False);self.create_validation(deny)
  if not progress.get('deny_enforced'):
   deadline=time.monotonic()+40;consecutive=0
   while time.monotonic()<deadline and consecutive<3:
    consecutive=0 if self.dns_probe(service_ip,'nebula.test','192.0.2.73') else consecutive+1
    if consecutive<3:time.sleep(1)
   need(consecutive==3,'network_policy_default_deny_not_enforced');progress['deny_enforced']=True;self.persist()
  allow=network_policy(ns,True);self.create_validation(allow)
  if not progress.get('allow_enforced'):
   deadline=time.monotonic()+40;allowed=False
   while time.monotonic()<deadline:
    if self.dns_probe(service_ip,'nebula.test','192.0.2.73'):allowed=True;break
    time.sleep(1)
   need(allowed,'network_policy_scoped_allow_not_enforced');progress['allow_enforced']=True;self.persist()
  forbidden=validation_objects(ns,image)[1];forbidden['metadata']['name']='must-be-denied';forbidden['spec']['hostPID']=True
  result=self.kubectl(['create','--dry-run=server','-f','-','-o','json'],input_bytes=json.dumps(forbidden).encode(),sensitive=True,check=False)
  need(result.returncode!=0 and b'violates PodSecurity' in result.stderr and b'restricted' in result.stderr,'restricted_pod_security_not_enforced')
  canary={'apiVersion':'v1','kind':'Secret','metadata':{'name':'encryption-canary','namespace':ns},'type':'Opaque','stringData':{'canary':'nebula-foundation-synthetic-canary'}}
  self.create_validation(canary)
  value=self.kubectl(['exec','-n','kube-system','etcd-'+name,'--','etcdctl','--endpoints=https://127.0.0.1:2379','--cacert=/etc/kubernetes/pki/etcd/ca.crt','--cert=/etc/kubernetes/pki/etcd/healthcheck-client.crt','--key=/etc/kubernetes/pki/etcd/healthcheck-client.key','get','/registry/secrets/'+ns+'/encryption-canary','--print-value-only'],sensitive=True).stdout
  need(value.startswith(b'k8s:enc:secretbox:v1:') and b'nebula-foundation-synthetic-canary' not in value,'actual_secret_at_rest_encryption_failed')
  self.api_security_checks()
  self.state['phase']='smoke_cleanup';self.state['acceptance']={'private_single_node_api':True,'node_ready':True,'locked_control_plane_and_addons':True,'calico_ready':True,'pod_to_service_network':True,'cluster_dns':True,'network_policy_deny_and_scoped_allow':True,'restricted_pod_security':True,'secretbox_encryption_at_rest':True,'metadata_audit_active':True,'control_plane_taint_retained':True,'no_bootstrap_join_token':True}
  self.persist();self.cleanup_validation()
 def cleanup_validation(self):
  need(self.state['phase']=='smoke_cleanup' and all(self.state['acceptance'].values()),'completed_owned_smoke_required')
  self.guard();ns='nebula-validate-'+self.run_id
  result=self.kubectl(['get','namespace',ns,'--ignore-not-found','-o','json'],sensitive=True).stdout
  if result.strip():
   _,current=self.validation_namespace()
   options={'apiVersion':'v1','kind':'DeleteOptions','preconditions':{'uid':current['metadata']['uid'],'resourceVersion':current['metadata']['resourceVersion']},'propagationPolicy':'Foreground'}
   self.state['validation_delete_requested']=True;self.persist()
   self.kubectl(['delete','--raw','/api/v1/namespaces/'+ns,'-f','-'],input_bytes=json.dumps(options).encode(),sensitive=True)
   deadline=time.monotonic()+90
   while time.monotonic()<deadline:
    result=self.kubectl(['get','namespace',ns,'--ignore-not-found','-o','json'],sensitive=True).stdout
    if not result.strip():break
    need(json.loads(result)['metadata']['uid']==self.state['validation_namespace_uid'],'validation_namespace_changed_during_delete');time.sleep(1)
   need(not result.strip(),'owned_validation_namespace_deletion_pending')
  else:need(self.state.get('validation_delete_requested') is True,'validation_namespace_disappeared_before_owned_delete')
  self.state['validation_namespace_deleted']=True;self.state['acceptance']['validation_namespace_cleaned']=True;self.state['phase']='accepted';self.persist()
def dispatch_phase(job,phase,execute=False,recovery_diagnostic=None,module_baseline=None):
 allowed=['check','stage','pull','recover-prephase','repair-probes','kubelet-authority','complete-kubelet-authority','init','verify-init','cni','smoke']
 need(phase in allowed,'unsupported_cluster_phase')
 need(phase in ['check','verify-init'] or execute is True,'explicit_phase_execution_required')
 require_context(getattr(job,'context',None),'guest')
 if phase=='check':return job.guard(routes=job.state['phase'] in ['not_started','staged','images_ready'])
 if phase=='recover-prephase':
  need(recovery_diagnostic is not None and module_baseline is not None,'explicit_recovery_evidence_required')
  return job.recover_prephase_failure(recovery_diagnostic,module_baseline)
 if phase=='repair-probes':return job.repair_probe_capabilities()
 if phase=='kubelet-authority':return job.restore_kubelet_authority()
 if phase=='complete-kubelet-authority':return job.complete_kubelet_authority()
 return getattr(job,{'verify-init':'verify_init'}.get(phase,phase))()

def run_phase(context,expected_uuid,run_id,address,phase,execute=False,recovery_diagnostic=None,module_baseline=None):
 allowed=['check','stage','pull','recover-prephase','repair-probes','kubelet-authority','complete-kubelet-authority','init','verify-init','cni','smoke']
 need(phase in allowed,'unsupported_cluster_phase')
 need(phase in ['check','verify-init'] or execute is True,'explicit_phase_execution_required')
 context=require_context(context,'guest')
 job=Cluster(expected_uuid,run_id,address,phase,context=context)
 lock=job.base/'cluster-operation.lock';fd=os.open(lock,os.O_CREAT|os.O_RDWR|os.O_NOFOLLOW,0o600)
 try:
  held=os.fstat(fd);need(stat.S_ISREG(held.st_mode) and held.st_uid==0 and held.st_nlink==1 and stat.S_IMODE(held.st_mode)==0o600,'unsafe_cluster_lock');fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
  fields=lambda st:tuple(getattr(st,k)for k in ['st_dev','st_ino','st_mode','st_uid','st_gid','st_nlink','st_size','st_mtime_ns','st_ctime_ns'])
  job.external_guard=lambda:need(fields(os.fstat(fd))==fields(held)==fields(lock.lstat()),'cluster_lock_replaced')
  job.external_guard();return dispatch_phase(job,phase,execute,recovery_diagnostic,module_baseline)
 except BaseException:
  job.m.write_exclusive((job.work if job.work.exists()else job.base)/('manual-review-'+os.urandom(5).hex()+'.json'),json.dumps({'status':'manual_review_required','phase':phase,'automatic_reset_or_key_regeneration':False}).encode());raise
 finally:os.close(fd)

def main():raise Refused('source_api_only_no_public_installer')
if __name__=='__main__':
 try:main()
 except Refused as e:print(json.dumps({'status':'refused','reason':str(e)}),file=sys.stderr);raise SystemExit(1)

import ast,base64,copy,hashlib,io,json,os,shutil,socket,struct,subprocess,sys,tarfile,tempfile,types,unittest,uuid
from pathlib import Path
from unittest.mock import patch,MagicMock
from tests.support import bundle,load_module,context_fixture
m=load_module('guest/cluster')
b=load_module('guest/bootstrap')
class PolicyTests(unittest.TestCase):
 def test_private_api_no_join_token_retained_taint_and_fixed_runtime(self):
  docs=m.init_documents('nebula-control-0123456789ab','192.168.240.23',Path('/private/cluster'));init,cluster,kubelet=docs
  self.assertEqual(init['skipPhases'],['bootstrap-token','show-join-command']);self.assertEqual(init['bootstrapTokens'],[]);self.assertEqual(init['nodeRegistration']['imagePullPolicy'],'Never');self.assertEqual(init['nodeRegistration']['criSocket'],m.CRI)
  self.assertEqual(init['nodeRegistration']['taints'],[{'key':'node-role.kubernetes.io/control-plane','effect':'NoSchedule'}])
  self.assertEqual(cluster['kubernetesVersion'],'v1.37.1');self.assertEqual(cluster['controlPlaneEndpoint'],'192.168.240.23:6443')
  args={x['name']:x['value'] for x in cluster['apiServer']['extraArgs']}
  self.assertEqual(args['bind-address'],'192.168.240.23');self.assertEqual(args['audit-log-maxsize'],'20')
  self.assertTrue(cluster['apiServer']['extraVolumes'][0]['readOnly']);self.assertFalse(cluster['apiServer']['extraVolumes'][1]['readOnly'])
  self.assertFalse(kubelet['authentication']['anonymous']['enabled'])
  for addr in ['8.8.8.8','127.0.0.1','0.0.0.0','::1']:
   with self.subTest(addr=addr),self.assertRaises(m.Refused):m.init_documents('owned',addr,Path('/private'))
 def test_encryption_key_is_32_bytes_local_and_metadata_audit_has_no_body_level(self):
  key=bytes(range(32));self.assertEqual(len(key),32)
  policy=m.encryption_policy(key);providers=policy['resources'][0]['providers']
  self.assertEqual(base64.b64decode(providers[0]['secretbox']['keys'][0]['secret']),key);self.assertIn('identity',providers[1])
  self.assertEqual(m.audit_policy()['rules'],[{'level':'Metadata'}]);self.assertTrue(m.audit_policy()['omitManagedFields'])
  with self.assertRaises(m.Refused):m.encryption_policy(b'bad')
 def test_restricted_defaults_only_exempt_required_system_namespace(self):
  conf=m.admission_policy()['plugins'][0]['configuration']
  self.assertEqual(conf['exemptions'],{'usernames':[],'runtimeClasses':[],'namespaces':['kube-system']})
  for mode in ['enforce','audit','warn']:self.assertEqual(conf['defaults'][mode],'restricted');self.assertEqual(conf['defaults'][mode+'-version'],'v1.37')
 def test_validation_pods_reuse_pinned_image_are_restricted_and_have_explicit_toleration(self):
  image='registry.k8s.io/coredns/coredns@sha256:'+'a'*64;objs=m.validation_objects('nebula-validate-0123456789ab',image)
  pods=[x for x in objs if x['kind']=='Pod'];self.assertEqual(len(pods),2)
  for pod in pods:
   self.assertFalse(pod['spec']['automountServiceAccountToken']);self.assertTrue(pod['spec']['securityContext']['runAsNonRoot']);self.assertEqual(pod['spec']['securityContext']['seccompProfile']['type'],'RuntimeDefault')
   container=pod['spec']['containers'][0];self.assertEqual(container['image'],image);self.assertEqual(container['imagePullPolicy'],'Never');self.assertEqual(container['securityContext']['capabilities'],{'drop':['ALL'],'add':['NET_BIND_SERVICE']});self.assertFalse(container['securityContext']['allowPrivilegeEscalation'])
   self.assertEqual(pod['spec']['tolerations'][0]['key'],'node-role.kubernetes.io/control-plane')
  self.assertEqual(m.network_policy('owned',False)['spec']['egress'],[])
  allow=m.network_policy('owned',True);self.assertEqual(allow['spec']['egress'][0]['to'],[{'podSelector':{'matchLabels':{'role':'server'}}}])
class ImageTests(unittest.TestCase):
 def test_exact_public_image_lock_and_schema(self):
  raw=bundle().bytes('locks/kubernetes-v1.37.1-linux-amd64.json');self.assertEqual(hashlib.sha256(raw).hexdigest(),m.IMAGE_LOCK_SHA);images=m.lock_images(raw);self.assertEqual(len(images),7)
  for kind in ['arch','tag','digest','duplicate']:
   bad=json.loads(raw)
   if kind=='arch':bad['architecture']='arm64'
   elif kind=='tag':bad['images'][0]['image']='registry.k8s.io/kube-apiserver:latest'
   elif kind=='digest':bad['images'][0]['index_digest']='sha256:'+'0'*64
   else:bad['images'][1]=copy.deepcopy(bad['images'][0])
   with self.subTest(kind=kind),self.assertRaises(m.Refused):m.lock_images(json.dumps(bad).encode())
 def test_local_content_digest_is_recomputed(self):
  j=object.__new__(m.Cluster);j.context=context_fixture(role='guest');raw=b'{"architecture":"amd64"}';d='sha256:'+hashlib.sha256(raw).hexdigest()
  j.run=lambda *a,**k:subprocess.CompletedProcess([],0,raw,b'')
  self.assertEqual(j.local_content(d),{'architecture':'amd64'})
  with self.assertRaises(m.Refused):j.local_content('sha256:'+'0'*64)
 def test_image_chain_platform_and_reference_are_exact(self):
  j=object.__new__(m.Cluster);j.context=context_fixture(role='guest');index='sha256:'+'a'*64;manifest='sha256:'+'b'*64;config='sha256:'+'c'*64;ref='registry.k8s.io/owned@'+index
  payload={index:{'manifests':[{'digest':manifest,'platform':{'os':'linux','architecture':'amd64'}}]},manifest:{'config':{'digest':config},'layers':[{'digest':'sha256:'+'d'*64}]},config:{'os':'linux','architecture':'amd64'}}
  j.local_content=lambda d:payload[d];j.alias_target=lambda n:index
  expected={'linux_amd64_manifest_digest':manifest,'config_digest':config,'layer_digests':['sha256:'+'d'*64]}
  self.assertEqual(j.verify_local_image(ref,expected)['config'],config)
  payload[config]['architecture']='arm64'
  with self.assertRaises(m.Refused):j.verify_local_image(ref,expected)
  payload[config]['architecture']='amd64';j.alias_target=lambda n:'sha256:'+'e'*64
  with self.assertRaises(m.Refused):j.verify_local_image(ref,expected)
 def test_init_cannot_repeat_an_owned_partial_attempt(self):
  j=object.__new__(m.Cluster);j.context=context_fixture(role='guest');j.state={'phase':'init_started'}
  with self.assertRaisesRegex(m.Refused,'init_once_images_ready_or_reviewed_recovery'):j.init()
class CustodyTests(unittest.TestCase):
 def test_exclusive_directory_does_not_replace_foreign_even_empty(self):
  with tempfile.TemporaryDirectory(prefix='nebula-init-test-') as d:
   root=Path(d);p=root/'new';record=m.exclusive_dir(p);self.assertEqual(m.dir_identity(p),record)
   foreign=root/'foreign';foreign.mkdir(mode=0o700);(foreign/'marker').write_bytes(b'public foreign fixture')
   with self.assertRaises(m.Refused):m.exclusive_dir(foreign)
   self.assertEqual((foreign/'marker').read_bytes(),b'public foreign fixture')
 def test_source_symlink_and_invalid_run_id_refused_before_source_read(self):
  # Final dependency API never accepts source paths, including dangling links.
  with tempfile.TemporaryDirectory(prefix='nebula-init-test-')as d:
   root=Path(d);actual=root/'source';actual.write_bytes(b'public fixture');actual.chmod(0o600);linked=root/'linked';linked.symlink_to(actual)
   with patch.object(m.os,'open')as opened:
    with self.assertRaises(RuntimeError):m.load_bootstrap(linked)
    opened.assert_not_called()
  context=context_fixture(role='guest')
  with patch.object(m,'load_bootstrap')as load,self.assertRaises(m.Refused):m.Cluster(context.inputs['expected_guest_uuid'],'../../foreign','192.168.240.23','stage',context=context)
  load.assert_not_called()
 def job(self,root):
  j=object.__new__(m.Cluster);j.context=context_fixture(role='guest');j.m=b;j.work=root;j.state_path=root/'state.json';j.expected_control=None;j.state={'phase':'stage_started','files':{},'directories':{},'images':{}}
  def guard():m.need(j.control()==j.expected_control,'cluster_control_state_changed')
  j.guard=guard;return j
 def test_private_control_cas_never_overwrites_foreign_replacement(self):
  with tempfile.TemporaryDirectory(prefix='nebula-init-test-') as d:
   root=Path(d);j=self.job(root);j.persist();j.state['phase']='staged';j.persist();other=root/'foreign';b.write_exclusive(other,b'FOREIGN CONTROL');os.replace(other,j.state_path)
   inode=j.state_path.stat().st_ino
   with self.assertRaisesRegex(m.Refused,'control_state_changed'):j.persist()
   self.assertEqual(j.state_path.read_bytes(),b'FOREIGN CONTROL');self.assertEqual(j.state_path.stat().st_ino,inode)
 def test_known_encryption_file_resume_does_not_regenerate_and_foreign_path_is_refused(self):
  with tempfile.TemporaryDirectory(prefix='nebula-init-test-') as d:
   root=Path(d);j=self.job(root);j.persist();p=root/'encryption';calls=[]
   j.own_file(p,lambda:(calls.append('created') or b'public fixture encryption'));j.own_file(p,lambda:(_ for _ in ()).throw(AssertionError('regenerated')))
   self.assertEqual(calls,['created'])
   other=root/'foreign-config';other.write_bytes(b'foreign');other.chmod(0o600)
   with self.assertRaises(m.Refused):j.own_file(other,lambda:b'ours')
   self.assertEqual(other.read_bytes(),b'foreign')
 def test_same_inode_postpublication_edit_is_never_adopted_initial_or_replacement(self):
  for kind in ['initial','replacement']:
   with self.subTest(kind=kind),tempfile.TemporaryDirectory(prefix='nebula-init-test-') as d:
    root=Path(d);j=self.job(root)
    if kind=='replacement':j.persist();j.state['phase']='staged'
    before=j.expected_control;raw=json.dumps(j.state,sort_keys=True,indent=2).encode();foreign=b'F'*len(raw);seen={}
    operation=m.os.link if kind=='initial' else m.os.replace
    def race(source,target,*a,**kw):
     result=operation(source,target,*a,**kw);target=Path(target);seen['inode']=target.stat().st_ino;target.write_bytes(foreign);return result
    name='link' if kind=='initial' else 'replace'
    with patch.object(m.os,name,side_effect=race),self.assertRaisesRegex(m.Refused,'postimage_unknown'):j.persist()
    self.assertEqual(j.state_path.stat().st_ino,seen['inode']);self.assertEqual(j.state_path.read_bytes(),foreign);self.assertEqual(j.expected_control,before)
 def test_same_inode_postpublication_permission_edit_is_preserved_not_adopted(self):
  with tempfile.TemporaryDirectory(prefix='nebula-init-test-') as d:
   root=Path(d);j=self.job(root);j.persist();before=j.expected_control;j.state['phase']='staged';replace=m.os.replace
   def race(source,target):
    result=replace(source,target);os.chmod(target,0o644);return result
   with patch.object(m.os,'replace',side_effect=race),self.assertRaisesRegex(m.Refused,'postimage_unknown'):j.persist()
   self.assertEqual(j.state_path.stat().st_mode&0o777,0o644);self.assertEqual(j.expected_control,before)
 def test_dangling_cluster_paths_refuse_stage_and_init_before_mutation(self):
  with tempfile.TemporaryDirectory(prefix='nebula-init-test-')as d:
   root=Path(d);dangling=root/'dangling';dangling.symlink_to(root/'absent');self.assertFalse(dangling.exists());self.assertTrue(os.path.lexists(dangling))
   targets=['/etc/kubernetes/admin.conf','/etc/kubernetes/pki','/var/lib/etcd/member'];original=m.os.path.lexists
   context=context_fixture(role='guest');run_id=context.inputs['run_id'];address=context.inputs['api_address'];work=root/'synthetic-cluster';work.mkdir(mode=0o700)
   config=work/'kubeadm.yaml';config_raw=m.serialize_documents(m.init_documents('nebula-control-'+run_id,address,work));b.write_exclusive(config,config_raw)
   for phase in ['stage','init']:
    for target in targets:
     with self.subTest(phase=phase,target=target):
      j=object.__new__(m.Cluster);j.context=context;j.m=b;j.work=work;j.run_id=run_id;j.address=address;j.state={'phase':'staged'if phase=='stage'else'images_ready'};j.guard=lambda **k:None;j.verify_images=lambda:None;j.persist=MagicMock();j.run=MagicMock();j.own_dir=MagicMock()
      def exists(path):
       value=str(path)
       return original(dangling)if value==target else(False if value in targets else original(path))
      error='existing_cluster_requires_review'if phase=='stage'else'unowned_existing_cluster_state'
      with patch.object(m.os.path,'lexists',side_effect=exists),self.assertRaisesRegex(m.Refused,error):getattr(j,phase)()
      j.persist.assert_not_called();j.run.assert_not_called();j.own_dir.assert_not_called();self.assertEqual(config.read_bytes(),config_raw)
 def test_mutating_phases_require_execute_before_any_guest_source_load(self):
  with patch.object(m,'require_context')as context,patch.object(m,'Cluster')as constructor,patch.object(m,'load_bootstrap')as load,patch.object(m.os,'open')as opened:
   for phase in ['stage','pull','recover-prephase','repair-probes','kubelet-authority','complete-kubelet-authority','init','cni','smoke']:
    with self.subTest(phase=phase),self.assertRaisesRegex(m.Refused,'explicit_phase_execution_required'):m.run_phase(None,'00000000-0000-4000-8000-000000000001','0123456789ab','192.168.240.23',phase)
   context.assert_not_called();constructor.assert_not_called();load.assert_not_called();opened.assert_not_called()
  with self.assertRaisesRegex(m.Refused,'source_api_only_no_public_installer'):m.main()
class DNSTests(unittest.TestCase):
 def execute_probe(self,mode):
  code=m.dns_client_code('10.96.1.73','nebula.test','192.0.2.73')
  class Fake:
   def settimeout(self,n):pass
   def sendto(self,packet,dest):self.packet=packet
   def recvfrom(self,n):
    if mode=='timeout':raise socket.timeout()
    question=self.packet[12:];response=self.packet[:2]+struct.pack('!HHHHH',0x8180,1,1,0,0)+question+b'\xc0\x0c'+struct.pack('!HHIH',1,1,30,4)+socket.inet_aton('192.0.2.73' if mode!='wrong' else '192.0.2.74')
    if mode=='malformed':response=b'bad'
    return response,('10.96.1.73',8053)
   def close(self):pass
  with patch.object(socket,'socket',return_value=Fake()),self.assertRaises(SystemExit) as result:exec(compile(code,'bounded-dns-fixture','exec'),{})
  return result.exception.code
 def test_actual_probe_parses_response_and_rejects_timeout_wrong_answer_and_malformed(self):
  self.assertEqual(self.execute_probe('pass'),0)
  for mode in ['timeout','wrong','malformed']:
   with self.subTest(mode=mode):self.assertEqual(self.execute_probe(mode),2)
 def test_probe_cannot_target_external_ip_arbitrary_query_or_answer(self):
  for args in [('8.8.8.8','nebula.test','192.0.2.73'),('10.96.1.73','external.example','192.0.2.73'),('10.96.1.73','nebula.test','8.8.8.8')]:
   with self.subTest(args=args),self.assertRaises(m.Refused):m.dns_client_code(*args)
class CleanupTests(unittest.TestCase):
 def test_namespace_delete_sends_exact_uid_and_resource_version_preconditions(self):
  j=object.__new__(m.Cluster);j.context=context_fixture(role='guest');j.state={'phase':'smoke_cleanup','acceptance':{'checks':True},'validation_namespace_uid':'known-uid'};j.run_id='0123456789ab';j.guard=lambda:None;j.persist=lambda:None;ns='nebula-validate-'+j.run_id;obj={'metadata':{'uid':'known-uid','resourceVersion':'123','labels':{'parallax.link/bootstrap':j.run_id}}};calls=[];get_count=0
  def api(args,**kw):
   nonlocal get_count
   calls.append((args,kw))
   if args[0]=='get':
    get_count+=1;return subprocess.CompletedProcess([],0,json.dumps(obj).encode() if get_count<=2 else b'',b'')
   if args[0]=='delete':
    body=json.loads(kw['input_bytes']);self.assertEqual(body['preconditions'],{'uid':'known-uid','resourceVersion':'123'});self.assertEqual(args[2],'/api/v1/namespaces/'+ns);return subprocess.CompletedProcess([],0,b'{}',b'')
   raise AssertionError('Unexpected API command')
  j.kubectl=api;j.cleanup_validation();self.assertEqual(j.state['phase'],'accepted');self.assertTrue(j.state['validation_namespace_deleted'])
 def test_foreign_namespace_uid_is_never_deleted(self):
  j=object.__new__(m.Cluster);j.context=context_fixture(role='guest');j.run_id='0123456789ab';j.state={'validation_namespace_uid':'known'}
  j.kubectl=lambda *a,**k:subprocess.CompletedProcess([],0,json.dumps({'metadata':{'uid':'FOREIGN','labels':{'parallax.link/bootstrap':j.run_id}}}).encode(),b'')
  with self.assertRaisesRegex(m.Refused,'identity_changed'):j.validation_namespace()
if __name__=='__main__':unittest.main(verbosity=2)


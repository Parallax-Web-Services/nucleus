import ast,copy,hashlib,importlib.util,json,os,subprocess,tempfile,unittest,io,sys,contextlib
from pathlib import Path
from unittest.mock import Mock,patch
from tests.support import load_module,context_fixture,ROOT
m=load_module('guest/cluster');b=load_module('guest/bootstrap')
def legacy_validation_objects(namespace,image):
 result=copy.deepcopy(m.validation_objects(namespace,image))
 for obj in result:
  if obj['kind']=='Pod':obj['spec']['containers'][0]['securityContext']['capabilities'].pop('add')
 return result
class LegacyFixture:
 validation_objects=staticmethod(legacy_validation_objects)
old=LegacyFixture()

class RepairTests(unittest.TestCase):
 def fixture(self,root):
  j=object.__new__(m.Cluster);j.m=b;j.work=root/'cluster';j.work.mkdir(mode=0o700);j.base=root;j.run_id='0123456789ab';j.address='192.168.240.23';j.expected_uuid='00000000-0000-4000-8000-000000000001';image='registry.k8s.io/coredns/coredns@sha256:'+'0'*64;j.images={'registry.k8s.io/coredns/coredns:v1.14.6':{'immutable_image':image}}
  ns='nebula-validate-'+j.run_id;objects={}
  for obj in old.validation_objects(ns,image):
   obj=copy.deepcopy(obj);key=obj['kind']+'/'+obj['metadata']['name'];obj['metadata'].update(uid='old-'+key,resourceVersion='1')
   if obj['kind']=='Pod':obj['spec']['nodeName']='nebula-control-'+j.run_id;obj['status']={'containerStatuses':[{'ready':False,'containerID':'containerd://'+('1' if obj['metadata']['name']=='probe-client' else '2')*64}]}
   objects[key]=obj
  namespace={'apiVersion':'v1','kind':'Namespace','metadata':{'name':ns,'uid':'owned-namespace','resourceVersion':'1','labels':{'parallax.link/bootstrap':j.run_id}}}
  j.state={'phase':'smoke_started','validation_namespace_uid':'owned-namespace','validation_objects':{k:v['metadata']['uid'] for k,v in objects.items()},'smoke_progress':{},'directories':{str(j.work):m.dir_identity(j.work)},'files':{}}
  j.expected_control=({'fixture':True},json.dumps(j.state).encode());j.guard=Mock();j.verify_images=Mock();persisted=[];deleted=[];created=[];options_seen=[];foreign_after_create=set();refuse_delete=False
  def persist():
   persisted.append(copy.deepcopy(j.state));j.expected_control=({'fixture':True},json.dumps(j.state).encode())
  j.persist=Mock(side_effect=persist)
  def result(value=None):
   return subprocess.CompletedProcess(['mock'],0,b'' if value is None else json.dumps(value).encode(),b'')
  def kubectl(args,**kwargs):
   nonlocal refuse_delete
   if args[0]=='get':
    kind=args[1].lower();name=args[2]
    if kind=='namespace':return result(copy.deepcopy(namespace))
    normal={'pod':'Pod','service':'Service','configmap':'ConfigMap'}[kind];key=normal+'/'+name
    if key not in objects:
     self.assertIn('--ignore-not-found',args);return result()
    obj=copy.deepcopy(objects[key])
    if name in foreign_after_create and obj['metadata']['uid'].startswith('new-'):obj['metadata']['uid']='FOREIGN-UID'
    return result(obj)
   if args[0]=='delete':
    self.assertEqual(args[1],'--raw');name=args[2].rsplit('/',1)[1];self.assertIn(name,['probe-client','probe-server']);self.assertEqual(args[2],'/api/v1/namespaces/'+ns+'/pods/'+name);key='Pod/'+name;opts=json.loads(kwargs['input_bytes']);options_seen.append(opts)
    self.assertEqual(opts['preconditions'],{'uid':objects[key]['metadata']['uid'],'resourceVersion':objects[key]['metadata']['resourceVersion']});self.assertEqual(opts['propagationPolicy'],'Foreground');self.assertNotIn('gracePeriodSeconds',opts)
    if refuse_delete:raise m.Refused('synthetic_resource_version_conflict')
    deleted.append(name);del objects[key];return result({})
   if args[0]=='create':
    obj=json.loads(kwargs['input_bytes']);self.assertEqual(obj['kind'],'Pod');name=obj['metadata']['name'];key='Pod/'+name;self.assertNotIn(key,objects);obj['metadata'].update(uid='new-'+name,resourceVersion='2');obj['spec']['nodeName']='nebula-control-'+j.run_id;obj['status']={'containerStatuses':[{'ready':True}]};objects[key]=copy.deepcopy(obj);created.append(name);return result(obj)
   if args[0]=='wait':return result()
   raise AssertionError(args)
  j.kubectl=Mock(side_effect=kubectl)
  def run(args,label,**kwargs):
   cid=args[-1]
   if 'inspect' in args:
    name='probe-client' if cid=='1'*64 else 'probe-server';pod=objects['Pod/'+name]
    return result({'status':{'state':'CONTAINER_EXITED','exitCode':255,'labels':{'io.kubernetes.pod.uid':pod['metadata']['uid']}},'info':{'runtimeSpec':{'process':{'capabilities':{}}}}})
   self.assertIn('logs',args);return subprocess.CompletedProcess(['mock'],0,b'',b'exec /coredns -conf /config/Corefile: operation not permitted')
  j.run=Mock(side_effect=run)
  def set_refuse():
   nonlocal refuse_delete;refuse_delete=True
  return j,objects,persisted,deleted,created,options_seen,foreign_after_create,set_refuse
 def test_only_net_bind_service_added_and_all_other_probe_hardening_preserved(self):
  image='registry.k8s.io/coredns/coredns@sha256:'+'0'*64;before=old.validation_objects('nebula-validate-test',image);after=m.validation_objects('nebula-validate-test',image)
  for obj in after:
   if obj['kind']=='Pod':
    c=obj['spec']['containers'][0]['securityContext'];self.assertEqual(c['capabilities'],{'drop':['ALL'],'add':['NET_BIND_SERVICE']});self.assertFalse(c['allowPrivilegeEscalation']);self.assertTrue(c['readOnlyRootFilesystem']);self.assertTrue(obj['spec']['securityContext']['runAsNonRoot']);self.assertEqual(obj['spec']['securityContext']['seccompProfile'],{'type':'RuntimeDefault'});c['capabilities'].pop('add')
  self.assertEqual(before,after)
  def policy(path):
   tree=ast.parse(path.read_text());return ast.dump(next(n for n in tree.body if isinstance(n,ast.FunctionDef)and n.name=='admission_policy'),include_attributes=False)
  self.assertEqual(policy(ROOT/'guest/cluster.py'),policy(ROOT/'reference/alpha-20261102/guest-cluster.py.reference'))
 def test_success_only_two_uid_rv_deletes_new_uid_adoption_others_preserved(self):
  with tempfile.TemporaryDirectory() as d:
   j,objects,persisted,deleted,created,opts,_,_=self.fixture(Path(d));others={k:copy.deepcopy(v) for k,v in objects.items() if not k.startswith('Pod/')};progress=copy.deepcopy(j.state['smoke_progress'])
   j.repair_probe_capabilities()
   self.assertEqual(deleted,['probe-client','probe-server']);self.assertEqual(created,deleted);self.assertEqual(len(opts),2)
   self.assertEqual({k:v for k,v in objects.items() if not k.startswith('Pod/')},others);self.assertEqual(j.state['smoke_progress'],progress);self.assertEqual(j.state['phase'],'smoke_started');self.assertEqual(j.state['probe_capability_repair']['status'],'ready')
   for name in deleted:self.assertEqual(j.state['validation_objects']['Pod/'+name],'new-'+name)
   self.assertTrue(any(s.get('probe_capability_repair',{}).get('status')=='started' and s['validation_objects']['Pod/probe-client']=='old-Pod/probe-client' for s in persisted))
   receipt=Path(j.state['probe_capability_repair']['private_receipt']);self.assertTrue((receipt/'before-cluster-state.private').is_file());self.assertTrue((receipt/'before-probe-objects.private').is_file())
 def test_foreign_old_uid_stops_before_any_delete(self):
  with tempfile.TemporaryDirectory() as d:
   j,objects,_,deleted,*_=self.fixture(Path(d));objects['Pod/probe-client']['metadata']['uid']='FOREIGN'
   with self.assertRaisesRegex(m.Refused,'identity_changed'):j.repair_probe_capabilities()
   self.assertFalse(deleted);self.assertNotIn('probe_capability_repair',j.state)
 def test_changed_old_spec_or_host_network_stops_before_any_delete(self):
  for mutation in ['uid','hostNetwork']:
   with tempfile.TemporaryDirectory() as d:
    j,objects,_,deleted,*_=self.fixture(Path(d))
    if mutation=='uid':objects['Pod/probe-client']['spec']['securityContext']['runAsUser']=0
    else:objects['Pod/probe-client']['spec']['hostNetwork']=True
    with self.assertRaises(m.Refused):j.repair_probe_capabilities()
    self.assertFalse(deleted)
 def test_changed_namespace_or_service_uid_stops_before_delete(self):
  with tempfile.TemporaryDirectory() as d:
   j,objects,_,deleted,*_=self.fixture(Path(d));objects['Service/probe-dns']['metadata']['uid']='FOREIGN'
   with self.assertRaises(m.Refused):j.repair_probe_capabilities()
   self.assertFalse(deleted)
 def test_namespace_uid_change_or_other_service_spec_change_refuses(self):
  for kind in ['namespace','service']:
   with tempfile.TemporaryDirectory() as d:
    j,objects,_,deleted,*_=self.fixture(Path(d))
    if kind=='namespace':j.state['validation_namespace_uid']='FOREIGN'
    else:objects['Service/probe-dns']['spec']['selector']={'role':'foreign'}
    with self.assertRaises(m.Refused):j.repair_probe_capabilities()
    self.assertFalse(deleted)
 def test_delete_resource_version_conflict_preserves_objects_and_stops(self):
  with tempfile.TemporaryDirectory() as d:
   j,objects,_,deleted,created,_,_,refuse=self.fixture(Path(d));before=copy.deepcopy(objects);refuse()
   with self.assertRaisesRegex(m.Refused,'resource_version_conflict'):j.repair_probe_capabilities()
   self.assertEqual(objects,before);self.assertFalse(deleted);self.assertFalse(created);self.assertEqual(j.state['probe_capability_repair']['status'],'started')
   with self.assertRaisesRegex(m.Refused,'initial_probe_failure'):j.repair_probe_capabilities()
 def test_extra_object_or_completed_progress_refuses(self):
  with tempfile.TemporaryDirectory() as d:
   j,_,_,deleted,*_=self.fixture(Path(d));j.state['validation_objects']['Secret/foreign']='foreign'
   with self.assertRaisesRegex(m.Refused,'inventory_changed'):j.repair_probe_capabilities()
   self.assertFalse(deleted)
  with tempfile.TemporaryDirectory() as d:
   j,_,_,deleted,*_=self.fixture(Path(d));j.state['smoke_progress']['baseline_dns']=True
   with self.assertRaisesRegex(m.Refused,'initial_probe_failure'):j.repair_probe_capabilities()
   self.assertFalse(deleted)
 def test_foreign_created_postimage_never_adopted_or_deleted(self):
  with tempfile.TemporaryDirectory() as d:
   j,objects,_,deleted,created,_,foreign,_=self.fixture(Path(d));foreign.add('probe-client')
   with self.assertRaisesRegex(m.Refused,'identity_changed'):j.repair_probe_capabilities()
   self.assertEqual(deleted,['probe-client']);self.assertEqual(created,['probe-client']);self.assertNotIn('Pod/probe-client',j.state['validation_objects']);self.assertNotIn('probe-client',j.state['probe_capability_repair']['new_pod_uids']);self.assertIn('Pod/probe-server',objects)
 def test_repair_intent_cannot_run_twice(self):
  with tempfile.TemporaryDirectory() as d:
   j,_,_,deleted,*_=self.fixture(Path(d));j.state['probe_capability_repair']={'status':'started'}
   with self.assertRaisesRegex(m.Refused,'initial_probe_failure'):j.repair_probe_capabilities()
   self.assertFalse(deleted);j.kubectl.assert_not_called()
 def test_explicit_dispatches_repair_without_init_or_smoke(self):
  job=Mock();job.context=context_fixture('guest');job.state={'phase':'smoke_started'}
  m.dispatch_phase(job,'repair-probes',execute=True)
  job.repair_probe_capabilities.assert_called_once_with();job.init.assert_not_called();job.smoke.assert_not_called()
if __name__=='__main__':unittest.main(verbosity=2)

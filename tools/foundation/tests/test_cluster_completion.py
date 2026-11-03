import ast,copy,contextlib,importlib.util,json,os,tempfile,unittest,sys,io
from pathlib import Path
from unittest.mock import Mock,patch
import subprocess,itertools
from tests.support import load_module,context_fixture,ROOT
m=load_module('guest/cluster');b=load_module('guest/bootstrap')

CONFIG='authentication:\n  anonymous:\n    enabled: false\n  webhook:\n    cacheTTL: 0s\n    enabled: true\n  x509:\n    clientCAFile: /etc/kubernetes/pki/ca.crt\nauthorization:\n  mode: Webhook\n  webhook:\n    cacheAuthorizedTTL: 5m0s\n    cacheUnauthorizedTTL: 30s\n'
class AuthorityTests(unittest.TestCase):
 def fixture(self,root):
  j=object.__new__(m.Cluster);j.m=b;j.work=root/'cluster';j.work.mkdir(mode=0o700);j.run_id='0123456789ab';j.state={'phase':'smoke_started','directories':{str(j.work):m.dir_identity(j.work)}};j.expected_control=({'fixture':True},json.dumps(j.state).encode());j.guard=Mock();j.verify_images=Mock();j.api_security_checks=Mock();j.validation_namespace=Mock()
  cert=root/'cert.crt';cert.write_bytes(b'SYNTHETIC PUBLIC CERTIFICATE');cert.chmod(0o644);config=root/'config.yaml';config.write_text(CONFIG);config.chmod(0o600);proc=root/'proc'/'99990';proc.mkdir(parents=True);(proc/'stat').write_text('99990 (kubelet) '+' '.join(['S']+['0']*18+['12345']));(proc/'cmdline').write_bytes(b'/usr/bin/kubelet\0--config=/var/lib/kubelet/config.yaml\0')
  data={'binding':None,'foreign':False,'role':{'apiVersion':'rbac.authorization.k8s.io/v1','kind':'ClusterRole','metadata':{'uid':'builtin-role','name':'system:kubelet-api-admin'},'rules':m.upstream_kubelet_role_rules()},'subject':'subject=CN=kube-apiserver-kubelet-client','prior_yes':False,'post_no':False,'post_sequence':[],'post_error':False,'mutate_during_no':None,'created':[],'persisted':[]}
  def persist():
   data['persisted'].append(copy.deepcopy(j.state));j.expected_control=({'fixture':True},json.dumps(j.state).encode())
  j.persist=Mock(side_effect=persist)
  def result(value=None,code=0,raw=False):return subprocess.CompletedProcess(['mock'],code,(value if isinstance(value,bytes) else json.dumps(value).encode()) if value is not None else b'',b'')
  def kubectl(args,**kwargs):
   if args[:2]==['get','clusterrole']:return result(copy.deepcopy(data['role']))
   if args[:2]==['get','clusterrolebinding']:
    if data['binding'] is None:return result()
    obj=copy.deepcopy(data['binding'])
    if data['foreign']:obj['metadata']['uid']='FOREIGN'
    return result(obj)
   if args[:2]==['get','pod']:return result({'spec':{'containers':[{'command':['--kubelet-client-certificate=/etc/kubernetes/pki/apiserver-kubelet-client.crt','--kubelet-client-key=/etc/kubernetes/pki/apiserver-kubelet-client.key']}]}})
   if args[:2]==['get','secrets']:return result()
   if args[:2]==['auth','can-i']:
    self.assertEqual(args,['auth','can-i','create','nodes','--subresource=proxy','--as=kube-apiserver-kubelet-client'])
    if data['binding'] is not None and data['post_error']:return result(b'UNEXPECTED RESPONSE',2)
    allowed=data['prior_yes'] if data['binding'] is None else (data['post_sequence'].pop(0) if data['post_sequence'] else not data['post_no'])
    if data['binding'] is not None and not allowed and data['mutate_during_no'] is not None:
     callback=data['mutate_during_no'];data['mutate_during_no']=None;callback()
    return result(b'yes\n' if allowed else b'no\n',0 if allowed else 1)
   if args[0]=='create':
    self.assertEqual(args,['create','-f','-','-o','json']);obj=json.loads(kwargs['input_bytes']);self.assertEqual(obj,m.upstream_kubelet_binding());self.assertEqual(j.state['upstream_kubelet_authority']['status'],'creating');j.persist.assert_called();obj['metadata'].update(uid='OWNED-NEW',resourceVersion='1');data['binding']=copy.deepcopy(obj);data['created'].append(copy.deepcopy(obj));return result(obj)
   raise AssertionError(args)
  j.kubectl=Mock(side_effect=kubectl)
  def run(args,label,**kwargs):
   if args[:2]==['openssl','x509']:return result(data['subject'].encode())
   if args[:2]==['openssl','verify']:return result(b'SYNTHETIC PUBLIC CERTIFICATE: OK\n')
   if args[0]=='systemctl':return result(b'99990\n')
   raise AssertionError(args)
  j.run=Mock(side_effect=run);real=m.Path;readlink=m.os.readlink
  def mapped(value,*args):
   if not args and value=='/etc/kubernetes/pki/apiserver-kubelet-client.crt':return cert
   if not args and value=='/var/lib/kubelet/config.yaml':return config
   if not args and value=='/proc':return root/'proc'
   return real(value,*args)
  def links(value,*args,**kwargs):
   if str(value)=='/proc/99990/exe':return '/usr/bin/kubelet'
   return readlink(value,*args,**kwargs)
  @contextlib.contextmanager
  def process_and_clock():
   with patch.object(m.os,'readlink',side_effect=links),patch.object(m.time,'sleep',return_value=None),patch.object(m.time,'monotonic',side_effect=itertools.count(0,0.1).__next__):yield
  j.state.update(credentials={},validation_namespace_uid='OWNED-NS',validation_objects={'Service/probe-dns':'SERVICE-UID'},smoke_progress={'baseline_dns':True,'deny_enforced':True,'allow_enforced':True})
  for name in ['admin.conf','super-admin.conf','ca.key']:
   path=root/name;path.write_bytes(('SYNTHETIC-'+name).encode());path.chmod(0o600);j.state['credentials'][str(path)]=m.normalize(b.file_snapshot(path,private=True))
  j.expected_control=({'fixture':True},json.dumps(j.state).encode())
  return j,data,config,proc,patch.object(m,'Path',side_effect=mapped),process_and_clock()
 def partial(self,j,data):
  data['post_error']=True
  with self.assertRaisesRegex(m.Refused,'unexpected_kubelet_client_authorization_response'):j.restore_kubelet_authority()
  self.assertEqual(j.state['upstream_kubelet_authority']['status'],'creating');self.assertNotIn('binding_uid',j.state['upstream_kubelet_authority']);self.assertEqual(len(data['created']),1)
  data['post_error']=False;j.kubectl.reset_mock()
 def test_completion_verifies_retained_uid_and_updates_only_private_ledger(self):
  with tempfile.TemporaryDirectory() as d:
   j,data,_,_,p1,p2=self.fixture(Path(d))
   with p1,p2:
    self.partial(j,data);binding=copy.deepcopy(data['binding']);j.complete_kubelet_authority()
   self.assertEqual(data['binding'],binding);self.assertEqual(len(data['created']),1);self.assertEqual(j.state['upstream_kubelet_authority']['status'],'ready');self.assertEqual(j.state['upstream_kubelet_authority']['binding_uid'],'OWNED-NEW');self.assertEqual(j.state['phase'],'smoke_started')
   self.assertFalse(any(c.args[0][0] in ['create','patch','apply','delete'] for c in j.kubectl.call_args_list))
   calls=[c for c in j.kubectl.call_args_list if c.args[0][:2]==['auth','can-i']];self.assertEqual(len(calls),1);self.assertEqual(calls[0].args[0],['auth','can-i','create','nodes','--subresource=proxy','--as=kube-apiserver-kubelet-client']);self.assertEqual(calls[0].kwargs['timeout'],20)
   proof=json.loads((Path(j.state['upstream_kubelet_authority']['private_receipt'])/'verification-only-completion.private').read_text());self.assertFalse(proof['unavailable_original_certificate_config_starttick_snapshots_compared']);self.assertTrue(proof['fresh_secure_certificate_config_process_validated'])
 def test_foreign_binding_or_changed_original_role_never_adopted(self):
  for target in ['binding','role']:
   with tempfile.TemporaryDirectory() as d:
    j,data,_,_,p1,p2=self.fixture(Path(d))
    with p1,p2:
     self.partial(j,data)
     if target=='binding':data['foreign']=True
     else:data['role']['metadata']['uid']='FOREIGN-ROLE'
     with self.assertRaises(m.Refused):j.complete_kubelet_authority()
    self.assertEqual(j.state['upstream_kubelet_authority']['status'],'creating');self.assertNotIn('binding_uid',j.state['upstream_kubelet_authority']);self.assertEqual(len(data['created']),1)
 def test_changed_saved_known_credential_or_namespace_state_refuses(self):
  for target in ['credential','namespace']:
   with tempfile.TemporaryDirectory() as d:
    j,data,_,_,p1,p2=self.fixture(Path(d))
    with p1,p2:
     self.partial(j,data)
     if target=='credential':Path(next(iter(j.state['credentials']))).write_bytes(b'FOREIGN')
     else:j.state['validation_namespace_uid']='FOREIGN'
     with self.assertRaises(m.Refused):j.complete_kubelet_authority()
    self.assertEqual(len(data['created']),1);self.assertEqual(j.state['upstream_kubelet_authority']['status'],'creating')
 def test_fresh_insecure_certificate_or_kubelet_configuration_refuses(self):
  for target in ['subject','config']:
   with tempfile.TemporaryDirectory() as d:
    j,data,config,_,p1,p2=self.fixture(Path(d))
    with p1,p2:
     self.partial(j,data)
     if target=='subject':data['subject']='subject=CN=FOREIGN,O=system:masters'
     else:config.write_text(CONFIG.replace('mode: Webhook','mode: AlwaysAllow'))
     with self.assertRaises(m.Refused):j.complete_kubelet_authority()
    self.assertEqual(len(data['created']),1);self.assertEqual(j.state['upstream_kubelet_authority']['status'],'creating')
 def test_correct_subresource_denial_stops_without_new_grant(self):
  with tempfile.TemporaryDirectory() as d:
   j,data,_,_,p1,p2=self.fixture(Path(d))
   with p1,p2:
    self.partial(j,data);data['post_no']=True
    with self.assertRaisesRegex(m.Refused,'exact_kubelet_client_proxy_authority_missing'):j.complete_kubelet_authority()
   self.assertEqual(len(data['created']),1);self.assertEqual(j.state['upstream_kubelet_authority']['status'],'creating')
 def test_retained_create_receipt_changed_during_completion_refuses(self):
  with tempfile.TemporaryDirectory() as d:
   j,data,_,_,p1,p2=self.fixture(Path(d))
   with p1,p2:
    self.partial(j,data);path=Path(j.state['upstream_kubelet_authority']['private_receipt'])/'created-binding.private';real=j.kubectl.side_effect
    def tamper(args,**kwargs):
     result=real(args,**kwargs)
     if args[:2]==['auth','can-i']:path.write_bytes(path.read_bytes()+b'\n')
     return result
    j.kubectl.side_effect=tamper
    with self.assertRaisesRegex(m.Refused,'fresh_precondition_changed'):j.complete_kubelet_authority()
   self.assertEqual(j.state['upstream_kubelet_authority']['status'],'creating');self.assertNotIn('binding_uid',j.state['upstream_kubelet_authority']);self.assertEqual(len(data['created']),1)
 def test_ready_or_unowned_partial_cannot_be_completed(self):
  with tempfile.TemporaryDirectory() as d:
   j,data,_,_,p1,p2=self.fixture(Path(d));j.state['upstream_kubelet_authority']={'status':'ready','binding_uid':'FOREIGN'}
   with p1,p2,self.assertRaisesRegex(m.Refused,'exact_owned_partial'):j.complete_kubelet_authority()
   j.kubectl.assert_not_called();self.assertFalse(data['created'])
 def test_explicit_dispatches_completion_without_creation_phase(self):
  job=Mock();job.context=context_fixture('guest');job.state={'phase':'smoke_started'}
  m.dispatch_phase(job,'complete-kubelet-authority',execute=True)
  job.complete_kubelet_authority.assert_called_once_with();job.restore_kubelet_authority.assert_not_called();job.init.assert_not_called();job.cni.assert_not_called();job.smoke.assert_not_called()
 def test_final_creation_and_completion_retain_reviewed_subresource_boundary(self):
  def method(raw,name):
   tree=ast.parse(raw);cls=next(n for n in tree.body if isinstance(n,ast.ClassDef)and n.name=='Cluster')
   return ast.get_source_segment(raw,next(n for n in cls.body if isinstance(n,ast.FunctionDef)and n.name==name))
  after=(ROOT/'guest/cluster.py').read_text();reference=(ROOT/'reference/alpha-20261102/guest-cluster.py.reference').read_text()
  self.assertEqual(method(after,'restore_kubelet_authority'),method(reference,'restore_kubelet_authority'))
  fn=method(after,'complete_kubelet_authority')
  for verb in ["['create',","['patch',","['delete',","['apply',"]:self.assertNotIn(verb,fn)
  self.assertIn("'--subresource=proxy'",method(after,'restore_kubelet_authority'))
if __name__=='__main__':unittest.main(verbosity=2)

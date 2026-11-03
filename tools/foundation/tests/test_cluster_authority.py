import ast,copy,contextlib,importlib.util,json,os,tempfile,unittest,sys,io
from pathlib import Path
from unittest.mock import Mock,patch
import subprocess
from tests.support import load_module,context_fixture,ROOT
m=load_module('guest/cluster');b=load_module('guest/bootstrap')

CONFIG='authentication:\n  anonymous:\n    enabled: false\n  webhook:\n    cacheTTL: 0s\n    enabled: true\n  x509:\n    clientCAFile: /etc/kubernetes/pki/ca.crt\nauthorization:\n  mode: Webhook\n  webhook:\n    cacheAuthorizedTTL: 5m0s\n    cacheUnauthorizedTTL: 30s\n'
class AuthorityTests(unittest.TestCase):
 def fixture(self,root):
  j=object.__new__(m.Cluster);j.m=b;j.work=root/'cluster';j.work.mkdir(mode=0o700);j.run_id='0123456789ab';j.state={'phase':'smoke_started','directories':{str(j.work):m.dir_identity(j.work)}};j.expected_control=({'fixture':True},json.dumps(j.state).encode());j.guard=Mock();j.verify_images=Mock();j.api_security_checks=Mock();j.validation_namespace=Mock()
  cert=root/'cert.crt';cert.write_bytes(b'SYNTHETIC PUBLIC CERTIFICATE');cert.chmod(0o644);config=root/'config.yaml';config.write_text(CONFIG);config.chmod(0o600);proc=root/'proc'/'99990';proc.mkdir(parents=True);(proc/'stat').write_text('99990 (kubelet) '+' '.join(['S']+['0']*18+['12345']));(proc/'cmdline').write_bytes(b'/usr/bin/kubelet\0--config=/var/lib/kubelet/config.yaml\0')
  data={'binding':None,'foreign':False,'role':{'apiVersion':'rbac.authorization.k8s.io/v1','kind':'ClusterRole','metadata':{'uid':'builtin-role','name':'system:kubelet-api-admin'},'rules':m.upstream_kubelet_role_rules()},'subject':'subject=CN=kube-apiserver-kubelet-client','prior_yes':False,'post_no':False,'created':[],'persisted':[]}
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
    self.assertEqual(args,['auth','can-i','create','nodes','--subresource=proxy','--as=kube-apiserver-kubelet-client']);allowed=data['prior_yes'] if data['binding'] is None else not data['post_no'];return result(b'yes\n' if allowed else b'no\n',0 if allowed else 1)
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
  return j,data,config,proc,patch.object(m,'Path',side_effect=mapped),patch.object(m.os,'readlink',side_effect=links)
 def test_exact_binding_is_only_upstream_named_user_and_existing_role(self):
  obj=m.upstream_kubelet_binding();self.assertEqual(obj['metadata'],{'name':'kubeadm:apiserver-kubelet-client'});self.assertEqual(obj['roleRef'],{'apiGroup':'rbac.authorization.k8s.io','kind':'ClusterRole','name':'system:kubelet-api-admin'});self.assertEqual(obj['subjects'],[{'apiGroup':'rbac.authorization.k8s.io','kind':'User','name':'kube-apiserver-kubelet-client'}])
 def test_auth_config_accepts_exact_secure_shape_rejects_weakenings_or_duplicate_blocks(self):
  self.assertTrue(m.kubelet_auth_config_secure(CONFIG))
  for bad in [CONFIG.replace('enabled: false','enabled: true'),CONFIG.replace('enabled: true','enabled: false'),CONFIG.replace('mode: Webhook','mode: AlwaysAllow'),CONFIG.replace('/etc/kubernetes/pki/ca.crt','/foreign/ca.crt'),CONFIG+'\nauthentication:\n  anonymous:\n    enabled: true\n']:
   self.assertFalse(m.kubelet_auth_config_secure(bad))
 def test_success_create_only_retained_uid_fresh_match_and_exact_authority(self):
  with tempfile.TemporaryDirectory() as d:
   j,data,config,proc,p1,p2=self.fixture(Path(d));config_before=b.file_snapshot(config)
   with p1,p2:j.restore_kubelet_authority()
   self.assertEqual(len(data['created']),1);self.assertEqual(j.state['upstream_kubelet_authority']['status'],'ready');self.assertEqual(j.state['upstream_kubelet_authority']['binding_uid'],'OWNED-NEW');self.assertEqual(j.state['phase'],'smoke_started');self.assertEqual(b.file_snapshot(config),config_before)
   self.assertTrue(any(x['upstream_kubelet_authority']['status']=='creating' for x in data['persisted']));self.assertEqual(data['role']['rules'],m.upstream_kubelet_role_rules());self.assertTrue((Path(j.state['upstream_kubelet_authority']['private_receipt'])/'created-binding.private').exists())
   self.assertFalse(any(c.args[0][0] in ['apply','patch','delete'] for c in j.kubectl.call_args_list))
 def test_existing_binding_or_modified_role_refuses_without_creation(self):
  for kind in ['binding','role']:
   with tempfile.TemporaryDirectory() as d:
    j,data,_,_,p1,p2=self.fixture(Path(d))
    if kind=='binding':data['binding']={'metadata':{'uid':'FOREIGN'}}
    else:data['role']['rules'][0]['resources'].append('secrets')
    with p1,p2,self.assertRaises(m.Refused):j.restore_kubelet_authority()
    self.assertFalse(data['created']);self.assertNotIn('upstream_kubelet_authority',j.state)
 def test_changed_certificate_or_weakened_kubelet_flags_refuse(self):
  for kind in ['subject','flags']:
   with tempfile.TemporaryDirectory() as d:
    j,data,_,proc,p1,p2=self.fixture(Path(d))
    if kind=='subject':data['subject']='subject=CN=FOREIGN,O=system:masters'
    else:(proc/'cmdline').write_bytes(b'/usr/bin/kubelet\0--config=/var/lib/kubelet/config.yaml\0--anonymous-auth=true\0')
    with p1,p2,self.assertRaises(m.Refused):j.restore_kubelet_authority()
    self.assertFalse(data['created'])
 def test_foreign_created_postimage_not_adopted_no_delete(self):
  with tempfile.TemporaryDirectory() as d:
   j,data,_,_,p1,p2=self.fixture(Path(d));data['foreign']=True
   with p1,p2,self.assertRaisesRegex(m.Refused,'postimage_changed'):j.restore_kubelet_authority()
   self.assertEqual(len(data['created']),1);self.assertEqual(j.state['upstream_kubelet_authority']['status'],'creating');self.assertNotIn('binding_uid',j.state['upstream_kubelet_authority']);self.assertFalse(any(c.args[0][0]=='delete' for c in j.kubectl.call_args_list))
 def test_subject_role_or_extra_subject_change_rejected(self):
  expected=m.upstream_kubelet_binding();obj=copy.deepcopy(expected);obj['metadata']['uid']='owned'
  for key in ['subjects','roleRef']:
   changed=copy.deepcopy(obj)
   if key=='subjects':changed[key].append({'kind':'Group','name':'system:authenticated','apiGroup':'rbac.authorization.k8s.io'})
   else:changed[key]['name']='cluster-admin'
   with self.assertRaises(m.Refused):m.require_upstream_binding(changed,expected,'owned')
 def test_preexisting_authority_or_ineffective_new_authority_fail_closed(self):
  for kind in ['before','after']:
   with tempfile.TemporaryDirectory() as d:
    j,data,_,_,p1,p2=self.fixture(Path(d));data['prior_yes']=kind=='before';data['post_no']=kind=='after'
    with p1,p2,self.assertRaises(m.Refused):j.restore_kubelet_authority()
    if kind=='before':self.assertFalse(data['created']);self.assertNotIn('upstream_kubelet_authority',j.state)
    else:self.assertEqual(len(data['created']),1);self.assertEqual(j.state['upstream_kubelet_authority']['status'],'creating')
 def test_second_phase_or_wrong_initial_phase_refuses(self):
  with tempfile.TemporaryDirectory() as d:
   j,data,_,_,p1,p2=self.fixture(Path(d));j.state['upstream_kubelet_authority']={'status':'creating'}
   with p1,p2,self.assertRaises(m.Refused):j.restore_kubelet_authority()
   j.kubectl.assert_not_called()
 def test_explicit_dispatches_only_authority_phase(self):
  job=Mock();job.context=context_fixture('guest');job.state={'phase':'smoke_started'}
  m.dispatch_phase(job,'kubelet-authority',execute=True)
  job.restore_kubelet_authority.assert_called_once_with();job.init.assert_not_called();job.cni.assert_not_called();job.smoke.assert_not_called()
 def test_wrong_phase_refuses_before_reading_or_creating_rbac(self):
  with tempfile.TemporaryDirectory() as d:
   j,data,_,_,p1,p2=self.fixture(Path(d));j.state['phase']='not_started'
   with p1,p2,self.assertRaisesRegex(m.Refused,'owned_unrestored_postinit'):j.restore_kubelet_authority()
   j.kubectl.assert_not_called();self.assertFalse(data['created'])
 def test_final_phase_methods_retain_reviewed_guard_implementations(self):
  def methods(path):
   tree=ast.parse(path.read_text());cls=next(n for n in tree.body if isinstance(n,ast.ClassDef)and n.name=='Cluster')
   return {n.name:ast.dump(n,include_attributes=False)for n in cls.body if isinstance(n,ast.FunctionDef)}
  source=methods(ROOT/'guest/cluster.py');reference=methods(ROOT/'reference/alpha-20261102/guest-cluster.py.reference')
  for name in ['init','verify_init','cni','smoke','cleanup_validation','restore_kubelet_authority']:
   with self.subTest(method=name):self.assertEqual(source[name],reference[name])
if __name__=='__main__':unittest.main(verbosity=2)

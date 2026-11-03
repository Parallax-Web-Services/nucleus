#!/usr/bin/env python3
"""Offline only, actual frozen088 guest transport with synthetic bridge/state/fake SSH."""
import hashlib,importlib.util,json,os,tempfile,types,unittest
from pathlib import Path
from unittest.mock import patch
def load(name,path):
 spec=importlib.util.spec_from_file_location(name,path);m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m);return m
a=load('tls_alpha','/tmp/nebula-managed-v3-consumers-rkss039w/source/nebula-kubelet-renewal-alpha.py');frozen=load('ro_fixtures','/tmp/nebula-managed-v3-source-egkc2mqv/test_foundation.py');w=frozen.w;d=frozen.d
class ActualComposition(unittest.TestCase):
 def fixture(self):
  f=frozen.Fixture();self.addCleanup(f.close);return f
 def plan(self,f):
  job=f.bridge.lifecycle();return json.dumps({'operation_id':'b'*32,'run_id':job.plan['run_id'],'expected_uuid':job.plan['new_domain_uuid'],'api_address':'192.0.2.7','enrollment':{'node_name':job.plan['proposed_name'],'authority':'verified-libvirt-reservation'}}).encode()
 def run_phase(self,f,phase='enable-renewal',answer=None,mutation=None):
  if answer is None:answer={'status':'passed','phase':phase,'no_serving_or_api_trust_change':True}
  def runner(args,label,timeout=60,input_bytes=None,pass_fds=()):
   f.calls.append((args,label,timeout));typed='fixed_guest_operation_namespace' in args[-1]
   if typed:
    if mutation:mutation()
    return json.dumps(answer).encode()
   return json.dumps(w.EXPECTED).encode()
  return a.one_phase(w,f.bridge,d,None,self.plan(f),phase,runner,f.fd,f.lock,f.held)
 def test_exact_frozen_guest_transport_and_readonly_checks_preserve_all_ledger_bytes(self):
  f=self.fixture()
  with patch.object(d.Durability,'record',side_effect=AssertionError('ledger write')):result=self.run_phase(f)
  self.assertEqual(result['status'],'passed');self.assertTrue(result['fresh_admitted_managed_health_checked']);self.assertTrue(result['original_alpha_local_guard_preserved']);self.assertFalse(result['health_writer_started']);self.assertEqual(len(f.calls),3);self.assertTrue(f.unchanged())
  for args,_,timeout in f.calls:
   self.assertEqual(args[0],'ssh');self.assertEqual(timeout,40);self.assertIn('StrictHostKeyChecking=yes',args);self.assertIn('IdentityAgent=none',args);self.assertIn('ClearAllForwardings=yes',args)
 def test_stale_managed_health_never_falls_back_or_runs_guest(self):
  f=self.fixture();f.health_ready=False
  with self.assertRaisesRegex(w.Refused,'managed_health_stale'):self.run_phase(f)
  self.assertEqual(f.calls,[])
 def test_remote_managed_owner_cannot_waive_local_alpha_engine_guard(self):
  f=self.fixture();f.local_marker='changed'
  with self.assertRaisesRegex(w.Refused,'original_local_engine_changed'):self.run_phase(f)
  self.assertEqual(f.calls,[])
 def test_guest_wrong_phase_is_not_accepted(self):
  f=self.fixture()
  with self.assertRaisesRegex(RuntimeError,'guest_phase_result_binding'):self.run_phase(f,answer={'status':'passed','phase':'other'})
  self.assertTrue(f.unchanged())
 def test_pending_only_for_exact_native_issuance_poll(self):
  f=self.fixture();result=self.run_phase(f,'verify-proof',{'status':'pending','phase':'verify-proof','native_issuance_pending':True});self.assertEqual(result['status'],'pending')
  f=self.fixture()
  with self.assertRaisesRegex(RuntimeError,'only_native_issuance_may_be_pending'):self.run_phase(f,'enable-renewal',{'status':'pending','phase':'enable-renewal','native_issuance_pending':True})
 def test_guest_failure_not_relabelled_or_retried(self):
  f=self.fixture()
  with self.assertRaisesRegex(RuntimeError,'guest_phase_result_binding'):self.run_phase(f,answer={'status':'refused','phase':'enable-renewal'})
  self.assertEqual(len(f.calls),2)
 def test_ledger_change_during_guest_is_not_adopted(self):
  f=self.fixture()
  with self.assertRaisesRegex(d.Refused,'durability_record_changed'):self.run_phase(f,mutation=lambda:(f.ledger/'baseline.json').write_bytes(b'FOREIGN'))
  self.assertEqual((f.ledger/'baseline.json').read_bytes(),b'FOREIGN')
 def test_current_local_guard_change_after_guest_is_not_ignored(self):
  f=self.fixture()
  def mutate():f.local_marker='changed'
  with self.assertRaisesRegex(w.Refused,'original_local_engine_changed'):self.run_phase(f,mutation=mutate)
 def test_different_guest_uuid_or_address_refused_before_typed_mutation(self):
  for field,value in [('expected_uuid','00000000-0000-4000-8000-000000000002'),('api_address','203.0.113.9')]:
   f=self.fixture();p=json.loads(self.plan(f));p[field]=value
   with patch.object(self,'plan',return_value=json.dumps(p).encode()),self.assertRaisesRegex(RuntimeError,'alpha_plan_and_enrollment_binding'):self.run_phase(f)
   self.assertEqual(len(f.calls),1)
 def test_completion_phase_maps_only_to_known_guest_success_alias(self):
  f=self.fixture();self.assertEqual(self.run_phase(f,'complete-renewal',{'status':'passed','phase':'enable-renewal'})['phase'],'complete-renewal')
class CustodyAndBudget(unittest.TestCase):
 def test_guest_pin_is_actual_current_source_and_no_staging_or_health_writer(self):
  self.assertEqual(a.GUEST_SHA,hashlib.sha256(Path('/tmp/nebula-kubelet-client-renewal.py').read_bytes()).hexdigest())
  self.assertNotIn('.mkdir(',a.RECEIVER);self.assertNotIn('admit(',a.RECEIVER);self.assertNotIn('healthrefresher',a.RECEIVER);self.assertIn("read(planpath,16384)==plan_raw",a.RECEIVER);self.assertIn('product_uuid',a.RECEIVER)
 def test_invalid_phase_cannot_become_remote_command(self):
  for phase in ['init','approve','restart','../other']:
   with self.assertRaisesRegex(RuntimeError,'typed_private_plan_and_phase'):a.guest_script(b'{}',phase)
 def test_runner_has_total_budget_cleanup_reserve_and_command_count(self):
  seen=[];common=types.SimpleNamespace(command=lambda *args,**kw:seen.append(kw) or b'OK')
  with patch.object(a.time,'monotonic',side_effect=[100,191]):runner=a.PhaseRunner(common,Path('/not-used'));self.assertEqual(runner(['true'],'safe',timeout=40),b'OK')
  self.assertEqual(seen[0]['timeout'],4)
  with patch.object(a.time,'monotonic',return_value=100):
   runner=a.PhaseRunner(common,Path('/not-used'));runner.calls=384
   with self.assertRaisesRegex(RuntimeError,'alpha_phase_command_bound'):runner(['true'],'safe')
 def test_verified_source_bytes_stay_pinned_until_postcheck(self):
  with tempfile.TemporaryDirectory(prefix='nebula-tls-source-',dir='/root') as temporary:
   root=Path(temporary);root.chmod(0o700);source=root/'source.py';source.write_bytes(b'VALUE=1\n');source.chmod(0o600);pin=hashlib.sha256(source.read_bytes()).hexdigest()
   with self.assertRaisesRegex(RuntimeError,'readonly_source_changed_after_phase'):
    with a.load_root_source(source,pin) as module:
     other=root/'other';other.write_bytes(b'VALUE=2\n');other.chmod(0o600);os.replace(other,source);self.assertEqual(module.VALUE,1)
   self.assertEqual(source.read_bytes(),b'VALUE=2\n')
if __name__=='__main__':unittest.main()

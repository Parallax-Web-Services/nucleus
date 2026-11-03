import copy,io,json,os,tempfile,time,unittest
from contextlib import redirect_stdout,redirect_stderr
from pathlib import Path
from unittest.mock import Mock,patch
from tests.support import load_module
m=load_module('adapters/fleet-health')
NOW=1800000000
EXPECTED={'fabric_id':'f'*64,'nodes':[{'node_id':'a'*64},{'node_id':'b'*64}]}
def view():return {'schema_version':1,'fabric_id':'f'*64,'collected_at_ms':NOW*1000,'nodes':[{'node_id':'a'*64,'status':'online','private':'SECRET-CANARY'},{'node_id':'b'*64,'status':'online'}]}
def proof():return {'managed_relay_binary_matches':True,'managed_relay_process_unchanged':True}
class HealthTests(unittest.TestCase):
 def test_all_known_views_and_explicit_relay_proof_are_required(self):
  out=m.payload(view,view,EXPECTED,proof,clock=lambda:NOW)
  self.assertTrue(out['same_fabric']);self.assertEqual(out['registered_node_count'],2);self.assertEqual(out['known_online_count'],2);self.assertTrue(out['managed_relay_process_unchanged']);self.assertEqual(set(out),m.FIELDS)
 def test_wrong_fabric_missing_members_and_offline_are_not_invented(self):
  for kind in ['fabric','missing','offline']:
   v=view()
   if kind=='fabric':v['fabric_id']='e'*64
   elif kind=='missing':v['nodes'].pop()
   else:v['nodes'][1]['status']='offline'
   result=m.payload(lambda:v,view,EXPECTED,proof,clock=lambda:NOW)
   if kind!='offline':self.assertFalse(result['same_fabric'])
   self.assertLess(result['known_online_count'],2)if kind!='fabric'else None
 def test_failed_fetch_or_relay_proof_does_not_reuse_success_or_leak(self):
  def fail():raise RuntimeError('SECRET-CANARY private endpoint/error')
  capture=io.StringIO()
  with redirect_stdout(capture),redirect_stderr(capture):
   good=m.payload(view,view,EXPECTED,proof,clock=lambda:NOW)
   out=m.payload(fail,view,EXPECTED,fail,clock=lambda:NOW)
  self.assertTrue(good['same_fabric']);self.assertFalse(out['same_fabric']);self.assertEqual(out['known_online_count'],0);self.assertFalse(out['managed_relay_binary_matches']);self.assertNotIn('SECRET',json.dumps(out)+capture.getvalue())
 def test_stale_future_or_duplicate_source_view_fails_closed(self):
  for kind in ['stale','future','duplicate']:
   v=view()
   if kind=='stale':v['collected_at_ms']-=60001
   elif kind=='future':v['collected_at_ms']+=5001
   else:v['nodes'].append(copy.deepcopy(v['nodes'][0]))
   out=m.payload(lambda:v,view,EXPECTED,proof,clock=lambda:NOW)
   self.assertFalse(out['same_fabric']);self.assertEqual(out['registered_node_count'],0)
 def test_old_future_extra_or_wrong_typed_safe_health_is_refused(self):
  good=m.payload(view,view,EXPECTED,proof,clock=lambda:NOW)
  for changes in [{'checked_at_unix':NOW-61},{'checked_at_unix':NOW+1},{'same_fabric':1},{'known_online_count':True},{'token':'SECRET'}]:
   with self.assertRaises(m.Refused):m.validate({**good,**changes},NOW)
 def test_transport_is_explicit_no_session_or_ssh_defaults(self):
  with self.assertRaises(m.Refused):m.payload(None,view,EXPECTED,proof,clock=lambda:NOW)
  with self.assertRaisesRegex(RuntimeError,'explicit_validated_foundation_context_required'):m.store(None,{'token':'SECRET'})
@unittest.skipUnless(os.geteuid()==0,'fresh root-only ownership fixtures')
class StoreTests(unittest.TestCase):
 def test_new_and_known_replacement_are_private_and_unknown_state_preserved(self):
  with tempfile.TemporaryDirectory(prefix='foundation-health-test-')as d:
   root=Path(d);work=root/'plan-0123456789ab';work.mkdir(mode=0o700)
   c=Mock();c.path.return_value=root;c.inputs={'run_id':'0123456789ab'};value=m.payload(view,view,EXPECTED,proof,clock=lambda:int(time.time()))
   with patch.object(m,'require_context',return_value=c):
    first=m.store(c,value);second=m.store(c,value,first);self.assertEqual((work/'external-health.json').stat().st_mode&0o777,0o600)
    replacement=work/'foreign';replacement.write_bytes(b'FOREIGN');replacement.chmod(0o600);os.replace(replacement,work/'external-health.json')
    with self.assertRaises(m.Refused):m.store(c,value,second)
    self.assertEqual((work/'external-health.json').read_bytes(),b'FOREIGN')
if __name__=='__main__':unittest.main()

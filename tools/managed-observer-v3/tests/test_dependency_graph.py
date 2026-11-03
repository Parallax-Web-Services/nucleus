"""Public source/reference provenance only; no installed/private paths required."""
import ast,hashlib,importlib.util,json,unittest
from pathlib import Path
PACKAGE=Path(__file__).resolve().parent.parent
SOURCE=PACKAGE/'source'
def digest(path):return hashlib.sha256(path.read_bytes()).hexdigest()
def load(name):
 spec=importlib.util.spec_from_file_location('package_'+name.replace('-','_').replace('.','_'),SOURCE/name);m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m);return m
class Graph(unittest.TestCase):
 def test_all_required_pins_resolve_to_exact_new_sources(self):
  prepare=load('prepare_config.py');overlay=load('managed-health-overlay.py');reducer=load('managed-alpha-health.py');bridge=load('alpha-managed-health-bridge.py');writer=load('alpha-managed-health-refresher.py');foundation=load('alpha-managed-foundation-readonly.py');retirement=load('controller-retirement.py')
  self.assertEqual(prepare.PRODUCER_SHA,digest(SOURCE/'producer.py'));self.assertEqual(overlay.PRODUCER_SHA,digest(SOURCE/'producer.py'));self.assertEqual(reducer.OVERLAY_SOURCE_SHA,digest(SOURCE/'managed-health-overlay.py'));self.assertEqual(bridge.REDUCER_SHA,digest(SOURCE/'managed-alpha-health.py'));self.assertEqual(writer.REDUCER_SHA,bridge.REDUCER_SHA);self.assertEqual(writer.BRIDGE_SHA,digest(SOURCE/'alpha-managed-health-bridge.py'));self.assertEqual(foundation.BRIDGE_SHA,writer.BRIDGE_SHA);self.assertEqual(retirement.HEALTH_SHA,reducer.OVERLAY_SOURCE_SHA)
  public='/usr/local/lib/parallax-nebula-managed-v3/'
  self.assertEqual(writer.REDUCER,public+'managed-alpha-health.py');self.assertEqual(writer.BRIDGE,public+'alpha-managed-health-bridge.py');self.assertEqual(writer.BASE_SOURCE,public+'managed-health-overlay.py');self.assertEqual(str(foundation.BRIDGE_SOURCE),writer.BRIDGE);self.assertEqual(str(retirement.REMOTE_HEALTH),writer.BASE_SOURCE)
 def test_public_frozen_reference_source_bytes_match_reviewed_beforeimages(self):
  manifest=json.loads((PACKAGE/'SOURCE_MANIFEST.json').read_bytes())
  for name,item in manifest['files'].items():
   with self.subTest(name=name):self.assertEqual(digest(PACKAGE/item['reference_path']),item['before_sha256']);self.assertEqual(digest(PACKAGE/item['path']),item['sha256'])
  for name,pin in manifest['fixture_reference_pins'].items():self.assertEqual(digest(PACKAGE/'reference'/name),pin)
  self.assertEqual(digest(SOURCE/'nebula-backup-common.py'),manifest['common_sha256'])
 def test_downstream_exact_literal_diffs_and_unchanged_producer_guards(self):
  manifest=json.loads((PACKAGE/'SOURCE_MANIFEST.json').read_bytes())
  for name,item in manifest['files'].items():
   before=(PACKAGE/item['reference_path']).read_text();after=(PACKAGE/item['path']).read_text()
   if name=='producer.py':
    def filtered(text):
     excluded_functions={'systemd_state','_read_systemd_output','_show_systemd_properties'};excluded_constants={'EMPTY_EXEC_FIELDS','SYSTEMD_BUS_OBJECT'}
     return ast.dump(ast.Module(body=[x for x in ast.parse(text).body if not(isinstance(x,ast.FunctionDef) and x.name in excluded_functions) and not(isinstance(x,ast.Assign) and any(isinstance(t,ast.Name) and t.id in excluded_constants for t in x.targets))],type_ignores=[]),include_attributes=False)
    self.assertEqual(filtered(before),filtered(after))
   else:
    for old,new in item['literal_changes'].items():before=before.replace(old,new)
    with self.subTest(name=name):self.assertEqual(before,after)
if __name__=='__main__':unittest.main()

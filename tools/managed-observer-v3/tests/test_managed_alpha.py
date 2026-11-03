import hashlib, importlib.util, json, os, stat, tempfile, types, unittest
from pathlib import Path
SOURCE_DIR = Path(__file__).resolve().parent.parent / 'source'
REFERENCE_DIR = Path(__file__).resolve().parent.parent / 'reference'
from unittest.mock import patch
spec = importlib.util.spec_from_file_location('h', str(SOURCE_DIR / 'managed-alpha-health.py'))
h = importlib.util.module_from_spec(spec)
spec.loader.exec_module(h)

class ManagedAlphaHealth(unittest.TestCase):

    def view(self):
        now = 100000
        return (now, {'view_collected_at_ms': now, 'hosts': [{'status': 'online', 'last_seen_at_ms': now, 'resource_collected_at_ms': now} for _ in range(5)]})

    def test_reports_actual_fifth_member_offline_and_stale_counts(self):
        (now, view) = self.view()
        view['hosts'][-1] = {'status': 'offline', 'last_seen_at_ms': now - 20000, 'resource_collected_at_ms': now - 20000}
        p = h.counts(view, now)
        self.assertEqual(p['owner_view_online_count'], 4)
        self.assertEqual(p['owner_view_resource_fresh_count'], 4)
        self.assertLess(p['all_five_samples_valid_until_unix_ms'], now)

    def test_missing_resource_timestamp_expires_deadline(self):
        (now, view) = self.view()
        view['hosts'][-1]['resource_collected_at_ms'] = None
        p = h.counts(view, now)
        self.assertEqual(p['owner_view_online_count'], 5)
        self.assertEqual(p['owner_view_resource_fresh_count'], 4)
        self.assertEqual(p['all_five_samples_valid_until_unix_ms'], 0)

    def test_deadline_uses_oldest_actual_sample_not_collection_time(self):
        (now, view) = self.view()
        view['hosts'][2]['last_seen_at_ms'] = now - 9000
        p = h.counts(view, now)
        self.assertEqual(p['all_five_samples_valid_until_unix_ms'], now + 1000)

    def test_future_sample_outside_tolerance_not_counted(self):
        (now, view) = self.view()
        view['hosts'][0]['resource_collected_at_ms'] = now + 5001
        self.assertEqual(h.counts(view, now)['owner_view_resource_fresh_count'], 4)

    def relay_fixture(self, root, pid=7, start='123'):
        binary = root / 'nucleus'
        binary.write_bytes(b'public fixture relay binary')
        os.chmod(binary, 365)
        digest = hashlib.sha256(binary.read_bytes()).hexdigest()
        proof = {'status': 'passed', 'relay_process': {'pid': pid, 'start_ticks': start}}
        api = types.SimpleNamespace(read=lambda *a: (json.dumps(proof).encode(), {'same': True}), decode=json.loads)
        return (binary, digest, proof, api)

    def test_relay_proof_binds_held_binary_and_saved_pid_start(self):
        with tempfile.TemporaryDirectory() as directory:
            (binary, digest, proof, api) = self.relay_fixture(Path(directory))
            read_text = Path.read_text
            path_stat = Path.stat
            readlink = os.readlink

            def text(path, *a, **k):
                return '7 (nucleus) ' + ' '.join(['S'] + ['0'] * 18 + ['123']) if str(path) == '/proc/7/stat' else read_text(path, *a, **k)

            def st(path, *a, **k):
                return path_stat(binary) if str(path) == '/proc/7/exe' else path_stat(path, *a, **k)
            with patch.object(h, 'RELAY_BINARY', binary), patch.object(h, 'RELAY_SHA', digest), patch.object(h.subprocess, 'run', return_value=types.SimpleNamespace(returncode=0, stdout=b'7\n')), patch.object(Path, 'read_text', new=text), patch.object(Path, 'stat', new=st), patch.object(h.os, 'readlink', side_effect=lambda p: str(binary) if str(p) == '/proc/7/exe' else readlink(p)):
                result = h.relay_proof(api)
                self.assertEqual(result, {'managed_relay_binary_matches': True, 'managed_relay_process_unchanged': True})
                proof['relay_process']['start_ticks'] = '124'
                result = h.relay_proof(api)
                self.assertTrue(result['managed_relay_binary_matches'])
                self.assertFalse(result['managed_relay_process_unchanged'])

    def test_failed_relay_receipt_never_reports_success(self):
        api = types.SimpleNamespace(read=lambda *a: (b'{"status":"failed"}', {}), decode=json.loads)
        with patch.object(h.subprocess, 'run') as run:
            self.assertEqual(h.relay_proof(api), {'managed_relay_binary_matches': False, 'managed_relay_process_unchanged': False})
        run.assert_not_called()

    def test_original_plan_context_mismatch_refuses_before_producer_fetch(self):
        api = types.SimpleNamespace(read=lambda *a: (json.dumps({'schema_version': 2, 'overlay_id': 'a' * 32, 'original_plan_record': {'expected': True}}).encode(), {}), decode=json.loads)
        with patch.object(h, 'load_overlay_source', return_value=api), self.assertRaisesRegex(h.Refused, 'original_plan_context_mismatch'):
            h.check(Path('/overlay'), Path('/source'), {'other': True})

    def test_additive_reducer_uses_one_actual_view_and_private_plan_context(self):
        (now, view) = self.view()
        record = {'fixed': True}
        context = {'original': True}
        o = {'schema_version': 2, 'overlay_id': 'a' * 32, 'original_plan_record': context, 'producer_path': '/producer', 'producer_record': record, 'origin_binding_path': '/origin', 'origin_binding_record': record, 'cutover_path': '/cutover', 'cutover_record': record, 'config_path': '/config', 'config_record': record, 'expected_members': list('abcde'), 'required_server_ids': list('abcd')}
        fetch = __import__('unittest.mock').mock.Mock(return_value={})
        m = types.SimpleNamespace(load_config=lambda p: ({}, record), record=lambda *a: record, fetch=fetch, normalize=lambda *a: view)
        api = types.SimpleNamespace(read=lambda p, *a: (json.dumps(o).encode(), record), decode=json.loads, load_producer=lambda p: (m, record), metadata_unchanged=lambda *a: None, reduce_health=lambda *a: {'registered_node_count': 5, 'required_server_count': 4, 'required_server_online_count': 4, 'same_fabric': True, 'required_server_resources_fresh': True})
        with patch.object(h, 'load_overlay_source', return_value=api), patch.object(h, 'relay_proof', return_value={'managed_relay_binary_matches': True, 'managed_relay_process_unchanged': True}), patch.object(h.time, 'time', return_value=now / 1000):
            proof = h.check(Path('/overlay'), Path('/source'), context)
        fetch.assert_called_once()
        self.assertTrue(proof['origin_plan_context_matches'])
        self.assertEqual(proof['owner_view_online_count'], 5)
        self.assertNotIn('original_plan_record', proof)
if __name__ == '__main__':
    unittest.main(verbosity=2)

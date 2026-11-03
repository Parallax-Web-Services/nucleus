import copy, importlib.util, os, tempfile, time, types, unittest
from pathlib import Path
SOURCE_DIR = Path(__file__).resolve().parent.parent / 'source'
REFERENCE_DIR = Path(__file__).resolve().parent.parent / 'reference'
from unittest.mock import patch
spec = importlib.util.spec_from_file_location('h', str(SOURCE_DIR / 'managed-health-overlay.py'))
h = importlib.util.module_from_spec(spec)
spec.loader.exec_module(h)

class OverlayGuards(unittest.TestCase):

    def fixture(self):
        now = 100000
        c = {'local_node_id': 'a' * 64}
        ids = [chr(97 + i) * 64 for i in range(5)]
        hosts = [{'node_id': x, 'status': 'online', 'last_seen_at_ms': now, 'resource_collected_at_ms': now} for x in ids]
        m = types.SimpleNamespace(normalize=lambda *a: {'view_collected_at_ms': now, 'hosts': hosts})
        return (now, c, ids, hosts, m)

    def test_four_servers_fresh_desktop_optional(self):
        (now, c, ids, hosts, m) = self.fixture()
        hosts[-1]['status'] = 'offline'
        result = h.reduce_health({}, c, ids, ids[:4], now, m)
        self.assertEqual(result['required_server_online_count'], 4)
        self.assertEqual(set(result), {'registered_node_count', 'required_server_count', 'required_server_online_count', 'same_fabric', 'required_server_resources_fresh'})

    def test_stale_resource_sample_rejected_even_online(self):
        (now, c, ids, hosts, m) = self.fixture()
        hosts[1]['resource_collected_at_ms'] = now - 10001
        with self.assertRaisesRegex(h.Refused, 'required_server_sample_not_fresh'):
            h.reduce_health({}, c, ids, ids[:4], now, m)

    def test_future_resource_sample_rejected(self):
        (now, c, ids, hosts, m) = self.fixture()
        hosts[1]['resource_collected_at_ms'] = now + 5001
        with self.assertRaisesRegex(h.Refused, 'required_server_sample_not_fresh'):
            h.reduce_health({}, c, ids, ids[:4], now, m)

    def test_required_server_offline_rejected(self):
        (now, c, ids, hosts, m) = self.fixture()
        hosts[1]['status'] = 'offline'
        with self.assertRaisesRegex(h.Refused, 'required_server_not_online'):
            h.reduce_health({}, c, ids, ids[:4], now, m)

    def test_membership_change_rejected(self):
        (now, c, ids, hosts, m) = self.fixture()
        hosts[-1]['node_id'] = 'f' * 64
        with self.assertRaisesRegex(h.Refused, 'managed_membership_set_differs'):
            h.reduce_health({}, c, ids, ids[:4], now, m)

    def test_required_scope_must_include_owner(self):
        (now, c, ids, hosts, m) = self.fixture()
        with self.assertRaisesRegex(h.Refused, 'approved_server_scope_differs'):
            h.reduce_health({}, c, ids, ids[1:], now, m)

    def test_duplicate_and_nonfinite_json_rejected(self):
        for data in [b'{"x":1,"x":2}', b'{"x":NaN}']:
            with self.assertRaises(h.Refused):
                h.decode(data)

    def test_cutover_metadata_check_never_reads_authority(self):
        with tempfile.TemporaryDirectory() as directory:
            p = Path(directory) / 'cutover'
            p.write_bytes(b'private-never-read')
            os.chmod(p, 384)
            record = {'identity': h.identity(p.lstat())}
            with patch.object(Path, 'read_bytes', side_effect=AssertionError('must not read')):
                h.metadata_unchanged(p, record)

    def test_replacement_at_overlay_adoption_preserves_unknown(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            os.chmod(root, 448)
            target = root / 'overlay'
            foreign = root / 'foreign'
            foreign.write_bytes(b'unknown')
            os.chmod(foreign, 384)
            link = os.link

            def replace_after_link(a, b, **kw):
                link(a, b, **kw)
                os.replace(foreign, b)
            with patch.object(h.os, 'link', side_effect=replace_after_link), self.assertRaisesRegex(h.Refused, 'overlay_postimage_unknown'):
                h.new_private(target, b'ours')
            self.assertEqual(target.read_bytes(), b'unknown')

    def test_source_compiles_exact_snapshot_without_reopen(self):
        data = b'x=7\n'
        record = {'sha256': h.PRODUCER_SHA}
        with patch.object(h, 'read', return_value=(data, record)):
            (m, r) = h.load_producer(Path('/synthetic-accepted-source'))
        self.assertEqual(m.x, 7)

    def test_each_check_fetches_fresh_managed_invocation_without_initial_pid_pin(self):
        (now, c, ids, hosts, m) = self.fixture()
        record = {'identity': {}, 'sha256': 'synthetic'}
        o = {'schema_version': 2, 'overlay_id': 'a' * 32, 'producer_path': '/producer', 'producer_record': record, 'origin_binding_path': '/origin', 'origin_binding_record': record, 'cutover_path': '/cutover', 'cutover_record': record, 'config_path': '/config', 'config_record': record, 'expected_members': ids, 'required_server_ids': ids[:4], 'initial_managed_process': {'pid': 11, 'start': 110}}
        m.load_config = lambda p: (c, record)
        m.record = lambda *a: record
        events = []
        m.fetch = lambda cfg: events.append('fresh-managed-invocation') or {}
        data = __import__('json').dumps(o).encode()

        def read(path, *a):
            return (data if str(path) == '/overlay' else b'{}', record)
        with patch.object(h, 'read', side_effect=read), patch.object(h, 'load_producer', return_value=(m, record)), patch.object(h, 'metadata_unchanged'), patch.object(h.time, 'time', return_value=now / 1000):
            a = h.check(Path('/overlay'))
            b = h.check(Path('/overlay'))
        self.assertEqual(events, ['fresh-managed-invocation'] * 2)
        self.assertNotIn('pid', a)
        self.assertNotIn('initial_managed_process', b)
if __name__ == '__main__':
    unittest.main(verbosity=2)

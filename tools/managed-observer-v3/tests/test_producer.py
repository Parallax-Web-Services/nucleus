import copy
import http.server
import importlib.util
import json
import os
import stat
import sys
import tempfile
import threading
import unittest
from pathlib import Path
SOURCE_DIR = Path(__file__).resolve().parent.parent / 'source'
REFERENCE_DIR = Path(__file__).resolve().parent.parent / 'reference'
from unittest.mock import patch
sys.dont_write_bytecode = True
spec = importlib.util.spec_from_file_location('producer', SOURCE_DIR / 'producer.py')
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)
NOW = 1800000000000
C = {'fabric_id': 'f' * 64, 'local_node_id': 'a' * 64}

def config(origin='http://127.0.0.1:12345'):
    return {**C, 'schema_version': 2, 'api_origin': origin, 'coordinator': {'unit': 'nucleus-coordinator.service', 'unit_sha256': 'a' * 64, 'binary_sha256': 'b' * 64, 'argv_sha256': 'c' * 64, 'uid': 12345, 'gid': 12345, 'state_device': 1, 'state_inode': 1, 'loopback_ports': [12344, 12345]}}

class SyntheticSource:

    def __init__(self, c):
        self.token = 'a' * 64

    def resolve(self):
        return self

    def guard(self):
        pass

    def close(self):
        self.token = None

def view():
    return {'schema_version': 1, 'fabric_id': C['fabric_id'], 'local_node_id': C['local_node_id'], 'collected_at_ms': NOW, 'endpoint': 'PRIVATE-DROP', 'available_capacity': {'logical_cores': 999999}, 'nodes': [{'node_id': 'a' * 64, 'name': 'synthetic-node', 'kind': 'local', 'status': 'online', 'last_seen_ms': NOW - 100, 'endpoint': 'PRIVATE-DROP', 'error': 'PRIVATE-DROP', 'resources': {'schema_version': 1, 'collected_at_ms': NOW - 150, 'cpu': {'logical_cores': 4, 'effective_cores': 2.5, 'model': 'DROP'}, 'memory': {'total_bytes': 8192, 'available_bytes': 4096, 'effective_total_bytes': 6144}, 'storage': {'mount': 'PRIVATE-DROP', 'total_bytes': 16384, 'available_bytes': 8192}, 'network': [{'private': 'DROP'}], 'gpu': {'address': 'DROP'}}}]}

class SchemaTests(unittest.TestCase):

    def test_exact_sanitized_shape_and_no_unknown_or_private_fields(self):
        result = m.normalize(view(), C, NOW)
        self.assertEqual(set(result), {'schema_version', 'source', 'captured_at_ms', 'view_collected_at_ms', 'available', 'hosts'})
        self.assertEqual(result['source'], 'nucleus-observations')
        self.assertEqual(result['hosts'][0]['effective_cpu_cores'], 2.5)
        self.assertEqual(result['hosts'][0]['memory_effective_limit_bytes'], 6144)
        self.assertNotIn('PRIVATE-DROP', json.dumps(result))
        self.assertNotIn('DROP', json.dumps(result))
        self.assertEqual(set(result['hosts'][0]), {'node_id', 'name', 'status', 'last_seen_at_ms', 'resource_collected_at_ms', 'logical_cpus', 'effective_cpu_cores', 'memory_total_bytes', 'memory_available_bytes', 'memory_effective_limit_bytes', 'storage_total_bytes', 'storage_available_bytes'})

    def test_old_offline_samples_do_not_invalidate_fresh_fleet(self):
        v = view()
        old = copy.deepcopy(v['nodes'][0])
        old.update(node_id='b' * 64, name='offline-node', kind='peer', status='offline', last_seen_ms=NOW - 1000000)
        old['resources']['collected_at_ms'] = NOW - 1000000
        v['nodes'].append(old)
        result = m.normalize(v, C, NOW)
        self.assertTrue(result['available'])
        self.assertEqual(result['hosts'][1]['last_seen_at_ms'], NOW - 1000000)

    def test_awaiting_host_has_no_invented_resources(self):
        v = view()
        v['nodes'].append({'node_id': 'b' * 64, 'name': 'awaiting', 'kind': 'peer', 'status': 'awaiting', 'last_seen_ms': None, 'resources': None})
        h = m.normalize(v, C, NOW)['hosts'][1]
        self.assertIsNone(h['logical_cpus'])
        self.assertIsNone(h['storage_total_bytes'])

    def test_stale_future_wrong_fabric_and_malformed_values_fail_closed(self):
        changes = [lambda v: v.update(collected_at_ms=NOW - 30001), lambda v: v.update(collected_at_ms=NOW + 5001), lambda v: v.update(fabric_id='e' * 64), lambda v: v['nodes'].append(copy.deepcopy(v['nodes'][0])), lambda v: v['nodes'][0].update(last_seen_ms=NOW + 5001), lambda v: v['nodes'][0]['resources'].update(collected_at_ms=NOW + 5001), lambda v: v['nodes'][0]['resources']['cpu'].update(logical_cores=True), lambda v: v['nodes'][0]['resources']['cpu'].update(logical_cores=4097), lambda v: v['nodes'][0]['resources']['memory'].update(total_bytes=(1 << 60) + 1), lambda v: v.update(collected_at_ms=NOW - 10000), lambda v: v['nodes'][0].update(last_seen_ms=0), lambda v: v['nodes'][0]['resources']['cpu'].update(effective_cores=float('nan')), lambda v: v['nodes'][0]['resources']['memory'].update(available_bytes=9000), lambda v: v['nodes'][0].update(name='unsafe\nname')]
        for change in changes:
            with self.subTest(change=changes.index(change)):
                v = view()
                change(v)
                out = m.observe(C, fetcher=lambda _: v, clock=lambda : NOW)
                self.assertEqual(out, m.unavailable(NOW))

    def test_awaiting_unknown_timestamp_is_null_and_zero_is_not_a_source_value(self):
        v = view()
        v['nodes'].append({'node_id': 'b' * 64, 'name': 'awaiting', 'kind': 'peer', 'status': 'awaiting', 'last_seen_ms': None, 'resources': None})
        self.assertIsNone(m.normalize(v, C, NOW)['hosts'][1]['last_seen_at_ms'])
        v['nodes'][1]['last_seen_ms'] = 0
        with self.assertRaises(m.Refused):
            m.normalize(v, C, NOW)

    def test_count_bound_duplicate_json_and_nonfinite_json(self):
        v = view()
        v['nodes'] *= 129
        with self.assertRaises(m.Refused):
            m.normalize(v, C, NOW)
        for raw in [b'{"schema_version":1,"schema_version":2}', b'{"n":NaN}']:
            with self.assertRaises(m.Refused):
                m.decode(raw)

    def test_fetch_failure_never_reuses_a_previous_success(self):
        self.assertTrue(m.observe(C, fetcher=lambda _: view(), clock=lambda : NOW)['available'])

        def fail(_):
            raise OSError('synthetic private error')
        self.assertEqual(m.observe(C, fetcher=fail, clock=lambda : NOW), m.unavailable(NOW))

class HTTPTests(unittest.TestCase):

    def test_503_and_redirect_are_not_followed_and_headers_are_fixed(self):
        hits = []

        class Handler(http.server.BaseHTTPRequestHandler):

            def log_message(self, *_):
                pass

            def do_GET(self):
                hits.append((self.path, self.headers.get('Host'), self.headers.get('Authorization')))
                self.send_response(302 if len(hits) == 1 else 503)
                self.send_header('Location', 'http://127.0.0.1:1/not-followed')
                self.end_headers()
        server = http.server.HTTPServer(('127.0.0.1', 0), Handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            c = {**C, 'api_origin': 'http://127.0.0.1:' + str(server.server_port)}
            for _ in range(2):
                with self.assertRaises(m.Refused):
                    m.fetch(c, source_factory=SyntheticSource)
            self.assertEqual(len(hits), 2)
            self.assertTrue(all((x == ('/api/v1/fabric', '127.0.0.1:' + str(server.server_port), 'Bearer ' + 'a' * 64) for x in hits)))
        finally:
            server.shutdown()
            server.server_close()
            thread.join(1)

@unittest.skipUnless(os.geteuid() == 0, 'private Linux-root fixtures only')
class PublicationTests(unittest.TestCase):

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='nebula-capacity-test-', dir='/run')
        self.root = Path(self.temp.name)
        self.root.chmod(488)
        self.output = self.root / 'fleet.json'
        self.config = self.root / 'producer.json'
        self.data = config()
        self.config.write_text(json.dumps(self.data))
        self.config.chmod(384)

    def tearDown(self):
        self.temp.cleanup()

    def publisher(self):
        return m.Publisher(self.output, self.config, forge_gid=0)

    def test_first_and_next_publications_have_exact_owner_modes_and_state(self):
        with self.publisher() as p:
            p.publish(m.normalize(view(), C, NOW))
        self.assertEqual(stat.S_IMODE(self.output.stat().st_mode), 416)
        self.assertEqual(self.output.stat().st_uid, 0)
        self.assertEqual(stat.S_IMODE((self.root / '.producer-state.json').stat().st_mode), 384)
        with self.publisher() as p:
            p.publish(m.unavailable(NOW + 1000))
        self.assertEqual(json.loads(self.output.read_bytes()), m.unavailable(NOW + 1000))

    def test_sanitized_output_limit_matches_importer_before_publication(self):
        with self.publisher() as p:
            with self.assertRaises(m.Refused):
                p.publish({'oversized': 'x' * m.MAX_OUTPUT})
            self.assertFalse(self.output.exists())

    def test_unclaimed_file_or_symlink_is_preserved(self):
        self.output.write_bytes(b'foreign-root-work')
        self.output.chmod(416)
        with self.assertRaises(m.Refused):
            with self.publisher():
                pass
        self.assertEqual(self.output.read_bytes(), b'foreign-root-work')
        self.output.unlink()
        target = self.root / 'foreign'
        target.write_bytes(b'leave-me')
        self.output.symlink_to(target)
        with self.assertRaises(m.Refused):
            with self.publisher():
                pass
        self.assertEqual(target.read_bytes(), b'leave-me')

    def test_identical_byte_foreign_inode_and_config_changes_refuse(self):
        with self.publisher() as p:
            p.publish(m.unavailable(NOW))
            replacement = self.root / 'replacement'
            replacement.write_bytes(self.output.read_bytes())
            replacement.chmod(416)
            os.replace(replacement, self.output)
            inode = self.output.stat().st_ino
            with self.assertRaises(m.Refused):
                p.publish(m.unavailable(NOW + 1))
            self.assertEqual(self.output.stat().st_ino, inode)
        self.output.unlink()
        (self.root / '.producer-state.json').unlink()
        with self.publisher() as p:
            self.config.write_text(json.dumps({**self.data, 'fabric_id': 'b' * 64}))
            with self.assertRaises(m.Refused):
                p.publish(m.unavailable(NOW))
            self.assertFalse(self.output.exists())

    def test_foreign_control_created_during_publication_is_never_overwritten(self):
        with self.publisher() as p:
            original = p.replace

            def replace(path, *args):
                if path == p.state_path:
                    path.write_bytes(b'foreign control')
                    path.chmod(384)
                return original(path, *args)
            with patch.object(p, 'replace', side_effect=replace), self.assertRaises(m.Refused):
                p.publish(m.unavailable(NOW))
            self.assertEqual(p.state_path.read_bytes(), b'foreign control')
            self.assertEqual(json.loads(self.output.read_bytes()), m.unavailable(NOW))

    def test_lock_path_replacement_refuses_without_new_snapshot(self):
        with self.publisher() as p:
            replacement = self.root / 'replacement'
            replacement.write_bytes(b'')
            replacement.chmod(384)
            os.replace(replacement, p.lock_path)
            with self.assertRaises(m.Refused):
                p.publish(m.unavailable(NOW))
            self.assertFalse(self.output.exists())

    def test_legacy_pid_and_token_config_cannot_be_admitted(self):
        legacy = {**C, 'schema_version': 1, 'api_origin': 'http://127.0.0.1:12345', 'bearer_token': 'a' * 64, 'process': {'pid': 123, 'start_ticks': '1'}}
        for candidate in [legacy, {**self.data, 'process': {'pid': 123}}, {**self.data, 'bearer_token': 'a' * 64}]:
            self.config.write_text(json.dumps(candidate))
            with self.assertRaises(m.Refused):
                m.load_config(self.config)

    def test_config_nonloopback_origin_and_unsafe_ownership_are_refused(self):
        for origin in ['https://127.0.0.1:12345', 'http://localhost:12345', 'http://127.0.0.1:12345/', 'http://user@127.0.0.1:12345', 'http://127.0.0.1:12345?x=y']:
            self.config.write_text(json.dumps({**self.data, 'api_origin': origin}))
            with self.assertRaises(m.Refused):
                m.load_config(self.config)
        self.config.write_text(json.dumps(self.data))
        self.config.chmod(420)
        with self.assertRaises(m.Refused):
            m.load_config(self.config)
if __name__ == '__main__':
    unittest.main()

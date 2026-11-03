import ast, base64, contextlib, copy, hashlib, importlib.util, io, json, os, tempfile, time, types, unittest
from pathlib import Path
SOURCE_DIR = Path(__file__).resolve().parent.parent / 'source'
REFERENCE_DIR = Path(__file__).resolve().parent.parent / 'reference'
from unittest.mock import patch
spec = importlib.util.spec_from_file_location('r', str(SOURCE_DIR / 'alpha-managed-health-refresher.py'))
r = importlib.util.module_from_spec(spec)
spec.loader.exec_module(r)
spec = importlib.util.spec_from_file_location('b', str(SOURCE_DIR / 'alpha-managed-health-bridge.py'))
b = importlib.util.module_from_spec(spec)
spec.loader.exec_module(b)

class ProofTransportGuards(unittest.TestCase):

    def fixture(self, directory):
        base = Path(directory)
        run_id = 'a' * 12
        root = base / ('plan-' + run_id)
        root.mkdir(mode=448)
        plan = root / 'plan.json'
        plan.write_bytes(b'{"public":"synthetic plan without secrets"}')
        os.chmod(plan, 384)
        record = b.read(plan)[1]
        now = int(time.time())
        proof = {'schema_version': 2, 'observation_basis': 'managed-owner-view', 'overlay_id': 'a' * 32, 'checked_at_unix': now, 'managed_owner_matches': True, 'cutover_receipt_unchanged': True, 'origin_plan_context_matches': True, 'registered_node_count': 5, 'required_server_count': 4, 'required_server_online_count': 4, 'same_fabric': True, 'required_server_resources_fresh': True, 'owner_view_online_count': 5, 'owner_view_last_seen_fresh_count': 5, 'owner_view_resource_fresh_count': 5, 'all_five_samples_valid_until_unix_ms': int(time.time() * 1000) + 7000, 'managed_relay_binary_matches': True, 'managed_relay_process_unchanged': True}
        envelope = {'schema_version': 1, 'transport': 'authenticated-administrative-ssh', 'reducer_sha256': b.REDUCER_SHA, 'original_plan_record': record, 'health': proof}
        x = {'run_id': run_id, 'overlay_id': 'a' * 32, 'envelope': envelope}
        wire = r.STORE.replace("Path('/var/lib/parallax-nebula-bootstrap')", 'Path(' + repr(str(base)) + ')')
        return (root, plan, x, wire)

    def execute(self, wire, x):
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            exec(compile(wire, 'synthetic-private-proof-store', 'exec'), {'Path': Path, 'os': os, 'stat': __import__('stat'), 'json': json, 'm': b, 'x': x})
        return json.loads(out.getvalue())

    def test_store_creates_new_typed_file_and_preserves_legacy_file(self):
        with tempfile.TemporaryDirectory() as directory:
            (root, plan, x, wire) = self.fixture(directory)
            legacy = root / 'external-health.json'
            legacy.write_bytes(b'legacy unchanged')
            os.chmod(legacy, 384)
            before = b.read(legacy)[1]
            out = self.execute(wire, x)
            self.assertTrue(out['stored'])
            self.assertTrue(out['ready'])
            self.assertEqual(b.read(legacy)[1], before)
            self.assertEqual(b.decode(b.read(root / 'managed-external-health.json')[0]), x['envelope'])

    def test_plan_changed_between_challenge_and_store_refuses_without_write(self):
        with tempfile.TemporaryDirectory() as directory:
            (root, plan, x, wire) = self.fixture(directory)
            plan.write_bytes(b'changed')
            with self.assertRaises(AssertionError):
                self.execute(wire, x)
            self.assertFalse((root / 'managed-external-health.json').exists())

    def test_nonready_truth_is_stored_and_reported_false(self):
        with tempfile.TemporaryDirectory() as directory:
            (root, plan, x, wire) = self.fixture(directory)
            x['envelope']['health']['owner_view_online_count'] = 4
            out = self.execute(wire, x)
            self.assertFalse(out['ready'])
            self.assertEqual(b.decode(b.read(root / 'managed-external-health.json')[0])['health']['owner_view_online_count'], 4)

    def test_unknown_replacement_at_adoption_preserved(self):
        with tempfile.TemporaryDirectory() as directory:
            (root, plan, x, wire) = self.fixture(directory)
            self.execute(wire, x)
            target = root / 'managed-external-health.json'
            foreign = root / 'foreign'
            foreign.write_bytes(b'foreign')
            os.chmod(foreign, 384)
            replace = os.replace

            def publish(a, c):
                replace(a, c)
                if Path(c) == target:
                    replace(foreign, target)
            with patch.object(os, 'replace', side_effect=publish), self.assertRaises(AssertionError):
                self.execute(wire, x)
            self.assertEqual(target.read_bytes(), b'foreign')

    def test_unapproved_target_never_launches_ssh(self):
        with patch.object(r.subprocess, 'run') as run, self.assertRaisesRegex(r.Refused, 'existing_owned_target_required'):
            r.remote('arbitrary.example', 'not executed')
        run.assert_not_called()

    def test_failed_collection_never_stores_or_falls_back(self):
        with patch.object(r, 'context', return_value={'private': 'synthetic record'}), patch.object(r, 'collect', side_effect=r.Refused('reduced_health_transport_failed')), patch.object(r, 'store') as store, self.assertRaises(r.Refused):
            r.once('root@alpha.wphyperdrive.com', 'a' * 12, 'a' * 32)
        store.assert_not_called()

    def test_public_source_pins_match_actual_candidates(self):
        self.assertEqual(hashlib.sha256(Path(str(SOURCE_DIR / 'managed-alpha-health.py')).read_bytes()).hexdigest(), r.REDUCER_SHA)
        self.assertEqual(hashlib.sha256(Path(str(SOURCE_DIR / 'alpha-managed-health-bridge.py')).read_bytes()).hexdigest(), r.BRIDGE_SHA)

    def test_generated_wire_compiles_and_binds_same_private_plan_record_end_to_end(self):
        record = {'identity': {'synthetic': True}, 'sha256': 'a' * 64}
        proof = {'schema_version': 2, 'observation_basis': 'managed-owner-view', 'overlay_id': 'a' * 32}
        calls = []

        def transport(target, wire):
            compile(wire, 'synthetic-generated-wire', 'exec')
            tree = ast.parse(wire)
            encoded = tree.body[1].value.args[0].args[0].value
            payload = json.loads(base64.b64decode(encoded))
            calls.append((target, payload))
            if target == 'slipstream.host':
                self.assertEqual(payload['original_plan_record'], record)
                return proof
            if 'envelope' in payload:
                self.assertEqual(payload['envelope']['original_plan_record'], record)
                self.assertEqual(payload['envelope']['health'], proof)
                return {'stored': True, 'ready': True}
            return record
        with patch.object(r, 'remote', side_effect=transport):
            result = r.once('root@alpha.wphyperdrive.com', 'a' * 12, 'a' * 32)
        self.assertTrue(result['ready'])
        self.assertEqual([x[0] for x in calls], ['root@alpha.wphyperdrive.com', 'slipstream.host', 'root@alpha.wphyperdrive.com'])

    def test_unknown_initial_root600_output_is_preserved_without_sidecar(self):
        with tempfile.TemporaryDirectory() as directory:
            (root, plan, x, wire) = self.fixture(directory)
            path = root / 'managed-external-health.json'
            path.write_bytes(b'foreign')
            os.chmod(path, 384)
            before = b.read(path)[1]
            with self.assertRaises(AssertionError):
                self.execute(wire, x)
            self.assertEqual(b.read(path)[1], before)
            self.assertFalse((root / '.managed-health-publisher.json').exists())
            self.assertFalse((root / '.managed-health-write.lock').exists())

    def test_stale_owned_proof_remains_refreshable(self):
        with tempfile.TemporaryDirectory() as directory:
            (root, plan, x, wire) = self.fixture(directory)
            self.execute(wire, x)
            before = b.read(root / 'managed-external-health.json')[1]
            future = int(time.time()) + 120
            updated = copy.deepcopy(x)
            updated['envelope']['health']['checked_at_unix'] = future
            updated['envelope']['health']['all_five_samples_valid_until_unix_ms'] = future * 1000 + 7000
            with patch.object(b.time, 'time', return_value=future):
                out = self.execute(wire, updated)
            self.assertTrue(out['ready'])
            self.assertNotEqual(b.read(root / 'managed-external-health.json')[1], before)

    def test_other_overlay_cannot_overwrite_known_publisher(self):
        with tempfile.TemporaryDirectory() as directory:
            (root, plan, x, wire) = self.fixture(directory)
            self.execute(wire, x)
            proof = root / 'managed-external-health.json'
            control = root / '.managed-health-publisher.json'
            before = (b.read(proof)[1], b.read(control)[1])
            other = copy.deepcopy(x)
            other['overlay_id'] = 'b' * 32
            other['envelope']['health']['overlay_id'] = 'b' * 32
            with self.assertRaises(AssertionError):
                self.execute(wire, other)
            self.assertEqual((b.read(proof)[1], b.read(control)[1]), before)

    def test_control_replacement_after_output_publication_is_preserved(self):
        with tempfile.TemporaryDirectory() as directory:
            (root, plan, x, wire) = self.fixture(directory)
            self.execute(wire, x)
            proof = root / 'managed-external-health.json'
            control = root / '.managed-health-publisher.json'
            foreign = root / 'foreign-control'
            foreign.write_bytes(b'foreign')
            os.chmod(foreign, 384)
            replace = os.replace

            def publish(a, c):
                replace(a, c)
                if Path(c) == proof:
                    replace(foreign, control)
            with patch.object(os, 'replace', side_effect=publish), self.assertRaises(AssertionError):
                self.execute(wire, x)
            self.assertEqual(control.read_bytes(), b'foreign')

    def test_output_before_control_interruption_is_not_silently_adopted(self):
        with tempfile.TemporaryDirectory() as directory:
            (root, plan, x, wire) = self.fixture(directory)
            control = root / '.managed-health-publisher.json'
            real = b.new_private

            def put(path, data):
                if path == control:
                    raise OSError('synthetic interrupted control publication')
                return real(path, data)
            with patch.object(b, 'new_private', side_effect=put), self.assertRaises(OSError):
                self.execute(wire, x)
            proof = root / 'managed-external-health.json'
            before = b.read(proof)[1]
            self.assertFalse(control.exists())
            with self.assertRaises(AssertionError):
                self.execute(wire, x)
            self.assertEqual(b.read(proof)[1], before)

    def test_replaced_lock_cannot_be_adopted(self):
        with tempfile.TemporaryDirectory() as directory:
            (root, plan, x, wire) = self.fixture(directory)
            self.execute(wire, x)
            proof = root / 'managed-external-health.json'
            before = b.read(proof)[1]
            foreign = root / 'foreign-lock'
            foreign.write_bytes(b'')
            os.chmod(foreign, 384)
            os.replace(foreign, root / '.managed-health-write.lock')
            with self.assertRaises(AssertionError):
                self.execute(wire, x)
            self.assertEqual(b.read(proof)[1], before)
if __name__ == '__main__':
    unittest.main(verbosity=2)

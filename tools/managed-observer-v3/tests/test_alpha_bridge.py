import copy, hashlib, importlib.util, json, os, tempfile, types, unittest
from pathlib import Path
SOURCE_DIR = Path(__file__).resolve().parent.parent / 'source'
REFERENCE_DIR = Path(__file__).resolve().parent.parent / 'reference'
from unittest.mock import patch
spec = importlib.util.spec_from_file_location('b', str(SOURCE_DIR / 'alpha-managed-health-bridge.py'))
b = importlib.util.module_from_spec(spec)
spec.loader.exec_module(b)

class AlphaBridgeGuards(unittest.TestCase):

    def fixture(self):
        now = 1000
        p = {'schema_version': 2, 'observation_basis': 'managed-owner-view', 'overlay_id': 'a' * 32, 'checked_at_unix': now, 'managed_owner_matches': True, 'cutover_receipt_unchanged': True, 'origin_plan_context_matches': True, 'registered_node_count': 5, 'required_server_count': 4, 'required_server_online_count': 4, 'same_fabric': True, 'required_server_resources_fresh': True, 'owner_view_online_count': 5, 'owner_view_last_seen_fresh_count': 5, 'owner_view_resource_fresh_count': 5, 'all_five_samples_valid_until_unix_ms': 1008000, 'managed_relay_binary_matches': True, 'managed_relay_process_unchanged': True}
        e = {'schema_version': 1, 'transport': 'authenticated-administrative-ssh', 'reducer_sha256': b.REDUCER_SHA, 'original_plan_record': {'identity': {k: 0 for k in b.FIELDS}, 'sha256': 'a' * 64}, 'health': p}
        return (now, e)

    def test_truthful_typed_owner_view_is_accepted(self):
        (now, e) = self.fixture()
        self.assertEqual(b.health(e, 'a' * 32, now)['owner_view_online_count'], 5)

    def test_legacy_v1_or_two_view_basis_is_not_silently_adopted(self):
        (now, e) = self.fixture()
        e['health'] = {'schema_version': 1, 'known_online_count': 5}
        with self.assertRaisesRegex(b.Refused, 'managed_owner_health_schema_or_binding_differs'):
            b.health(e, 'a' * 32, now)
        (now, e) = self.fixture()
        e['health']['observation_basis'] = 'legacy-two-view'
        with self.assertRaises(b.Refused):
            b.health(e, 'a' * 32, now)

    def test_actual_fifth_offline_can_be_stored_but_cannot_pass_guard(self):
        (now, e) = self.fixture()
        e['health']['owner_view_online_count'] = 4
        b.health(e, 'a' * 32, now, require_ready=False)
        with self.assertRaisesRegex(b.Refused, 'all_five_managed_owner_observations_required'):
            b.health(e, 'a' * 32, now)

    def test_false_relay_can_be_stored_but_cannot_pass_guard(self):
        (now, e) = self.fixture()
        e['health']['managed_relay_process_unchanged'] = False
        b.health(e, 'a' * 32, now, require_ready=False)
        with self.assertRaisesRegex(b.Refused, 'managed_owner_or_relay_proof_failed'):
            b.health(e, 'a' * 32, now)

    def test_oldest_sample_expiry_is_enforced_even_when_proof_timestamp_fresh(self):
        (now, e) = self.fixture()
        e['health']['all_five_samples_valid_until_unix_ms'] = 999999
        with self.assertRaisesRegex(b.Refused, 'all_five_samples_expired'):
            b.health(e, 'a' * 32, now)

    def test_boolean_count_and_extra_token_field_are_refused(self):
        (now, e) = self.fixture()
        e['health']['owner_view_online_count'] = True
        with self.assertRaisesRegex(b.Refused, 'managed_health_count_or_bool_type_differs'):
            b.health(e, 'a' * 32, now)
        (now, e) = self.fixture()
        e['health']['token'] = 'must not be transported'
        with self.assertRaises(b.Refused):
            b.health(e, 'a' * 32, now)

    def test_overlay_identity_mismatch_refuses(self):
        (now, e) = self.fixture()
        with self.assertRaisesRegex(b.Refused, 'managed_owner_health_schema_or_binding_differs'):
            b.health(e, 'b' * 32, now)

    def test_every_original_guard_is_called_with_same_arguments(self):
        events = []

        class Original:

            def guard(self, health=True, volume_exception=None):
                events.append(('original', health, volume_exception))
                raise RuntimeError('original-local-process-assertion-failed')
        bridge = types.SimpleNamespace(binding=lambda job: events.append(('binding',)), external_health=lambda job: events.append(('health',)))
        cls = b.lifecycle_class(types.SimpleNamespace(Lifecycle=Original), bridge)
        job = cls()
        sentinel = object()
        with self.assertRaisesRegex(RuntimeError, 'original-local-process-assertion-failed'):
            job.guard(health=False, volume_exception=sentinel)
        self.assertEqual(events, [('binding',), ('original', False, sentinel)])

    def test_exact_6b_guard_function_is_not_replaced_or_edited(self):
        path = Path(str(REFERENCE_DIR / 'legacy-lifecycle.py'))
        self.assertEqual(hashlib.sha256(path.read_bytes()).hexdigest(), b.LIFECYCLE_SHA)
        spec = importlib.util.spec_from_file_location('actual_alpha_6b', path)
        m = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(m)
        original = m.Lifecycle.guard
        bridge = types.SimpleNamespace(binding=lambda job: None, external_health=lambda job: None)
        cls = b.lifecycle_class(m, bridge)
        self.assertIs(m.Lifecycle.guard, original)
        self.assertIn(m.Lifecycle, cls.__mro__)
        job = cls.__new__(cls)
        job.state_path = Path('/synthetic-control')
        job.expected_control = 'accepted'
        with patch.object(m, 'control_state', return_value='foreign'), self.assertRaisesRegex(m.Refused, 'lifecycle_control_state_changed'):
            job.guard()

    def test_guard_still_calls_original_external_lock_guard(self):
        events = []

        class Original:

            def guard(self, health=True, volume_exception=None):
                if hasattr(self, 'external_guard'):
                    self.external_guard()
                if health:
                    self.external_health()
        bridge = types.SimpleNamespace(binding=lambda job: events.append('binding'), external_health=lambda job: events.append('managed-health'))
        job = b.lifecycle_class(types.SimpleNamespace(Lifecycle=Original), bridge)()
        job.external_guard = lambda : events.append('original-lock-guard')
        job.guard()
        self.assertEqual(events, ['binding', 'original-lock-guard', 'managed-health', 'binding'])

    def test_unknown_overlay_postimage_preserved(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            os.chmod(root, 448)
            target = root / 'overlay'
            foreign = root / 'foreign'
            foreign.write_bytes(b'foreign')
            os.chmod(foreign, 384)
            link = os.link

            def publish(a, c, **kw):
                link(a, c, **kw)
                os.replace(foreign, c)
            with patch.object(b.os, 'link', side_effect=publish), self.assertRaisesRegex(b.Refused, 'overlay_postimage_unknown'):
                b.new_private(target, b'ours')
            self.assertEqual(target.read_bytes(), b'foreign')

    def test_duplicate_json_rejected(self):
        with self.assertRaisesRegex(b.Refused, 'duplicate_json_key'):
            b.decode(b'{"x":1,"x":2}')

    def test_authenticated_proof_cannot_be_reused_for_a_different_original_plan(self):
        (now, e) = self.fixture()
        expected = copy.deepcopy(e['original_plan_record'])
        expected['sha256'] = 'b' * 64
        with self.assertRaisesRegex(b.Refused, 'original_plan_context_mismatch'):
            b.health(e, 'a' * 32, now, expected_plan_record=expected)
if __name__ == '__main__':
    unittest.main(verbosity=2)

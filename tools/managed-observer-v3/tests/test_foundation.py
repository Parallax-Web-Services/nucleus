"""Offline only: real frozen methods with synthetic private records/fake bridge/SSH."""
import ast, copy, hashlib, importlib.util, json, os, stat, sys, tempfile, types, unittest
from pathlib import Path
SOURCE_DIR = Path(__file__).resolve().parent.parent / 'source'
REFERENCE_DIR = Path(__file__).resolve().parent.parent / 'reference'
from unittest.mock import patch

def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module
w = load('wrapper', str(SOURCE_DIR / 'alpha-managed-foundation-readonly.py'))
d = load('frozen_durability', str(REFERENCE_DIR / 'legacy-durability.py'))
b = load('frozen_bridge', str(SOURCE_DIR / 'alpha-managed-health-bridge.py'))
l = load('frozen_lifecycle', str(REFERENCE_DIR / 'legacy-lifecycle.py'))

class Fixture:

    def __init__(self):
        self.tmp = tempfile.TemporaryDirectory(prefix='nebula-managed-ro-test-', dir='/root')
        self.root = Path(self.tmp.name)
        self.root.chmod(448)
        self.work = self.root / 'plan'
        self.work.mkdir(mode=448)
        self.ledger = self.work / 'durability'
        self.ledger.mkdir(mode=448)
        self.lock = self.root / 'bootstrap.lock'
        self.lock.write_bytes(b'')
        self.lock.chmod(384)
        self.fd = os.open(self.lock, os.O_RDWR | os.O_NOFOLLOW)
        self.held = d.identity(os.fstat(self.fd))
        (self.work / 'guest-known-hosts').write_bytes(b'192.0.2.7 ssh-ed25519 SYNTHETIC-PUBLIC-HOSTKEY\n')
        (self.work / 'guest-known-hosts').chmod(384)
        baseline = {'schema_version': 1, 'run_id': 'a' * 12, 'journal_directory': d.identity(self.ledger.lstat())[:6]}
        for name in w.COMPLETED_DURABILITY_RECORDS:
            value = {**baseline, **(w.EXPECTED if name == 'cluster-postcheck.json' else {})}
            (self.ledger / name).write_text(json.dumps(value))
            (self.ledger / name).chmod(384)
        self.before = {x.name: x.read_bytes() for x in self.ledger.iterdir()}
        self.calls = []
        self.health_ready = True
        self.local_marker = 'original-alpha-local-engine'
        self.job = None
        self.mutate = None
        self.answer = copy.deepcopy(w.EXPECTED)
        fixture = self

        class Base:

            def __init__(self, runner):
                self.work = fixture.work
                self.plan = {'new_domain_uuid': '00000000-0000-4000-8000-000000000001', 'run_id': 'a' * 12, 'proposed_name': 'nebula-control-' + 'a' * 12, 'network': {'uuid': '00000000-0000-4000-8000-000000000002', 'subnet': '192.0.2.0/24', 'name': 'default'}}
                self.state = {'mac': '52:54:00:00:00:01'}
                self.runner = runner

            def guard(self, health=True, volume_exception=None):
                if hasattr(self, 'external_guard'):
                    self.external_guard()
                w.need(fixture.local_marker == 'original-alpha-local-engine', 'original_local_engine_changed')
                if health:
                    self.external_health()

        class Bridge:
            m = types.SimpleNamespace(private_dir=l.private_dir, read=l.read)

            def binding(self, job):
                w.need(job.work == fixture.work, 'unchanged_original_plan_required')

            def external_health(self, job):
                w.need(fixture.health_ready, 'managed_health_stale')

            def lifecycle(self, runner=None):
                cls = b.lifecycle_class(types.SimpleNamespace(Lifecycle=Base), self)
                fixture.job = cls(runner)
                return fixture.job
        self.bridge = Bridge()

    def runner(self, args, label, timeout=60, input_bytes=None, pass_fds=()):
        self.calls.append((args, label, timeout))
        if self.mutate:
            self.mutate()
        return json.dumps(self.answer).encode()

    def check(self):
        return w.check_composition(self.bridge, d, self.runner, self.fd, self.lock, self.held)

    def unchanged(self):
        return self.before == {x.name: x.read_bytes() for x in self.ledger.iterdir()}

    def close(self):
        os.close(self.fd)
        self.tmp.cleanup()

@unittest.skipUnless(os.geteuid() == 0, 'root-private synthetic records')
class CompositionTests(unittest.TestCase):

    def fixture(self):
        f = Fixture()
        self.addCleanup(f.close)
        return f

    def test_real_dynamic_bridge_class_breaks_naive_module_lookup_but_explicit_adapter_works(self):
        f = self.fixture()
        job = f.bridge.lifecycle(runner=f.runner)
        self.assertEqual(job.__class__.__module__, b.__name__)
        with self.assertRaises(AttributeError):
            d.Durability(job, job.work / 'durability')
        adapter = w.readonly_adapter(d, job, f.bridge.m)
        self.assertIs(adapter.m, f.bridge.m)
        self.assertIs(type(adapter).guest_execute, d.Durability.guest_execute)
        self.assertIs(type(adapter).journal_guard, d.Durability.journal_guard)
        self.assertTrue(f.unchanged())

    def test_full_composition_runs_only_inherited_readonly_guest_payload_and_preserves_ledger(self):
        f = self.fixture()
        with patch.object(d.Durability, 'record', side_effect=AssertionError('ledger write forbidden')):
            result = f.check()
        self.assertEqual(result['status'], 'passed')
        self.assertTrue(result['original_alpha_local_engine_guard_preserved'])
        self.assertTrue(result['durability_ledger_not_written'])
        self.assertFalse(result['proof_writer_started'])
        self.assertEqual(len(f.calls), 1)
        self.assertEqual(f.calls[0][0][0], 'ssh')
        self.assertEqual(f.calls[0][2], 40)
        self.assertIn('StrictHostKeyChecking=yes', f.calls[0][0])
        self.assertTrue(f.unchanged())

    def test_stale_managed_health_never_falls_back_to_old_health_or_executes_guest(self):
        f = self.fixture()
        f.health_ready = False
        with self.assertRaisesRegex(w.Refused, 'managed_health_stale'):
            f.check()
        self.assertEqual(f.calls, [])
        self.assertTrue(f.unchanged())

    def test_healthy_remote_owner_cannot_waive_original_alpha_local_engine_guard(self):
        f = self.fixture()
        f.local_marker = 'changed'
        with self.assertRaisesRegex(w.Refused, 'original_local_engine_changed'):
            f.check()
        self.assertEqual(f.calls, [])
        self.assertTrue(f.unchanged())

    def test_new_unknown_durability_record_is_preserved_and_never_adopted(self):
        f = self.fixture()
        foreign = f.ledger / 'foreign.json'
        foreign.write_bytes(b'FOREIGN')
        foreign.chmod(384)
        with self.assertRaisesRegex(d.Refused, 'unknown_durability_record'):
            f.check()
        self.assertEqual(foreign.read_bytes(), b'FOREIGN')
        self.assertEqual(f.calls, [])

    def test_ledger_modified_during_guest_proof_is_refused(self):
        f = self.fixture()
        f.mutate = lambda : (f.ledger / 'baseline.json').write_bytes(b'FOREIGN')
        with self.assertRaisesRegex(d.Refused, 'durability_record_changed'):
            f.check()
        self.assertEqual((f.ledger / 'baseline.json').read_bytes(), b'FOREIGN')

    def test_bootstrap_lock_replacement_is_refused_after_guest_proof(self):
        f = self.fixture()

        def changed():
            replacement = f.root / 'foreign-lock'
            replacement.write_bytes(b'')
            replacement.chmod(384)
            os.replace(replacement, f.lock)
        f.mutate = changed
        with self.assertRaisesRegex(d.Refused, 'lifecycle_lock_changed'):
            f.check()
        self.assertTrue(f.unchanged())

    def test_nonexact_cluster_answer_is_not_success(self):
        f = self.fixture()
        f.answer['customer_or_unrelated_pod_count'] = 1
        with self.assertRaisesRegex(w.Refused, 'accepted_readonly_postcheck_failed'):
            f.check()
        self.assertTrue(f.unchanged())

    def test_original_payload_requires_exact_13flags_and_accepted_source(self):
        self.assertIn('7fe61c84b6e5167be8658e66c70063463f52baa7cc0de401f9bb83257242612c', d.CLUSTER_POSTCHECK)
        self.assertIn('accepted_phase_and_13_flags_unchanged', d.CLUSTER_POSTCHECK)
        self.assertNotIn('.smoke(', d.CLUSTER_POSTCHECK)
        self.assertNotIn('.record(', d.CLUSTER_POSTCHECK)

    def test_absent_durability_directory_is_not_created_or_treated_as_empty(self):
        f = self.fixture()
        for path in f.ledger.iterdir():
            path.unlink()
        f.ledger.rmdir()
        with self.assertRaisesRegex(w.Refused, 'existing_completed_durability_required'):
            f.check()
        self.assertFalse(f.ledger.exists())
        self.assertEqual(f.calls, [])

    def test_partial_durability_record_set_is_not_accepted_as_completed(self):
        f = self.fixture()
        (f.ledger / 'cluster-postcheck.json').unlink()
        with self.assertRaisesRegex(w.Refused, 'completed_durability_record_set_required'):
            f.check()
        self.assertEqual(f.calls, [])

    def test_reverted_durability_is_not_accepted(self):
        f = self.fixture()
        record = f.ledger / 'rolled-back.json'
        record.write_bytes((f.ledger / 'baseline.json').read_bytes())
        record.chmod(384)
        with self.assertRaisesRegex(w.Refused, 'completed_durability_record_set_required'):
            f.check()
        self.assertTrue(record.exists())
        self.assertEqual(f.calls, [])

    def test_historical_false_postcheck_cannot_be_relabelled_by_fresh_ro_result(self):
        f = self.fixture()
        path = f.ledger / 'cluster-postcheck.json'
        value = json.loads(path.read_bytes())
        value['ready_node_count'] = 0
        path.write_text(json.dumps(value))
        with self.assertRaisesRegex(w.Refused, 'historical_accepted_postcheck_required'):
            f.check()
        self.assertEqual(f.calls, [])

    def test_constructor_ast_diff_is_only_explicit_verified_module_binding(self):
        original = ast.parse(Path(str(REFERENCE_DIR / 'legacy-durability.py')).read_text())
        cls = next((n for n in original.body if isinstance(n, ast.ClassDef) and n.name == 'Durability'))
        expected = next((n for n in cls.body if isinstance(n, ast.FunctionDef) and n.name == '__init__'))
        wrapper = ast.parse(Path(str(SOURCE_DIR / 'alpha-managed-foundation-readonly.py')).read_text())
        factory = next((n for n in wrapper.body if isinstance(n, ast.FunctionDef) and n.name == 'readonly_adapter'))
        cls = next((n for n in factory.body if isinstance(n, ast.ClassDef)))
        actual = next((n for n in cls.body if isinstance(n, ast.FunctionDef) and n.name == '__init__'))

        class Normalize(ast.NodeTransformer):

            def visit_Attribute(self, node):
                self.generic_visit(node)
                return ast.copy_location(ast.Name(id=node.attr, ctx=node.ctx), node) if isinstance(node.value, ast.Name) and node.value.id == 'd' else node

            def visit_Assign(self, node):
                self.generic_visit(node)
                if any((isinstance(x, ast.Attribute) and isinstance(x.value, ast.Name) and (x.value.id == 'self') and (x.attr == 'm') for x in node.targets)):
                    node.value = ast.Name(id='VERIFIED_LIFECYCLE_MODULE', ctx=ast.Load())
                return node
        self.assertEqual(ast.dump(Normalize().visit(copy.deepcopy(expected)), include_attributes=False), ast.dump(Normalize().visit(copy.deepcopy(actual)), include_attributes=False))

class BudgetTests(unittest.TestCase):

    def test_each_command_is_capped_by_remaining_total_budget(self):
        seen = []
        common = types.SimpleNamespace(command=lambda *a, **k: seen.append(k) or b'OK')
        with patch.object(w.time, 'monotonic', side_effect=[100, 184]):
            runner = w.BoundedRunner(common, Path('/synthetic'))
            self.assertEqual(runner(['true'], 'read', timeout=60), b'OK')
        self.assertEqual(seen[0]['timeout'], 6)

    def test_expired_budget_never_launches_a_command(self):
        common = types.SimpleNamespace(command=lambda *a, **k: (_ for _ in ()).throw(AssertionError('must not run')))
        with patch.object(w.time, 'monotonic', side_effect=[100, 191]):
            runner = w.BoundedRunner(common, Path('/synthetic'))
            with self.assertRaisesRegex(w.Refused, 'readonly_check_budget_expired'):
                runner(['true'], 'read')

    def test_command_count_is_bounded(self):
        common = types.SimpleNamespace(command=lambda *a, **k: b'OK')
        with patch.object(w.time, 'monotonic', return_value=100):
            runner = w.BoundedRunner(common, Path('/synthetic'))
            runner.calls = 128
            with self.assertRaisesRegex(w.Refused, 'readonly_command_count_bound'):
                runner(['true'], 'read')

@unittest.skipUnless(os.geteuid() == 0, 'root-private synthetic source custody')
class SourceCustodyTests(unittest.TestCase):

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix='nebula-ro-source-fixture-', dir='/root')
        self.root = Path(self.tmp.name)
        self.root.chmod(448)

    def tearDown(self):
        self.tmp.cleanup()

    def source(self):
        p = self.root / 'public.py'
        raw = b'VALUE = 1\n'
        p.write_bytes(raw)
        p.chmod(384)
        return (p, hashlib.sha256(raw).hexdigest())

    def test_wrong_source_pin_is_never_executed(self):
        (p, pin) = self.source()
        with self.assertRaisesRegex(w.Refused, 'frozen_source_changed'):
            with w.pinned_source(p, '0' * 64, 'fixture_wrong'):
                self.fail('executed')

    def test_verified_byte_buffer_load_and_replacement_postcheck(self):
        (p, pin) = self.source()
        with self.assertRaisesRegex(w.Refused, 'frozen_source_changed_after_check'):
            with w.pinned_source(p, pin, 'fixture_good') as module:
                self.assertEqual(module.VALUE, 1)
                replacement = self.root / 'foreign'
                replacement.write_bytes(b'VALUE=2\n')
                replacement.chmod(384)
                os.replace(replacement, p)
                self.assertEqual(module.VALUE, 1)
        self.assertEqual(p.read_bytes(), b'VALUE=2\n')

    def test_nonprivate_mode_refuses_source_load(self):
        (p, pin) = self.source()
        p.chmod(420)
        with self.assertRaisesRegex(w.Refused, 'private_frozen_source_required'):
            with w.pinned_source(p, pin, 'fixture_nonprivate'):
                self.fail('executed')
if __name__ == '__main__':
    unittest.main()

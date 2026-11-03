import importlib.util, signal, time, types, unittest
from pathlib import Path
SOURCE_DIR = Path(__file__).resolve().parent.parent / 'source'
REFERENCE_DIR = Path(__file__).resolve().parent.parent / 'reference'
from unittest.mock import patch
spec = importlib.util.spec_from_file_location('r', str(SOURCE_DIR / 'controller-retirement.py'))
r = importlib.util.module_from_spec(spec)
spec.loader.exec_module(r)

class RetirementGuards(unittest.TestCase):

    def fixture(self):
        q = types.SimpleNamespace(private=lambda p: True, no_pending_signals=lambda pid: None)
        job = r.Retirement(q, Path('/synthetic-request'), Path('/synthetic-receipt'))
        controllers = {str(i): {'parent': {'pid': i, 'start': 10 * i}, 'outer': {'pid': 99}} for i in range(1, 5)}
        job.job = types.SimpleNamespace(data={'controllers': controllers})
        job.data = {'phase': 'planned', 'checked_at_unix': int(time.time()), 'config': {'health_overlay_id': 'a' * 32, 'evidence_report': '/synthetic-evidence'}, 'evidence_report': True, 'retired': [], 'pending_retirement': None, 'children': {str(i): {} for i in range(1, 5)}}
        job.load = lambda : None
        job.save = lambda : None
        job.guard = lambda : None
        job.remaining = lambda : None
        return job

    def contexts(self, health=None, survival=None):
        return patch.multiple(r, remote_health=health or (lambda *a: True), surviving_after=survival or (lambda *a: True), dead=lambda *a: True)

    def test_kill_only_exact_paused_parent_pidfds(self):
        job = self.fixture()
        signals = []
        with self.contexts(), patch.object(r.os, 'pidfd_open', side_effect=lambda pid, *a: pid + 100), patch.object(r.os, 'close'), patch.object(r.signal, 'pidfd_send_signal', side_effect=lambda fd, s, *a: signals.append((fd, s))):
            result = job.retire(True)
        self.assertEqual(signals, [(i + 100, signal.SIGKILL) for i in range(1, 5)])
        self.assertEqual(result['status'], 'retired')
        self.assertFalse(result['engine_or_tunnel_durability_claimed'])

    def test_irreversible_ack_required_before_any_action(self):
        job = self.fixture()
        with patch.object(r.signal, 'pidfd_send_signal') as send, self.assertRaisesRegex(r.Refused, 'explicit_irreversible_retirement_required'):
            job.retire(False)
        send.assert_not_called()

    def test_stale_plan_refuses_without_signal(self):
        job = self.fixture()
        job.data['checked_at_unix'] -= 121
        with patch.object(r.signal, 'pidfd_send_signal') as send, self.assertRaisesRegex(r.Refused, 'retirement_plan_expired_or_phase_differs'):
            job.retire(True)
        send.assert_not_called()

    def test_failed_prehealth_sends_no_signal(self):
        job = self.fixture()
        with self.contexts(health=lambda *a: (_ for _ in ()).throw(r.Refused('managed_health_unavailable'))), patch.object(r.os, 'pidfd_open', return_value=99), patch.object(r.os, 'close'), patch.object(r.signal, 'pidfd_send_signal') as send, self.assertRaises(r.Refused):
            job.retire(True)
        send.assert_not_called()

    def test_failed_posthealth_preserves_pending_and_remaining_paused(self):
        job = self.fixture()
        signals = []
        calls = []

        def health(*a):
            calls.append(True)
            if len(calls) == 2:
                raise r.Refused('managed_health_unavailable')
        with self.contexts(health=health), patch.object(r.os, 'pidfd_open', side_effect=lambda pid, *a: pid + 100), patch.object(r.os, 'close'), patch.object(r.signal, 'pidfd_send_signal', side_effect=lambda fd, s, *a: signals.append((fd, s))), self.assertRaises(r.Refused):
            job.retire(True)
        self.assertEqual(signals, [(101, signal.SIGKILL)])
        self.assertEqual(job.data['pending_retirement'], '1')
        self.assertEqual(job.data['retired'], [])

    def test_failed_survival_stops_after_exact_first_parent(self):
        job = self.fixture()
        signals = []
        with self.contexts(survival=lambda *a: (_ for _ in ()).throw(r.Refused('preserved_child_did_not_survive'))), patch.object(r.os, 'pidfd_open', return_value=99), patch.object(r.os, 'close'), patch.object(r.signal, 'pidfd_send_signal', side_effect=lambda fd, s, *a: signals.append(s)), self.assertRaises(r.Refused):
            job.retire(True)
        self.assertEqual(signals, [signal.SIGKILL])
        self.assertEqual(job.data['retired'], [])

    def test_explicit_resume_plan_reconciles_only_known_pending_exit(self):
        job = self.fixture()
        job.data['phase'] = 'retiring'
        job.data['pending_retirement'] = '1'
        with self.contexts(), patch.object(r.signal, 'pidfd_send_signal') as send:
            result = job.resume_plan()
        self.assertEqual(result['retired_parent_count'], 1)
        self.assertEqual(job.data['phase'], 'resume-planned')
        send.assert_not_called()

    def test_resume_never_rekills_retired_parent(self):
        job = self.fixture()
        job.data['phase'] = 'resume-planned'
        job.data['retired'] = ['1']
        signals = []
        with self.contexts(), patch.object(r.os, 'pidfd_open', side_effect=lambda pid, *a: pid + 100), patch.object(r.os, 'close'), patch.object(r.signal, 'pidfd_send_signal', side_effect=lambda fd, s, *a: signals.append(fd)):
            job.retire(True)
        self.assertEqual(signals, [102, 103, 104])

    def test_wrong_reparent_target_refuses(self):
        before = {'process': {'pid': 11, 'start': 110, 'ppid': 1, 'cgroup': 'scope'}, 'stdio': {'safe': True}}
        after = {'process': {**before['process'], 'ppid': 77}, 'stdio': before['stdio']}
        q = types.SimpleNamespace(stable=lambda p: p, process=lambda pid: {'pid': 99}, child=lambda pid: after)
        with patch.object(r, 'dead', return_value=False), self.assertRaisesRegex(r.Refused, 'child_not_reparented_to_proved_outer'):
            r.surviving_after(q, {'outer': {'pid': 99}}, {'11': before})

    def test_changed_child_cgroup_refuses_even_reparented(self):
        before = {'process': {'pid': 11, 'start': 110, 'ppid': 1, 'cgroup': 'scope'}, 'stdio': {'safe': True}}
        after = {'process': {**before['process'], 'ppid': 99, 'cgroup': 'unknown'}, 'stdio': before['stdio']}
        q = types.SimpleNamespace(stable=lambda p: p, process=lambda pid: {'pid': 99}, child=lambda pid: after)
        with patch.object(r, 'dead', return_value=False), self.assertRaisesRegex(r.Refused, 'reparented_child_context_changed'):
            r.surviving_after(q, {'outer': {'pid': 99}}, {'11': before})

    def signal_status(self, thread='0', shared='0', tracer='0', role='owner'):
        text = 'SigPnd:\t' + thread + '\nShdPnd:\t' + shared + '\nTracerPid:\t' + tracer + '\n'
        with patch.object(Path, 'read_text', return_value=text):
            r.paused_signals({'parent': {'pid': 1}, 'role': role})

    def test_only_expected_owner_sigchld_pending_is_accepted(self):
        bit = format(1 << signal.SIGCHLD - 1, 'x')
        self.signal_status(thread=bit)
        self.signal_status(shared=bit)

    def test_pending_sigchld_without_known_owner_departure_scope_refuses(self):
        with self.assertRaisesRegex(r.Refused, 'paused_parent_unreviewed_pending_signal'):
            self.signal_status(thread=format(1 << signal.SIGCHLD - 1, 'x'), role='member')

    def test_other_pending_signals_refuse(self):
        for sig in [signal.SIGTERM, signal.SIGINT, signal.SIGHUP, signal.SIGKILL]:
            with self.assertRaisesRegex(r.Refused, 'paused_parent_unreviewed_pending_signal'):
                self.signal_status(thread=format(1 << sig - 1, 'x'))

    def test_tracer_refuses_even_with_allowed_chld(self):
        with self.assertRaisesRegex(r.Refused, 'paused_parent_traced_or_signal_shape_differs'):
            self.signal_status(thread=format(1 << signal.SIGCHLD - 1, 'x'), tracer='77')
if __name__ == '__main__':
    unittest.main(verbosity=2)

"""Offline only: fixed own-unit protocol snapshots and anonymous-output custody."""
import copy, fcntl, hashlib, importlib.util, itertools, json, os, subprocess, sys, time, types, unittest
from pathlib import Path
SOURCE_DIR = Path(__file__).resolve().parent.parent / 'source'
REFERENCE_DIR = Path(__file__).resolve().parent.parent / 'reference'
from unittest.mock import patch
HERE = Path(__file__).parent
spec = importlib.util.spec_from_file_location('compat_managed_fixture', HERE / 'test_managed_source.py')
fixture = importlib.util.module_from_spec(spec)
spec.loader.exec_module(fixture)
m = fixture.m

def complete():
    value = {key: '' for key in m.SYSTEMD_FIELDS}
    value.update(Id=m.COORDINATOR_UNIT, LoadState='loaded', MainPID='123', InvocationID='a' * 32, NeedDaemonReload='no')
    return value

def encoded(value):
    return ''.join((k + '=' + v + '\n' for (k, v) in value.items())).encode()

class Protocol:

    def __init__(self, first, second=None, answers=None):
        self.first = first
        self.second = copy.deepcopy(first) if second is None else second
        self.answers = answers or {}
        self.calls = []
        self.show_count = 0
        self.timeouts = []

    def run(self, args, **kw):
        self.calls.append(args)
        self.timeouts.append(kw['timeout'])
        assert kw['stdin'] == subprocess.DEVNULL and kw['stderr'] == subprocess.DEVNULL and (kw['env'] == {'PATH': '/usr/bin:/bin', 'LC_ALL': 'C'})
        fd = kw['stdout']
        seals = fcntl.fcntl(fd, fcntl.F_GET_SEALS)
        assert seals == fcntl.F_SEAL_GROW | fcntl.F_SEAL_SHRINK | fcntl.F_SEAL_SEAL
        if args[0] == '/usr/bin/systemctl':
            assert args == ['/usr/bin/systemctl', 'show', m.COORDINATOR_UNIT, '--no-pager', *['--property=' + k for k in m.SYSTEMD_FIELDS]]
            raw = self.first if not self.show_count else self.second
            self.show_count += 1
            raw = encoded(raw) if isinstance(raw, dict) else raw
        else:
            assert args[:6] == ['/usr/bin/busctl', '--system', 'get-property', 'org.freedesktop.systemd1', m.SYSTEMD_BUS_OBJECT, 'org.freedesktop.systemd1.Service']
            assert len(args) == 7 and args[6] in m.EMPTY_EXEC_FIELDS
            raw = self.answers.get(args[-1], b'a(sasbttttuii) 0\n')
            if isinstance(raw, BaseException):
                raise raw
        if isinstance(raw, tuple):
            (rc, raw) = raw
        else:
            rc = 0
        os.write(fd, raw)
        return types.SimpleNamespace(returncode=rc)

    def execute(self):
        with patch.object(m.subprocess, 'run', side_effect=self.run):
            return m.systemd_state()

class Completion(unittest.TestCase):

    def test_complete_output_unchanged_and_never_queries_bus(self):
        expected = complete()
        p = Protocol(expected)
        self.assertEqual(p.execute(), expected)
        self.assertEqual(len(p.calls), 1)

    def test_all_31_nonempty_missing_subsets_exact_queries_and_authoritative_empty(self):
        expected = complete()
        for mask in range(1, 32):
            missing = {v for (i, v) in enumerate(m.EMPTY_EXEC_FIELDS) if mask & 1 << i}
            first = {k: v for (k, v) in expected.items() if k not in missing}
            p = Protocol(first)
            with self.subTest(mask=mask):
                self.assertEqual(p.execute(), expected)
                self.assertEqual([x[-1] for x in p.calls if x[0] == '/usr/bin/busctl'], [x for x in m.EMPTY_EXEC_FIELDS if x in missing])
                self.assertEqual(p.show_count, 2)

    def test_nonempty_present_values_are_never_normalized_or_queried(self):
        for prop in m.EMPTY_EXEC_FIELDS:
            expected = complete()
            expected[prop] = 'FORBIDDEN-COMMAND'
            p = Protocol(expected)
            with self.subTest(prop=prop):
                self.assertEqual(p.execute()[prop], 'FORBIDDEN-COMMAND')
                self.assertEqual(len(p.calls), 1)

    def test_present_nonempty_property_still_rejected_by_unchanged_checked_unit(self):
        for prop in m.EMPTY_EXEC_FIELDS:
            f = fixture.ManagedFixture()
            try:
                f.loaded[prop] = 'FORBIDDEN-COMMAND'
                with self.subTest(prop=prop), self.assertRaises(m.Refused):
                    m.checked_unit(f.config)
                f.native_mock.assert_not_called()
            finally:
                f.close()

    def test_unknown_missing_property_refuses_without_bus_queries(self):
        for field in [k for k in m.SYSTEMD_FIELDS if k not in m.EMPTY_EXEC_FIELDS]:
            first = complete()
            first.pop(field)
            p = Protocol(first)
            with self.subTest(field=field), self.assertRaises(m.Refused):
                p.execute()
            self.assertEqual(len(p.calls), 1)

    def test_wrong_own_unit_never_receives_empty_completion(self):
        first = complete()
        first.pop('ExecStop')
        first['Id'] = 'foreign.service'
        p = Protocol(first)
        with self.assertRaises(m.Refused):
            p.execute()
        self.assertEqual(len(p.calls), 1)

    def test_wrong_type_nonempty_extra_payload_or_noncanonical_value_refuses(self):
        for prop in m.EMPTY_EXEC_FIELDS:
            for raw in [b'as 0\n', b'a(sasbttttuii) 1 /bin/false\n', b'a(sasbttttuii) 0 0\n', b'a(sasbttttuii) 0\nSECOND', b'', b'0\n', b'a(sasbttttuii) 00\n']:
                first = complete()
                first.pop(prop)
                with self.subTest(prop=prop, raw=raw), self.assertRaises(m.Refused):
                    Protocol(first, answers={prop: raw}).execute()

    def test_query_nonzero_and_timeout_refuse(self):
        for result in [(1, b'a(sasbttttuii) 0\n'), subprocess.TimeoutExpired('fixed-busctl', 0.1), OSError('synthetic')]:
            first = complete()
            first.pop('ExecStop')
            with self.subTest(kind=type(result).__name__), self.assertRaises((m.Refused, subprocess.TimeoutExpired, OSError)):
                Protocol(first, answers={'ExecStop': result}).execute()

    def test_any_overlapping_property_drift_refuses(self):
        first = complete()
        first.pop('ExecStop')
        for prop in first:
            second = copy.deepcopy(first)
            second[prop] += 'CHANGED'
            with self.subTest(prop=prop), self.assertRaises(m.Refused):
                Protocol(first, second).execute()

    def test_missing_presence_change_refuses_even_when_new_value_is_empty(self):
        first = complete()
        first.pop('ExecStop')
        with self.assertRaises(m.Refused):
            Protocol(first, complete()).execute()

    def test_duplicate_unknown_or_malformed_systemctl_lines_refuse(self):
        for extra in [b'Id=nucleus-coordinator.service\n', b'Unknown=x\n', b'NO-EQUALS\n']:
            with self.subTest(extra=extra), self.assertRaises(m.Refused):
                Protocol(encoded(complete()) + extra).execute()

    def test_late_fifth_failure_never_returns_partial_completion(self):
        first = {k: v for (k, v) in complete().items() if k not in m.EMPTY_EXEC_FIELDS}
        p = Protocol(first, answers={m.EMPTY_EXEC_FIELDS[-1]: b'a(sasbttttuii) 1 bad\n'})
        with self.assertRaises(m.Refused):
            p.execute()
        self.assertEqual(p.show_count, 1)
        self.assertEqual(len(p.calls), 6)

    def test_all_subcommands_share_one_decreasing_two_second_budget(self):
        first = complete()
        first.pop('ExecStop')
        p = Protocol(first)
        ticks = iter([100, 100.1, 100.2, 100.3, 100.4, 100.5, 100.6, 100.7, 100.8, 100.9, 101])
        with patch.object(m.time, 'monotonic', side_effect=lambda : next(ticks)):
            p.execute()
        self.assertTrue(all((0 < x <= 2 for x in p.timeouts)))
        self.assertEqual(p.timeouts, sorted(p.timeouts, reverse=True))

    def test_exhausted_aggregate_budget_launches_no_later_command(self):
        first = complete()
        first.pop('ExecStop')
        p = Protocol(first)
        ticks = iter([100, 100.1, 100.2, 102.1])
        with patch.object(m.time, 'monotonic', side_effect=lambda : next(ticks)), self.assertRaises(m.Refused):
            p.execute()
        self.assertEqual(len(p.calls), 1)

class AnonymousBoundedCapture(unittest.TestCase):

    def test_actual_child_emits_exact_positive_audit_protocol(self):
        raw = m._read_systemd_output(['/usr/bin/python3', '-I', '-c', 'import os;os.write(1,b"a(sasbttttuii) 0\\n")'], 128, time.monotonic() + 2)
        self.assertEqual(raw, b'a(sasbttttuii) 0\n')

    def test_actual_output_beyond_fixed_anonymous_capacity_refuses(self):
        script = 'import os;os.write(1,b"X"*1000000)'
        with self.assertRaises(m.Refused):
            m._read_systemd_output(['/usr/bin/python3', '-I', '-c', script], 128, time.monotonic() + 2)

    def test_empty_actual_child_output_refuses(self):
        with self.assertRaises(m.Refused):
            m._read_systemd_output(['/usr/bin/python3', '-I', '-c', 'pass'], 128, time.monotonic() + 2)

    def test_actual_timeout_is_bounded_and_reaps_own_child(self):
        started = time.monotonic()
        with self.assertRaises(subprocess.TimeoutExpired):
            m._read_systemd_output(['/usr/bin/python3', '-I', '-c', 'import time;time.sleep(20)'], 128, started + 0.15)
        self.assertLess(time.monotonic() - started, 2)
if __name__ == '__main__':
    unittest.main()

"""Offline managed-coordinator admission, restart, and HTTP custody fixtures.

Root fixtures use only newly created /run directories and a synthetic /proc tree.
No service, production path, coordinator executable, or identity command is run.
"""
import copy
import errno
import hashlib
import http.server
import importlib.util
import json
import os
import stat
import sys
import tempfile
import threading
import time
import types
import unittest
from contextlib import ExitStack
from pathlib import Path
SOURCE_DIR = Path(__file__).resolve().parent.parent / 'source'
REFERENCE_DIR = Path(__file__).resolve().parent.parent / 'reference'
from unittest.mock import patch
sys.dont_write_bytecode = True
_spec = importlib.util.spec_from_file_location('managed_source_under_test', SOURCE_DIR / 'producer.py')
m = importlib.util.module_from_spec(_spec)
sys.modules[_spec.name] = m
_spec.loader.exec_module(m)

def digest(raw):
    return hashlib.sha256(raw).hexdigest()

class ManagedFixture:
    """Real permissions/symlinks with only systemd/account discovery mocked."""
    (uid, gid) = (60041, 60042)
    ports = [32155, 32156]

    def __init__(self):
        self.temp = tempfile.TemporaryDirectory(prefix='nebula-managed-source-test-', dir='/run')
        self.root = Path(self.temp.name)
        self.root.chmod(448)
        self.stack = ExitStack()
        self.unit = self.root / 'systemd/nucleus-coordinator.service'
        self.enable = self.root / 'systemd/multi-user.target.wants/nucleus-coordinator.service'
        self.binary = self.root / 'code/nucleus'
        self.home = self.root / 'state'
        self.log = self.root / 'log/startup.log'
        self.proc = self.root / 'proc'
        self.config_path = self.root / 'config/producer.json'
        for directory in [self.unit.parent, self.enable.parent, self.binary.parent, self.home, self.log.parent, self.proc / 'net', self.config_path.parent]:
            directory.mkdir(parents=True, exist_ok=True)
            directory.chmod(448)
        os.chown(self.home, self.uid, self.gid)
        self.binary.write_bytes(b'OFFLINE TEST FIXTURE; NEVER EXECUTE\n')
        self.binary.chmod(365)
        self.binary.parent.chmod(365)
        self.argv = [str(self.binary), 'run', '--no-open', '--ui', '127.0.0.1:' + str(self.ports[0]), '--listen', '127.0.0.1:' + str(self.ports[1])]
        self.command = b'\x00'.join((arg.encode() for arg in self.argv)) + b'\x00'
        self.unit_text = '\n'.join(['[Unit]', 'Description=Offline managed-source fixture', '[Service]', 'User=' + m.COORDINATOR_ACCOUNT, 'Group=' + m.COORDINATOR_ACCOUNT, 'Type=simple', 'WorkingDirectory=' + str(self.home), 'Environment=NUCLEUS_HOME=' + str(self.home), 'Environment=HOME=' + str(self.home), 'ExecStart=' + ' '.join(self.argv), 'StandardOutput=truncate:' + str(self.log), 'StandardError=inherit', 'Restart=on-failure', 'KillMode=control-group', '[Install]', 'WantedBy=multi-user.target', ''])
        self.unit.write_text(self.unit_text)
        self.unit.chmod(420)
        self.enable.symlink_to(self.unit)
        self.loaded = {key: '' for key in m.SYSTEMD_FIELDS}
        self.loaded.update({'Id': m.COORDINATOR_UNIT, 'LoadState': 'loaded', 'ActiveState': 'active', 'SubState': 'running', 'UnitFileState': 'enabled', 'FragmentPath': str(self.unit), 'DropInPaths': '', 'NeedDaemonReload': 'no', 'Transient': 'no', 'ControlGroup': '/system.slice/' + m.COORDINATOR_UNIT, 'User': m.COORDINATOR_ACCOUNT, 'Group': m.COORDINATOR_ACCOUNT, 'Type': 'simple', 'WorkingDirectory': str(self.home), 'Environment': 'NUCLEUS_HOME=' + str(self.home) + ' HOME=' + str(self.home), 'StandardOutput': 'truncate', 'StandardError': 'inherit'})
        self.stack.enter_context(patch.multiple(m, UNIT_PATH=self.unit, ENABLE_PATH=self.enable, BINARY=self.binary, STATE_HOME=self.home, STARTUP_LOG=self.log, PROC=self.proc))
        self.stack.enter_context(patch.object(m, 'systemd_state', side_effect=lambda : dict(self.loaded)))
        self.account_mock = self.stack.enter_context(patch.object(m.pwd, 'getpwnam', return_value=types.SimpleNamespace(pw_uid=self.uid, pw_gid=self.gid)))
        self.native_mock = self.stack.enter_context(patch.object(m.subprocess, 'run', side_effect=OSError(errno.EROFS, 'legacy identity is forbidden')))
        self.restart(41001, 'a' * 64, 'a' * 32)
        s = self.home.stat()
        self.config = {'schema_version': 2, 'api_origin': 'http://127.0.0.1:' + str(self.ports[0]), 'fabric_id': 'f' * 64, 'local_node_id': 'd' * 64, 'coordinator': {'unit': m.COORDINATOR_UNIT, 'unit_sha256': digest(self.unit.read_bytes()), 'binary_sha256': digest(self.binary.read_bytes()), 'argv_sha256': digest(self.command), 'uid': self.uid, 'gid': self.gid, 'state_device': s.st_dev, 'state_inode': s.st_ino, 'loopback_ports': list(self.ports)}}
        self.config_path.write_text(json.dumps(self.config, sort_keys=True))
        self.config_path.chmod(384)

    def close(self):
        self.stack.close()
        self.temp.cleanup()

    def write_status(self, uid=None, gid=None):
        uid = self.uid if uid is None else uid
        gid = self.gid if gid is None else gid
        self.process.joinpath('status').write_text('Name:\toffline-fixture\nUid:\t' + '\t'.join(map(str, [uid] * 4)) + '\nGid:\t' + '\t'.join(map(str, [gid] * 4)) + '\n')

    def write_start(self, ticks):
        self.start = ticks
        self.process.joinpath('stat').write_text(str(self.pid) + ' (offline fixture) ' + ' '.join(['S'] + ['0'] * 18 + [str(ticks)]) + '\n')
        self.loaded['ExecMainStartTimestampMonotonic'] = str(ticks * 1000000 // os.sysconf('SC_CLK_TCK'))

    def write_log(self, token=None, extra=b''):
        token = self.token if token is None else token
        self.log.write_bytes(('Resource map: http://127.0.0.1:' + str(self.ports[0]) + '/#token=' + token + '\n').encode() + extra)
        self.log.chmod(384)
        os.chown(self.log, 0, 0)

    def listeners(self, entries=None, tcp6=None):
        entries = self.socket_entries if entries is None else entries
        header = 'sl local_address rem_address st tx_queue tr retrnsmt uid timeout inode\n'

        def row(address, inode):
            return '0: ' + address + ' 00000000:0000 0A 00000000:00000000 00:00000000 00000000 0 0 ' + str(inode) + ' 1\n'
        self.proc.joinpath('net/tcp').write_text(header + ''.join((row(a, i) for (a, i) in entries)))
        self.proc.joinpath('net/tcp6').write_text(header + ''.join((row(a, i) for (a, i) in tcp6 or [])))

    def restart(self, pid, token, invocation):
        (self.pid, self.token) = (pid, token)
        self.process = self.proc / str(pid)
        self.process.mkdir(exist_ok=True)
        self.process.joinpath('fd').mkdir(exist_ok=True)
        self.write_start(int(time.monotonic() * os.sysconf('SC_CLK_TCK')) - 100)
        self.write_status()
        self.process.joinpath('cmdline').write_bytes(self.command)
        self.process.joinpath('cgroup').write_text('0::/system.slice/' + m.COORDINATOR_UNIT + '\n')
        for (name, target) in [('exe', self.binary), ('fd/1', self.log), ('fd/2', self.log)]:
            path = self.process / name
            if os.path.lexists(path):
                path.unlink()
            path.symlink_to(target)
        self.socket_entries = [('0100007F:' + format(port, '04X'), 81000 + pid * 2 + i) for (i, port) in enumerate(self.ports)]
        for (i, (_, inode)) in enumerate(self.socket_entries):
            path = self.process / 'fd' / str(10 + i)
            if os.path.lexists(path):
                path.unlink()
            path.symlink_to('socket:[' + str(inode) + ']')
        self.listeners()
        self.write_log()
        self.loaded.update(MainPID=str(pid), InvocationID=invocation)

    def source(self):
        return m.ManagedSource(copy.deepcopy(self.config))

    def replace_same_bytes(self, path, mode):
        replacement = path.with_name(path.name + '.replacement')
        replacement.write_bytes(path.read_bytes())
        replacement.chmod(mode)
        os.replace(replacement, path)

@unittest.skipUnless(os.geteuid() == 0, 'isolated Linux-root metadata fixtures only')
class ManagedSourceTests(unittest.TestCase):

    def setUp(self):
        self.f = ManagedFixture()
        self.addCleanup(self.f.close)

    def source(self, resolve=False):
        source = self.f.source()
        self.addCleanup(source.close)
        return source.resolve() if resolve else source

    def test_snapshot_checks_real_metadata_links_and_both_owned_listeners(self):
        binding = self.source().snapshot()
        self.assertEqual(binding['listeners'], [(address, str(inode)) for (address, inode) in self.f.socket_entries])
        self.assertEqual(binding['home']['st_uid'], self.f.uid)
        self.assertEqual(binding['home']['st_gid'], self.f.gid)
        self.assertEqual(binding['unit']['loaded']['MainPID'], str(self.f.pid))
        self.assertEqual(m.load_config(self.f.config_path)[0], self.f.config)
        self.f.native_mock.assert_not_called()

    def test_restart_resolves_new_pid_invocation_and_token_without_config_rewrite(self):
        before = m.record(self.f.config_path)
        a = self.source(resolve=True)
        self.assertEqual(a.token, 'a' * 64)
        old_binding = copy.deepcopy(a.binding)
        self.f.restart(41002, 'b' * 64, 'b' * 32)
        with self.assertRaises(m.Refused):
            a.guard()
        a.close()
        b = self.source(resolve=True)
        self.assertEqual(b.token, 'b' * 64)
        self.assertNotEqual(b.binding['unit']['loaded']['MainPID'], old_binding['unit']['loaded']['MainPID'])
        self.assertNotEqual(b.binding['unit']['loaded']['InvocationID'], old_binding['unit']['loaded']['InvocationID'])
        self.assertEqual(m.record(self.f.config_path), before)
        self.assertNotIn('bearer_token', self.f.config)
        self.assertNotIn('process', self.f.config)
        self.f.native_mock.assert_not_called()

    def test_resolve_is_read_only_even_when_legacy_identity_would_raise_erofs(self):
        before = m.record(self.f.config_path)
        source = self.source(resolve=True)
        source.guard()
        self.assertEqual(list(self.f.home.iterdir()), [])
        self.assertEqual(m.record(self.f.config_path), before)
        self.f.native_mock.assert_not_called()
        source.close()
        self.assertIsNone(source.fd)
        self.assertIsNone(source.token)

    def test_pid_reuse_with_new_start_is_not_same_cohort(self):
        source = self.source(resolve=True)
        self.f.write_start(self.f.start + 1)
        with self.assertRaises(m.Refused):
            source.guard()

    def test_invocation_change_with_same_pid_and_start_is_refused(self):
        source = self.source(resolve=True)
        self.f.loaded['InvocationID'] = 'c' * 32
        with self.assertRaises(m.Refused):
            source.guard()

    def test_identical_unit_inode_replacement_during_collection_is_refused(self):
        source = self.source(resolve=True)
        self.f.replace_same_bytes(self.f.unit, 420)
        with self.assertRaises(m.Refused):
            source.guard()

    def test_enabled_link_replacement_or_wrong_target_is_refused(self):
        source = self.source(resolve=True)
        replacement = self.f.enable.with_name('replacement')
        replacement.symlink_to(self.f.unit)
        os.replace(replacement, self.f.enable)
        with self.assertRaises(m.Refused):
            source.guard()
        self.f.enable.unlink()
        self.f.enable.symlink_to(self.f.root / 'foreign-unit')
        with self.assertRaises(m.Refused):
            self.source().snapshot()

    def test_disabled_reload_dropin_or_wrong_unit_state_never_resolves(self):
        good = dict(self.f.loaded)
        cases = {'UnitFileState': 'disabled', 'NeedDaemonReload': 'yes', 'DropInPaths': '/foreign/dropin.conf', 'ActiveState': 'inactive', 'SubState': 'dead', 'Transient': 'yes', 'FragmentPath': '/foreign/unit', 'User': 'root', 'Group': 'root', 'ControlGroup': '/system.slice/other.service', 'ExecStartPre': '/foreign/helper'}
        for (key, value) in cases.items():
            with self.subTest(field=key):
                self.f.loaded = {**good, key: value}
                with self.assertRaises(m.Refused):
                    self.source().snapshot()
        self.f.loaded = good

    def test_unreviewed_unit_bytes_and_forbidden_helpers_are_refused(self):
        self.f.unit.write_text(self.f.unit_text + '# unreviewed change\n')
        with self.assertRaises(m.Refused):
            self.source().snapshot()
        for directive in ['ExecStartPre=/foreign/helper', 'EnvironmentFile=/foreign/env', 'ExecReload=/foreign/helper', 'StandardOutput=append:' + str(self.f.log)]:
            with self.subTest(directive=directive):
                text = self.f.unit_text.replace('[Service]\n', '[Service]\n' + directive + '\n')
                self.f.unit.write_text(text)
                self.f.config['coordinator']['unit_sha256'] = digest(text.encode())
                with self.assertRaises(m.Refused):
                    self.source().snapshot()

    def test_each_real_effective_saved_and_filesystem_uid_gid_is_checked(self):
        for label in ['Uid:', 'Gid:']:
            for index in range(4):
                with self.subTest(label=label, index=index):
                    self.f.write_status()
                    lines = self.f.process.joinpath('status').read_text().splitlines()
                    for (i, line) in enumerate(lines):
                        if line.startswith(label):
                            fields = line.split()[1:]
                            fields[index] = '0'
                            lines[i] = label + '\t' + '\t'.join(fields)
                    self.f.process.joinpath('status').write_text('\n'.join(lines) + '\n')
                    with self.assertRaises(m.Refused):
                        self.source().snapshot()
        self.f.write_status()

    def test_account_id_drift_and_process_cgroup_mismatch_are_refused(self):
        self.f.account_mock.return_value = types.SimpleNamespace(pw_uid=self.f.uid + 1, pw_gid=self.f.gid)
        with self.assertRaises(m.Refused):
            self.source().snapshot()
        self.f.account_mock.return_value = types.SimpleNamespace(pw_uid=self.f.uid, pw_gid=self.f.gid)
        self.f.process.joinpath('cgroup').write_text('0::/system.slice/foreign.service\n')
        with self.assertRaises(m.Refused):
            self.source().snapshot()

    def test_wrong_executable_or_changed_argv_is_refused(self):
        self.f.process.joinpath('cmdline').write_bytes(self.f.command + b'--foreign\x00')
        with self.assertRaises(m.Refused):
            self.source().snapshot()
        altered = self.f.command + b'--foreign\x00'
        self.f.config['coordinator']['argv_sha256'] = digest(altered)
        with self.assertRaises(m.Refused):
            self.source().snapshot()
        self.f.config['coordinator']['argv_sha256'] = digest(self.f.command)
        self.f.process.joinpath('cmdline').write_bytes(self.f.command)
        foreign = self.f.root / 'foreign-binary'
        foreign.write_bytes(self.f.binary.read_bytes())
        foreign.chmod(365)
        self.f.process.joinpath('exe').unlink()
        self.f.process.joinpath('exe').symlink_to(foreign)
        with self.assertRaises(m.Refused):
            self.source().snapshot()

    def test_binary_replacement_after_resolve_is_refused_even_with_identical_bytes(self):
        source = self.source(resolve=True)
        self.f.replace_same_bytes(self.f.binary, 365)
        with self.assertRaises(m.Refused):
            source.guard()

    def test_binary_changed_bytes_or_writable_parent_is_refused(self):
        self.f.binary.write_bytes(b'unreviewed code')
        with self.assertRaises(m.Refused):
            self.source().snapshot()
        self.f.binary.write_bytes(b'OFFLINE TEST FIXTURE; NEVER EXECUTE\n')
        self.f.binary.parent.chmod(493)
        with self.assertRaises(m.Refused):
            self.source().snapshot()

    def test_same_owner_mode_state_directory_replacement_requires_new_admission(self):
        self.f.home.rename(self.f.root / 'retained-state')
        self.f.home.mkdir(mode=448)
        os.chown(self.f.home, self.f.uid, self.f.gid)
        with self.assertRaises(m.Refused):
            self.source().snapshot()

    def test_missing_duplicate_foreign_wildcard_and_ipv6_listeners_are_refused(self):
        (a, b) = self.f.socket_entries
        cases = [([a], []), ([a, b, a], []), ([a, (b[0], b[1] + 999)], []), ([a, ('00000000:' + format(self.f.ports[1], '04X'), b[1])], []), ([a], [('00000000000000000000000001000000:' + format(self.f.ports[1], '04X'), b[1])])]
        for (entries, tcp6) in cases:
            with self.subTest(entries=entries, tcp6=tcp6):
                self.f.listeners(entries, tcp6)
                with self.assertRaises(m.Refused):
                    self.source().snapshot()
        self.f.listeners()

    def test_listener_inode_custody_transfer_mid_collection_is_refused(self):
        source = self.source(resolve=True)
        self.f.process.joinpath('fd/10').unlink()
        self.f.process.joinpath('fd/10').symlink_to('socket:[99999999]')
        with self.assertRaises(m.Refused):
            source.guard()

    def test_old_startup_log_cannot_supply_current_invocation_token(self):
        born_ns = time.time_ns() - time.monotonic_ns() + int(self.f.loaded['ExecMainStartTimestampMonotonic']) * 1000
        stale = born_ns - 5000000000
        os.utime(self.f.log, ns=(stale, stale))
        with self.assertRaises(m.Refused):
            self.source(resolve=True)

    def test_missing_ambiguous_or_wrong_port_token_is_refused_and_closed(self):
        good = self.f.log.read_bytes()
        for raw in [b'no startup token\n', good + good, good.replace(str(self.f.ports[0]).encode(), b'32157')]:
            with self.subTest(raw=raw[:30]):
                self.f.log.write_bytes(raw)
                source = self.source()
                with self.assertRaises(m.Refused):
                    source.resolve()
                self.assertIsNone(source.fd)
                self.assertIsNone(source.token)
        self.f.log.write_bytes(good)
        self.f.native_mock.assert_not_called()

    def test_log_permissions_and_hardlinks_are_refused(self):
        self.f.log.chmod(420)
        with self.assertRaises(m.Refused):
            self.source().snapshot()
        self.f.log.chmod(384)
        os.link(self.f.log, self.f.root / 'foreign-log-link')
        with self.assertRaises(m.Refused):
            self.source().snapshot()

    def test_log_path_symlink_and_wrong_stdout_inode_are_refused(self):
        foreign = self.f.root / 'foreign-log'
        foreign.write_bytes(self.f.log.read_bytes())
        foreign.chmod(384)
        self.f.process.joinpath('fd/2').unlink()
        self.f.process.joinpath('fd/2').symlink_to(foreign)
        with self.assertRaises(m.Refused):
            self.source().snapshot()
        self.f.process.joinpath('fd/2').unlink()
        self.f.process.joinpath('fd/2').symlink_to(self.f.log)
        self.f.log.unlink()
        self.f.log.symlink_to(foreign)
        with self.assertRaises(m.Refused):
            self.source().snapshot()

    def test_identical_log_inode_replacement_and_append_during_cohort_are_refused(self):
        source = self.source(resolve=True)
        self.f.replace_same_bytes(self.f.log, 384)
        with self.assertRaises(m.Refused):
            source.guard()
        source.close()
        next_source = self.source(resolve=True)
        with self.f.log.open('ab') as out:
            out.write(b'another runtime line\n')
        with self.assertRaises(m.Refused):
            next_source.guard()

    def test_held_log_descriptor_replacement_refuses_and_preserves_foreign_path(self):
        source = self.source(resolve=True)
        (log_fd, binary_fd) = (source.log_fd, source.fd)
        held = os.fstat(log_fd)
        self.assertEqual((held.st_dev, held.st_ino), (self.f.log.stat().st_dev, self.f.log.stat().st_ino))
        replacement = self.f.log.with_name('foreign-replacement')
        replacement.write_bytes(b'foreign log must survive\n')
        replacement.chmod(384)
        os.replace(replacement, self.f.log)
        foreign = m.record(self.f.log)
        self.assertEqual(os.fstat(log_fd).st_ino, held.st_ino)
        self.assertNotEqual(self.f.log.stat().st_ino, held.st_ino)
        with self.assertRaises(m.Refused):
            source.guard()
        self.assertEqual(m.record(self.f.log), foreign)
        self.assertEqual(self.f.log.read_bytes(), b'foreign log must survive\n')
        source.close()
        self.assertIsNone(source.fd)
        self.assertIsNone(source.log_fd)
        self.assertIsNone(source.token)
        for descriptor in [log_fd, binary_fd]:
            with self.assertRaises(OSError) as error:
                os.fstat(descriptor)
            self.assertEqual(error.exception.errno, errno.EBADF)

    def test_unlinked_log_refuses_while_old_descriptor_remains_and_never_recreates_path(self):
        source = self.source(resolve=True)
        (log_fd, binary_fd) = (source.log_fd, source.fd)
        original = os.pread(log_fd, 65536, 0)
        self.f.log.unlink()
        self.assertEqual(os.fstat(log_fd).st_nlink, 0)
        self.assertEqual(os.pread(log_fd, 65536, 0), original)
        with self.assertRaises(m.Refused):
            source.guard()
        self.assertFalse(os.path.lexists(self.f.log))
        source.close()
        self.assertIsNone(source.fd)
        self.assertIsNone(source.log_fd)
        self.assertIsNone(source.token)
        for descriptor in [log_fd, binary_fd]:
            with self.assertRaises(OSError) as error:
                os.fstat(descriptor)
            self.assertEqual(error.exception.errno, errno.EBADF)

    def test_coordinator_restart_between_snapshot_reads_is_refused(self):
        original = m.systemd_state
        reads = 0

        def changing():
            nonlocal reads
            reads += 1
            result = original()
            if reads == 1:
                self.f.loaded['InvocationID'] = 'c' * 32
            return result
        with patch.object(m, 'systemd_state', side_effect=changing):
            with self.assertRaises(m.Refused):
                self.source().snapshot()

    def test_legacy_pid_token_configs_and_root_coordinator_are_refused(self):
        for config in [{'schema_version': 1, 'api_origin': self.f.config['api_origin'], 'fabric_id': 'f' * 64, 'local_node_id': 'd' * 64, 'process': {'pid': self.f.pid}, 'bearer_token': 'a' * 64}, {**self.f.config, 'process': {'pid': self.f.pid}}, {**self.f.config, 'bearer_token': 'a' * 64}, {**self.f.config, 'coordinator': {**self.f.config['coordinator'], 'uid': 0}}, {**self.f.config, 'coordinator': {**self.f.config['coordinator'], 'unit': 'foreign.service'}}]:
            with self.subTest(config_keys=sorted(config)):
                with self.assertRaises(m.Refused):
                    m.validate_config(config)

class ManagedHTTPTests(unittest.TestCase):
    """Real synthetic loopback HTTP with an injected ephemeral managed cohort."""
    now = 1800000000000

    def setUp(self):
        self.epoch = 1
        self.hits = []
        self.instances = []
        outer = self

        class Source:

            def __init__(self, config):
                self.token = None
                self.closed = False
                outer.instances.append(self)

            def resolve(self):
                self.epoch = outer.epoch
                self.token = 'PRIVATE-CANARY-' + str(self.epoch)
                return self

            def guard(self):
                m.require(self.epoch == outer.epoch)

            def close(self):
                self.closed = True
                self.token = None
        self.factory = Source

    def start_server(self, restart_during_body=False):
        outer = self

        class Handler(http.server.BaseHTTPRequestHandler):

            def log_message(self, *args):
                pass

            def do_GET(self):
                outer.hits.append((self.path, self.headers.get('Authorization')))
                body = json.dumps(outer.view()).encode()
                self.send_response(200)
                self.send_header('Content-Type', 'application/json')
                self.send_header('Content-Length', str(len(body)))
                self.end_headers()
                if restart_during_body:
                    outer.epoch += 1
                self.wfile.write(body)
        server = http.server.HTTPServer(('127.0.0.1', 0), Handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()

        def cleanup():
            server.shutdown()
            server.server_close()
            thread.join(2)
        self.addCleanup(cleanup)
        return {'api_origin': 'http://127.0.0.1:' + str(server.server_port), 'fabric_id': 'f' * 64, 'local_node_id': 'd' * 64}

    def view(self):
        return {'schema_version': 1, 'fabric_id': 'f' * 64, 'local_node_id': 'd' * 64, 'collected_at_ms': self.now, 'nodes': [{'node_id': 'd' * 64, 'name': 'offline-only', 'kind': 'local', 'status': 'awaiting', 'last_seen_ms': None, 'resources': None}]}

    def test_restart_after_connect_sends_no_authorization_or_http_request(self):
        config = self.start_server()
        connect = m.socket.create_connection

        def restarted(*args, **kwargs):
            sock = connect(*args, **kwargs)
            self.epoch += 1
            return sock
        with patch.object(m.socket, 'create_connection', side_effect=restarted):
            with self.assertRaises(m.Refused):
                m.fetch(config, source_factory=self.factory)
        self.assertEqual(self.hits, [])
        self.assertTrue(self.instances[0].closed)
        self.assertIsNone(self.instances[0].token)

    def test_restart_while_receiving_discards_view_and_never_reuses_previous_success(self):
        config = self.start_server(restart_during_body=True)
        result = m.observe(config, fetcher=lambda c: m.fetch(c, source_factory=self.factory), clock=lambda : self.now)
        self.assertEqual(result, m.unavailable(self.now))
        self.assertEqual(self.hits, [('/api/v1/fabric', 'Bearer PRIVATE-CANARY-1')])
        self.assertNotIn('PRIVATE-CANARY', json.dumps(result))
        self.assertTrue(self.instances[0].closed)
        self.assertIsNone(self.instances[0].token)

    def test_next_collection_resolves_rotated_token_and_wrong_public_identity_is_unavailable(self):
        config = self.start_server()
        first = m.observe(config, fetcher=lambda c: m.fetch(c, source_factory=self.factory), clock=lambda : self.now)
        self.assertTrue(first['available'])
        self.epoch = 2
        second = m.observe(config, fetcher=lambda c: m.fetch(c, source_factory=self.factory), clock=lambda : self.now)
        self.assertTrue(second['available'])
        self.assertEqual([hit[1] for hit in self.hits], ['Bearer PRIVATE-CANARY-1', 'Bearer PRIVATE-CANARY-2'])
        self.assertTrue(all((instance.closed and instance.token is None for instance in self.instances)))
        wrong = self.view()
        wrong['fabric_id'] = 'e' * 64
        self.assertEqual(m.observe(config, fetcher=lambda _: wrong, clock=lambda : self.now), m.unavailable(self.now))
        wrong = self.view()
        wrong['local_node_id'] = 'e' * 64
        self.assertEqual(m.observe(config, fetcher=lambda _: wrong, clock=lambda : self.now), m.unavailable(self.now))
if __name__ == '__main__':
    unittest.main(verbosity=2)

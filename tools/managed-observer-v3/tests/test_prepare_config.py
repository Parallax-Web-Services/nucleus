import contextlib
import copy
import hashlib
import importlib.util
import io
import json
import os
import sys
import tempfile
import types
import unittest
from pathlib import Path
SOURCE_DIR = Path(__file__).resolve().parent.parent / 'source'
REFERENCE_DIR = Path(__file__).resolve().parent.parent / 'reference'
from unittest.mock import patch
sys.dont_write_bytecode = True
HERE = SOURCE_DIR
spec = importlib.util.spec_from_file_location('prepare_config', HERE / 'prepare_config.py')
p = importlib.util.module_from_spec(spec)
spec.loader.exec_module(p)
m = p.load_reviewed()

class LoaderTests(unittest.TestCase):

    def test_loader_pin_matches_exact_producer_and_executes_accepted_buffer(self):
        self.assertEqual(hashlib.sha256((HERE / 'producer.py').read_bytes()).hexdigest(), p.PRODUCER_SHA)
        self.assertTrue(callable(p.load_reviewed().ManagedSource))

@unittest.skipUnless(os.geteuid() == 0, 'private local root fixtures only')
class AdmissionTests(unittest.TestCase):

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix='nebula-capacity-test-admission-', dir='/run')
        self.root = Path(self.tmp.name)
        self.root.chmod(448)
        self.stage = self.root / 'prepared' / 'binding-0123456789abcdef'
        self.admission = self.root / 'admission.json'
        self.c = {'schema_version': 2, 'api_origin': 'http://127.0.0.1:12345', 'fabric_id': 'f' * 64, 'local_node_id': 'a' * 64, 'coordinator': {'unit': 'nucleus-coordinator.service', 'unit_sha256': 'b' * 64, 'binary_sha256': 'c' * 64, 'argv_sha256': 'd' * 64, 'uid': 12345, 'gid': 12345, 'state_device': 1, 'state_inode': 1, 'loopback_ports': [12344, 12345]}}
        self.admission.write_text(json.dumps(self.c))
        self.admission.chmod(384)
        self.ident = {'schema_version': 1, 'node_id': 'a' * 64, 'owner_id': 'a' * 64, 'fabric_id': 'f' * 64}
        self.calls = []
        outer = self

        class Source:

            def __init__(self, c):
                self.fd = 123
                self.token = 'SECRET_RUNTIME_TOKEN_NOT_TO_PERSIST'

            def resolve(self):
                outer.calls.append('resolve')
                return self

            def guard(self):
                outer.calls.append('guard')

            def close(self):
                outer.calls.append('close')
        self.source = Source

    def tearDown(self):
        self.tmp.cleanup()

    def run_candidate(self, identity=None, admission_data=None, release='synthetic-linux'):
        if admission_data is not None:
            self.admission.write_text(json.dumps(admission_data))
        response = types.SimpleNamespace(returncode=0, stdout=json.dumps(self.ident if identity is None else identity).encode())
        stdout = io.StringIO()
        with patch.object(p, 'load_reviewed', return_value=m), patch.object(m, 'ManagedSource', self.source), patch.object(p.os, 'uname', return_value=types.SimpleNamespace(release=release)), patch.object(p, 'PREPARED', self.stage.parent), patch.object(p.subprocess, 'run', return_value=response) as native, patch.object(sys, 'argv', ['prepare_config.py', '--admission', str(self.admission), '--stage', str(self.stage)]), contextlib.redirect_stdout(stdout):
            p.main()
        return (stdout.getvalue(), native)

    def test_only_explicit_preparation_validates_native_identity_as_state_owner(self):
        (out, native) = self.run_candidate()
        saved = (self.stage / 'producer.json').read_text()
        self.assertEqual(json.loads(saved), self.c)
        self.assertNotIn('SECRET_RUNTIME', saved + out)
        self.assertNotIn('pid', saved)
        self.assertNotIn('bearer', saved)
        self.assertEqual((self.stage / 'producer.json').stat().st_mode & 511, 384)
        self.assertEqual(self.stage.stat().st_mode & 511, 448)
        self.assertEqual(native.call_args.kwargs['user'], 12345)
        self.assertEqual(native.call_args.kwargs['group'], 12345)
        self.assertEqual(native.call_args.kwargs['extra_groups'], [])
        self.assertEqual(native.call_args.kwargs['stderr'], p.subprocess.DEVNULL)
        self.assertEqual(native.call_args.args[0], ['/proc/self/fd/123', 'identity'])
        self.assertEqual(self.calls, ['resolve', 'guard', 'guard', 'guard', 'close'])
        self.assertEqual(json.loads(out), {'prepared': True, 'owner_on_wsl': False, 'owner_on_server': True})

    def test_wrong_native_owner_fabric_schema_never_writes_a_candidate(self):
        for changes in [{'owner_id': 'b' * 64}, {'node_id': 'b' * 64}, {'fabric_id': 'b' * 64}, {'schema_version': True}]:
            with self.subTest(changes=changes), self.assertRaises(RuntimeError):
                self.run_candidate(identity={**self.ident, **changes})
            self.assertFalse(self.stage.exists())
            self.assertEqual(self.calls[-1], 'close')

    def test_legacy_admission_is_rejected_before_any_runtime_resolution(self):
        with self.assertRaises(m.Refused):
            self.run_candidate(admission_data={**self.c, 'process': {'pid': 123}})
        self.assertFalse(self.stage.exists())
        self.assertEqual(self.calls, [])

    def test_desktop_kernel_cannot_prepare_managed_admission(self):
        with self.assertRaises(RuntimeError):
            self.run_candidate(release='synthetic-microsoft-standard')
        self.assertFalse(self.stage.exists())
        self.assertEqual(self.calls, [])

    def test_existing_candidate_is_never_replaced(self):
        self.stage.parent.mkdir(mode=448)
        self.stage.mkdir(mode=448)
        saved = self.stage / 'producer.json'
        saved.write_bytes(b'foreign')
        saved.chmod(384)
        with self.assertRaises(RuntimeError):
            self.run_candidate()
        self.assertEqual(saved.read_bytes(), b'foreign')
if __name__ == '__main__':
    unittest.main()

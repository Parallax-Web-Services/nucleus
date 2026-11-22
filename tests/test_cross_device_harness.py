"""Local safety checks for the opt-in cross-device harness; no network is used."""
import argparse
import importlib.util
import json
import os
from pathlib import Path
import shutil
import struct
import subprocess
import sys
import tempfile
import time
import unittest
from unittest import mock

MODULE_PATH = Path(__file__).resolve().parents[1] / "scripts/test_cross_device.py"
spec = importlib.util.spec_from_file_location("cross_device_harness", MODULE_PATH)
harness = importlib.util.module_from_spec(spec)
spec.loader.exec_module(harness)

class HarnessSafety(unittest.TestCase):
    def test_target_and_remote_cleanup_paths_are_bounded(self):
        self.assertEqual(harness.validate_target("slipstream.host"), "slipstream.host")
        self.assertEqual(harness.validate_target("user@host.example"), "user@host.example")
        for value in ("-oProxyCommand=id", "host;id", "host\nHost *", "https://host", ""):
            with self.assertRaises(argparse.ArgumentTypeError):
                harness.validate_target(value)
        self.assertEqual(harness.checked_remote_path("/tmp/nucleus-cross-device.a_123456"), "/tmp/nucleus-cross-device.a_123456")
        for value in ("/tmp", "/", "/tmp/nucleus-cross-device.abcdef/../other", "/home/nucleus-cross-device.abcdef"):
            with self.assertRaises(harness.HarnessError):
                harness.checked_remote_path(value)

    def test_static_binary_check_rejects_dynamic_and_wrong_arch(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "nucleus"
            data = bytearray(120)
            data[:6] = b"\x7fELF\x02\x01"
            struct.pack_into("<H", data, 18, 62)
            struct.pack_into("<Q", data, 32, 64)
            struct.pack_into("<HH", data, 54, 56, 1)
            path.write_bytes(data)
            self.assertEqual(harness.static_elf(path)[0], "x86_64")
            struct.pack_into("<I", data, 64, 3)
            path.write_bytes(data)
            with self.assertRaisesRegex(harness.HarnessError, "dynamically"):
                harness.static_elf(path)
            data[4] = 1
            path.write_bytes(data)
            with self.assertRaises(harness.HarnessError):
                harness.static_elf(path)

    def test_ssh_config_drops_inherited_forwarding_and_hooks(self):
        config = b"""host test
hostname 192.168.1.20
user operator
port 2222
identityfile /tmp/key with-spaces
identitiesonly yes
userknownhostsfile /home/operator/.ssh/known_hosts
globalknownhostsfile /etc/ssh/ssh_known_hosts
proxycommand none
proxyjump none
knownhostscommand none
localforward 0.0.0.0:9000 host:22
remotecommand dangerous-command
localcommand dangerous-local
requesttty yes
"""
        with tempfile.TemporaryDirectory() as directory, mock.patch.object(harness, "run_checked", return_value=config):
            ssh = harness.SSH("test", Path(directory))
            written = ssh.config.read_text()
            self.assertIn('identityfile "/tmp/key with-spaces"', written)
            self.assertNotIn("localforward", written)
            self.assertNotIn("dangerous", written)
            self.assertIn("StrictHostKeyChecking=yes", ssh.common)
            self.assertIn("PermitLocalCommand=no", ssh.common)
            self.assertEqual(ssh.config.stat().st_mode & 0o777, 0o600)
            command = ssh.command(["printf", "$(id); echo unsafe", "quote'here"])
            self.assertIn("ClearAllForwardings=yes", command)
            self.assertIn("'$(id); echo unsafe'", command[-1])
            self.assertIn("RemoteCommand=none", command)
        for hook in ("proxycommand", "proxyjump", "knownhostscommand"):
            with tempfile.TemporaryDirectory() as directory, mock.patch.object(harness, "run_checked", return_value=config + f"{hook} unsafe\n".encode()):
                with self.assertRaises(harness.HarnessError):
                    harness.SSH("test", Path(directory))

    def test_default_algorithms_do_not_override_pinned_key_preference(self):
        resolved = b"""hostname selected.example
user operator
port 22
identityfile none
certificatefile none
identityagent none
hostkeyalgorithms ssh-ed25519,ecdsa-sha2-nistp256
pubkeyacceptedalgorithms ssh-ed25519
userknownhostsfile /home/operator/.ssh/known_hosts
"""
        defaults = b"""hostkeyalgorithms ssh-ed25519,ecdsa-sha2-nistp256
pubkeyacceptedalgorithms ssh-ed25519
"""
        with tempfile.TemporaryDirectory() as directory, mock.patch.object(
                harness, "run_checked", side_effect=[resolved, defaults]):
            ssh = harness.SSH("operator@selected.example", Path(directory))
            written = ssh.config.read_text()
            self.assertEqual(written.splitlines()[0], "Host *")
            self.assertNotIn("  hostkeyalgorithms ", written)
            self.assertNotIn("  pubkeyacceptedalgorithms ", written)
            self.assertIn('identityagent "none"', written)
            self.assertIn('identityfile "none"', written)
            self.assertIn('certificatefile "none"', written)
        custom = resolved.replace(b"hostkeyalgorithms ssh-ed25519,ecdsa-sha2-nistp256",
                                  b"hostkeyalgorithms ecdsa-sha2-nistp256")
        with tempfile.TemporaryDirectory() as directory, mock.patch.object(
                harness, "run_checked", side_effect=[custom, defaults]):
            ssh = harness.SSH("selected.example", Path(directory))
            self.assertIn('hostkeyalgorithms "ecdsa-sha2-nistp256"', ssh.config.read_text())

    def test_private_files_are_exclusive_and_errors_do_not_disclose_secrets(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "private"
            harness.private_write(path, b"original")
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)
            with self.assertRaises(FileExistsError):
                harness.private_write(path, b"replacement")
            self.assertEqual(path.read_bytes(), b"original")
        result = subprocess.CompletedProcess(["fake"], 7, b"secret-token", b"secret-key")
        with mock.patch.object(harness.subprocess, "run", return_value=result):
            with self.assertRaises(harness.HarnessError) as caught:
                harness.run_checked(["fake"], label="operation")
            self.assertNotIn("secret", str(caught.exception))

    def test_expanded_fleet_capacity_includes_all_online_nodes(self):
        def node(identity, cores, status="online"):
            return {"node_id": identity, "status": status,
                    "resources": {"cpu": {"logical_cores": cores}}}
        view = {
            "local_node_id": "owner",
            "nodes": [
                node("owner", 8), node("member", 12),
                node("alpha", 8), node("tarragon", 32),
                node("offline-cached", 128, "offline"),
                {"node_id": "awaiting", "status": "awaiting", "resources": None},
            ],
            "available_capacity": {"logical_cores": 60},
        }
        self.assertIs(harness.assert_both(view, "owner", "member", viewer_id="owner"), view)
        view["available_capacity"]["logical_cores"] = 20
        with self.assertRaises(harness.HarnessError):
            harness.assert_both(view, "owner", "member", viewer_id="owner")
        view["available_capacity"]["logical_cores"] = 60
        view["nodes"][1]["status"] = "offline"
        self.assertFalse(harness.assert_both(view, "owner", "member", viewer_id="owner"))
        view["nodes"].pop(1)
        self.assertFalse(harness.assert_both(view, "owner", "member", viewer_id="owner"))

    def test_fast_restart_publishes_new_browser_token_even_while_online(self):
        session = harness.Session.__new__(harness.Session)
        session.tunnel_process = mock.Mock()
        session.tunnel_process.poll.return_value = None
        session.owner_process = mock.Mock()
        session.owner_process.poll.return_value = 0
        session.member_process = mock.Mock()
        session.member_process.poll.return_value = None
        session.ssh = mock.Mock()
        session.remote = "/tmp/nucleus-cross-device.abcdefgh"
        session.owner_id, session.member_id = "owner", "member"
        session.owner_url = "old-private-url"
        session.args = argparse.Namespace(report=Path("/not-written"))
        session.report = {}
        session.publish_session = mock.Mock()
        def restarted():
            session.owner_url = "new-private-url"
        session.start_owner = mock.Mock(side_effect=restarted)
        session.owner_view = mock.Mock(return_value={
            "local_node_id": "owner",
            "nodes": [
                {"node_id": "owner", "status": "online", "resources": {"cpu": {"logical_cores": 1}}},
                {"node_id": "member", "status": "online", "resources": {"cpu": {"logical_cores": 1}}},
            ],
            "available_capacity": {"logical_cores": 2},
        })
        with mock.patch.object(harness, "write_json"), mock.patch.object(
                harness.time, "sleep", side_effect=KeyboardInterrupt):
            with self.assertRaises(KeyboardInterrupt):
                session.supervise()
        self.assertEqual(session.owner_url, "new-private-url")
        session.publish_session.assert_called_once_with("running")

    @unittest.skipUnless(sys.platform == "linux", "remote cleanup protocol targets Linux")
    def test_remote_guard_refuses_symlink_and_wrong_mode(self):
        with tempfile.TemporaryDirectory(prefix="nucleus-cross-device.", dir="/tmp") as directory:
            root = Path(directory)
            source = harness.REMOTE_COMMON + '\nprint("verified")\n'
            good = subprocess.run([sys.executable, "-c", source, str(root)], capture_output=True)
            self.assertEqual(good.returncode, 0, good.stderr)
            root.chmod(0o755)
            wrong_mode = subprocess.run([sys.executable, "-c", source, str(root)], capture_output=True)
            self.assertNotEqual(wrong_mode.returncode, 0)
            root.chmod(0o700)
        with tempfile.TemporaryDirectory(prefix="nucleus-cross-device.", dir="/tmp") as directory:
            root = Path(directory)
            link = Path(str(root) + "_link")
            try:
                link.symlink_to(root, target_is_directory=True)
                bad_link = subprocess.run([sys.executable, "-c", source, str(link)], capture_output=True)
                self.assertNotEqual(bad_link.returncode, 0)
            finally:
                link.unlink(missing_ok=True)

    @unittest.skipUnless(sys.platform == "linux", "process cleanup protocol targets Linux")
    def test_remote_stop_requires_exact_executable_and_starttime(self):
        with tempfile.TemporaryDirectory(prefix="nucleus-cross-device.", dir="/tmp") as directory:
            root = Path(directory)
            shutil.copyfile("/bin/sleep", root / "nucleus")
            (root / "nucleus").chmod(0o700)
            process = subprocess.Popen([str(root / "nucleus"), "60"])
            try:
                proc = Path("/proc") / str(process.pid)
                start = proc.joinpath("stat").read_text().rsplit(")", 1)[1].split()[19]
                record = {"pid": process.pid, "starttime": "wrong", "executable": str(root / "nucleus")}
                (root / "owner.pid.json").write_text(json.dumps(record))
                result = subprocess.run([sys.executable, "-c", harness.REMOTE_STOP, str(root)], capture_output=True, timeout=10)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertIsNone(process.poll(), "wrong process generation was signaled")
                record["starttime"] = start
                (root / "owner.pid.json").write_text(json.dumps(record))
                result = subprocess.run([sys.executable, "-c", harness.REMOTE_STOP, str(root)], capture_output=True, timeout=10)
                self.assertEqual(result.returncode, 0, result.stderr)
                process.wait(timeout=3)
                self.assertLess(process.returncode, 0)
            finally:
                if process.poll() is None:
                    process.terminate()
                    process.wait(timeout=3)

if __name__ == "__main__":
    unittest.main(verbosity=2)

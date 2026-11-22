"""Offline rollout safety checks. No SSH connections or deployments are made."""
import importlib.util
import json
import os
from pathlib import Path
import stat
import subprocess
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock

spec=importlib.util.spec_from_file_location("rollout_under_test",Path(__file__).resolve().parents[1]/"scripts/rollout_remote.py")
rollout=importlib.util.module_from_spec(spec);spec.loader.exec_module(rollout)

class RolloutSafety(unittest.TestCase):
    def test_remote_commands_are_shell_only_and_parse(self):
        for name in ("COMMON","CHECK","TEMP","UPLOAD","CLI","FILE","START","STOP","REMOVE","OWNER_FILES","PORT"):
            code=getattr(rollout,name)
            self.assertNotIn("python",code.lower(),name)
            result=subprocess.run(["sh","-n"],input=code,text=True,capture_output=True)
            self.assertEqual(result.returncode,0,(name,result.stderr))

    def test_remote_workspace_and_cleanup_scope(self):
        self.assertEqual(rollout.checked_workspace("/tmp/nucleus-rollout.abcdef12"),"/tmp/nucleus-rollout.abcdef12")
        for value in ("/tmp","/","/tmp/nucleus-rollout.abcdef/../other","/tmp/nucleus-cross-device.abcdef","/home/nucleus-rollout.abcdef"):
            with self.assertRaises(rollout.Error):rollout.checked_workspace(value)
        with tempfile.TemporaryDirectory(prefix="nucleus-cross-device.",dir="/tmp") as directory:
            witness=Path(directory)/"keep";witness.write_text("owner-state")
            result=subprocess.run(["sh","-c",rollout.REMOVE,"test",directory,"a"*32],capture_output=True)
            self.assertNotEqual(result.returncode,0)
            self.assertEqual(witness.read_text(),"owner-state")

    def test_process_stop_cannot_kill_an_unrelated_pid(self):
        with tempfile.TemporaryDirectory(prefix="nucleus-rollout.",dir="/tmp") as directory:
            root=Path(directory);(root/".rollout-id").write_text("a"*32)
            child=subprocess.Popen(["sleep","10"])
            try:
                started=Path(f"/proc/{child.pid}/stat").read_text().split()[21]
                (root/"member.pid").write_text(f"{child.pid} {started}\n")
                result=subprocess.run(["sh","-c",rollout.STOP,"test",directory,"a"*32],capture_output=True)
                self.assertEqual(result.returncode,0,result.stderr)
                self.assertIsNone(child.poll(),"unrelated process was killed")
            finally:
                child.terminate();child.wait()

    def test_duplicate_machine_reservations_are_serialized(self):
        device={"machine_id_sha256":"a"*64,"boot_id_sha256":"b"*64}
        with tempfile.TemporaryDirectory() as directory:
            registry=Path(directory)/"members.json"
            rollout.reserve(registry,"first.example",device,"a"*32,[])
            with self.assertRaises(rollout.Error):rollout.reserve(registry,"alias.example",device,"b"*32,[])
            distinct={"machine_id_sha256":"c"*64,"boot_id_sha256":"d"*64}
            rollout.reserve(registry,"second.example",distinct,"c"*32,[])
            self.assertEqual(len(json.loads(registry.read_text())),2)
            self.assertEqual(stat.S_IMODE(registry.stat().st_mode),0o600)
            with self.assertRaises(rollout.Error):rollout.reserve(registry,"owner.example",{"machine_id_sha256":"e"*64,"boot_id_sha256":"f"*64},"d"*32,[{"machine_id_sha256":"e"*64}])

    def test_ssh_override_keeps_strict_verification(self):
        ssh=SimpleNamespace(common=["ssh","-o","StrictHostKeyChecking=yes","-o","BatchMode=yes"])
        rollout.override_ssh(ssh,"alpha.wphyperdrive.com","alpha.parallaxws.com")
        self.assertIn("StrictHostKeyChecking=yes",ssh.common)
        self.assertIn("HostName=alpha.wphyperdrive.com",ssh.common)
        self.assertIn("HostKeyAlias=alpha.parallaxws.com",ssh.common)
        for value in ("-oProxyCommand=id","host;id","host\nHost *"):
            with self.assertRaises(rollout.Error):rollout.override_ssh(SimpleNamespace(common=[]),value)

    def test_reverse_tunnel_is_loopback_on_both_ends(self):
        instance=object.__new__(rollout.Rollout)
        instance.ssh=SimpleNamespace(common=["ssh","-o","StrictHostKeyChecking=yes"])
        instance.port=19461;instance.args=SimpleNamespace(ssh_target="selected.example")
        command=instance.reverse_command()
        self.assertIn("-R",command)
        self.assertIn("127.0.0.1:19461:127.0.0.1:19461",command)
        self.assertIn("ExitOnForwardFailure=yes",command)
        self.assertEqual(command[-2:],["--","selected.example"])

    def test_public_report_excludes_private_access_urls(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory)
            instance=object.__new__(rollout.Rollout)
            instance.root=root;instance.report={"schema_version":1,"fabric_id":"f"*64}
            instance.args=SimpleNamespace(report=root/"public.json",ssh_target="selected.example",coordinator_session=root/"coordinator.json")
            instance.member_id="b"*64;instance.fabric_id="f"*64;instance.remote=None
            instance.process_info={"pid":123,"start_time":"456"};instance.tunnel=None
            secret="c"*64;instance.map_url="http://127.0.0.1:9999/#token="+secret
            instance.coordinator={"member_map_url":"http://127.0.0.1:8888/#token="+secret}
            instance.ssh=SimpleNamespace(common=["ssh"]);instance.port=19461
            instance.publish("running")
            self.assertNotIn(secret,(root/"public.json").read_text())
            self.assertNotIn("#token=",(root/"public.json").read_text())
            private=json.loads((root/"session.json").read_text())
            self.assertIn(secret,private["shared_map_url"])
            self.assertEqual(stat.S_IMODE((root/"session.json").stat().st_mode),0o600)

    def test_existing_coordinator_identity_mismatch_stops_before_enrollment(self):
        instance=object.__new__(rollout.Rollout)
        instance.owner_id="a"*64;instance.fabric_id="b"*64
        instance.owner_cli=mock.Mock(return_value=json.dumps({"node_id":"c"*64,"fabric_id":"b"*64}).encode())
        instance.remote_cli=mock.Mock()
        with self.assertRaises(rollout.Error):instance.execute()
        instance.remote_cli.assert_not_called()
        instance.owner_cli.assert_called_once_with("identity")

    def test_explicit_stop_revokes_only_new_member(self):
        instance=object.__new__(rollout.Rollout)
        instance.member_id="b"*64;instance.owner_id="a"*64;instance.remote="/tmp/nucleus-rollout.abcdef12"
        instance.owner_root="/tmp/nucleus-cross-device.abcdef12";instance.run_id="c"*32
        instance.ssh=object();instance.owner=object();instance.tunnel=None
        instance.registry=Path("/unused/registry.json");instance.report={};instance.publish=mock.Mock()
        instance.owner_cli=mock.Mock(side_effect=[json.dumps({"members":{instance.owner_id:{},instance.member_id:{}}}).encode(),b""])
        with mock.patch.object(rollout,"shell",return_value=b"") as shell, mock.patch.object(rollout,"registry_update"),mock.patch.object(rollout.helpers,"stop_process"):
            instance.close(True)
        self.assertEqual(instance.owner_cli.call_args_list,[mock.call("members"),mock.call("revoke",instance.member_id)])
        self.assertTrue(any(call.args[1]==rollout.REMOVE and call.args[2]==instance.remote for call in shell.call_args_list))
        instance.publish.assert_called_once_with("stopped")


    def test_remote_workspace_mode_arguments(self):
        common=["--ssh-target","selected.example","--coordinator-session","coordinator.json",
                "--session-dir","fresh-session","--report","fresh-report.json"]
        self.assertEqual(rollout.arguments(common).remote_workspace,"tmp")
        self.assertEqual(rollout.arguments(common+["--remote-workspace","home"]).remote_workspace,"home")
        with mock.patch("sys.stderr"):
            with self.assertRaises(SystemExit):
                rollout.arguments(common+["--remote-workspace","unsafe"])

    def test_home_workspace_creation_guard_and_cleanup(self):
        with tempfile.TemporaryDirectory(prefix="nucleus-home-test-") as directory:
            home=Path(directory)
            environment=dict(os.environ,HOME=str(home))
            created=subprocess.run(["sh","-c",rollout.TEMP,"test","a"*32,"home"],
                                   env=environment,text=True,capture_output=True)
            self.assertEqual(created.returncode,0,created.stderr)
            workspace=Path(created.stdout.strip())
            self.assertEqual(rollout.checked_workspace(str(workspace),str(home)),str(workspace))
            self.assertEqual(workspace.parent,home/".local/share/nucleus-prototype")
            self.assertEqual((workspace/".rollout-id").read_text().strip(),"a"*32)
            self.assertEqual(stat.S_IMODE(workspace.stat().st_mode),0o700)
            self.assertEqual(stat.S_IMODE(workspace.parent.stat().st_mode),0o700)
            accepted=subprocess.run(["sh","-c",rollout.COMMON+"printf verified","test",str(workspace),"a"*32],
                                    env=environment,capture_output=True)
            self.assertEqual(accepted.returncode,0,accepted.stderr)
            wrong_run=subprocess.run(["sh","-c",rollout.REMOVE,"test",str(workspace),"b"*32],
                                     env=environment,capture_output=True)
            self.assertNotEqual(wrong_run.returncode,0)
            self.assertTrue(workspace.exists())
            os.chmod(workspace.parent,0o755)
            loose_parent=subprocess.run(["sh","-c",rollout.COMMON,"test",str(workspace),"a"*32],
                                        env=environment,capture_output=True)
            self.assertNotEqual(loose_parent.returncode,0)
            os.chmod(workspace.parent,0o700)
            removed=subprocess.run(["sh","-c",rollout.REMOVE,"test",str(workspace),"a"*32],
                                   env=environment,capture_output=True)
            self.assertEqual(removed.returncode,0,removed.stderr)
            self.assertFalse(workspace.exists())
            self.assertTrue(workspace.parent.exists())

    def test_home_workspace_rejects_escape_and_other_home(self):
        home="/home/operator"
        valid=home+"/.local/share/nucleus-prototype/node.abcdef12"
        self.assertEqual(rollout.checked_workspace(valid,home),valid)
        for value,claimed_home in (
            (valid,None),(valid,"/home/other"),
            (home+"/.local/share/nucleus-prototype/node.abcdef/../other",home),
            (home+"/.local/share/nucleus-prototype",home),
            ("/tmp/../home/operator/.local/share/nucleus-prototype/node.abcdef12",home),
            ("/home/operator/../other/.local/share/nucleus-prototype/node.abcdef12","/home/operator/../other"),
        ):
            with self.assertRaises(rollout.Error):
                rollout.checked_workspace(value,claimed_home)
        with tempfile.TemporaryDirectory(prefix="nucleus-home-test-") as directory:
            parent=Path(directory)
            real=parent/"real";real.mkdir(mode=0o700)
            environment=dict(os.environ,HOME=str(real))
            made=subprocess.run(["sh","-c",rollout.TEMP,"test","a"*32,"home"],
                                env=environment,text=True,capture_output=True)
            self.assertEqual(made.returncode,0,made.stderr)
            workspace=Path(made.stdout.strip())
            wrong=parent/"wrong";wrong.mkdir(mode=0o700)
            denied=subprocess.run(["sh","-c",rollout.REMOVE,"test",str(workspace),"a"*32],
                                  env=dict(os.environ,HOME=str(wrong)),capture_output=True)
            self.assertNotEqual(denied.returncode,0)
            self.assertTrue(workspace.exists())

    def test_home_workspace_rejects_symlink_ancestors(self):
        with tempfile.TemporaryDirectory(prefix="nucleus-home-test-") as directory:
            parent=Path(directory)
            home=parent/"home";home.mkdir(mode=0o700)
            outside=parent/"outside";outside.mkdir(mode=0o700)
            (home/".local").symlink_to(outside,target_is_directory=True)
            denied=subprocess.run(["sh","-c",rollout.TEMP,"test","a"*32,"home"],
                                  env=dict(os.environ,HOME=str(home)),capture_output=True)
            self.assertNotEqual(denied.returncode,0)
            self.assertFalse((outside/"share").exists())
            (home/".local").unlink()
            alias=parent/"alias";alias.symlink_to(home,target_is_directory=True)
            denied_home=subprocess.run(["sh","-c",rollout.TEMP,"test","a"*32,"home"],
                                       env=dict(os.environ,HOME=str(alias)),capture_output=True)
            self.assertNotEqual(denied_home.returncode,0)
            self.assertFalse((home/".local").exists())

    def test_healthy_supervision_avoids_remote_start_checks(self):
        instance=object.__new__(rollout.Rollout)
        instance.tunnel=mock.Mock();instance.tunnel.poll.return_value=None
        instance.online=mock.Mock(return_value=True)
        instance.start_member=mock.Mock();instance.start_tunnel=mock.Mock()
        self.assertEqual(instance.supervise_once(),"running")
        instance.start_member.assert_not_called()
        instance.start_tunnel.assert_not_called()
        instance.online.return_value=False
        self.assertEqual(instance.supervise_once(),"reconnecting")
        instance.start_member.assert_called_once_with()

if __name__=="__main__":unittest.main()

#!/usr/bin/env python3
"""First-contact protocol acceptance using two isolated installations on one host.
This is not the physical two-computer LAN acceptance test.
"""
import argparse
import json
import os
from pathlib import Path
import re
import socket
import stat
import subprocess
import tempfile
import time
import unittest
import urllib.error
import urllib.request

ROOT = Path(__file__).resolve().parents[1]
BINARY = ROOT / "bin/nucleus"
OPENER = urllib.request.build_opener(urllib.request.ProxyHandler({}))

def free_port():
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        return listener.getsockname()[1]

class FirstContact(unittest.TestCase):
    def test_bilateral_membership_heartbeat_and_recovery(self):
        with tempfile.TemporaryDirectory(prefix="nucleus-first-contact-") as directory:
            root = Path(directory)
            homes = {name: root / name for name in ("owner", "member", "stranger")}
            processes = []
            logs = []
            def run(name, *args, ok=True):
                environment = dict(os.environ, NUCLEUS_HOME=str(homes[name]))
                result = subprocess.run([str(BINARY), *args], env=environment, text=True, capture_output=True, timeout=15)
                if ok:
                    self.assertEqual(result.returncode, 0, result.stderr)
                return result
            def document(name, *args):
                return json.loads(run(name, *args).stdout)
            def wait_for(predicate, message, timeout=20):
                deadline = time.monotonic() + timeout
                last_error = None
                while time.monotonic() < deadline:
                    try:
                        result = predicate()
                        if result:
                            return result
                    except (OSError, ValueError, KeyError, urllib.error.URLError) as error:
                        last_error = error
                    time.sleep(0.2)
                self.fail(f"{message}: {last_error}")
            def start(name):
                log_path = root / f"{name}-{len(logs)}.log"
                log = os.fdopen(os.open(log_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), "w")
                logs.append(log)
                process = subprocess.Popen([str(BINARY), "run", "--no-open"], env=dict(os.environ, NUCLEUS_HOME=str(homes[name])), stdout=log, stderr=log)
                processes.append(process)
                def ready():
                    if process.poll() is not None:
                        self.fail(f"{name} exited {process.returncode}: {log_path.read_text()}")
                    match = re.search(r"Resource map: (http://127[.]0[.]0[.]1:\d+/#token=[0-9a-f]+)", log_path.read_text())
                    return match.group(1) if match else None
                url = wait_for(ready, f"{name} map startup")
                return process, url
            def stop(process):
                if process.poll() is None:
                    process.terminate()
                    process.wait(timeout=5)
            def fetch(url, token=True, method="GET", host=None):
                base, secret = url.split("/#token=")
                request = urllib.request.Request(base + "/api/v1/fabric", method=method)
                if token:
                    request.add_header("Authorization", "Bearer " + secret)
                if host:
                    request.add_header("Host", host)
                with OPENER.open(request, timeout=5) as response:
                    return json.load(response)
            try:
                for name in homes:
                    run(name, "init", "--name", name)
                owner_id = document("owner", "identity")["node_id"]
                member_id = document("member", "identity")["node_id"]
                run("member", "init", "--name", "ignored-new-name")
                self.assertEqual(document("member", "identity")["node_id"], member_id)
                invitation, request, grant = [root / filename for filename in ("invite.json", "request.json", "grant.json")]
                endpoint = f"https://127.0.0.1:{free_port()}/"
                run("owner", "invite", "--endpoint", endpoint, "--out", str(invitation))
                run("member", "join", str(invitation), "--out", str(request))
                self.assertEqual(document("member", "identity")["fabric_id"], "")
                self.assertEqual(document("owner", "inspect", str(request))["node_id"], member_id)
                run("owner", "accept", str(request), "--out", str(grant))
                retry = root / "retry-grant.json"
                run("owner", "accept", str(request), "--out", str(retry))
                self.assertEqual(json.loads(grant.read_text()), json.loads(retry.read_text()))
                self.assertEqual(document("member", "identity")["fabric_id"], "")
                run("member", "join", "--accept", str(grant))
                self.assertEqual(document("member", "identity")["fabric_id"], document("owner", "identity")["fabric_id"])
                self.assertNotEqual(owner_id, member_id)
                for path in (invitation, request, grant, homes["owner"] / "state.json"):
                    self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
                self.assertNotEqual(run("stranger", "join", "--accept", str(grant), ok=False).returncode, 0)
                owner, owner_url = start("owner")
                initial = fetch(owner_url)
                peer = next(node for node in initial["nodes"] if node["node_id"] == member_id)
                self.assertEqual(peer["status"], "awaiting")
                self.assertEqual(initial["available_capacity"]["logical_cores"], initial["nodes"][0]["resources"]["cpu"]["logical_cores"])
                member, member_url = start("member")
                def both_online(url):
                    view = fetch(url)
                    return view if len(view["nodes"]) == 2 and all(node["status"] == "online" for node in view["nodes"]) else None
                online = wait_for(lambda: both_online(owner_url), "authenticated two-node heartbeat")
                worker_view = wait_for(lambda: both_online(member_url), "member fabric map")
                self.assertEqual(worker_view["local_node_id"], member_id)
                self.assertEqual(online["available_capacity"]["logical_cores"], sum(node["resources"]["cpu"]["logical_cores"] for node in online["nodes"]))
                for kwargs, expected in (({"token": False}, 401), ({"method": "POST"}, 405), ({"host": "evil.example"}, 403)):
                    with self.assertRaises(urllib.error.HTTPError) as caught:
                        fetch(owner_url, **kwargs)
                    self.assertEqual(caught.exception.code, expected)
                print("PASS: bilateral membership, real mTLS heartbeats, two maps, browser boundary", flush=True)
                stop(member)
                def offline_view():
                    view = fetch(owner_url)
                    peer = next(node for node in view["nodes"] if node["node_id"] == member_id)
                    return view if peer["status"] == "offline" else None
                offline = wait_for(offline_view, "disconnected member capacity removed", timeout=18)
                local = next(node for node in offline["nodes"] if node["kind"] == "local")
                self.assertEqual(offline["available_capacity"]["logical_cores"], local["resources"]["cpu"]["logical_cores"])
                member, member_url = start("member")
                wait_for(lambda: both_online(owner_url), "automatic reconnect")
                print("PASS: disconnect removes capacity; reconnect restores without pairing", flush=True)
                stop(owner)
                owner, owner_url = start("owner")
                wait_for(lambda: both_online(owner_url), "coordinator restart recovery")
                print("PASS: owner restart preserves membership and reacquires live telemetry", flush=True)
                run("owner", "revoke", member_id)
                wait_for(lambda: len(fetch(owner_url)["nodes"]) == 1, "revoked member removed from capacity")
                time.sleep(2.5)
                self.assertNotIn(member_id, [node["node_id"] for node in fetch(owner_url)["nodes"]])
                print("PASS: revoked member cannot restore itself with continuing heartbeats", flush=True)
            finally:
                for process in reversed(processes):
                    stop(process)
                for log in logs:
                    log.close()

if __name__ == "__main__":
    if not BINARY.exists():
        raise SystemExit("Build bin/nucleus with bash scripts/build.sh first")
    unittest.main(verbosity=2)

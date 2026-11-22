#!/usr/bin/env python3
"""Protocol-only acceptance for an owner plus two local inference workers.

Uses real Nucleus binaries, invitations, mTLS, scheduling and subprocess limits.
The tiny metadata fixture is NOT a language model and the Python server is NOT
llama.cpp. No model inference or performance benchmark is claimed or recorded.
Build bin/nucleus first, then run: python3 tests/test_inference_fleet.py
"""
from concurrent.futures import ThreadPoolExecutor
import hashlib
import json
import os
from pathlib import Path
import signal
import socket
import struct
import subprocess
import sys
import tempfile
import threading
import time
import unittest
import urllib.error
import urllib.request

ROOT = Path(__file__).resolve().parents[1]
BINARY = Path(os.environ.get("NUCLEUS_TEST_BINARY", ROOT / "bin/nucleus")).resolve()
KEY = "protocol-only-inference-fixture-key-0123456789"
OPENER = urllib.request.build_opener(urllib.request.ProxyHandler({}))

FAKE_LLAMA = r'''#!/usr/bin/env python3
# Protocol fixture only. Deliberately emits no throughput timings.
from http.server import BaseHTTPRequestHandler, HTTPServer
import json
import os
from pathlib import Path
import sys
import time
if "--version" in sys.argv:
    print("llama.cpp PROTOCOL FIXTURE ONLY - NOT A BENCHMARK")
    raise SystemExit(0)
args = sys.argv[1:]
values = {arg: args[i+1] for i, arg in enumerate(args[:-1]) if arg.startswith("--")}
secret = Path(values["--api-key-file"]).read_text().strip()
alias = values["--alias"]
Path(__file__).with_suffix(".pid").write_text(str(os.getpid()))
class Handler(BaseHTTPRequestHandler):
    def log_message(self, *_args): pass
    def authorized(self):
        if self.headers.get("Authorization") == "Bearer " + secret:
            return True
        self.send_response(401)
        self.end_headers()
        return False
    def do_GET(self):
        if not self.authorized(): return
        if self.path not in ("/v1/models", "/health"):
            self.send_response(404); self.end_headers(); return
        body = json.dumps({"data": [{"id": alias}]}).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)
    def do_POST(self):
        if not self.authorized(): return
        body = json.loads(self.rfile.read(int(self.headers.get("Content-Length", "0"))))
        prompt = json.dumps(body.get("messages"))
        if "hold" in prompt: time.sleep(20)
        elif "concurrent" in prompt: time.sleep(1.5)
        output = {"id": "protocol-fixture", "object": "chat.completion",
                  "model": alias, "usage": {"prompt_tokens": 1, "completion_tokens": 1, "total_tokens": 2}}
        if body.get("stream"):
            output["object"] = "chat.completion.chunk"
            output["choices"] = [{"index": 0, "delta": {"content": "protocol fixture"}, "finish_reason": "stop"}]
            encoded = ("data: " + json.dumps(output) + "\n\ndata: [DONE]\n\n").encode()
            media = "text/event-stream"
        else:
            output["choices"] = [{"index": 0, "message": {"role": "assistant", "content": "protocol fixture"}, "finish_reason": "stop"}]
            encoded = json.dumps(output).encode()
            media = "application/json"
        self.send_response(200)
        self.send_header("Content-Type", media)
        self.send_header("Content-Length", str(len(encoded)))
        self.end_headers()
        try: self.wfile.write(encoded)
        except (BrokenPipeError, ConnectionResetError): pass
HTTPServer((values["--host"], int(values["--port"])), Handler).serve_forever()
'''


def free_port():
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        return listener.getsockname()[1]


def private_json(path, document):
    path.write_text(json.dumps(document))
    path.chmod(0o600)


def fixture_model(path):
    # Metadata matches the parser's supported transformer dimensions; tensor
    # weights are intentionally absent and the fake runtime never reads them.
    data = bytearray(b"GGUF" + struct.pack("<IQQ", 3, 1, 7))
    def string(value):
        encoded = value.encode()
        data.extend(struct.pack("<Q", len(encoded)))
        data.extend(encoded)
    string("general.architecture")
    data.extend(struct.pack("<I", 8))
    string("llama")
    for name, value in (
        ("general.file_type", 2), ("llama.block_count", 2),
        ("llama.embedding_length", 32), ("llama.attention.head_count", 4),
        ("llama.attention.head_count_kv", 1), ("llama.context_length", 4096),
    ):
        string(name)
        data.extend(struct.pack("<II", 4, value))
    path.write_bytes(data)
    path.chmod(0o600)
    return {
        "id": "protocol-test-model", "revision": "fixture-only",
        "source": "local-protocol-fixture", "license": "test-only",
        "architecture": "llama", "format": "GGUF", "quantization": "Q4_0",
        "sha256": hashlib.sha256(data).hexdigest(), "size_bytes": len(data),
        "required_memory_bytes": 512 << 20, "workloads": ["text-generation"],
        "runtime": "llama.cpp", "path": str(path),
        "provenance": {
            "publisher": "Nucleus protocol test fixture", "country": "US",
            "evidence": ["https://example.org/nucleus/test-fixture"],
            "lineage_complete": True, "base_models": [],
        },
    }


@unittest.skipUnless(sys.platform == "linux", "CPU fleet runtime targets Linux or WSL2")
class InferenceFleet(unittest.TestCase):
    def test_two_workers_over_authenticated_fabric(self):
        if not BINARY.is_file():
            self.fail("Build bin/nucleus with bash scripts/build.sh first")
        with tempfile.TemporaryDirectory(prefix="nucleus-inference-fleet-") as directory:
            self.root = Path(directory)
            self.homes = {name: self.root / name for name in ("owner", "worker-a", "worker-b")}
            self.processes = []
            self.logs = []
            self.endpoint = f"https://127.0.0.1:{free_port()}/"
            self.api = f"http://127.0.0.1:{free_port()}"
            try:
                for name in self.homes:
                    self.cli(name, "init", "--name", name)
                self.ids = {name: json.loads(self.cli(name, "identity").stdout)["node_id"] for name in self.homes}
                for name in ("worker-a", "worker-b"):
                    self.pair(name)
                model = fixture_model(self.root / "protocol-fixture.gguf")
                # Fictional provenance describes generated test metadata only;
                # there are no pretrained model weights in this fixture.
                approvals = [{"sha256": model["sha256"], "provenance": model["provenance"]}]
                self.configs = {}
                for name in ("worker-a", "worker-b"):
                    fake = self.homes[name] / "fake-llama.py"
                    fake.write_text(FAKE_LLAMA)
                    fake.chmod(0o700)
                    self.configs[name] = {
                        "approved_models": approvals,
                        "runtime": {"binary": str(fake), "threads": 1,
                            "context_length": 512, "max_tokens": 32,
                            "memory_limit_bytes": 1 << 30, "reserve_memory_bytes": 1,
                            "startup_timeout_seconds": 15, "models": [model]},
                    }
                self.configs["owner"] = {
                    "approved_models": approvals,
                    "api_key": KEY, "allowed_workers": [self.ids["worker-a"]],
                    "queue_limit": 8, "request_timeout_seconds": 30,
                    "worker_ttl_seconds": 3, "max_cpu_percent": 100,
                }
                owner = self.start("owner")
                worker_a = self.start("worker-a")
                self.wait(lambda: self.online_nodes() == {self.ids["worker-a"]}, "first worker capabilities")
                for token in (None, "incorrect-token"):
                    with self.assertRaises(urllib.error.HTTPError) as caught:
                        self.request("/v1/models", token=token)
                    self.assertEqual(caught.exception.code, 401)
                # Pairing confers fabric membership; the separate worker allowlist
                # must still deny execution until the owner grants permission.
                worker_b = self.start("worker-b")
                self.wait(lambda: "not authorized for inference" in worker_b[1].read_text(), "worker permission rejection")
                self.assertNotIn(self.ids["worker-b"], self.online_nodes())
                self.stop(owner[0])
                self.configs["owner"]["allowed_workers"].append(self.ids["worker-b"])
                owner = self.start("owner")
                self.wait(lambda: self.online_nodes() == {self.ids["worker-a"], self.ids["worker-b"]}, "two explicitly authorized workers")
                models = self.json_request("/v1/models")
                self.assertEqual([m["id"] for m in models["data"]], ["protocol-test-model"])
                self.assertEqual(models["data"][0]["nucleus"]["sha256"], model["sha256"])
                print("PASS: real CLI pairing, mTLS capability discovery, bearer auth and worker permissions", flush=True)

                barrier = threading.Barrier(2)
                def concurrent(_index):
                    barrier.wait(timeout=5)
                    return self.complete("concurrent protocol request")
                with ThreadPoolExecutor(max_workers=2) as executor:
                    results = list(executor.map(concurrent, range(2)))
                placements = [self.job(job_id) for job_id, _body in results]
                self.assertEqual({job["node_id"] for job in placements}, {self.ids["worker-a"], self.ids["worker-b"]})
                self.assertTrue(all(job["status"] == "completed" for job in placements), placements)
                self.assertLess(max(job["started_at"] for job in placements), min(job["finished_at"] for job in placements))
                for job in placements:
                    self.assertIn("PROTOCOL FIXTURE", job["metrics"]["runtime_version"])
                    self.assertEqual(job["metrics"]["prompt_tokens_per_second"], 0)
                    self.assertEqual(job["metrics"]["generation_tokens_per_second"], 0)
                print("PASS: independent streamed jobs run concurrently on distinct workers; no synthetic throughput", flush=True)

                with self.request("/v1/chat/completions", payload=self.payload("hold for cancellation", allowed=[self.ids["worker-a"]])) as stream:
                    job_id = stream.headers["X-Nucleus-Job-ID"]
                    self.wait(lambda: self.job(job_id)["status"] == "running", "cancellable request running")
                    with self.request("/v1/inference/jobs/" + job_id, method="DELETE") as deleted:
                        self.assertEqual(deleted.status, 204)
                    stream.read()
                self.assertEqual(self.job(job_id)["status"], "cancelled")
                pid_path = self.homes["worker-a"] / "fake-llama.pid"
                pid = int(pid_path.read_text())
                self.wait(lambda: not Path(f"/proc/{pid}").exists(), "cancelled subprocess terminated")
                self.complete("after cancellation", allowed=[self.ids["worker-a"]])
                print("PASS: cancellation crosses mTLS and terminates the active runtime subprocess", flush=True)

                # Terminate only the Nucleus worker PID, never its process group.
                # A retained warm runtime must be synchronously killed and reaped
                # before Nucleus exits, rather than relying on goroutine timing.
                warm_pid = int(pid_path.read_text())
                self.assertTrue(Path(f"/proc/{warm_pid}").exists())
                self.stop_worker_pid(worker_a[0])
                self.wait(lambda: not Path(f"/proc/{warm_pid}").exists(), "warm runtime reaped after worker PID termination")
                worker_a = self.start("worker-a")
                self.complete("after graceful worker restart", allowed=[self.ids["worker-a"]])
                print("PASS: worker PID-only SIGTERM reaps the retained warm runtime before exit", flush=True)

                # A running request fails on disconnection and is never replayed.
                with self.request("/v1/chat/completions", payload=self.payload("hold during disconnect", allowed=[self.ids["worker-a"]])) as stream:
                    failed_id = stream.headers["X-Nucleus-Job-ID"]
                    self.wait(lambda: self.job(failed_id)["status"] == "running", "request running before disconnect")
                    active_pid = int(pid_path.read_text())
                    self.stop_worker_pid(worker_a[0])
                    self.wait(lambda: not Path(f"/proc/{active_pid}").exists(), "active runtime reaped after worker PID termination")
                    failed_stream = stream.read().decode()
                failed = self.job(failed_id)
                self.assertEqual(failed["status"], "failed", failed)
                self.assertEqual(failed["node_id"], self.ids["worker-a"])
                self.assertIn("not replayed", failed_stream)
                self.wait(lambda: self.online_nodes() == {self.ids["worker-b"]}, "disconnected node excluded")
                surviving_id, _ = self.complete("new request uses surviving node")
                self.assertEqual(self.job(surviving_id)["node_id"], self.ids["worker-b"])
                print("PASS: lost running work fails without replay; fresh requests use the healthy worker", flush=True)

                # Restart with a host reserve larger than available RAM, producing
                # an authentic zero-memory capability advertisement.
                self.stop(worker_b[0])
                self.configs["worker-b"]["runtime"]["reserve_memory_bytes"] = 1 << 60
                worker_b = self.start("worker-b")
                def exhausted_worker():
                    return any(node["node_id"] == self.ids["worker-b"] and node["online"] and
                               node["available_memory_bytes"] == 0 and not node.get("warm_models")
                               for node in self.json_request("/v1/inference/status")["nodes"])
                self.wait(exhausted_worker, "resource policy advertisement")
                for payload, expected in (
                    (self.payload("cannot fit", allowed=[self.ids["worker-b"]]), "insufficient available memory"),
                    (dict(self.payload("token budget"), max_tokens=33), "max_tokens exceeds worker policy"),
                ):
                    with self.assertRaises(urllib.error.HTTPError) as caught:
                        self.request("/v1/chat/completions", payload=payload)
                    self.assertEqual(caught.exception.code, 503)
                    self.assertIn(expected, caught.exception.read().decode())
                print("PASS: insufficient-memory reserve and generation-token limits return actionable errors", flush=True)
                print("PROTOCOL ONLY: no real model weights, model inference, or benchmark results", flush=True)
            finally:
                for process, _path in reversed(self.processes):
                    self.stop(process)
                # Failure cleanup is separate from the assertions above. Restrict
                # emergency cleanup to this test's exact fixture executable.
                for name in ("worker-a", "worker-b"):
                    fake = self.homes[name] / "fake-llama.py"
                    try:
                        pid = int(fake.with_suffix(".pid").read_text())
                        command = Path(f"/proc/{pid}/cmdline").read_bytes()
                        if str(fake).encode() in command:
                            os.kill(pid, signal.SIGKILL)
                    except (OSError, ValueError):
                        pass
                for log in self.logs:
                    log.close()

    def cli(self, name, *args):
        result = subprocess.run([str(BINARY), *args],
            env=dict(os.environ, NUCLEUS_HOME=str(self.homes[name])),
            text=True, capture_output=True, timeout=15)
        self.assertEqual(result.returncode, 0, result.stderr)
        return result

    def pair(self, name):
        invitation, request, grant = [self.root / f"{name}-{kind}.json" for kind in ("invite", "request", "grant")]
        self.cli("owner", "invite", "--endpoint", self.endpoint, "--out", str(invitation))
        self.cli(name, "join", str(invitation), "--out", str(request))
        self.cli("owner", "accept", str(request), "--out", str(grant))
        self.cli(name, "join", "--accept", str(grant))

    def start(self, name):
        path = self.root / f"{name}-inference.json"
        private_json(path, self.configs[name])
        if self.configs[name].get("runtime") is not None:
            self.cli(name, "validate-models", "--config", str(path))
        log_path = self.root / f"{name}-{len(self.logs)}.log"
        log = os.fdopen(os.open(log_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), "w")
        self.logs.append(log)
        args = [str(BINARY), "run", "--no-open", "--inference", str(path)]
        if name == "owner":
            args.extend(["--inference-api", self.api.removeprefix("http://")])
        process = subprocess.Popen(args, env=dict(os.environ, NUCLEUS_HOME=str(self.homes[name])),
                                   stdout=log, stderr=log, start_new_session=True)
        self.processes.append((process, log_path))
        def ready():
            if process.poll() is not None:
                self.fail(f"{name} exited: {log_path.read_text()}")
            return "Resource map:" in log_path.read_text()
        self.wait(ready, name + " startup")
        return process, log_path

    def stop_worker_pid(self, process):
        self.assertIsNone(process.poll(), "worker already exited before PID-only shutdown")
        process.terminate()
        try:
            result = process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            self.fail("worker did not finish synchronous inference cleanup after SIGTERM")
        self.assertEqual(result, 0, "graceful worker shutdown failed")

    def stop(self, process):
        if process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                os.killpg(process.pid, signal.SIGKILL)
                process.wait(timeout=5)

    def wait(self, predicate, label, timeout=20):
        deadline = time.monotonic() + timeout
        last = None
        while time.monotonic() < deadline:
            try:
                result = predicate()
                if result:
                    return result
            except (OSError, ValueError, KeyError, urllib.error.URLError) as error:
                last = error
            time.sleep(.1)
        logs = "\n".join(f"{path.name}: {path.read_text()[-2000:]}" for _process, path in self.processes)
        self.fail(f"{label}: {last}\n{logs}")

    def request(self, path, payload=None, method=None, token=KEY):
        headers = {}
        if token is not None:
            headers["Authorization"] = "Bearer " + token
        data = None
        if payload is not None:
            data = json.dumps(payload).encode()
            headers["Content-Type"] = "application/json"
        request = urllib.request.Request(self.api + path, data=data, headers=headers, method=method)
        return OPENER.open(request, timeout=35)

    def json_request(self, path):
        with self.request(path) as response:
            return json.load(response)

    def online_nodes(self):
        return {node["node_id"] for node in self.json_request("/v1/inference/status")["nodes"] if node["online"]}

    def job(self, job_id):
        return self.json_request("/v1/inference/jobs/" + job_id)

    def payload(self, prompt, allowed=None):
        payload = {"model": "protocol-test-model", "messages": [{"role": "user", "content": prompt}],
                   "stream": True, "max_tokens": 4}
        if allowed:
            payload["nucleus_allowed_nodes"] = allowed
        return payload

    def complete(self, prompt, allowed=None):
        with self.request("/v1/chat/completions", payload=self.payload(prompt, allowed)) as response:
            self.assertIn("text/event-stream", response.headers["Content-Type"])
            job_id = response.headers["X-Nucleus-Job-ID"]
            body = response.read().decode()
        events = [json.loads(line[6:]) for line in body.splitlines()
                  if line.startswith("data: ") and line != "data: [DONE]"]
        self.assertTrue(any(event.get("choices", [{}])[0].get("delta", {}).get("content") == "protocol fixture"
                            for event in events), body)
        self.assertIn("data: [DONE]", body)
        self.assertNotIn('"error"', body)
        return job_id, body


if __name__ == "__main__":
    unittest.main(verbosity=2)


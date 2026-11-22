#!/usr/bin/env python3
"""Opt-in real CPU inference demonstration using already provisioned local files.

Never downloads models or runtimes. Runs actual Nucleus CLI pairing, mTLS and
llama.cpp inference. The fleet consists of isolated processes on ONE host.
"""
import argparse
from concurrent.futures import ThreadPoolExecutor
from copy import deepcopy
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import shutil
import signal
import socket
import subprocess
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.request

ROOT = Path(__file__).resolve().parents[1]
OPENER = urllib.request.build_opener(urllib.request.ProxyHandler({}))
GIB = 1 << 30
PROMPT = "Explain in a short paragraph how quantized language models run on ordinary CPUs."


class DemoError(RuntimeError):
    pass


def free_port():
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        return listener.getsockname()[1]


def private_json(path, document):
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary = tempfile.mkstemp(prefix=".demo-json-", dir=path.parent)
    try:
        with os.fdopen(descriptor, "w") as output:
            json.dump(document, output, indent=2)
            output.write("\n")
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def file_sha256(path):
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def descendants(pid):
    result, pending = [], [pid]
    for _depth in range(4):
        following = []
        for parent in pending:
            try:
                tasks = list(Path(f"/proc/{parent}/task").glob("*/children"))
            except OSError:
                continue
            for task in tasks:
                try:
                    following.extend(int(child) for child in task.read_text().split())
                except (OSError, ValueError):
                    continue
        following = list(set(following) - set(result))
        result.extend(following)
        pending = following
    return result


def runtime_proof(process, runtime_binary):
    for pid in descendants(process.pid):
        try:
            args = Path(f"/proc/{pid}/cmdline").read_bytes().decode().strip("\x00").split("\x00")
        except (OSError, UnicodeError):
            continue
        if str(runtime_binary) not in args:
            continue
        pairs = dict(zip(args[:-1], args[1:]))
        redacted = list(args)
        if "--api-key-file" in redacted:
            redacted[redacted.index("--api-key-file") + 1] = "<private temporary file>"
        return {
            "pid": pid,
            "arguments": redacted,
            "cpu_forced": pairs.get("--device") == "none" and pairs.get("--n-gpu-layers") == "0",
            "gpu_kv_offload_disabled": "--no-kv-offload" in args,
            "operation_offload_disabled": "--no-op-offload" in args,
        }
    return {"cpu_forced": False, "error": "resident runtime process was not found"}


def job_intervals_overlap(jobs):
    """Compare actual worker execution intervals, including cold initialization."""
    def timestamp(value):
        # Python 3.10 requires microsecond precision; Go emits RFC3339 nanoseconds.
        value = re.sub(r"(\.\d{6})\d+", r"\1", value)
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    starts = [timestamp(job["started_at"]) for job in jobs]
    finishes = [timestamp(job["finished_at"]) for job in jobs]
    return bool(jobs) and max(starts) < min(finishes)


def bounded_policy(supplied, document):
    """Apply demo ceilings without widening the operator's resource policy."""
    runtime = {
        "threads": min(2, supplied.get("threads", 2), os.cpu_count() or 1),
        "context_length": min(1024, supplied.get("context_length", 1024)),
        "max_tokens": min(64, supplied.get("max_tokens", 64)),
        "memory_limit_bytes": min(4*GIB, supplied.get("memory_limit_bytes", 4*GIB)),
        "reserve_memory_bytes": max(GIB, supplied.get("reserve_memory_bytes", GIB)),
        "startup_timeout_seconds": min(120, supplied.get("startup_timeout_seconds", 120)),
    }
    scheduler = {
        "request_timeout_seconds": min(300, document.get("request_timeout_seconds", 300)),
        "max_cpu_percent": document.get("max_cpu_percent", 90),
    }
    return runtime, scheduler


def validate_catalog(binary, config):
    """Use Nucleus policy validation before copying weights or starting work."""
    environment = dict(os.environ)
    environment.pop("NUCLEUS_HOME", None)
    environment.pop("NUCLEUS_INFERENCE_API_KEY", None)
    result = subprocess.run([str(binary), "validate-models", "--config", str(config)],
                            env=environment, capture_output=True, text=True, timeout=120)
    if result.returncode:
        raise DemoError("Model catalog preflight rejected the demo: " + result.stderr.strip())


class Demo:
    def __init__(self, args):
        self.args = args
        self.binary = args.binary.resolve()
        self.source_config = args.config.resolve()
        self.processes, self.logs = [], []
        self.report = {
            "schema_version": 1, "real_model": True,
            "measured_at_utc": datetime.now(timezone.utc).isoformat(),
            "physical_host_count": 1, "two_processes_one_machine": True,
            "scope": "Real model inference and mTLS fleet execution on one physical host; no two-machine speedup claim.",
            "measurements": {}, "checks": {}, "status": "initializing",
        }

    def environment(self, name):
        environment = dict(os.environ, NUCLEUS_HOME=str(self.homes[name]))
        environment.pop("NUCLEUS_INFERENCE_API_KEY", None)
        return environment

    def cli(self, name, *arguments, timeout=30):
        result = subprocess.run([str(self.binary), *arguments], env=self.environment(name),
                                capture_output=True, text=True, timeout=timeout)
        if result.returncode:
            raise DemoError(f"Nucleus {arguments[0]} failed: {result.stderr.strip()}")
        return result.stdout

    def config(self, name, value):
        path = self.directory / (name + "-inference.json")
        private_json(path, value)
        return path

    def start(self, name, config):
        if json.loads(config.read_text()).get("runtime") is not None:
            validate_catalog(self.binary, config)
        path = self.directory / f"{name}-{len(self.logs)}.log"
        log = os.fdopen(os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), "w")
        self.logs.append(log)
        command = [str(self.binary), "run", "--inference", str(config), "--no-open"]
        if name == "owner":
            command += ["--inference-api", self.api.removeprefix("http://")]
        process = subprocess.Popen(command, env=self.environment(name), stdout=log, stderr=log,
                                   start_new_session=True)
        self.processes.append((process, path))
        def ready():
            if process.poll() is not None:
                raise DemoError(f"{name} stopped during startup; inspect {path}")
            return "Resource map:" in path.read_text()
        self.wait(ready, name + " startup")
        return process

    def stop(self, process):
        if process.poll() is None:
            try:
                os.killpg(process.pid, signal.SIGTERM)
            except ProcessLookupError:
                pass
            try:
                process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                os.killpg(process.pid, signal.SIGKILL)
                process.wait(timeout=5)

    def wait(self, predicate, label, timeout=120):
        deadline, last = time.monotonic() + timeout, None
        while time.monotonic() < deadline:
            try:
                result = predicate()
                if result:
                    return result
            except (OSError, ValueError, KeyError, urllib.error.URLError) as error:
                last = error
            time.sleep(.1)
        raise DemoError(f"{label} did not complete: {last}")

    def request(self, path, payload=None, method=None):
        headers = {"Authorization": "Bearer " + self.key}
        data = None
        if payload is not None:
            data = json.dumps(payload).encode()
            headers["Content-Type"] = "application/json"
        request = urllib.request.Request(self.api + path, data=data, headers=headers, method=method)
        return OPENER.open(request, timeout=120)

    def get(self, path):
        with self.request(path) as response:
            return json.load(response)

    def online(self):
        return {node["node_id"] for node in self.get("/v1/inference/status")["nodes"] if node["online"]}

    def job(self, job_id):
        return self.get("/v1/inference/jobs/" + job_id)

    def payload(self, prompt, allowed=None):
        value = {"model": self.model["id"], "messages": [{"role": "user", "content": prompt}],
                 "stream": True, "max_tokens": self.runtime["max_tokens"], "temperature": 0}
        if allowed:
            value["nucleus_allowed_nodes"] = allowed
        return value

    def generate(self, prompt=PROMPT, allowed=None, barrier=None):
        if barrier is not None:
            barrier.wait(timeout=10)
        started, first_content = time.monotonic(), None
        text, finish_reason, errors, chunks = "", None, [], 0
        with self.request("/v1/chat/completions", self.payload(prompt, allowed)) as response:
            job_id = response.headers["X-Nucleus-Job-ID"]
            if not response.headers.get("Content-Type", "").startswith("text/event-stream"):
                raise DemoError("Inference did not return SSE")
            done = False
            for raw in response:
                line = raw.decode().strip()
                if not line.startswith("data:"):
                    continue
                data = line[5:].strip()
                if data == "[DONE]":
                    done = True
                    break
                event = json.loads(data)
                chunks += 1
                if event.get("error"):
                    errors.append(event["error"])
                for choice in event.get("choices", []):
                    content = choice.get("delta", {}).get("content") or ""
                    if content and first_content is None:
                        first_content = time.monotonic()
                    text += content
                    if choice.get("finish_reason") is not None:
                        finish_reason = choice["finish_reason"]
        ended = time.monotonic()
        job = self.job(job_id)
        if not done or errors or job["status"] != "completed" or not text:
            raise DemoError(f"Generation {job_id} failed: {errors or job.get('error') or 'incomplete SSE'}")
        return {
            "job": job, "prompt": prompt, "output": text, "finish_reason": finish_reason,
            "sse_json_events": chunks, "client_started_monotonic": started,
            "client_finished_monotonic": ended,
            "client_first_content_ms": (first_content-started)*1000 if first_content else None,
            "client_elapsed_ms": (ended-started)*1000,
            "timing_note": "First-content latency observes the first nonempty delta.content; phase speeds come only from llama.cpp.",
        }

    def provision(self, name):
        model = deepcopy(self.model)
        directory = self.homes[name] / "models"
        directory.mkdir(mode=0o700)
        destination = directory / (self.model["sha256"] + ".gguf")
        shutil.copyfile(self.model_path, destination)
        destination.chmod(0o600)
        if file_sha256(destination) != self.model["sha256"]:
            raise DemoError(f"{name} model copy failed integrity verification")
        model["path"] = str(destination)
        runtime = dict(self.runtime, models=[model])
        return dict(self.scheduler_policy, runtime=runtime, approved_models=deepcopy(self.approved_models))

    def pair(self, name):
        invitation, request, grant = [self.directory / f"{name}-{kind}.json" for kind in ("invite", "request", "grant")]
        self.cli("owner", "invite", "--endpoint", self.endpoint, "--out", str(invitation))
        self.cli(name, "join", str(invitation), "--out", str(request))
        self.cli("owner", "accept", str(request), "--out", str(grant))
        self.cli(name, "join", "--accept", str(grant))

    def run(self):
        if sys.platform != "linux":
            raise DemoError("Run this demonstration on Linux or WSL2")
        if not self.binary.is_file():
            raise DemoError("Build the Nucleus binary first")
        document = json.loads(self.source_config.read_text())
        if not isinstance(document.get("runtime"), dict):
            raise DemoError("The demo requires a private fleet config with runtime and reviewed approved_models")
        validate_catalog(self.binary, self.source_config)
        self.approved_models = deepcopy(document.get("approved_models", []))
        supplied = document["runtime"]
        models = supplied.get("models", [])
        matches = [model for model in models if not self.args.model or model["id"] == self.args.model]
        if len(matches) != 1:
            raise DemoError("Select exactly one explicitly provisioned model with --model")
        self.model = deepcopy(matches[0])
        self.model_path = Path(self.model["path"]).resolve()
        runtime_binary = Path(supplied["binary"]).resolve()
        if not self.model_path.is_file() or not runtime_binary.is_file():
            raise DemoError("The GGUF weights and llama-server binary must already exist locally")
        if file_sha256(self.model_path) != self.model["sha256"] or self.model_path.stat().st_size != self.model["size_bytes"]:
            raise DemoError("The provisioned model does not match its catalog hash and size")
        runtime_policy, self.scheduler_policy = bounded_policy(supplied, document)
        self.runtime = dict(runtime_policy, binary=str(runtime_binary))
        if self.model["required_memory_bytes"] > self.runtime["memory_limit_bytes"]:
            raise DemoError("Model exceeds the bounded process address-space cap")
        workdir = self.args.workdir.resolve()
        workdir.mkdir(parents=True, exist_ok=True, mode=0o700)
        self.directory = Path(tempfile.mkdtemp(prefix="run-", dir=workdir))
        self.homes = {name: self.directory / name for name in ("owner", "worker-a", "worker-b")}
        self.report_path = self.args.report.resolve() if self.args.report else self.directory / "report.json"
        self.report.update({
            "artifact_directory": str(self.directory), "model": {key: value for key, value in self.model.items() if key != "path"},
            "settings": self.runtime,
            "scheduler_policy": self.scheduler_policy,
            "memory_note": "The demo caps address space at 4 GiB and preserves any lower operator cap. Host RAM reserve is at least 1 GiB and preserves any higher operator reserve. Limits are per process, not a shared fleet RAM partition.",
            "rss_note": "peak_rss_bytes samples /proc VmHWM: the runtime process lifetime resident-memory high-water mark, including startup and earlier requests.",
        })
        self.key = secrets.token_hex(32)
        self.endpoint = f"https://127.0.0.1:{free_port()}/"
        self.api = f"http://127.0.0.1:{free_port()}"
        try:
            for name in self.homes:
                self.cli(name, "init", "--name", "cpu-demo-" + name)
            self.ids = {name: json.loads(self.cli(name, "identity"))["node_id"] for name in self.homes}
            self.report["nodes"] = self.ids
            self.report["hardware"] = json.loads(self.cli("owner", "snapshot"))
            self.cli("owner", "invite", "--endpoint", self.endpoint, "--out", str(self.directory / "initialize-fabric.json"))
            owner_config = self.provision("owner")
            owner_config.update(api_key=self.key)
            owner_path = self.config("owner", owner_config)
            print("Running real single-node CPU streaming and warm-reuse requests.", flush=True)
            owner = self.start("owner", owner_path)
            self.wait(lambda: self.online() == {self.ids["owner"]}, "local runtime advertisement")
            self.report["measurements"]["single_node_cold"] = self.generate()
            self.report["measurements"]["single_node_warm"] = self.generate()
            self.report["checks"]["single_node_warm_reuse"] = self.report["measurements"]["single_node_warm"]["job"]["metrics"]["cold_start_ms"] == 0
            if not self.report["checks"]["single_node_warm_reuse"]:
                raise DemoError("The second single-node request unexpectedly reloaded the model")
            self.report["single_node_runtime_proof"] = runtime_proof(owner, runtime_binary)
            if not self.report["single_node_runtime_proof"]["cpu_forced"]:
                raise DemoError("Could not verify actual CPU-only subprocess flags")
            self.stop(owner)

            for name in ("worker-a", "worker-b"):
                self.pair(name)
            configs = {name: self.config(name, self.provision(name)) for name in ("worker-a", "worker-b")}
            print("Running the explicitly authorized local CPU benchmark on worker-a.", flush=True)
            benchmark = json.loads(self.cli("worker-a", "benchmark", "--config", str(configs["worker-a"]),
                                          "--model", self.model["id"], "--max-tokens", str(self.runtime["max_tokens"]),
                                          "--prompt", PROMPT, timeout=300))
            self.report["measurements"]["explicit_benchmark"] = benchmark
            if benchmark["metrics"]["generation_tokens_per_second"] <= 0:
                raise DemoError("The runtime did not supply real generation phase timings")
            coordinator = dict(self.scheduler_policy, api_key=self.key,
                               allowed_workers=[self.ids["worker-a"], self.ids["worker-b"]],
                               approved_models=deepcopy(self.approved_models), worker_ttl_seconds=3)
            owner = self.start("owner", self.config("owner", coordinator))
            worker_a = self.start("worker-a", configs["worker-a"])
            self.wait(lambda: self.online() == {self.ids["worker-a"]}, "first trusted worker")
            self.report["measurements"]["one_remote_worker"] = self.generate()
            worker_b = self.start("worker-b", configs["worker-b"])
            self.wait(lambda: self.online() == {self.ids["worker-a"], self.ids["worker-b"]}, "two trusted workers")
            self.report["catalog"] = self.get("/v1/models")
            print("Running concurrent real streamed requests through the two-worker mTLS fleet.", flush=True)
            barrier = threading.Barrier(2)
            concurrent_start = time.monotonic()
            with ThreadPoolExecutor(max_workers=2) as executor:
                futures = [executor.submit(self.generate, PROMPT, None, barrier) for _ in range(2)]
                concurrent = [future.result() for future in futures]
            self.report["measurements"]["concurrent_requests"] = concurrent
            self.report["measurements"]["concurrent_wall_ms"] = (time.monotonic()-concurrent_start)*1000
            distinct = {result["job"]["node_id"] for result in concurrent} == {self.ids["worker-a"], self.ids["worker-b"]}
            self.report["checks"]["concurrent_distinct_workers"] = distinct
            self.report["checks"]["concurrent_client_intervals_overlap"] = (
                max(result["client_started_monotonic"] for result in concurrent) <
                min(result["client_finished_monotonic"] for result in concurrent))
            self.report["checks"]["concurrent_job_intervals_overlap"] = job_intervals_overlap(
                [result["job"] for result in concurrent])
            if (not distinct or not self.report["checks"]["concurrent_client_intervals_overlap"]
                    or not self.report["checks"]["concurrent_job_intervals_overlap"]):
                raise DemoError("Concurrent requests did not have overlapping execution intervals on distinct workers")
            self.report["worker_runtime_proofs"] = {
                "worker-a": runtime_proof(worker_a, runtime_binary),
                "worker-b": runtime_proof(worker_b, runtime_binary),
            }
            if not all(value["cpu_forced"] for value in self.report["worker_runtime_proofs"].values()):
                raise DemoError("Could not verify both worker processes use CPU-only runtime flags")

            with self.request("/v1/chat/completions", self.payload(
                    "Count the integers from 1 to 100, separated by commas. Continue until the token limit.",
                    [self.ids["worker-a"]])) as stream:
                job_id = stream.headers["X-Nucleus-Job-ID"]
                state = self.wait(lambda: (job if (job := self.job(job_id))["status"] in ("running", "completed", "failed") else None),
                                  "cancellation candidate")
                if state["status"] == "running":
                    with self.request("/v1/inference/jobs/" + job_id, method="DELETE"):
                        pass
                    stream.read()
                    self.report["checks"]["real_request_cancellation"] = self.job(job_id)["status"] == "cancelled"
                elif state["status"] == "completed":
                    self.report["checks"]["real_request_cancellation"] = "request finished before cancellation could be applied"
                else:
                    raise DemoError("The cancellation candidate failed before cancellation")
                if self.report["checks"]["real_request_cancellation"] is False:
                    raise DemoError("The explicit cancellation was not honored")
            self.stop(worker_b)
            self.wait(lambda: self.online() == {self.ids["worker-a"]}, "disconnected worker exclusion")
            self.report["measurements"]["after_worker_disconnect"] = self.generate()
            self.report["checks"]["disconnected_worker_excluded"] = (
                self.report["measurements"]["after_worker_disconnect"]["job"]["node_id"] == self.ids["worker-a"])
            if not self.report["checks"]["disconnected_worker_excluded"]:
                raise DemoError("A request was assigned to the disconnected worker")
            self.report["final_fleet_status"] = self.get("/v1/inference/status")
            self.report["status"] = "passed"
            print("Real CPU model streaming, measured benchmark, warm reuse and two-worker placement passed.", flush=True)
        except BaseException as error:
            self.report.update(status="failed", error=str(error))
            raise
        finally:
            for process, _path in reversed(self.processes):
                self.stop(process)
            for log in self.logs:
                log.close()
            private_json(self.report_path, self.report)
            print(f"Report: {self.report_path}", flush=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", type=Path, required=True, help="Private fleet JSON with runtime, reviewed approved_models, and local provisioned weights")
    parser.add_argument("--model", help="Catalog ID; required when the config contains multiple models")
    parser.add_argument("--binary", type=Path, default=ROOT / "bin/nucleus")
    parser.add_argument("--workdir", type=Path, default=ROOT / ".runtime/real-cpu-demo")
    parser.add_argument("--report", type=Path, help="Optional exact JSON report destination")
    args = parser.parse_args()
    try:
        Demo(args).run()
    except (DemoError, OSError, ValueError, subprocess.SubprocessError, urllib.error.URLError) as error:
        raise SystemExit(str(error))


if __name__ == "__main__":
    main()

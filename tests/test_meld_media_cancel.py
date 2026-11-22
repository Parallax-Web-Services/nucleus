#!/usr/bin/env python3
"""Opt-in REAL CPU vision cancellation through an already running local gateway.

No service startup, downloads, generation or second review. Requires Linux/WSL,
private operator configuration, an existing PNG and explicit execution opt-in:
  NUCLEUS_RUN_REAL_MEDIA_CANCEL=1 python3 tests/test_meld_media_cancel.py \
    --owner /ABS/owner.json --profile /ABS/profile.json \
    --candidate /ABS/output.png --review-work-dir /ABS/review-jobs \
    --shared-lock /ABS/node-execution.lock --evidence /ABS/cancellation.json

The legacy private parameters.json profile is also accepted. The helper reads
credentials only into memory, never emits keys/prompts, and never kills a PID.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import fcntl
import hashlib
import http.client
import ipaddress
import json
import os
from pathlib import Path
import secrets
import select
import socket
import stat
import struct
import sys
import time
import unittest
from urllib.parse import urlsplit

ROOT = Path(__file__).resolve().parents[1]
ENABLED = os.environ.get("NUCLEUS_RUN_REAL_MEDIA_CANCEL") == "1"
ARGS = None
MANIFEST = "X-Nucleus-Manifest-SHA256"
NONCE = "X-Nucleus-Request-Nonce"


def checked_path(raw, *, directory=False, private=False):
    path = Path(raw)
    if not path.is_absolute() or any(p.is_symlink() for p in (path, *path.parents)):
        raise ValueError("absolute nonsymlink paths are required")
    info = path.stat()
    if not (stat.S_ISDIR(info.st_mode) if directory else stat.S_ISREG(info.st_mode)):
        raise ValueError("expected a regular local file or directory")
    if private and (info.st_uid != os.geteuid() or info.st_mode & 0o077):
        raise ValueError("operator files/directories must be owned and private")
    return path


def private_document(raw):
    path = checked_path(raw, private=True)
    if path.stat().st_size > 1024**2:
        raise ValueError("operator configuration exceeds 1 MiB")
    return json.loads(path.read_bytes())


def endpoint(raw):
    value = urlsplit(raw)
    if (value.scheme != "http" or value.username or value.password or
            value.path not in ("", "/") or value.query or value.fragment or
            not value.port or not ipaddress.ip_address(value.hostname).is_loopback):
        raise ValueError("only explicit literal-loopback HTTP endpoints are allowed")
    return value.hostname, value.port


def connection(raw, timeout=5):
    return http.client.HTTPConnection(*endpoint(raw), timeout=timeout)


def request(raw, token, method, path, body=None, headers=None):
    wire_headers = {"Authorization": "Bearer " + token, "Connection": "close"}
    wire_headers.update(headers or {})
    client = connection(raw)
    try:
        client.request(method, path, body=body, headers=wire_headers)
        response = client.getresponse()
        value = response.read(1024**2 + 1)
        if len(value) > 1024**2:
            raise ValueError("probe response exceeds 1 MiB")
        return response.status, response.headers, value
    finally:
        client.close()


def multipart(candidate):
    boundary = "nucleus-cancel-" + secrets.token_hex(16)
    brief = b"Inspect this existing studio portrait for visual defects. Return the required JSON verdict."
    body = (b"--" + boundary.encode() + b'\r\nContent-Disposition: form-data; name="prompt"\r\n\r\n' + brief +
            b"\r\n--" + boundary.encode() + b'\r\nContent-Disposition: form-data; name="candidate"; filename="candidate.png"\r\nContent-Type: image/png\r\n\r\n' +
            candidate + b"\r\n--" + boundary.encode() + b"--\r\n")
    return body, "multipart/form-data; boundary=" + boundary


def processes():
    """PID identity includes kernel start time, so a recycled PID is distinct."""
    output = {}
    for path in Path("/proc").iterdir():
        if not path.name.isdigit():
            continue
        try:
            if path.stat().st_uid != os.geteuid():
                continue
            fields = (path / "stat").read_text().rsplit(")", 1)[1].split()
            try:
                executable = os.readlink(path / "exe")
            except OSError:
                executable = ""  # Retain zombies: their process group must disappear too.
            output[int(path.name)] = {
                "pid": int(path.name), "state": fields[0], "parent": int(fields[1]),
                "group": int(fields[2]), "start_ticks": int(fields[19]),
                "argv": (path / "cmdline").read_bytes().split(b"\0")[:-1],
                "executable": executable,
            }
        except (OSError, ValueError, IndexError):
            pass
    return output


def unlocked(path):
    descriptor = os.open(path, os.O_RDWR | os.O_NOFOLLOW)
    try:
        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            return False
        fcntl.flock(descriptor, fcntl.LOCK_UN)
        return True
    finally:
        os.close(descriptor)


def reset(client):
    if client is not None:
        if client.sock is not None:
            try:
                client.sock.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack("ii", 1, 0))
            except OSError:
                pass
        client.close()


def evidence(path, value):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "w") as target:
        json.dump(value, target, indent=2)
        target.write("\n")


@unittest.skipUnless(ENABLED and sys.platform == "linux", "set NUCLEUS_RUN_REAL_MEDIA_CANCEL=1 explicitly on Linux/WSL; executes one real vision review")
class RealMediaCancellation(unittest.TestCase):
    def test_review_disconnect_reaps_owned_engine_and_llama_and_releases_slots(self):
        for field in ("owner", "profile", "candidate", "evidence"):
            self.assertTrue(getattr(ARGS, field), "explicit operator config, profile, candidate and evidence paths required")
        owner = private_document(ARGS.owner)
        profile = private_document(ARGS.profile)
        meld = owner["meld"]
        gateway = profile["gateway_url"]
        review_url = meld["review_url"]
        endpoint(gateway)
        endpoint(review_url)
        pin = profile.get("review_manifest_sha256", profile.get("pins", {}).get("review"))
        self.assertEqual(pin, meld["review_manifest_sha256"], "profile and owner manifest pins differ")
        self.assertTrue(isinstance(pin, str) and len(pin) == 64 and all(c in "0123456789abcdef" for c in pin))
        work = checked_path(ARGS.review_work_dir or str(Path(ARGS.profile).parent / "review-jobs"), directory=True, private=True)
        lock = checked_path(ARGS.shared_lock or profile["shared_lock"], private=True)
        report_path = Path(ARGS.evidence)
        checked_path(report_path.parent, directory=True, private=True)
        self.assertFalse(report_path.exists(), "use a new evidence path; existing reports are preserved")
        candidate_path = checked_path(ARGS.candidate)
        self.assertLessEqual(candidate_path.stat().st_size, 16 * 1024**2)
        candidate = candidate_path.read_bytes()
        self.assertTrue(candidate.startswith(b"\x89PNG\r\n\x1a\n"), "an existing real candidate PNG is required")
        candidate_hash = hashlib.sha256(candidate).hexdigest()
        self.assertFalse(list(work.glob("job-*")), "review runtime must be idle before this opt-in test")
        self.assertTrue(unlocked(lock), "shared node budget must be idle before this opt-in test")
        status, headers, manifest_body = request(review_url, meld["review_token"], "GET", "/v1/runtime-manifest")
        self.assertEqual(status, 200)
        self.assertEqual(headers.get(MANIFEST), pin)
        self.assertEqual(hashlib.sha256(manifest_body).hexdigest(), pin)
        manifest = json.loads(manifest_body)
        self.assertEqual(manifest["backend"], "llama_cpp_vlm")
        self.assertEqual(manifest["model"], meld["review_model"])
        nonce = secrets.token_hex(32)
        receipt = {MANIFEST: pin, NONCE: nonce}
        report = {"schema_version": 1, "real_model_inference": True,
                  "recorded_at_utc": datetime.now(timezone.utc).isoformat(),
                  "scope": "one existing local candidate; real CPU vision request cancelled after review_image; no second inference",
                  "manifest_sha256": pin, "candidate_sha256": candidate_hash,
                  "nonce_sha256": hashlib.sha256(nonce.encode()).hexdigest(),
                  "backend": manifest["backend"], "model": manifest["model"], "status": "failed"}
        client = None
        started = time.monotonic()
        try:
            body, content_type = multipart(candidate)
            client = connection(gateway, timeout=15)
            client.request("POST", "/v1/reviews", body=body,
                           headers={"Authorization": "Bearer " + owner["api_key"],
                                    "Content-Type": content_type, "Connection": "close", **receipt})
            deadline = time.monotonic() + ARGS.start_timeout
            observed = None
            engine_path = str((ROOT / "runtimes/meld/engine.py").resolve()).encode()
            while time.monotonic() < deadline:
                for directory in work.glob("job-*"):
                    try:
                        job_path = directory / "job.json"
                        job = json.loads(job_path.read_bytes())
                        if (job["operation"] != "review" or job["manifest_sha256"] != pin or
                                hashlib.sha256(Path(job["request"]["candidate"]).read_bytes()).hexdigest() != candidate_hash):
                            continue
                        if (directory / "phase.txt").read_text().strip() != "review_image":
                            continue
                        snapshot = processes()
                        engines = [p for p in snapshot.values() if engine_path in p["argv"] and str(job_path).encode() in p["argv"]]
                        self.assertEqual(len(engines), 1, "must identify exactly this request's owned engine")
                        engine = engines[0]
                        self.assertEqual(engine["group"], engine["pid"], "engine must own its process session")
                        self.assertEqual(engine["parent"], job["parent_pid"])
                        llamas = [p for p in snapshot.values() if p["group"] == engine["group"] and p["parent"] == engine["pid"] and Path(p["executable"]).name == "llama-server"]
                        if not llamas:
                            continue
                        self.assertEqual(len(llamas), 1)
                        observed = engine, llamas[0], directory
                        break
                    except (OSError, ValueError, KeyError):
                        continue
                if observed:
                    break
                ready, _, _ = select.select([client.sock], [], [], 0)
                self.assertFalse(ready, "review finished/rejected before active image inference was observed")
                time.sleep(0.02)
            self.assertIsNotNone(observed, "real review_image phase and owned llama child were not observed before deadline")
            engine, llama, job_dir = observed
            self.assertFalse(unlocked(lock), "shared execution lock must be held during real review")
            report.update(observed_phase="review_image", observed_after_seconds=round(time.monotonic()-started, 3),
                          engine={k:engine[k] for k in ("pid", "parent", "group", "start_ticks")},
                          llama={k:llama[k] for k in ("pid", "parent", "group", "start_ticks")})
            # The malformed probe proves the gateway slot is occupied, without
            # containing a candidate that could dispatch another inference.
            empty = b"--slot-proof--\r\n"
            probe_headers = {MANIFEST: pin, NONCE: secrets.token_hex(32), "Content-Type": "multipart/form-data; boundary=slot-proof"}
            busy, _, _ = request(gateway, owner["api_key"], "POST", "/v1/reviews", empty, probe_headers)
            self.assertEqual(busy, 429, "gateway must report its active review slot busy")
            reset(client)
            client = None
            disconnected = time.monotonic()
            deadline = disconnected + ARGS.stop_timeout
            while time.monotonic() < deadline:
                snapshot = processes()
                same = [p for p in snapshot.values() if p["group"] == engine["group"] or
                        any(p["pid"] == old["pid"] and p["start_ticks"] == old["start_ticks"] for old in (engine,llama))]
                if not same and not job_dir.exists() and unlocked(lock):
                    break
                time.sleep(0.05)
            else:
                self.fail("owned engine/llama process group, private job or shared execution lock survived disconnect deadline")
            report.update(owned_process_group_gone=True, private_job_removed=True, shared_lock_released=True,
                          cleanup_seconds=round(time.monotonic()-disconnected, 3))
            failure = private_document(str(work / "last-failure.json"))
            self.assertEqual(failure["error_code"], "cancelled")
            self.assertEqual(failure["phase"], "review_image")
            self.assertEqual(failure["manifest_sha256"], pin)
            report["runtime_cancellation"] = {k:failure[k] for k in ("error_code", "phase", "child_exit_code", "elapsed_ms", "device", "threads")}
            probe_headers[NONCE] = secrets.token_hex(32)
            status, _, _ = request(gateway, owner["api_key"], "POST", "/v1/reviews", empty, probe_headers)
            self.assertEqual(status, 400, "gateway slot must admit a malformed request after cancellation")
            probe_headers[NONCE] = secrets.token_hex(32)
            status, _, _ = request(review_url, meld["review_token"], "POST", "/v1/reviews", empty, probe_headers)
            self.assertEqual(status, 422, "runtime slot must validate a malformed request after cancellation")
            report.update(gateway_slot_released=True, runtime_slot_released=True, status="passed")
        finally:
            reset(client)
            report["elapsed_seconds"] = round(time.monotonic()-started, 3)
            evidence(report_path, report)


def main():
    global ARGS
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("owner", "profile", "candidate", "review-work-dir", "shared-lock", "evidence"):
        parser.add_argument("--" + name)
    parser.add_argument("--start-timeout", type=float, default=180)
    parser.add_argument("--stop-timeout", type=float, default=20)
    ARGS = parser.parse_args()
    if not 1 <= ARGS.start_timeout <= 300 or not 1 <= ARGS.stop_timeout <= 60:
        parser.error("bounded start/stop timeouts required (1..300 / 1..60 seconds)")
    unittest.main(argv=[sys.argv[0]], verbosity=2)


if __name__ == "__main__":
    main()



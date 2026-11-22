"""Bounded private operational diagnostics, excluding prompts and image data."""
from __future__ import annotations

from datetime import datetime, timezone
import json
import os
from pathlib import Path
import re
import secrets


def atomic_private(path, data):
    temporary = path.with_name("." + path.name + "." + secrets.token_hex(8))
    descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    try:
        with os.fdopen(descriptor, "wb") as target:
            target.write(data)
            target.flush()
            os.fsync(target.fileno())
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


def _tail(path, limit=16384):
    try:
        with path.open("rb") as source:
            source.seek(0, os.SEEK_END)
            source.seek(max(0, source.tell() - limit))
            return source.read(limit).decode("utf-8", errors="replace")
    except OSError:
        return ""


def _scrubber(payload, token, job_dir):
    sensitive = [token, payload.prompt, payload.negative_prompt]
    sensitive.extend(getattr(payload, "names", []))
    try:
        sensitive.append((job_dir / "llama-key").read_text().strip())
    except OSError:
        pass
    words = set()
    for text in sensitive:
        words.update(re.findall(r"\w+", text, re.UNICODE))
    pattern = re.compile(r"\b(?:" + "|".join(re.escape(word) for word in sorted(words, key=len, reverse=True)) + r")\b", re.IGNORECASE) if words else None

    def scrub(text):
        text = str(text)
        for value in sensitive:
            if value:
                text = text.replace(value, "[input redacted]")
        text = re.sub(r"(?i)bearer\s+[^\s\"']+", "Bearer [redacted]", text)
        text = re.sub(r"data:image/[^\s\"']+", "[image data redacted]", text)
        text = re.sub(r"[A-Za-z0-9+/_=-]{80,}", "[opaque value redacted]", text)
        text = re.sub(r"\x1b\[[0-?]*[ -/]*[@-~]", "", text)
        if pattern:
            text = pattern.sub("[input]", text)
        return "".join(char for char in text if char.isprintable() or char in "\n\t")[-16384:]
    return scrub


class ProcessMetrics:
    def __init__(self):
        self.sampled_peak_tree_rss_bytes = 0
        self.sampled_peak_leader_vm_bytes = 0
        self.leader_vm_hwm_bytes = 0

    def sample(self, pid):
        pending, seen, rss = [pid], set(), 0
        while pending and len(seen) < 64:
            current = pending.pop()
            if current in seen:
                continue
            seen.add(current)
            try:
                values = {}
                for line in Path(f"/proc/{current}/status").read_text().splitlines():
                    fields = line.split()
                    if fields and fields[0] in {"VmRSS:", "VmHWM:", "VmPeak:"}:
                        values[fields[0]] = int(fields[1]) * 1024
                rss += values.get("VmRSS:", 0)
                if current == pid:
                    self.leader_vm_hwm_bytes = max(self.leader_vm_hwm_bytes, values.get("VmHWM:", 0))
                    self.sampled_peak_leader_vm_bytes = max(self.sampled_peak_leader_vm_bytes, values.get("VmPeak:", 0))
                children = Path(f"/proc/{current}/task/{current}/children").read_text().split()
                pending.extend(int(child) for child in children)
            except (OSError, ValueError):
                pass
        self.sampled_peak_tree_rss_bytes = max(self.sampled_peak_tree_rss_bytes, rss)


def record(manifest, settings, operation, payload, job_dir, process, started, metrics, failure):
    report = {
        "recorded_at": datetime.now(timezone.utc).isoformat(),
        "operation": operation, "backend": manifest.document["backend"], "model": manifest.document["model"],
        "manifest_sha256": manifest.sha256, "runtime_version": manifest.document["runtime_version"],
        "elapsed_ms": round((__import__("time").monotonic() - started) * 1000, 3),
        "child_exit_code": process.returncode, "threads": settings.threads,
        "address_space_limit_bytes": settings.memory_limit_bytes,
        "device": settings.device if operation == "generate" else "cpu",
        **vars(metrics),
    }
    if failure is None:
        report["status"] = "completed"
        atomic_private(settings.work_dir / "last-success.json", json.dumps(report, indent=2).encode())
        return
    report["status"] = "failed"
    report["error_code"] = getattr(failure, "code", "cancelled" if isinstance(failure, __import__("asyncio").CancelledError) else "model_execution_failed")
    scrub = _scrubber(payload, settings.token, job_dir)
    report["supervisor_error"] = scrub(str(failure))[:2000]
    try:
        phase = (job_dir / "phase.txt").read_text().strip()
        if re.fullmatch(r"[a-z_]{1,64}", phase):
            report["phase"] = phase
    except OSError:
        pass
    try:
        path = job_dir / "error.json"
        if path.stat().st_size <= 16384:
            detail = json.loads(path.read_bytes())
            kind = str(detail.get("error", ""))
            if re.fullmatch(r"[A-Za-z_][A-Za-z0-9_.]{0,127}", kind):
                report["engine_error_class"] = kind
            report["engine_error_message"] = scrub(detail.get("message", ""))[:2000]
            report["stack"] = [{"file": str(frame.get("file", ""))[:512], "line": int(frame.get("line", 0)), "function": str(frame.get("function", ""))[:128]} for frame in detail.get("frames", [])[-20:] if isinstance(frame, dict)]
    except (OSError, ValueError, TypeError):
        pass
    log = scrub(_tail(job_dir / "engine.log"))
    report["engine_log_tail"] = log
    atomic_private(settings.work_dir / "last-failure.log", log.encode())
    atomic_private(settings.work_dir / "last-failure.json", json.dumps(report, indent=2).encode())

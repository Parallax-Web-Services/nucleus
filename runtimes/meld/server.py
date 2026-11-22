"""Authenticated loopback supervisor; model execution happens in owned children."""
from __future__ import annotations

import argparse
import asyncio
from contextlib import asynccontextmanager
from dataclasses import asdict, dataclass
import fcntl
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import secrets
import shutil
import signal
import stat
import sys
import tempfile
import time

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse, Response
from . import contracts, diagnostics
from .contracts import Generation, Rejected
from .manifest import HEX64, VerifiedManifest

MANIFEST_HEADER = "X-Nucleus-Manifest-SHA256"
NONCE_HEADER = "X-Nucleus-Request-Nonce"
RESULT_HEADER = "X-Nucleus-Result-SHA256"


@dataclass
class Settings:
    token: str
    work_dir: Path
    shared_lock: Path
    device: str = "cpu"
    threads: int = 2
    memory_limit_bytes: int = 32 * 1024**3
    reserve_memory_bytes: int = 4 * 1024**3
    timeout_seconds: int = 900
    upload_timeout_seconds: float = 30.0
    max_body_bytes: int = 32 * 1024**2
    max_response_bytes: int = 16 * 1024**2
    max_pixels: int = 2 * 1024**2
    max_steps: int = 50
    llama_binary: str = ""
    context_length: int = 4096
    max_tokens: int = 256
    strength: float = 0.65

    def validate(self):
        if not 32 <= len(self.token) <= 4096 or self.device not in {"cpu", "cuda"}:
            raise ValueError("private bearer token and explicit CPU/CUDA device required")
        if not 1 <= self.threads <= (os.cpu_count() or 1) or not 1 <= self.timeout_seconds <= 3600:
            raise ValueError("invalid CPU threads or wall timeout")
        if not 256 * 1024**2 <= self.memory_limit_bytes <= 1024**4 or not 0 <= self.reserve_memory_bytes <= 1024**4:
            raise ValueError("invalid process memory limit or host reserve")
        if not 4096 <= self.max_body_bytes <= 128 * 1024**2 or not 4096 <= self.max_response_bytes <= 32 * 1024**2:
            raise ValueError("invalid upload or result budget")
        if not 0 < self.strength <= 1 or not 128 <= self.context_length <= 8192 or not 1 <= self.max_tokens <= 1024:
            raise ValueError("invalid generation strength or review context budget")
        if not 0.01 <= self.upload_timeout_seconds <= 120:
            raise ValueError("upload timeout must be positive and at most 120 seconds")
        self.work_dir, self.shared_lock = Path(self.work_dir), Path(self.shared_lock)
        if not self.work_dir.is_absolute() or not self.shared_lock.is_absolute() or self.work_dir.is_symlink() or self.shared_lock.is_symlink():
            raise ValueError("absolute nonsymlink private runtime paths required")
        self.work_dir.mkdir(parents=True, mode=0o700, exist_ok=True)
        if self.work_dir.stat().st_mode & 0o077:
            raise ValueError("runtime work directory must be private (0700)")
        if not self.shared_lock.parent.is_dir():
            raise ValueError("shared-lock parent directory must already exist")


def available_memory():
    values = {}
    for line in Path("/proc/meminfo").read_text().splitlines():
        fields = line.split()
        if len(fields) >= 2:
            values[fields[0].rstrip(":")] = int(fields[1]) * 1024
    available = values.get("MemAvailable", 0)
    # Honor the common unified cgroup limit in addition to the VM's RAM view.
    try:
        group = Path("/sys/fs/cgroup")
        maximum = (group / "memory.max").read_text().strip()
        if maximum != "max":
            available = min(available, max(0, int(maximum) - int((group / "memory.current").read_text())))
    except (OSError, ValueError):
        pass
    return available


def private_write(path, data):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "wb") as target:
        target.write(data)


class SubprocessRunner:
    def __init__(self, manifest, settings, *, engine_path=None):
        self.manifest, self.settings = manifest, settings
        self.engine_path = Path(engine_path or Path(__file__).with_name("engine.py")).resolve()
        self.processes = set()
        self.closed = False
        self.prlimit = shutil.which("prlimit")
        if not self.prlimit:
            raise ValueError("util-linux prlimit is required for process resource limits")

    async def _stop(self, process):
        # Kill the owned session even when its leader exited unexpectedly, so
        # an engine-owned llama-server cannot remain behind after a failure.
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        await process.wait()

    async def close(self):
        self.closed = True
        await asyncio.gather(*(self._stop(p) for p in list(self.processes)))

    async def run(self, operation, payload, request):
        if self.closed:
            raise Rejected("runtime is shutting down", 503, "runtime_unavailable")
        if available_memory() < self.settings.reserve_memory_bytes + self.settings.memory_limit_bytes:
            raise Rejected("available RAM cannot preserve the configured host reserve and process budget", 503, "resource_unavailable")
        with tempfile.TemporaryDirectory(prefix="job-", dir=self.settings.work_dir) as directory:
            job_dir = Path(directory)
            data = asdict(payload)
            if isinstance(payload, Generation):
                guide = data.pop("pose_guide",None)
                if guide is not None:
                    guide_path = job_dir / "pose-guide.img"
                    private_write(guide_path,guide)
                    data["pose_guide"] = str(guide_path)
                else:
                    data["pose_guide"] = None
                data.pop("sources")
                data["sources"] = []
                for i, raw in enumerate(payload.sources):
                    path = job_dir / ("source-" + str(i) + ".img")
                    private_write(path, raw)
                    data["sources"].append(str(path))
            else:
                path = job_dir / "candidate.img"
                private_write(path, payload.candidate)
                data["candidate"] = str(path)
            config = asdict(self.settings)
            config.pop("token")
            config["work_dir"], config["shared_lock"] = str(config["work_dir"]), str(config["shared_lock"])
            job = {"operation": operation, "request": data, "settings": config,
                   "manifest": str(self.manifest.path), "manifest_sha256": self.manifest.sha256,
                   "model_root": str(self.manifest.root), "job_dir": str(job_dir), "parent_pid": os.getpid()}
            job_path = job_dir / "job.json"
            private_write(job_path, json.dumps(job).encode())
            env = {k: v for k, v in os.environ.items() if not k.upper().startswith(("HF_", "LLAMA_")) and "PROXY" not in k.upper() and k not in {"NUCLEUS_MELD_RUNTIME_TOKEN", "POSITRONIC_IMAGE_API_TOKEN"}}
            env.update(HF_HUB_OFFLINE="1", TRANSFORMERS_OFFLINE="1", HF_HOME=str(job_dir / "empty-hf-cache"),
                       HF_HUB_DISABLE_TELEMETRY="1", DO_NOT_TRACK="1", TOKENIZERS_PARALLELISM="false",
                       OMP_NUM_THREADS=str(self.settings.threads), MKL_NUM_THREADS=str(self.settings.threads),
                       OPENBLAS_NUM_THREADS=str(self.settings.threads), NUMEXPR_NUM_THREADS=str(self.settings.threads))
            if self.settings.device == "cpu" or operation == "review":
                env["CUDA_VISIBLE_DEVICES"] = "-1"
            log_path = job_dir / "engine.log"
            with os.fdopen(os.open(log_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), "wb") as log:
                command = [self.prlimit, "--as=" + str(self.settings.memory_limit_bytes),
                           "--fsize=" + str(32 * 1024**2),
                           "--cpu=" + str(self.settings.timeout_seconds * self.settings.threads + 10), "--",
                           sys.executable, str(self.engine_path), str(job_path)]
                process = await asyncio.create_subprocess_exec(*command, env=env, stdout=log, stderr=log, start_new_session=True)
                self.processes.add(process)
                started = time.monotonic()
                metrics = diagnostics.ProcessMetrics()
                failure = None
                try:
                    while process.returncode is None:
                        metrics.sample(process.pid)
                        if await request.is_disconnected():
                            raise Rejected("client disconnected; execution cancelled", 499, "cancelled")
                        if time.monotonic() - started >= self.settings.timeout_seconds:
                            raise Rejected("model execution exceeded its wall timeout", 504, "timeout")
                        if available_memory() < self.settings.reserve_memory_bytes:
                            raise Rejected("host RAM reserve was exhausted; execution stopped", 503, "resource_unavailable")
                        await asyncio.sleep(0.05)
                    if process.returncode:
                        raise Rejected("model execution failed; private last-failure diagnostics were recorded", 502, "model_execution_failed")
                    result_path = job_dir / ("result.png" if operation == "generate" else "result.json")
                    info = result_path.lstat()
                    if not stat.S_ISREG(info.st_mode) or info.st_size > self.settings.max_response_bytes:
                        raise Rejected("model result exceeded its response budget", 502, "invalid_model_output")
                    return result_path.read_bytes()
                except BaseException as error:
                    failure = error
                    if isinstance(error, (OSError, ValueError)) and not isinstance(error, Rejected):
                        raise Rejected("model did not produce a valid bounded result", 502, "model_execution_failed") from error
                    raise
                finally:
                    await self._stop(process)
                    self.processes.discard(process)
                    try:
                        diagnostics.record(self.manifest, self.settings, operation, payload, job_dir, process, started, metrics, failure)
                    except (OSError, ValueError, TypeError):
                        # Diagnostics must not replace the execution outcome.
                        print("could not persist private runtime diagnostics", file=sys.stderr)


async def bounded_body(request, limit):
    try:
        declared = request.headers.get("content-length")
        if declared is not None and (int(declared) < 0 or int(declared) > limit):
            raise Rejected("multipart request exceeds the upload budget", 413, "request_too_large")
    except ValueError as error:
        if isinstance(error, Rejected):
            raise
        raise Rejected("invalid Content-Length") from error
    body = bytearray()
    async for chunk in request.stream():
        if len(body) + len(chunk) > limit:
            raise Rejected("multipart request exceeds the upload budget", 413, "request_too_large")
        body.extend(chunk)
    return bytes(body)


def create_app(manifest: VerifiedManifest, settings: Settings, *, runner=None):
    settings.validate()
    runner = runner or SubprocessRunner(manifest, settings)

    @asynccontextmanager
    async def lifespan(_app):
        yield
        await runner.close()

    app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None, lifespan=lifespan)
    app.state.runner = runner
    active = False
    nonces = {}

    def authorize(request):
        actual = request.headers.get("authorization", "").encode()
        if not secrets.compare_digest(actual, ("Bearer " + settings.token).encode()):
            raise Rejected("runtime bearer token required", 401, "unauthorized")

    @app.exception_handler(Rejected)
    async def rejected(_request, error):
        return JSONResponse({"error": {"code": error.code, "message": str(error)}}, status_code=error.status,
                            headers={"Cache-Control": "no-store", "X-Content-Type-Options": "nosniff"})

    @app.get("/healthz")
    async def health(request: Request):
        authorize(request)
        return {"state": "artifacts_verified", "models_loaded": False, "backend": manifest.document["backend"],
                "model": manifest.document["model"], "manifest_sha256": manifest.sha256,
                "device": settings.device if manifest.document["workload"] == "image-generation" else "cpu",
                "pose_guide": manifest.document["backend"] == "sdxl_readout",
                "identity_strength": manifest.document["backend"] == "sdxl_readout", "anchored_generation": False,
                "conditioning": "generic learned appearance and RGB pose readout" if manifest.document["backend"] == "sdxl_readout" else "weighted pixel img2img" if manifest.document["backend"] == "sdxl_img2img" else "vision review",
                "learned_face_identity": False,
                "pose_guide_formats": (["rgb"] + (["depth"] if any(item["path"] == "conditioning/readout_sdxl_spatial_depth.pt" for item in manifest.document["artifacts"]) else [])) if manifest.document["backend"] == "sdxl_readout" else []}

    @app.get("/v1/runtime-manifest")
    async def runtime_manifest(request: Request):
        authorize(request)
        return Response(manifest.raw, media_type="application/json", headers={MANIFEST_HEADER: manifest.sha256, "Cache-Control": "no-store"})

    async def execute(request, operation):
        nonlocal active
        authorize(request)
        nonce = request.headers.get(NONCE_HEADER, "")
        if request.headers.get(MANIFEST_HEADER) != manifest.sha256 or not HEX64.fullmatch(nonce):
            raise Rejected("approved manifest pin and 64-hex request nonce required", 403, "model_policy_rejected")
        expected = "image-generation" if operation == "generate" else "image-review"
        if manifest.document["workload"] != expected:
            raise Rejected("workload not installed in this runtime", 503, "workload_unavailable")
        if active:
            raise Rejected("runtime concurrency budget is busy", 429, "resource_busy")
        now = time.monotonic()
        for old in [key for key, seen in nonces.items() if now - seen > 3600]:
            del nonces[old]
        if nonce in nonces:
            raise Rejected("request nonce has already been dispatched; it will not be replayed", 409, "duplicate_request")
        if len(nonces) >= 4096:
            raise Rejected("request replay cache is full", 503, "resource_busy")
        fd = os.open(settings.shared_lock, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
        if os.fstat(fd).st_uid != os.geteuid() or os.fstat(fd).st_mode & 0o077:
            os.close(fd)
            raise Rejected("shared node execution lock is not private", 503, "resource_unavailable")
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            os.close(fd)
            raise Rejected("another local model owns the node execution budget", 429, "resource_busy")
        active = True
        form = None
        try:
            if request.headers.get("content-type", "").split(";", 1)[0].strip().lower() != "multipart/form-data":
                raise Rejected("multipart/form-data required", 415, "invalid_request")
            async def parse_upload():
                nonlocal form
                body = await bounded_body(request, settings.max_body_bytes)
                delivered = False

                async def receive():
                    nonlocal delivered
                    if delivered:
                        return {"type": "http.disconnect"}
                    delivered = True
                    return {"type": "http.request", "body": body, "more_body": False}

                cached = Request(request.scope, receive)
                try:
                    form = await cached.form(max_files=11, max_fields=100, max_part_size=65536)
                except Exception as error:
                    raise Rejected("invalid or oversized multipart request") from error
                payload = await contracts.generation(form, manifest.document["model"], settings.max_pixels, settings.max_steps, backend=manifest.document["backend"]) if operation == "generate" else await contracts.review(form)
                if operation == "generate":
                    contracts.validate_generation_execution(payload,manifest.document["backend"],settings.strength,settings.device,
                                                            installed_artifacts={item["path"] for item in manifest.document["artifacts"]})
                return body, payload

            try:
                body, payload = await asyncio.wait_for(parse_upload(), timeout=settings.upload_timeout_seconds)
            except asyncio.TimeoutError as error:
                raise Rejected("multipart upload or parsing exceeded its deadline", 408, "upload_timeout") from error
            nonces[nonce] = now
            result = await runner.run(operation, payload, request)
            if len(result) > settings.max_response_bytes:
                raise Rejected("result exceeded the response budget", 502, "invalid_model_output")
            headers = {MANIFEST_HEADER: manifest.sha256, NONCE_HEADER: nonce,
                       RESULT_HEADER: hashlib.sha256(result).hexdigest(), "Cache-Control": "no-store", "X-Content-Type-Options": "nosniff"}
            if operation == "generate":
                if not result.startswith(b"\x89PNG\r\n\x1a\n") or contracts.image_bytes(result) != (payload.width, payload.height):
                    raise Rejected("model did not produce the requested PNG dimensions", 502, "invalid_model_output")
                headers.update({"X-Image-Backend": manifest.document["backend"], "X-Image-Model": manifest.document["model"],
                                "X-Image-Preview": "false", "X-Image-AI": "true", "X-Image-Seed": str(payload.seed),
                                "X-Image-Provenance": hashlib.sha256((manifest.sha256 + nonce).encode() + body).hexdigest()})
                return Response(result, media_type="image/png", headers=headers)
            value = contracts.verdict(result)
            result = json.dumps(value, separators=(",", ":"), ensure_ascii=False).encode()
            headers[RESULT_HEADER] = hashlib.sha256(result).hexdigest()
            headers.update({"X-Reviewer-Backend": manifest.document["backend"], "X-Reviewer-Model": manifest.document["model"],
                            "X-Candidate-SHA256": hashlib.sha256(payload.candidate).hexdigest()})
            return Response(result, media_type="application/json", headers=headers)
        finally:
            if form is not None:
                await form.close()
            active = False
            fcntl.flock(fd, fcntl.LOCK_UN)
            os.close(fd)

    @app.post("/v1/generations")
    async def generate(request: Request):
        return await execute(request, "generate")

    @app.post("/v1/reviews")
    async def review(request: Request):
        return await execute(request, "review")

    return app


def main():
    parser = argparse.ArgumentParser(description="Private offline Meld model runtime")
    for flag in ("manifest", "manifest-sha256", "model-root", "token-file", "shared-lock", "work-dir"):
        parser.add_argument("--" + flag, required=True)
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8011)
    parser.add_argument("--device", choices=("cpu", "cuda"), default="cpu")
    parser.add_argument("--threads", type=int, default=2)
    parser.add_argument("--memory-limit-bytes", type=int, default=32 * 1024**3)
    parser.add_argument("--reserve-memory-bytes", type=int, default=4 * 1024**3)
    parser.add_argument("--timeout-seconds", type=int, default=900)
    parser.add_argument("--upload-timeout-seconds", type=float, default=30.0)
    parser.add_argument("--max-body-bytes", type=int, default=32 * 1024**2)
    parser.add_argument("--max-response-bytes", type=int, default=16 * 1024**2)
    parser.add_argument("--max-pixels", type=int, default=2 * 1024**2)
    parser.add_argument("--max-steps", type=int, default=50)
    parser.add_argument("--llama-binary", default="")
    parser.add_argument("--context-length", type=int, default=4096)
    parser.add_argument("--max-tokens", type=int, default=256)
    parser.add_argument("--strength", type=float, default=0.65)
    args = parser.parse_args()
    if not ipaddress.ip_address(args.host).is_loopback or not 1 <= args.port <= 65535:
        parser.error("only a literal loopback listener is permitted")
    token_path = Path(args.token_file)
    if not token_path.is_absolute() or token_path.is_symlink():
        parser.error("token file requires an absolute nonsymlink path")
    info = token_path.stat()
    if not stat.S_ISREG(info.st_mode) or info.st_mode & 0o077 or info.st_uid != os.geteuid():
        parser.error("token file must be an owned private regular file (0600)")
    token = token_path.read_text().strip()
    manifest = VerifiedManifest.load(args.manifest, args.model_root, args.manifest_sha256)
    values = dict(vars(args))
    for name in ("manifest", "manifest_sha256", "model_root", "token_file", "host", "port"):
        values.pop(name)
    settings = Settings(token=token, **values)
    os.umask(0o077)
    import uvicorn
    uvicorn.run(create_app(manifest, settings), host=args.host, port=args.port, access_log=False,
                workers=1, limit_concurrency=16, timeout_graceful_shutdown=5)


if __name__ == "__main__":
    main()





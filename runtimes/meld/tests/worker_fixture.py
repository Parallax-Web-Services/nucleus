"""Tensor-free subprocess fixture; never represents model performance."""
import json
import os
from pathlib import Path
import resource
import struct
import sys
import time
import zlib
job = json.loads(Path(sys.argv[1]).read_bytes())
settings, request = job["settings"], job["request"]
soft, hard = resource.getrlimit(resource.RLIMIT_AS)
if soft != settings["memory_limit_bytes"] or hard != soft or os.environ.get("HF_HUB_OFFLINE") != "1" or os.environ.get("CUDA_VISIBLE_DEVICES") != "-1" or os.environ.get("OMP_NUM_THREADS") != str(settings["threads"]):
    raise SystemExit(21)
Path(settings["work_dir"], "worker.pid").write_text(str(os.getpid()))
if request["prompt"].startswith("fail-private"):
    Path(job["job_dir"], "phase.txt").write_text("fixture_failure")
    message = "allocator fixture failure " + request["prompt"] + " Bearer " + request["negative_prompt"] + " " + request["names"][0]
    Path(job["job_dir"], "error.json").write_text(json.dumps({"error":"RuntimeError", "message":message, "frames":[{"file":__file__,"line":20,"function":"fixture"}]}))
    print(message, file=sys.stderr)
    time.sleep(.1)
    raise SystemExit(23)
if request["prompt"] == "guide-fixture":
    import hashlib
    path = Path(request["pose_guide"])
    Path(settings["work_dir"],"guide-fixture.json").write_text(json.dumps({"is_path":path.parent == Path(job["job_dir"]),"mode":path.stat().st_mode & 0o777,"sha256":hashlib.sha256(path.read_bytes()).hexdigest()}))
if request["prompt"] == "wait":
    time.sleep(60)
def chunk(name, body):
    return struct.pack(">I", len(body)) + name + body + struct.pack(">I", zlib.crc32(name + body) & 0xffffffff)
w, h = request["width"], request["height"]
raw = (b"\0" + bytes([20, 40, 60]) * w) * h
png = b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", struct.pack(">IIBBBBB", w, h, 8, 2, 0, 0, 0)) + chunk(b"IDAT", zlib.compress(raw)) + chunk(b"IEND", b"")
Path(job["job_dir"], "result.png").write_bytes(png)



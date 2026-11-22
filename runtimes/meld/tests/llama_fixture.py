#!/usr/bin/env python3
"""Tensor-free managed llama HTTP fixture; this is not inference."""
from http.server import BaseHTTPRequestHandler, HTTPServer
import json
import os
from pathlib import Path
import sys
args = sys.argv[1:]
values = {value: args[i+1] for i, value in enumerate(args[:-1]) if value.startswith("--")}
for key, expected in {"--host":"127.0.0.1", "--device":"none", "--n-gpu-layers":"0", "--threads":"1", "--threads-batch":"1", "--threads-http":"2", "--parallel":"1", "--cache-ram":"0"}.items():
    if values.get(key) != expected:
        raise SystemExit(21)
for flag in ("--no-mmproj-offload", "--no-op-offload", "--no-kv-offload", "--no-warmup", "--no-webui"):
    if flag not in args:
        raise SystemExit(22)
key_path = Path(values["--api-key-file"])
if key_path.stat().st_mode & 0o077:
    raise SystemExit(23)
secret = key_path.read_text().strip()
Path(key_path.parent.parent, "llama.pid").write_text(str(os.getpid()))
class Handler(BaseHTTPRequestHandler):
    def log_message(self, *_args): pass
    def allowed(self):
        if self.headers.get("Authorization") == "Bearer " + secret: return True
        self.send_response(401); self.end_headers(); return False
    def reply(self, body):
        encoded = json.dumps(body).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(encoded)))
        self.end_headers(); self.wfile.write(encoded)
    def do_GET(self):
        if self.allowed(): self.reply({"data":[{"id":values["--alias"]}]})
    def do_POST(self):
        if not self.allowed(): return
        body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
        content = body["messages"][0]["content"]
        if not any(part.get("type") == "image_url" and part["image_url"]["url"].startswith("data:image/png;base64,") for part in content):
            self.send_response(400); self.end_headers(); return
        schema = body.get("response_format",{}).get("schema",{})
        calls_path = key_path.parent.parent / "llama-calls.json"
        calls = json.loads(calls_path.read_bytes()) if calls_path.exists() else []
        calls.append({"max_tokens":body["max_tokens"], "required":schema.get("required"), "text":content[0]["text"]})
        calls_path.write_text(json.dumps(calls))
        if schema.get("required") == ["appearance","evidence"]:
            if "Brief data:" in content[0]["text"]:
                self.send_response(400); self.end_headers(); return
            output = {"appearance":"photographic", "evidence":"protocol fixture only; no real image assessment"}
        elif schema.get("required") == ["accepted","issues","summary","quality_score"]:
            output = {"accepted":True,"issues":[],"summary":"protocol fixture only","quality_score":80}
        else:
            self.send_response(400); self.end_headers(); return
        self.reply({"model":values["--alias"],"choices":[{"message":{"content":json.dumps(output)}}]})
HTTPServer((values["--host"], int(values["--port"])), Handler).serve_forever()


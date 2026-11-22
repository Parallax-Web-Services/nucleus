"""Protocol/resource tests only: no pretrained weights or tensor inference."""
from __future__ import annotations
import asyncio
import hashlib
import io
import json
import os
from pathlib import Path
import secrets
import tempfile
import time
import unittest
from unittest.mock import patch

from fastapi.testclient import TestClient
from PIL import Image
from runtimes.meld.contracts import Generation, Rejected
from runtimes.meld.manifest import VerifiedManifest
from runtimes.meld.server import MANIFEST_HEADER, NONCE_HEADER, RESULT_HEADER, Settings, SubprocessRunner, create_app

TOKEN = "protocol-fixture-token-" + "a" * 40
HERE = Path(__file__).resolve().parent


def png(width=64, height=64):
    output = io.BytesIO()
    Image.new("RGB", (width, height), "navy").save(output, format="PNG")
    return output.getvalue()


def manifest_fixture(directory, review=False):
    root = directory / "models"
    root.mkdir()
    artifacts = []
    for name in (["model.gguf", "mmproj.gguf"] if review else ["config.json"]):
        content = b"protocol-only-fixture-" + name.encode()
        (root / name).write_bytes(content)
        provenance = {"publisher":"Example Fixture Lab", "country":"US", "evidence":["https://example.org/fictional-fixture"], "lineage_complete":True, "base_models":[]}
        artifacts.append({"path":name,"model":{"id":"protocol-fixture", "revision":"fixture-revision", "source":"https://example.org/fixture", "license":"fixture-only", "format":"GGUF" if review else "JSON", "runtime":"protocol-fixture", "sha256":hashlib.sha256(content).hexdigest(), "size_bytes":len(content), "workloads":["image-review" if review else "image-generation"], "provenance":provenance}})
    document = {"schema_version":1,"runtime_version":"protocol-fixture-only","backend":"llama_cpp_vlm" if review else "sdxl_img2img","workload":"image-review" if review else "image-generation","model":"protocol-fixture","artifact_set_complete":True,"artifacts":artifacts}
    path = directory / "manifest.json"
    path.write_text(json.dumps(document))
    digest = hashlib.sha256(path.read_bytes()).hexdigest()
    return VerifiedManifest.load(path,root,digest)


def settings_fixture(directory):
    return Settings(token=TOKEN, work_dir=directory / "jobs", shared_lock=directory / "node.lock", threads=1,
                    memory_limit_bytes=256*1024**2, reserve_memory_bytes=0, timeout_seconds=2)


def headers(manifest, nonce=None):
    return {"Authorization":"Bearer " + TOKEN, MANIFEST_HEADER:manifest.sha256, NONCE_HEADER:nonce or secrets.token_hex(32)}


def multipart(extra=None):
    values = [("prompt",(None,"a protocol fixture")), ("width",(None,"64")), ("height",(None,"64")),
              ("steps",(None,"2")), ("guidance_scale",(None,"5")),
              ("sources",("one.png",png(),"image/png")), ("sources",("two.png",png(),"image/png")),
              ("names",(None,"one")), ("names",(None,"two")),
              ("weights_basis_points",(None,"6500")), ("weights_basis_points",(None,"3500"))]
    return values + (extra or [])


class FakeRunner:
    def __init__(self): self.calls=[]; self.review=b'{"accepted":true,"issues":[],"summary":"protocol fixture","quality_score":80}'
    async def run(self, operation,payload,request):
        self.calls.append((operation,payload))
        return png(payload.width,payload.height) if operation == "generate" else self.review
    async def close(self): pass


class ManifestTests(unittest.TestCase):
    def test_hash_inventory_and_symlinks_fail_closed(self):
        with tempfile.TemporaryDirectory() as raw:
            manifest=manifest_fixture(Path(raw))
            (manifest.root / "undeclared.json").write_text("{}")
            with self.assertRaises(ValueError): manifest.verify_files()
            (manifest.root / "undeclared.json").unlink()
            path=manifest.root / "config.json"
            original=path.read_bytes(); path.write_bytes(b"changed")
            with self.assertRaises(ValueError): manifest.verify_files()
            path.write_bytes(original)
            (manifest.root / "link.json").symlink_to(path)
            with self.assertRaises(ValueError): manifest.verify_files()
            with self.assertRaises(ValueError): VerifiedManifest.load(manifest.path,manifest.root,"0"*64)

    def test_pinned_publisher_disclosure_does_not_claim_complete_or_bypass_denials(self):
        with tempfile.TemporaryDirectory() as raw:
            manifest=manifest_fixture(Path(raw))
            document=json.loads(manifest.raw)
            provenance=document["artifacts"][0]["model"]["provenance"]
            provenance["lineage_complete"]=False
            manifest.path.write_text(json.dumps(document))
            with self.assertRaises(ValueError):
                VerifiedManifest.load(manifest.path,manifest.root,hashlib.sha256(manifest.path.read_bytes()).hexdigest())
            provenance["lineage_disclosure"]="publisher-disclosed"
            manifest.path.write_text(json.dumps(document))
            digest=hashlib.sha256(manifest.path.read_bytes()).hexdigest()
            reviewed=VerifiedManifest.load(manifest.path,manifest.root,digest)
            self.assertIs(reviewed.document["artifacts"][0]["model"]["provenance"]["lineage_complete"],False)
            with self.assertRaises(ValueError):
                VerifiedManifest.load(manifest.path,manifest.root,manifest.sha256)
            provenance["country"]="CN"
            manifest.path.write_text(json.dumps(document))
            with self.assertRaises(ValueError):
                VerifiedManifest.load(manifest.path,manifest.root,hashlib.sha256(manifest.path.read_bytes()).hexdigest())

    def test_local_policy_matches_encoded_short_and_unicode_denials(self):
        for identity in ("https://example.org/qw%65n", "GLM-4", "Yi-1.5", "h94", "阿里巴巴", "https://chat.z.ai/models", "北京智源"):
            with tempfile.TemporaryDirectory() as raw:
                manifest=manifest_fixture(Path(raw))
                document=json.loads(manifest.raw)
                document["artifacts"][0]["model"]["id"]=identity
                manifest.path.write_text(json.dumps(document))
                with self.assertRaises(ValueError):
                    VerifiedManifest.load(manifest.path,manifest.root,hashlib.sha256(manifest.path.read_bytes()).hexdigest())
        with tempfile.TemporaryDirectory() as raw:
            manifest=manifest_fixture(Path(raw))
            document=json.loads(manifest.raw)
            document["artifacts"][0]["model"]["provenance"]["lineage_disclosure"]="publisher-disclosed"
            manifest.path.write_text(json.dumps(document))
            with self.assertRaises(ValueError):
                VerifiedManifest.load(manifest.path,manifest.root,hashlib.sha256(manifest.path.read_bytes()).hexdigest())

    def test_unknown_and_forbidden_provenance_rejected_before_engine_load(self):
        with tempfile.TemporaryDirectory() as raw:
            manifest=manifest_fixture(Path(raw))
            document=json.loads(manifest.raw)
            for country in ("CN","HK","MO","XX"):
                document["artifacts"][0]["model"]["provenance"]["country"]=country
                manifest.path.write_text(json.dumps(document))
                with self.assertRaises(ValueError):
                    VerifiedManifest.load(manifest.path,manifest.root,hashlib.sha256(manifest.path.read_bytes()).hexdigest())


class APITests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory(); self.directory=Path(self.temp.name)
        self.manifest=manifest_fixture(self.directory); self.settings=settings_fixture(self.directory)
        self.runner=FakeRunner();self.client=TestClient(create_app(self.manifest,self.settings,runner=self.runner))
    def tearDown(self): self.client.close();self.temp.cleanup()

    def test_manifest_authentication_and_exact_receipts(self):
        self.assertEqual(self.client.get("/v1/runtime-manifest").status_code,401)
        response=self.client.get("/v1/runtime-manifest",headers=headers(self.manifest))
        self.assertEqual(response.content,self.manifest.raw)
        self.assertEqual(response.headers[MANIFEST_HEADER],self.manifest.sha256)
        request_headers=headers(self.manifest)
        response=self.client.post("/v1/generations",headers=request_headers,files=multipart())
        self.assertEqual(response.status_code,200,response.text)
        self.assertEqual(response.headers[RESULT_HEADER],hashlib.sha256(response.content).hexdigest())
        self.assertEqual(response.headers[NONCE_HEADER],request_headers[NONCE_HEADER])
        self.assertEqual(response.headers[MANIFEST_HEADER],self.manifest.sha256)
        self.assertEqual(response.headers["X-Image-Backend"],"sdxl_img2img")
        self.assertEqual(response.headers["X-Image-Preview"],"false")
        self.assertEqual(response.headers["X-Image-AI"],"true")
        self.assertTrue(0<=int(response.headers["X-Image-Seed"])<2**32)
        self.assertEqual(self.runner.calls[0][1].weights_basis_points,[6500,3500])
        again=self.client.post("/v1/generations",headers=request_headers,files=multipart())
        self.assertEqual(again.status_code,409)
        self.assertEqual(len(self.runner.calls),1)

    def test_unsupported_conditioning_is_never_silently_ignored(self):
        for field,value in [("identity_strength","1"),("pose_guide_strength","0"),("morphology_strength","0.1")]:
            response=self.client.post("/v1/generations",headers=headers(self.manifest),files=multipart([(field,(None,value))]))
            self.assertEqual(response.status_code,422,response.text)
            self.assertEqual(response.json()["error"]["code"],"unsupported_feature")
        for field,values in [("anchor_scopes",["face","auto"]),("anchor_targets",["nose",""])]:
            response=self.client.post("/v1/generations",headers=headers(self.manifest),files=multipart([(field,(None,value)) for value in values]))
            self.assertEqual(response.status_code,422,response.text)
        self.assertEqual(self.runner.calls,[])
        response=self.client.post("/v1/generations",headers=headers(self.manifest),files=multipart([("anchor_scopes",(None,"auto")),("anchor_scopes",(None,"auto")),("anchor_targets",(None,"")),("anchor_targets",(None,"")),("morphology_strength",(None,"0"))]))
        self.assertEqual(response.status_code,200,response.text)

    def test_upload_and_shared_node_limits(self):
        self.settings.max_body_bytes=4096
        response=self.client.post("/v1/generations",headers=headers(self.manifest),content=b"x"*5000)
        self.assertEqual(response.status_code,415)
        response=self.client.post("/v1/generations",headers={**headers(self.manifest),"Content-Type":"multipart/form-data; boundary=fixture"},content=b"x"*5000)
        self.assertEqual(response.status_code,413)
        import fcntl
        fd=os.open(self.settings.shared_lock,os.O_RDWR|os.O_CREAT,0o600)
        try:
            fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
            response=self.client.post("/v1/generations",headers=headers(self.manifest),files=multipart())
            self.assertEqual(response.status_code,429)
        finally: os.close(fd)
        self.assertEqual(self.runner.calls,[])

    def test_review_hash_and_real_verdict_schema(self):
        directory=self.directory / "review";directory.mkdir()
        manifest=manifest_fixture(directory,True);runner=FakeRunner()
        with TestClient(create_app(manifest,settings_fixture(directory),runner=runner)) as client:
            candidate=png()
            files=[("candidate",("candidate.png",candidate,"image/png")),("prompt",(None,"one person"))]
            response=client.post("/v1/reviews",headers=headers(manifest),files=files)
            self.assertEqual(response.status_code,200,response.text)
            self.assertEqual(response.headers["X-Candidate-SHA256"],hashlib.sha256(candidate).hexdigest())
            self.assertEqual(response.headers["X-Reviewer-Backend"],"llama_cpp_vlm")
            self.assertEqual(response.headers[RESULT_HEADER],hashlib.sha256(response.content).hexdigest())
            for invalid in [b'```json\n{}\n```',b'{"accepted":true,"issues":["invented"],"summary":"x","quality_score":80}',b'{"accepted":true,"issues":["multiple_people"],"summary":"x","quality_score":80}']:
                runner.review=invalid
                response=client.post("/v1/reviews",headers=headers(manifest),files=files)
                self.assertEqual(response.status_code,502,response.text)


class ReviewGroundingTests(unittest.TestCase):
    def test_appearance_is_strict_and_uncertainty_is_not_photographic(self):
        from runtimes.meld.engine import appearance_assessment, requires_photographic_appearance
        for appearance in ("photographic","illustrated","uncertain"):
            self.assertEqual(appearance_assessment(json.dumps({"appearance":appearance,"evidence":"visible fixture contours"}))["appearance"],appearance)
        for invalid in ('```json\n{}\n```','{"appearance":[],"evidence":"x"}','{"appearance":"camera-authentic","evidence":"x"}','{"appearance":"photographic","evidence":""}'):
            with self.assertRaises(Rejected): appearance_assessment(invalid)
        self.assertTrue(requires_photographic_appearance("A photorealistic generated studio portrait"))
        self.assertTrue(requires_photographic_appearance("A photographic image"))
        self.assertFalse(requires_photographic_appearance("A deliberately illustrated vector portrait"))

    def test_medium_mismatch_cannot_be_accepted_or_excused_as_clothing(self):
        from runtimes.meld.engine import grounded_verdict, review_schema
        self.assertEqual(review_schema(True)["properties"]["accepted"]["enum"],[False])
        for value in ({"accepted":True,"issues":[],"summary":"looks plausible","quality_score":95},
                      {"accepted":False,"issues":["extra_or_missing_parts"],"summary":"ordinary clothes","quality_score":20}):
            with self.assertRaises(Rejected): grounded_verdict(json.dumps(value),True)
        rejected={"accepted":False,"issues":["composition_mismatch"],"summary":"Visible ink outlines and flat fills conflict with photographic appearance.","quality_score":20}
        self.assertEqual(grounded_verdict(json.dumps(rejected),True),rejected)
        accepted={"accepted":True,"issues":[],"summary":"Visible materials and shading match the brief.","quality_score":85}
        self.assertEqual(grounded_verdict(json.dumps(accepted),False),accepted)

class NoDisconnect:
    async def is_disconnected(self): return False


class ProcessTests(unittest.IsolatedAsyncioTestCase):
    async def test_child_resource_limits_and_reaping_on_timeout_and_disconnect(self):
        with tempfile.TemporaryDirectory() as raw:
            directory=Path(raw);manifest=manifest_fixture(directory);settings=settings_fixture(directory);settings.validate()
            runner=SubprocessRunner(manifest,settings,engine_path=HERE / "worker_fixture.py")
            payload=Generation("fixture","",64,64,2,5,42,[png()],["one"],[10000])
            with patch("runtimes.meld.server.available_memory",return_value=1<<40):
                result=await runner.run("generate",payload,NoDisconnect())
                self.assertTrue(result.startswith(b"\x89PNG"));self.assertFalse(runner.processes)
                pid=int((settings.work_dir / "worker.pid").read_text());self.assertFalse(Path(f"/proc/{pid}").exists())
                payload.prompt="wait";settings.timeout_seconds=1
                with self.assertRaises(Rejected) as caught: await runner.run("generate",payload,NoDisconnect())
                self.assertEqual(caught.exception.status,504)
                pid=int((settings.work_dir / "worker.pid").read_text());self.assertFalse(Path(f"/proc/{pid}").exists())
                settings.timeout_seconds=5
                started=time.monotonic()
                class Disconnect:
                    async def is_disconnected(self): return time.monotonic()-started>.15
                with self.assertRaises(Rejected) as caught: await runner.run("generate",payload,Disconnect())
                self.assertEqual(caught.exception.status,499)
                pid=int((settings.work_dir / "worker.pid").read_text());self.assertFalse(Path(f"/proc/{pid}").exists())
            await runner.close()

    async def test_owned_llama_cpu_projector_and_image_protocol_without_weights(self):
        with tempfile.TemporaryDirectory() as raw:
            directory=Path(raw);manifest=manifest_fixture(directory,True);settings=settings_fixture(directory)
            settings.memory_limit_bytes=1024**3;settings.timeout_seconds=5
            fake=directory / "fake-llama.py";fake.write_bytes((HERE / "llama_fixture.py").read_bytes());fake.chmod(0o700)
            settings.llama_binary=str(fake);settings.validate()
            runner=SubprocessRunner(manifest,settings)
            from runtimes.meld.contracts import Review
            with patch("runtimes.meld.server.available_memory",return_value=1<<40):
                result=await runner.run("review",Review("one person","",png()),NoDisconnect())
            self.assertEqual(json.loads(result)["summary"],"protocol fixture only")
            calls=json.loads((settings.work_dir / "llama-calls.json").read_bytes())
            self.assertEqual([call["required"] for call in calls],[["appearance","evidence"],["accepted","issues","summary","quality_score"]])
            self.assertEqual(sum(call["max_tokens"] for call in calls),settings.max_tokens)
            self.assertNotIn("one person",calls[0]["text"])
            self.assertIn("one person",calls[1]["text"])
            audit_path=settings.work_dir / "last-review-assessment.json"
            audit=json.loads(audit_path.read_bytes())
            self.assertEqual(audit["appearance_assessment"]["appearance"],"photographic")
            self.assertEqual(audit["candidate_sha256"],hashlib.sha256(png()).hexdigest())
            self.assertEqual(audit["manifest_sha256"],manifest.sha256)
            self.assertEqual(audit["status"],"reviewed")
            self.assertEqual(audit_path.stat().st_mode & 0o777,0o600)
            pid=int((settings.work_dir / "llama.pid").read_text());self.assertFalse(Path(f"/proc/{pid}").exists())
            self.assertFalse(runner.processes)
            await runner.close()

    async def test_private_failure_record_is_bounded_redacted_and_preserves_cause(self):
        with tempfile.TemporaryDirectory() as raw:
            directory=Path(raw);manifest=manifest_fixture(directory);settings=settings_fixture(directory);settings.validate()
            runner=SubprocessRunner(manifest,settings,engine_path=HERE / "worker_fixture.py")
            payload=Generation("fail-private-person",TOKEN,64,64,2,5,42,[png()],["protected-name"],[10000])
            with patch("runtimes.meld.server.available_memory",return_value=1<<40):
                with self.assertRaises(Rejected):
                    await runner.run("generate",payload,NoDisconnect())
            path=settings.work_dir / "last-failure.json"
            report=json.loads(path.read_bytes())
            self.assertEqual(report["child_exit_code"],23)
            self.assertEqual(report["engine_error_class"],"RuntimeError")
            self.assertEqual(report["phase"],"fixture_failure")
            self.assertIn("allocator",report["engine_error_message"])
            self.assertEqual(report["address_space_limit_bytes"],settings.memory_limit_bytes)
            self.assertGreater(report["sampled_peak_tree_rss_bytes"],0)
            for private in (payload.prompt,TOKEN,"protected-name"):
                self.assertNotIn(private,path.read_text())
                self.assertNotIn(private,(settings.work_dir / "last-failure.log").read_text())
            self.assertLess(path.stat().st_size,65536)
            self.assertLessEqual((settings.work_dir / "last-failure.log").stat().st_size,16384)
            self.assertEqual(path.stat().st_mode & 0o777,0o600)
            self.assertEqual((settings.work_dir / "last-failure.log").stat().st_mode & 0o777,0o600)
            await runner.close()

    async def test_stalled_upload_deadline_releases_local_and_shared_budget(self):
        with tempfile.TemporaryDirectory() as raw:
            directory=Path(raw);manifest=manifest_fixture(directory);settings=settings_fixture(directory)
            settings.upload_timeout_seconds=.05
            runner=FakeRunner();app=create_app(manifest,settings,runner=runner)
            request_headers=[(key.lower().encode(),value.encode()) for key,value in headers(manifest).items()]
            request_headers.append((b"content-type",b"multipart/form-data; boundary=fixture"))
            entered=asyncio.Event();messages=[]
            async def receive():
                entered.set()
                await asyncio.Event().wait()
            async def send(message): messages.append(message)
            scope={"type":"http","asgi":{"version":"3.0"},"http_version":"1.1","method":"POST","scheme":"http","path":"/v1/generations","raw_path":b"/v1/generations","query_string":b"","headers":request_headers,"server":("127.0.0.1",8011),"client":("127.0.0.1",1234)}
            task=asyncio.create_task(app(scope,receive,send))
            await entered.wait()
            await asyncio.wait_for(task,1)
            self.assertEqual(messages[0]["status"],408)
            self.assertEqual(runner.calls,[])
            with TestClient(app) as client:
                response=client.post("/v1/generations",headers=headers(manifest),files=multipart())
                self.assertEqual(response.status_code,200,response.text)
            self.assertEqual(len(runner.calls),1)

    async def test_denied_requests_do_not_read_the_payload(self):
        with tempfile.TemporaryDirectory() as raw:
            directory=Path(raw);manifest=manifest_fixture(directory)
            app=create_app(manifest,settings_fixture(directory),runner=FakeRunner())
            for request_headers,expected in [([],401),([(b"authorization",("Bearer "+TOKEN).encode())],403)]:
                reads=[];messages=[]
                async def receive(): reads.append(True);raise AssertionError("body must not be read")
                async def send(message): messages.append(message)
                scope={"type":"http","asgi":{"version":"3.0"},"http_version":"1.1","method":"POST","scheme":"http","path":"/v1/generations","raw_path":b"/v1/generations","query_string":b"","headers":request_headers,"server":("127.0.0.1",8011),"client":("127.0.0.1",1234)}
                await app(scope,receive,send)
                self.assertEqual(messages[0]["status"],expected)
                self.assertEqual(reads,[])


if __name__ == "__main__": unittest.main(verbosity=2)




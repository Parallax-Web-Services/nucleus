"""Readout contract and tiny autograd fixtures; never loads pretrained tensors."""
import asyncio
import hashlib
import io
import json
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from fastapi.testclient import TestClient
from PIL import Image
from runtimes.meld.manifest import VerifiedManifest
from runtimes.meld.server import SubprocessRunner,create_app
from runtimes.meld.contracts import Generation,Rejected
from test_runtime import manifest_fixture,settings_fixture,headers,multipart,FakeRunner,NoDisconnect,HERE

try:
    import torch
except ModuleNotFoundError:
    torch=None


def readout_manifest(directory,depth=False):
    manifest=manifest_fixture(directory)
    document=dict(manifest.document,backend="sdxl_readout")
    if depth:
        relative="conditioning/readout_sdxl_spatial_depth.pt"
        target=manifest.root/relative;target.parent.mkdir();target.write_bytes(b"protocol-only-depth-head")
        artifact={"path":relative,"model":dict(document["artifacts"][0]["model"],format="PT",sha256=hashlib.sha256(target.read_bytes()).hexdigest(),size_bytes=target.stat().st_size)}
        document["artifacts"]=document["artifacts"]+[artifact]
    manifest.path.write_text(json.dumps(document))
    return VerifiedManifest.load(manifest.path,manifest.root,hashlib.sha256(manifest.path.read_bytes()).hexdigest())


def image_bytes(color="navy",size=(64,64)):
    output=io.BytesIO();Image.new("RGB",size,color).save(output,format="PNG");return output.getvalue()


def depth_bytes(reverse=False):
    image=Image.new("L",(64,64))
    image.putdata([int((63-x if reverse else x)*255/63) for y in range(64) for x in range(64)])
    output=io.BytesIO();image.save(output,format="PNG");return output.getvalue()


def readout_form(extra=None,steps=4):
    return [(name,(None,str(steps))) if name=="steps" else (name,value) for name,value in multipart(extra)]


class ReadoutContractTests(unittest.TestCase):
    def test_readout_controls_and_preload_budget_validation(self):
        with tempfile.TemporaryDirectory() as raw:
            directory=Path(raw);manifest=readout_manifest(directory);runner=FakeRunner()
            with TestClient(create_app(manifest,settings_fixture(directory),runner=runner)) as client:
                response=client.post("/v1/generations",headers=headers(manifest),files=readout_form([
                    ("identity_strength",(None,"0.25")),("pose_guide",("guide.png",image_bytes(),"image/png")),("pose_guide_strength",(None,"0.7"))]))
                self.assertEqual(response.status_code,200,response.text)
                payload=runner.calls[-1][1]
                self.assertEqual(payload.identity_strength,.25)
                self.assertEqual(payload.pose_guide_strength,.7)
                self.assertEqual(payload.pose_guide,image_bytes())
                response=client.post("/v1/generations",headers=headers(manifest),files=readout_form(steps=2))
                self.assertEqual(response.status_code,422)
                self.assertEqual(response.json()["error"]["code"],"insufficient_guidance_steps")
                self.assertEqual(len(runner.calls),1)
                response=client.post("/v1/generations",headers=headers(manifest),files=readout_form([("identity_strength",(None,"0"))],steps=2))
                self.assertEqual(response.status_code,200,response.text)
                self.assertEqual(runner.calls[-1][1].identity_strength,0)

    def test_malformed_pose_pairs_and_unsupported_controls_fail_before_dispatch(self):
        with tempfile.TemporaryDirectory() as raw:
            directory=Path(raw);manifest=readout_manifest(directory);runner=FakeRunner()
            with TestClient(create_app(manifest,settings_fixture(directory),runner=runner)) as client:
                for extra in [
                    [("pose_guide_strength",(None,"0.7"))],
                    [("pose_guide",("x.png",image_bytes(),"image/png"))],
                    [("pose_guide",("x.png",b"", "image/png")),("pose_guide_strength",(None,"0.7"))],
                    [("pose_guide",("x.png",image_bytes(),"image/png")),("pose_guide_strength",(None,"0"))],
                    [("identity_strength",(None,"nan"))],[("morphology_strength",(None,"0.1"))],
                    [("anchor_scopes",(None,"face")),("anchor_scopes",(None,"auto"))],
                ]:
                    response=client.post("/v1/generations",headers=headers(manifest),files=readout_form(extra))
                    self.assertEqual(response.status_code,422,response.text)
                extras=[]
                for n in range(3):
                    extras.extend([("sources",("x.png",image_bytes(),"image/png")),("names",(None,"extra")),("weights_basis_points",(None,"1"))])
                response=client.post("/v1/generations",headers=headers(manifest),files=readout_form(extras))
                self.assertEqual(response.status_code,422)
                self.assertIn("1..4",response.text)
                self.assertEqual(runner.calls,[])
                health=client.get("/healthz",headers=headers(manifest)).json()
                self.assertTrue(health["pose_guide"])
                self.assertFalse(health["learned_face_identity"])


    def test_depth_requires_explicit_format_nonflat_grayscale_and_installed_head(self):
        for has_head in (False,True):
            with tempfile.TemporaryDirectory() as raw:
                directory=Path(raw);manifest=readout_manifest(directory,depth=has_head);runner=FakeRunner()
                with TestClient(create_app(manifest,settings_fixture(directory),runner=runner)) as client:
                    extra=[("pose_guide_format",(None,"depth")),("pose_guide_strength",(None,"0.5")),("pose_guide",("depth.png",depth_bytes(),"image/png"))]
                    response=client.post("/v1/generations",headers=headers(manifest),files=readout_form(extra))
                    self.assertEqual(response.status_code,200 if has_head else 422,response.text)
                    if has_head:
                        self.assertEqual(runner.calls[-1][1].pose_guide_format,"depth")
                        self.assertEqual(runner.calls[-1][1].pose_guide,depth_bytes())
                        self.assertEqual(client.get("/healthz",headers=headers(manifest)).json()["pose_guide_formats"],["rgb","depth"])
                    else:
                        self.assertEqual(runner.calls,[])
                        self.assertIn("does not install a depth",response.text)

    def test_depth_rejects_color_flat_invalid_or_unsupported_format_before_model_load(self):
        with tempfile.TemporaryDirectory() as raw:
            directory=Path(raw);manifest=readout_manifest(directory,depth=True);runner=FakeRunner()
            with TestClient(create_app(manifest,settings_fixture(directory),runner=runner)) as client:
                for guide,kind in [(image_bytes("red"),"depth"),(image_bytes("gray"),"depth"),(b"not an image","depth"),(depth_bytes(),"openpose"),(depth_bytes(),"DEPTH")]:
                    extra=[("pose_guide_format",(None,kind)),("pose_guide_strength",(None,"0.5")),("pose_guide",("control.png",guide,"image/png"))]
                    response=client.post("/v1/generations",headers=headers(manifest),files=readout_form(extra))
                    self.assertEqual(response.status_code,422,response.text)
                response=client.post("/v1/generations",headers=headers(manifest),files=readout_form([("pose_guide_format",(None,"depth"))]))
                self.assertEqual(response.status_code,422)
                self.assertEqual(runner.calls,[])

class ReadoutSerializationTests(unittest.IsolatedAsyncioTestCase):
    async def test_uploaded_guide_is_private_file_in_owned_job_not_json_bytes(self):
        with tempfile.TemporaryDirectory() as raw:
            directory=Path(raw);manifest=readout_manifest(directory);settings=settings_fixture(directory);settings.validate()
            runner=SubprocessRunner(manifest,settings,engine_path=HERE/"worker_fixture.py")
            payload=Generation("guide-fixture","",64,64,4,5,42,[image_bytes()],["one"],[10000],.4,image_bytes("red"),.7)
            with patch("runtimes.meld.server.available_memory",return_value=1<<40):
                result=await runner.run("generate",payload,NoDisconnect())
            self.assertTrue(result.startswith(b"\x89PNG"))
            report=json.loads((settings.work_dir/"guide-fixture.json").read_bytes())
            self.assertTrue(report["is_path"])
            self.assertEqual(report["mode"],0o600)
            self.assertEqual(report["sha256"],hashlib.sha256(payload.pose_guide).hexdigest())
            self.assertFalse(list(settings.work_dir.glob("job-*")))
            await runner.close()


@unittest.skipIf(torch is None,"tiny gradient fixtures require optional PyTorch; no pretrained model is loaded")
class TinyAutogradTests(unittest.TestCase):
    def setUp(self):
        torch.set_num_threads(1)

    def test_source_weights_change_actual_latent_gradient_direction(self):
        from runtimes.meld.readout import appearance_loss,bounded_latent_update,MAX_LATENT_DELTA
        reference_a=torch.tensor([1.,0.]).reshape(1,2,1,1)
        reference_b=torch.tensor([0.,1.]).reshape(1,2,1,1)
        initial=torch.tensor([.5,.5]).reshape(1,2,1,1)
        def update(weights):
            def objective(value):
                loss,per_source=appearance_loss(value,[reference_a,reference_b],weights)
                return loss,{"per_source":[float(x.detach()) for x in per_source]}
            return bounded_latent_update(initial,objective)
        toward_a,details=update([9000,1000]);toward_b,_=update([1000,9000])
        self.assertGreater(float(toward_a[0,0]),float(toward_a[0,1]))
        self.assertGreater(float(toward_b[0,1]),float(toward_b[0,0]))
        self.assertGreater(details["latent_delta_l2"],0)
        self.assertLessEqual(details["latent_delta_max"],MAX_LATENT_DELTA+1e-7)
        self.assertIn("no post-update forward",details["loss_measurement"])

    def test_frozen_tiny_readout_backpropagates_only_to_input(self):
        from runtimes.meld.readout import AggregationNetwork
        torch.manual_seed(5)
        model=AggregationNetwork(feature_dims=[32],projection_dim=128,emb_channels=8).eval().requires_grad_(False)
        features=torch.randn(1,32,4,4,requires_grad=True)
        embedding=torch.randn(1,8)
        output=model([features],embedding,(4,4))
        output.square().mean().backward()
        self.assertTrue(torch.isfinite(features.grad).all())
        self.assertGreater(float(features.grad.abs().sum()),0)
        self.assertTrue(all(parameter.grad is None for parameter in model.parameters()))

    def test_pose_target_changes_actual_callback_latent_update(self):
        from runtimes.meld.readout import ReadoutGuidance
        controller=ReadoutGuidance.__new__(ReadoutGuidance)
        controller.enabled=True;controller.head=None;controller.strength=0;controller.pose_strength=.7
        controller.steps=[];controller.request={"steps":2};controller.settings={"strength":1}
        controller.feature_size=(2,2);controller.noise=torch.zeros(1,4,2,2)
        controller._embedding=lambda _latents,_t:torch.zeros(1,8)
        controller._features=lambda value,_t,_s:(value,)
        controller.pose_head=lambda features,_embedding,_size:features[0][:,:3]
        controller._record=lambda:None
        scheduler=SimpleNamespace(step_index=1,timesteps=torch.tensor([999.,1.]),sigmas=torch.tensor([1.,.1,0.]))
        pipeline=SimpleNamespace(scheduler=scheduler)
        controller.pose_latent=torch.ones(1,4,2,2)
        positive=controller(pipeline,0,999.,{"latents":torch.zeros(1,4,2,2)})["latents"]
        self.assertGreater(float(positive[:,:3].mean()),0)
        self.assertGreater(controller.steps[0]["pose_mse_loss"],0)
        controller.steps=[];controller.pose_strength=.2
        weaker=controller(pipeline,0,999.,{"latents":torch.zeros(1,4,2,2)})["latents"]
        self.assertLess(float(weaker[:,:3].mean()),float(positive[:,:3].mean()))
        controller.pose_strength=.7
        controller.steps=[];controller.pose_latent=-torch.ones(1,4,2,2)
        negative=controller(pipeline,0,999.,{"latents":torch.zeros(1,4,2,2)})["latents"]
        self.assertLess(float(negative[:,:3].mean()),0)

    def test_distinct_supplied_depth_maps_change_real_latent_gradient(self):
        from runtimes.meld.readout import ReadoutGuidance,depth_target
        with tempfile.TemporaryDirectory() as raw:
            directory=Path(raw)
            first=directory/"first.png";second=directory/"second.png"
            first.write_bytes(depth_bytes());second.write_bytes(depth_bytes(True))
            target=depth_target(first,(4,4))
            self.assertEqual(tuple(target.shape),(1,3,4,4))
            self.assertGreaterEqual(float(target.min()),-.5)
            self.assertLessEqual(float(target.max()),.5)
            controller=ReadoutGuidance.__new__(ReadoutGuidance)
            controller.enabled=True;controller.head=None;controller.strength=0;controller.pose_strength=.7
            controller.guide_format="depth";controller.steps=[];controller.request={"steps":2};controller.settings={"strength":1}
            controller.feature_size=(4,4);controller.noise=torch.zeros(1,4,4,4)
            controller._embedding=lambda _latents,_t:torch.zeros(1,8)
            controller._features=lambda value,_t,_s:(value,)
            controller.pose_head=lambda features,_embedding,_size:features[0][:,:3]
            controller._record=lambda:None
            scheduler=SimpleNamespace(step_index=1,timesteps=torch.tensor([999.,1.]),sigmas=torch.tensor([1.,.1,0.]))
            pipeline=SimpleNamespace(scheduler=scheduler)
            controller.depth_control=target
            forward=controller(pipeline,0,999.,{"latents":torch.zeros(1,4,4,4)})["latents"]
            self.assertGreater(controller.steps[0]["depth_mse_loss"],0)
            self.assertNotIn("pose_mse_loss",controller.steps[0])
            controller.steps=[];controller.depth_control=depth_target(second,(4,4))
            reverse=controller(pipeline,0,999.,{"latents":torch.zeros(1,4,4,4)})["latents"]
            self.assertLess(float(forward[0,0,0,0]),0)
            self.assertGreater(float(reverse[0,0,0,0]),0)
            self.assertGreater(float((forward-reverse).norm()),0)

    def test_zero_appearance_skips_head_load_and_optimizer(self):
        from runtimes.meld.readout import ReadoutGuidance
        with tempfile.TemporaryDirectory() as raw:
            directory=Path(raw);source=directory/"source.png";source.write_bytes(image_bytes())
            pipeline=SimpleNamespace(unet=torch.nn.Identity(),vae=torch.nn.Identity(),text_encoder=None,text_encoder_2=None)
            manifest=SimpleNamespace(root=directory,sha256="a"*64)
            request={"sources":[str(source)],"weights_basis_points":[10000],"width":64,"height":64,"identity_strength":0,"pose_guide_strength":0,"seed":42}
            settings={"work_dir":str(directory),"strength":1}
            conditioning={"prompt_embeds":torch.zeros(1,2,3),"pooled_prompt_embeds":torch.zeros(1,4)}
            with patch("runtimes.meld.readout.load_head",side_effect=AssertionError("zero strength must not load a head")):
                controller=ReadoutGuidance(pipeline,manifest,request,conditioning,settings)
                original={"latents":torch.ones(1,4,8,8)}
                self.assertIs(controller(pipeline,0,999,original),original)
                self.assertFalse(controller.enabled)
                self.assertEqual(controller.steps,[])
                controller.close()

    def test_guide_contains_head_and_feet_without_cropping(self):
        from runtimes.meld.readout import contained_image
        with tempfile.TemporaryDirectory() as raw:
            path=Path(raw)/"tall.png"
            image=Image.new("RGB",(10,40),"white")
            for x in range(10):
                for y in range(5):image.putpixel((x,y),(255,0,0));image.putpixel((x,39-y),(0,0,255))
            image.save(path)
            result=contained_image(path,(40,40))
            self.assertEqual(result.getpixel((20,0)),(255,0,0))
            self.assertEqual(result.getpixel((20,39)),(0,0,255))
            self.assertEqual(result.getpixel((0,20)),(224,224,224))


if __name__=="__main__":unittest.main(verbosity=2)



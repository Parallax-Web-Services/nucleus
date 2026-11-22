# Copyright 2024 The Google Research Authors.
# Copyright 2026 Nucleus contributors.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
# Unless required by applicable law or agreed to in writing, software distributed
# under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR
# CONDITIONS OF ANY KIND, either express or implied. See the License for the
# specific language governing permissions and limitations under the License.
"""Bounded CPU adaptation of Google's Readout Guidance, not a face-ID model.

Aggregation math adapted from google-research/readout_guidance commit
 a8a699c320f412bfcdb4e5a316b9ccb7fc0f4c15, dhf/aggregation_network.py and
 readout_guidance/rg_operators.py. That code credits Diffusion Hyperfeatures.
Changes: strict weights-only loading, current-Diffusers conv2 hooks, sequential
conditional references, bounded latent-only AdamW and RGB pose readout targets.
No pretrained model import/load occurs unless this backend is explicitly used.
"""
from __future__ import annotations

import hashlib
import io
import json
import math
from pathlib import Path

import torch
from torch import nn
from torch.nn import functional as F
from torch.utils.checkpoint import checkpoint

from .contracts import Rejected, depth_map_image
from .diagnostics import atomic_private

FEATURE_DIMS = (1280,1280,1280,640,640,640,320,320,320)
MAX_GUIDED_STEPS = 4
LEARNING_RATE = 0.02
MAX_LATENT_DELTA = 0.05
DEFAULT_APPEARANCE_STRENGTH = 0.6


class ConvNorm(nn.Conv2d):
    def __init__(self, in_channels, out_channels, kernel_size):
        super().__init__(in_channels, out_channels, kernel_size, padding=kernel_size//2, bias=False)
        self.norm = nn.GroupNorm(32, out_channels)

    def forward(self, value):
        return self.norm(super().forward(value))


class BottleneckBlock(nn.Module):
    def __init__(self, in_channels, projection_dim=384, emb_channels=1280):
        super().__init__()
        narrow = projection_dim // 4
        self.shortcut = ConvNorm(in_channels, projection_dim, 1) if in_channels != projection_dim else None
        self.conv1 = ConvNorm(in_channels, narrow, 1)
        self.conv2 = ConvNorm(narrow, narrow, 3)
        self.conv3 = ConvNorm(narrow, projection_dim, 1)
        self.emb_layers = nn.Linear(emb_channels, narrow)

    def forward(self, value, embedding):
        result = F.relu(self.conv1(value))
        result = result + F.relu(self.emb_layers(embedding))[:, :, None, None]
        result = self.conv3(F.relu(self.conv2(result)))
        return F.relu(result + (self.shortcut(value) if self.shortcut is not None else value))


class AggregationNetwork(nn.Module):
    def __init__(self, feature_dims=FEATURE_DIMS, projection_dim=384, pose=False, emb_channels=1280):
        super().__init__()
        self.feature_dims = tuple(feature_dims)
        self.bottleneck_layers = nn.ModuleList([BottleneckBlock(c,projection_dim,emb_channels) for c in feature_dims])
        self.mixing_weights = nn.Parameter(torch.ones(len(feature_dims)))
        self.output_head = (nn.Sequential(nn.Conv2d(projection_dim,128,3,padding=1), nn.SiLU(True),
                                         nn.Conv2d(128,32,3,padding=1), nn.SiLU(True), nn.Conv2d(32,3,1), nn.Tanh())
                            if pose else nn.Identity())

    def forward(self, features, embedding, size):
        if len(features) != len(self.feature_dims):
            raise RuntimeError("unexpected number of SDXL hidden features")
        result = None
        weights = self.mixing_weights.softmax(dim=0)
        for i,(feature,channels) in enumerate(zip(features,self.feature_dims)):
            if feature.shape[1] != channels:
                raise RuntimeError("SDXL hidden-feature channel layout differs from approved readout")
            resized = F.interpolate(feature,size=size,mode="bilinear",align_corners=False)
            projected = self.bottleneck_layers[i](resized,embedding) * weights[i]
            result = projected if result is None else result + projected
        return self.output_head(result)


def load_head(path, *, pose, spatial_kind="rgb"):
    if path.stat().st_size > 32*1024**2:
        raise RuntimeError("readout checkpoint exceeds its supported bound")
    # No unsafe pickle fallback, added globals, remote code or checkpoint-selected classes.
    document = torch.load(path,map_location="cpu",weights_only=True)
    if not isinstance(document,dict) or set(document) != {"step","config","aggregation_network"}:
        raise RuntimeError("unsupported readout checkpoint envelope")
    config,state = document["config"],document["aggregation_network"]
    if not isinstance(config,dict) or not isinstance(state,dict):
        raise RuntimeError("invalid readout checkpoint configuration")
    options = config.get("aggregation_kwargs",{})
    if (config.get("dims") != list(FEATURE_DIMS) or config.get("projection_dim") != 384 or
            config.get("save_timestep") != [0] or config.get("num_timesteps") != 1000 or
            config.get("load_resolution") != 1024 or config.get("output_resolution") != 128 or
            options.get("bottleneck_sequential") is not False or options.get("use_output_head") is not pose or
            (pose and options.get("output_head_channels",3) != 3)):
        raise RuntimeError("readout checkpoint architecture is not the reviewed SDXL architecture")
    if not all(isinstance(value,torch.Tensor) and value.dtype == torch.float32 and torch.isfinite(value).all() for value in state.values()):
        raise RuntimeError("readout weights must be finite CPU float32 tensors")
    if spatial_kind == "depth" and (not pose or config.get("dataset_args",{}).get("control_range") != [-1,1]):
        raise RuntimeError("depth guidance requires the reviewed depth-trained spatial head")
    head = AggregationNetwork(pose=pose)
    head.load_state_dict(state,strict=True)
    return head.eval().requires_grad_(False)


def contained_image(path, size):
    """Keep a complete RGB guide/reference; never crop head/feet to change aspect."""
    from PIL import Image, ImageOps
    with Image.open(path) as image:
        image = ImageOps.exif_transpose(image).convert("RGBA")
        background = Image.new("RGBA",image.size,(255,255,255,255))
        background.alpha_composite(image)
        image = ImageOps.contain(background.convert("RGB"),size,Image.Resampling.LANCZOS)
    output = Image.new("RGB",size,(224,224,224))
    output.paste(image,((size[0]-image.width)//2,(size[1]-image.height)//2))
    return output


def depth_target(path,size):
    """Declared depth values in canonical [-.5,.5], no VAE/pose inference."""
    import numpy as np
    from PIL import Image,ImageOps
    gray=depth_map_image(Path(path).read_bytes())
    resized=ImageOps.contain(gray,(size[1],size[0]),Image.Resampling.BILINEAR)
    canvas=Image.new("L",(size[1],size[0]),0)
    canvas.paste(resized,((canvas.width-resized.width)//2,(canvas.height-resized.height)//2))
    values=torch.from_numpy(np.asarray(canvas,dtype=np.float32).copy())/255.0-.5
    return values[None,None,:,:].repeat(1,3,1,1)

def weighted_initial(images, basis_points):
    import numpy as np
    if len(images) != len(basis_points) or sum(basis_points) != 10000:
        raise ValueError("source images require exact basis-point weights")
    from PIL import Image
    pixels = sum(np.asarray(image,dtype=np.float32)*(weight/10000) for image,weight in zip(images,basis_points))
    return Image.fromarray(np.rint(np.clip(pixels,0,255)).astype(np.uint8),"RGB")


def appearance_loss(observed, references, basis_points):
    if not 1 <= len(references) <= 4 or len(references) != len(basis_points) or sum(basis_points) != 10000:
        raise ValueError("readout supports 1..4 exactly weighted references")
    losses = [(1-F.cosine_similarity(observed,target,dim=1,eps=1e-8)).mean() for target in references]
    return sum(loss*(weight/10000) for loss,weight in zip(losses,basis_points)),losses


def bounded_latent_update(latents, loss_function, *, lr=LEARNING_RATE):
    """One finite latent-only update. Loss is measured BEFORE the update."""
    with torch.enable_grad():
        variable = latents.detach().clone().requires_grad_(True)
        optimizer = torch.optim.AdamW([variable],lr=lr,weight_decay=0)
        loss,details = loss_function(variable)
        if loss.ndim != 0 or not torch.isfinite(loss):
            raise RuntimeError("nonfinite readout loss")
        optimizer.zero_grad(set_to_none=True)
        loss.backward()
        if variable.grad is None or not torch.isfinite(variable.grad).all():
            raise RuntimeError("missing or nonfinite readout latent gradients")
        gradient_norm = float(torch.nn.utils.clip_grad_norm_([variable],1.0,error_if_nonfinite=True))
        optimizer.step()
        with torch.no_grad():
            delta = (variable-latents).clamp(-MAX_LATENT_DELTA,MAX_LATENT_DELTA)
            updated = latents + delta
            if not torch.isfinite(updated).all():
                raise RuntimeError("nonfinite optimized latents")
        details.update(loss_before_update=float(loss.detach()),gradient_norm_before_clip=gradient_norm,
                       latent_delta_l2=float(delta.norm()),latent_delta_max=float(delta.abs().max()),
                       loss_measurement="before update; no post-update forward was performed")
        return updated.detach(),details


class ReadoutGuidance:
    def __init__(self,pipeline,manifest,request,conditioning,settings):
        self.pipeline,self.request,self.settings = pipeline,request,settings
        self.size=(request["width"]//8,request["height"]//8)
        self.feature_size=(self.size[1],self.size[0])
        self.strength = request.get("identity_strength")
        self.strength = DEFAULT_APPEARANCE_STRENGTH if self.strength is None else self.strength
        self.pose_strength = request.get("pose_guide_strength",0)
        self.guide_format = request.get("pose_guide_format","rgb")
        spatial_relative = "conditioning/readout_sdxl_spatial_depth.pt" if self.guide_format == "depth" else "conditioning/readout_sdxl_spatial_pose.pt"
        self.head = load_head(manifest.root / "conditioning/readout_sdxl_drag_appearance.pt",pose=False) if self.strength > 0 else None
        self.pose_head = load_head(manifest.root / spatial_relative,pose=True,spatial_kind=self.guide_format) if self.pose_strength > 0 else None
        self.enabled = self.head is not None or self.pose_head is not None
        self.steps=[]
        self.handles=[]
        self.capture=None
        for module in (pipeline.unet,pipeline.vae,pipeline.text_encoder,pipeline.text_encoder_2):
            if module is not None: module.eval().requires_grad_(False)
        self.context=conditioning["prompt_embeds"].detach()
        self.pooled=conditioning["pooled_prompt_embeds"].detach()
        self.time_ids=torch.tensor([[request["height"],request["width"],0,0,request["height"],request["width"]]],dtype=self.context.dtype)
        self.condition={"text_embeds":self.pooled,"time_ids":self.time_ids}
        self.images=[contained_image(path,(request["width"],request["height"])) for path in request["sources"]]
        self.initial_image=weighted_initial(self.images,request["weights_basis_points"])
        if self.enabled:
            layers=[resnet for block in pipeline.unet.up_blocks for resnet in block.resnets]
            if len(layers) != len(FEATURE_DIMS) or tuple(layer.conv2.out_channels for layer in layers) != FEATURE_DIMS:
                raise RuntimeError("readout requires the reviewed nine SDXL up-block hidden features")
            for index,layer in enumerate(layers):
                self.handles.append(layer.conv2.register_forward_hook(self._hook(index)))
            self.reference_latents=[self._encode(image) for image in self.images] if self.head is not None else []
            self.depth_control=depth_target(request["pose_guide"],self.feature_size) if self.pose_head is not None and self.guide_format == "depth" else None
            self.pose_latent=self._encode(contained_image(request["pose_guide"],(request["width"],request["height"]))) if self.pose_head is not None and self.guide_format == "rgb" else None
            self.noise=torch.randn((1,4,*self.feature_size),generator=torch.Generator(device="cpu").manual_seed(request["seed"] ^ 0x52474E),dtype=torch.float32)
        self.audit={"schema_version":1,"backend":"sdxl_readout","conditioning":"generic learned appearance; not face identity embeddings",
                    "basis_points":request["weights_basis_points"],"appearance_strength":self.strength,
                    "pose_strength":self.pose_strength,"pose_guide_format":self.guide_format,"guidance_step_cap":MAX_GUIDED_STEPS,
                    "spatial_head_path":spatial_relative if self.pose_head is not None else None,
                    "spatial_head_sha256":next((a["model"]["sha256"] for a in manifest.document["artifacts"] if a["path"] == spatial_relative),None) if self.pose_head is not None else None,
                    "depth_target_range":[-.5,.5] if self.guide_format == "depth" else None,
                    "depth_head_native_range":[-1,1] if self.guide_format == "depth" else None,
                    "head_training_image_resolution":1024,"actual_image_size":[request["width"],request["height"]],
                    "manifest_sha256":manifest.sha256,"seed":request["seed"],"optimized_steps":self.steps}
        self.audit_path=Path(settings["work_dir"]) / "last-readout-guidance.json"
        self._record()

    def _record(self):
        self.audit["optimized_step_count"]=len(self.steps)
        atomic_private(self.audit_path,json.dumps(self.audit,indent=2).encode())

    def _encode(self,image):
        with torch.no_grad():
            tensor=self.pipeline.image_processor.preprocess(image).to(dtype=torch.float32,device="cpu")
            return (self.pipeline.vae.encode(tensor).latent_dist.mean*self.pipeline.vae.config.scaling_factor).detach()

    def _hook(self,index):
        def save(_module,_inputs,output):
            if self.capture is not None: self.capture[index]=output
        return save

    def _features(self,latents,timestep,sigma):
        store={}
        self.capture=store
        try:
            self.pipeline.unet(latents/(sigma.square()+1).sqrt(),timestep,
                               encoder_hidden_states=self.context,added_cond_kwargs=self.condition,return_dict=False)
            if len(store) != len(FEATURE_DIMS): raise RuntimeError("incomplete readout feature capture")
            return tuple(store[i] for i in range(len(FEATURE_DIMS)))
        finally:
            self.capture=None

    def _embedding(self,latents,timestep):
        timesteps=timestep.reshape(1).expand(latents.shape[0])
        return self.pipeline.unet.time_embedding(self.pipeline.unet.time_proj(timesteps).to(dtype=latents.dtype),None)

    def __call__(self,pipeline,index,timestep,callback_kwargs):
        if not self.enabled: return callback_kwargs
        scheduler=pipeline.scheduler
        position=scheduler.step_index
        if position is None or position >= len(scheduler.timesteps): return callback_kwargs
        total=int(self.request["steps"]*self.settings["strength"])
        interval=max(1,math.ceil(max(total-1,1)/MAX_GUIDED_STEPS))
        if index % interval or len(self.steps) >= MAX_GUIDED_STEPS: return callback_kwargs
        next_t=scheduler.timesteps[position]
        sigma=scheduler.sigmas[position].to(dtype=torch.float32,device="cpu")
        current=callback_kwargs["latents"].detach()
        with torch.no_grad():
            embedding=self._embedding(current,next_t)
            targets=[]
            if self.head is not None:
                for reference in self.reference_latents:
                    features=self._features(reference+self.noise*sigma,next_t,sigma)
                    targets.append(self.head(features,embedding,self.feature_size).detach())
            pose_target=None
            if self.pose_head is not None:
                if getattr(self,"guide_format","rgb") == "depth":
                    pose_target=self.depth_control
                else:
                    features=self._features(self.pose_latent+self.noise*sigma,next_t,sigma)
                    pose_target=self.pose_head(features,embedding,self.feature_size).detach()
        def loss_function(variable):
            features=checkpoint(lambda value:self._features(value,next_t,sigma),variable,use_reentrant=False)
            loss=variable.sum()*0
            details={"callback_index":index,"scheduler_position":int(position),"timestep":float(next_t),"sigma":float(sigma)}
            if self.head is not None:
                observed=self.head(features,embedding,self.feature_size)
                app,per_source=appearance_loss(observed,targets,self.request["weights_basis_points"])
                loss=loss+self.strength*app
                details.update(appearance_cosine_loss=float(app.detach()),per_source_cosine_loss=[float(value.detach()) for value in per_source])
            if self.pose_head is not None:
                predicted=self.pose_head(features,embedding,self.feature_size)
                is_depth=getattr(self,"guide_format","rgb") == "depth"
                if is_depth: predicted=predicted/2.0  # Native depth head [-1,1] to canonical [-.5,.5].
                pose_loss=F.mse_loss(predicted,pose_target)
                loss=loss+self.pose_strength*pose_loss
                details["depth_mse_loss" if is_depth else "pose_mse_loss"]=float(pose_loss.detach())
            return loss,details
        effective_lr=LEARNING_RATE*max(self.strength if self.head is not None else 0,self.pose_strength if self.pose_head is not None else 0)
        updated,details=bounded_latent_update(current,loss_function,lr=effective_lr)
        details["optimizer_learning_rate"]=effective_lr
        self.steps.append(details)
        self._record()
        callback_kwargs["latents"]=updated
        return callback_kwargs

    def close(self):
        for handle in self.handles: handle.remove()
        self.handles=[]
        self.capture=None


def generate(job,manifest):
    from compel import CompelForSDXL
    from diffusers import StableDiffusionXLImg2ImgPipeline
    from .engine import phase,write_private
    request,settings=job["request"],job["settings"]
    if settings["device"] != "cpu":
        raise Rejected("the bounded Readout backend currently supports CPU execution only",422,"unsupported_feature")
    torch.set_num_threads(settings["threads"])
    torch.set_num_interop_threads(1)
    phase(job,"load_readout_generator")
    pipeline=StableDiffusionXLImg2ImgPipeline.from_pretrained(str(manifest.root),dtype=torch.float32,
                variant="fp16",use_safetensors=True,local_files_only=True,add_watermarker=False).to("cpu")
    pipeline.set_progress_bar_config(disable=True)
    pipeline.vae.enable_slicing()
    pipeline.vae.enable_tiling()
    for encoder in (pipeline.tokenizer,pipeline.tokenizer_2):
        for prompt in (request["prompt"],request["negative_prompt"]):
            if len(encoder.encode(prompt,truncation=False,add_special_tokens=False)) > 1024:
                raise Rejected("prompt exceeds the configured per-encoder token budget")
    # no_grad tensors remain usable by latent backward; inference_mode tensors do not.
    with torch.no_grad():
        conditioning=CompelForSDXL(pipeline,device="cpu")(request["prompt"],negative_prompt=request["negative_prompt"])
        kwargs={"prompt_embeds":conditioning.embeds.detach(),"pooled_prompt_embeds":conditioning.pooled_embeds.detach(),
                "negative_prompt_embeds":conditioning.negative_embeds.detach(),"negative_pooled_prompt_embeds":conditioning.negative_pooled_embeds.detach()}
    controller=ReadoutGuidance(pipeline,manifest,request,kwargs,settings)
    try:
        phase(job,"diffuse_readout")
        image=pipeline(**kwargs,image=controller.initial_image,strength=settings["strength"],
                       num_inference_steps=request["steps"],guidance_scale=request["guidance_scale"],
                       generator=torch.Generator(device="cpu").manual_seed(request["seed"]),
                       callback_on_step_end=controller,callback_on_step_end_tensor_inputs=["latents"]).images[0]
        if controller.enabled and not controller.steps:
            raise RuntimeError("requested readout controls did not execute a latent optimization step")
        phase(job,"encode_png")
        output=io.BytesIO()
        image.convert("RGB").save(output,format="PNG",compress_level=6)
        write_private(Path(job["job_dir"])/"result.png",output.getvalue())
        controller.audit["result_sha256"]=hashlib.sha256(output.getvalue()).hexdigest()
        controller.audit["status"]="completed"
        controller._record()
    finally:
        controller.close()




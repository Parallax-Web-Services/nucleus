"""Bounded Meld multipart inputs and strict model-produced verdicts."""
from __future__ import annotations

from dataclasses import dataclass
import io
import math
import secrets
from PIL import Image
from starlette.datastructures import UploadFile
from .manifest import strict_json

MAX_IMAGE_BYTES = 8 * 1024 * 1024
MAX_IMAGE_PIXELS = 16 * 1024 * 1024
ISSUES = {"detached_anatomy", "malformed_anatomy", "extra_or_missing_parts", "multiple_people", "furniture_body_merge", "literal_unrequested_prop", "wardrobe_mismatch", "morphology_mismatch", "composition_mismatch", "embedded_text", "reference_leakage", "contact_sheet", "other_major_defect"}


class Rejected(ValueError):
    def __init__(self, message, status=422, code="invalid_request"):
        super().__init__(message)
        self.status, self.code = status, code


@dataclass
class Generation:
    prompt: str
    negative_prompt: str
    width: int
    height: int
    steps: int
    guidance_scale: float
    seed: int
    sources: list[bytes]
    names: list[str]
    weights_basis_points: list[int]
    identity_strength: float | None = None
    pose_guide: bytes | None = None
    pose_guide_strength: float = 0.0
    pose_guide_format: str = "rgb"


@dataclass
class Review:
    prompt: str
    negative_prompt: str
    candidate: bytes


def image_bytes(data):
    if not data or len(data) > MAX_IMAGE_BYTES:
        raise Rejected("image exceeds the upload byte limit")
    try:
        with Image.open(io.BytesIO(data)) as image:
            if image.format not in {"PNG", "JPEG", "WEBP"} or image.width * image.height > MAX_IMAGE_PIXELS or getattr(image, "is_animated", False):
                raise Rejected("unsupported image format, animation or pixel count")
            size = image.size
            image.verify()
            return size
    except Rejected:
        raise
    except Exception as error:
        raise Rejected("invalid image upload") from error


def depth_map_image(data):
    """Validate a declared 8-bit depth map; never estimate depth from RGB."""
    from PIL import ImageChops, ImageStat, ImageOps
    image_bytes(data)
    with Image.open(io.BytesIO(data)) as original:
        if original.mode not in {"L","LA","RGB","RGBA","P"}:
            raise Rejected("depth guide requires an 8-bit grayscale image")
        if "transparency" in original.info or ("A" in original.getbands() and original.getchannel("A").getextrema() != (255,255)):
            raise Rejected("depth guide must be opaque")
        rgb=ImageOps.exif_transpose(original).convert("RGB")
        red,green,blue=rgb.split()
        if ImageChops.difference(red,green).getextrema()[1] or ImageChops.difference(red,blue).getextrema()[1]:
            raise Rejected("depth guide contains color; declare rgb for a photographic guide")
        low,high=red.getextrema()
        if high-low < 8 or ImageStat.Stat(red).stddev[0] < 1:
            raise Rejected("depth guide is flat or has insufficient depth variation")
        return red.copy()

def scalar(form, name, default=None):
    values = form.getlist(name)
    if not values:
        return default
    if len(values) != 1 or not isinstance(values[0], str):
        raise Rejected("expected one text value for " + name)
    return values[0]


def text(form, name, default=""):
    value = scalar(form, name, default)
    if not isinstance(value, str) or len(value) > 16000 or "\x00" in value:
        raise Rejected("invalid or oversized " + name)
    return value


def number(value, name, lower, upper, integer=False):
    try:
        if integer:
            if not isinstance(value, str) or not value.isascii() or not value.isdecimal():
                raise ValueError()
            result = int(value)
        else:
            result = float(value)
        if not math.isfinite(result) or result < lower or result > upper:
            raise ValueError()
        return result
    except (TypeError, ValueError, OverflowError) as error:
        raise Rejected("invalid " + name) from error


async def generation(form, model, max_pixels=2 * 1024 * 1024, max_steps=50, *, backend="sdxl_img2img"):
    readout = backend == "sdxl_readout"
    allowed = {"prompt", "negative_prompt", "width", "height", "steps", "guidance_scale", "seed", "model", "sources", "names", "weights_basis_points", "anchor_scopes", "anchor_targets", "morphology_strength", "identity_strength", "pose_guide", "pose_guide_strength", "pose_guide_format"}
    if set(form) - allowed:
        raise Rejected("unsupported generation fields")
    if not readout and any(name in form for name in ("identity_strength", "pose_guide", "pose_guide_strength", "pose_guide_format")):
        raise Rejected("SDXL img2img does not implement identity-strength or pose-guide conditioning", code="unsupported_feature")
    if number(scalar(form, "morphology_strength", "0"), "morphology_strength", 0, 1) != 0:
        raise Rejected("SDXL img2img does not implement morphology controls", code="unsupported_feature")
    if scalar(form, "model", model) != model:
        raise Rejected("model does not match the approved runtime manifest")
    prompt = text(form, "prompt")
    if not prompt.strip():
        raise Rejected("prompt is required")
    width = number(scalar(form, "width", "1024"), "width", 64, 2048, True)
    height = number(scalar(form, "height", "1024"), "height", 64, 2048, True)
    if width % 8 or height % 8 or width * height > max_pixels:
        raise Rejected("dimensions must be multiples of eight within the configured pixel budget")
    uploads = form.getlist("sources")
    names, weights = form.getlist("names"), form.getlist("weights_basis_points")
    source_limit = 4 if readout else 10
    if not 1 <= len(uploads) <= source_limit or len(names) != len(uploads) or len(weights) != len(uploads):
        raise Rejected("provide 1.." + str(source_limit) + " matched sources, names and basis-point weights")
    if any(not isinstance(name, str) or not name.strip() or len(name) > 120 for name in names):
        raise Rejected("source names must be bounded nonempty text")
    weights = [number(value, "weights_basis_points", 1, 10000, True) for value in weights]
    if sum(weights) != 10000:
        raise Rejected("source weights must total 10000 basis points")
    scopes, targets = form.getlist("anchor_scopes"), form.getlist("anchor_targets")
    if scopes and (len(scopes) != len(uploads) or any(value != "auto" for value in scopes)):
        raise Rejected("SDXL img2img supports only neutral automatic anchors", code="unsupported_feature")
    if targets and (len(targets) != len(uploads) or any(value != "" for value in targets)):
        raise Rejected("SDXL img2img does not implement anchor targets", code="unsupported_feature")
    sources = []
    for upload in uploads:
        if not isinstance(upload, UploadFile):
            raise Rejected("sources must be image file parts")
        data = await upload.read(MAX_IMAGE_BYTES + 1)
        image_bytes(data)
        sources.append(data)
    identity_strength = number(scalar(form,"identity_strength"),"identity_strength",0,1) if "identity_strength" in form else None
    pose_guide,pose_strength = None,0.0
    guide_format = scalar(form,"pose_guide_format","rgb")
    if guide_format not in {"rgb","depth"}:
        raise Rejected("pose_guide_format must be exactly rgb or depth")
    if readout and any(name in form for name in ("pose_guide","pose_guide_strength","pose_guide_format")):
        guides = form.getlist("pose_guide")
        if len(guides) != 1 or not isinstance(guides[0],UploadFile) or "pose_guide_strength" not in form:
            raise Rejected("provide exactly one RGB pose guide and an explicit positive pose-guide strength")
        pose_strength = number(scalar(form,"pose_guide_strength"),"pose_guide_strength",0,1)
        if pose_strength <= 0:
            raise Rejected("an uploaded RGB pose guide requires positive pose-guide strength")
        pose_guide = await guides[0].read(MAX_IMAGE_BYTES + 1)
        image_bytes(pose_guide)
        if guide_format == "depth":
            depth_map_image(pose_guide)
    return Generation(prompt, text(form, "negative_prompt"), width, height,
                      number(scalar(form, "steps", "30"), "steps", 1, max_steps, True),
                      number(scalar(form, "guidance_scale", "5"), "guidance_scale", 0, 20),
                      number(scalar(form, "seed", str(secrets.randbits(32))), "seed", 0, 2**32 - 1, True),
                      sources, names, weights, identity_strength, pose_guide, pose_strength, guide_format)


def validate_generation_execution(payload, backend, strength, device="cpu", installed_artifacts=None):
    if backend != "sdxl_readout":
        return
    if device != "cpu":
        raise Rejected("the bounded Readout backend currently supports CPU execution only",code="unsupported_feature")
    if payload.pose_guide_format == "depth" and (installed_artifacts is None or "conditioning/readout_sdxl_spatial_depth.pt" not in installed_artifacts):
        raise Rejected("the approved runtime manifest does not install a depth readout head",code="unsupported_feature")
    appearance = 0.6 if payload.identity_strength is None else payload.identity_strength
    if (appearance > 0 or payload.pose_guide_strength > 0) and int(payload.steps * strength) <= 1:
        raise Rejected("positive Readout controls require at least two effective img2img denoising steps",code="insufficient_guidance_steps")


async def review(form):
    if set(form) - {"candidate", "prompt", "negative_prompt"}:
        raise Rejected("unsupported review fields")
    candidates = form.getlist("candidate")
    if len(candidates) != 1 or not isinstance(candidates[0], UploadFile):
        raise Rejected("one candidate image file is required")
    data = await candidates[0].read(MAX_IMAGE_BYTES + 1)
    image_bytes(data)
    prompt = text(form, "prompt")
    if not prompt.strip():
        raise Rejected("review prompt is required")
    return Review(prompt, text(form, "negative_prompt"), data)


def verdict(data):
    try:
        result = strict_json(data)
    except (ValueError, TypeError, UnicodeError) as error:
        raise Rejected("visual reviewer did not produce strict JSON", 502, "invalid_model_output") from error
    if not isinstance(result, dict) or set(result) != {"accepted", "issues", "summary", "quality_score"}:
        raise Rejected("visual reviewer returned the wrong verdict schema", 502, "invalid_model_output")
    issues = result["issues"]
    if type(result["accepted"]) is not bool or not isinstance(issues, list) or any(not isinstance(issue, str) or issue not in ISSUES for issue in issues) or len(set(issues)) != len(issues):
        raise Rejected("visual reviewer returned invalid issue categories", 502, "invalid_model_output")
    if result["accepted"] and issues:
        raise Rejected("visual reviewer returned an inconsistent accepted verdict", 502, "invalid_model_output")
    if type(result["quality_score"]) is not int or not 0 <= result["quality_score"] <= 100 or not isinstance(result["summary"], str) or not result["summary"].strip() or len(result["summary"]) > 2000:
        raise Rejected("visual reviewer returned invalid score or summary", 502, "invalid_model_output")
    return result




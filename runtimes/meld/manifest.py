"""Pinned all-file model manifests. This module never imports an inference engine."""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
from urllib.parse import urlparse, unquote

HEX64 = re.compile(r"[0-9a-f]{64}\Z")
DENIED_HASH = "74a4da8c9fdbcd15bd1f6d01d621410d31c6fc00986f5eb687824e7b93d7a9db"
COUNTRIES = set("AD AE AF AG AI AL AM AO AQ AR AS AT AU AW AX AZ BA BB BD BE BF BG BH BI BJ BL BM BN BO BQ BR BS BT BV BW BY BZ CA CC CD CF CG CH CI CK CL CM CN CO CR CU CV CW CX CY CZ DE DJ DK DM DO DZ EC EE EG EH ER ES ET FI FJ FK FM FO FR GA GB GD GE GF GG GH GI GL GM GN GP GQ GR GS GT GU GW GY HK HM HN HR HT HU ID IE IL IM IN IO IQ IR IS IT JE JM JO JP KE KG KH KI KM KN KP KR KW KY KZ LA LB LC LI LK LR LS LT LU LV LY MA MC MD ME MF MG MH MK ML MM MN MO MP MQ MR MS MT MU MV MW MX MY MZ NA NC NE NF NG NI NL NO NP NR NU NZ OM PA PE PF PG PH PK PL PM PN PR PS PT PW PY QA RE RO RS RU RW SA SB SC SD SE SG SH SI SJ SK SL SM SN SO SR SS ST SV SX SY SZ TC TD TF TG TH TJ TK TL TM TN TO TR TT TV TW TZ UA UG UM US UY UZ VA VC VE VG VI VN VU WF WS YE YT ZA ZM ZW".split())
DENIED_NAMES = ("alibaba", "aliyun", "qwen", "qianwen", "tongyi", "deepseek", "bytedance", "doubao", "seedoss", "minimax", "zhipu", "zaiorg", "chatglm", "moonshot", "baidu", "ernie", "tencent", "hunyuan", "baai", "beijingacademyofartificialintelligence", "internlm", "internvl", "opengvlab", "shanghaiailab", "shanghaiartificialintelligencelaboratory", "modelbest", "minicpm", "openbmb", "stepfun", "sensetime", "sensenova", "iflytek", "thudm", "cogview", "cogvideo", "ipadapter", "01ai", "zerooneai", "阿里巴巴", "通义千问", "深度求索", "字节跳动", "智谱", "月之暗面", "百度", "腾讯", "北京智源", "零一万物", "阶跃星辰", "商汤", "科大讯飞")
DENIED_SHORT_FAMILIES = re.compile(r"(?i)(^|[^a-z0-9])(glm|kimi|yi|bge)([0-9._/ -]|$)|(^|[^a-z0-9])(seed|step)[._ -]?[0-9]|(^|[^a-z0-9])h94([^a-z0-9]|$)")


def strict_json(data: bytes | str):
    def unique(items):
        result = {}
        for key, value in items:
            if key in result:
                raise ValueError("duplicate JSON key")
            result[key] = value
        return result
    return json.loads(data, object_pairs_hook=unique, parse_constant=lambda _: (_ for _ in ()).throw(ValueError("nonfinite JSON")))


def digest_file(path: Path) -> str:
    value = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            value.update(chunk)
    return value.hexdigest()


def _https(value):
    if not isinstance(value, str) or not 1 <= len(value) <= 2048:
        raise ValueError("reviewed HTTPS evidence is required")
    parsed = urlparse(value)
    if parsed.scheme != "https" or not parsed.hostname or parsed.username is not None or parsed.password is not None or parsed.fragment:
        raise ValueError("invalid HTTPS provenance evidence")
    return value


def _identity(value):
    value = str(value)
    for _ in range(2):
        decoded = unquote(value, errors="strict")
        if decoded == value:
            break
        value = decoded
    lower = value.lower()
    text = "".join(character for character in lower if character.isalpha() or character.isdigit())
    host = (urlparse(value).hostname or "").lower()
    if (text == "zai" or any(name in text for name in DENIED_NAMES)
            or DENIED_SHORT_FAMILIES.search(lower) or host == "z.ai" or host.endswith(".z.ai")):
        raise ValueError("model identity is forbidden by the model-origin policy")


def _publisher(origin):
    publisher = origin.get("publisher")
    country = origin.get("country")
    evidence = origin.get("evidence")
    if not isinstance(publisher, str) or not publisher.strip() or publisher.lower() in {"unknown", "unverified", "none", "n/a"}:
        raise ValueError("unknown model publisher")
    if country not in COUNTRIES or country in {"CN", "HK", "MO"}:
        raise ValueError("model publisher jurisdiction is not eligible")
    _identity(publisher)
    if not isinstance(evidence, list) or not 1 <= len(evidence) <= 8:
        raise ValueError("model evidence is required")
    for url in evidence:
        _https(url)


def _model(model, workload):
    if not isinstance(model, dict):
        raise ValueError("artifact model metadata required")
    for name in ("id", "revision", "source", "license", "format", "runtime"):
        if not isinstance(model.get(name), str) or not 1 <= len(model[name]) <= 2048:
            raise ValueError("incomplete artifact model metadata")
    for value in (model["id"], model["source"]):
        _identity(value)
    _https(model["source"])
    if not HEX64.fullmatch(str(model.get("sha256", ""))) or model["sha256"] == DENIED_HASH:
        raise ValueError("invalid or forbidden artifact hash")
    if type(model.get("size_bytes")) is not int or model["size_bytes"] <= 0:
        raise ValueError("artifact size required")
    if workload not in model.get("workloads", []):
        raise ValueError("artifact workload mismatch")
    provenance = model.get("provenance")
    if not isinstance(provenance, dict):
        raise ValueError("reviewed artifact provenance required")
    _publisher(provenance)
    complete = provenance.get("lineage_complete") is True
    disclosed = (provenance.get("lineage_complete") is False
                 and provenance.get("lineage_disclosure") == "publisher-disclosed")
    # This only validates a declaration inside an explicitly operator-pinned
    # manifest. The Nucleus gateway still requires an exact artifact-hash owner
    # approval with allow_publisher_disclosed_lineage and a reviewed note.
    # It never turns a disclosure gap into a claim of complete ancestry.
    if (not complete and not disclosed) or not isinstance(provenance.get("base_models"), list):
        raise ValueError("reviewed complete or explicitly publisher-disclosed lineage required")
    if complete and provenance.get("lineage_disclosure", ""):
        raise ValueError("complete lineage cannot also claim incomplete publisher disclosure")
    if provenance.get("lineage_disclosure", "") not in {"", "publisher-disclosed"}:
        raise ValueError("unknown lineage disclosure mode")
    if len(provenance["base_models"]) > 64:
        raise ValueError("model lineage exceeds bound")
    for base in provenance["base_models"]:
        if not isinstance(base, dict) or not base.get("id") or not base.get("revision"):
            raise ValueError("incomplete upstream model identity")
        _publisher(base)
        _https(base.get("source"))
        _identity(base["id"])
        _identity(base["source"])
        if base.get("sha256") == DENIED_HASH:
            raise ValueError("forbidden upstream artifact")


@dataclass(frozen=True)
class VerifiedManifest:
    path: Path
    root: Path
    raw: bytes
    sha256: str
    document: dict

    @classmethod
    def load(cls, path, root, expected_sha256):
        path, root = Path(path), Path(root)
        if not path.is_absolute() or not root.is_absolute() or path.is_symlink() or root.is_symlink():
            raise ValueError("manifest and model root require absolute nonsymlink paths")
        if not HEX64.fullmatch(str(expected_sha256)):
            raise ValueError("explicit owner-pinned manifest SHA-256 is required")
        raw = path.read_bytes()
        if len(raw) > 1024 * 1024 or hashlib.sha256(raw).hexdigest() != expected_sha256:
            raise ValueError("manifest size or pinned hash mismatch")
        doc = strict_json(raw)
        fields = {"schema_version", "runtime_version", "backend", "workload", "model", "artifact_set_complete", "artifacts"}
        if not isinstance(doc, dict) or set(doc) != fields or doc["schema_version"] != 1 or doc["artifact_set_complete"] is not True:
            raise ValueError("complete runtime manifest schema version 1 required")
        expected = {"sdxl_img2img": "image-generation", "sdxl_readout": "image-generation", "llama_cpp_vlm": "image-review"}
        if expected.get(doc["backend"]) != doc["workload"]:
            raise ValueError("unsupported runtime backend/workload")
        if not isinstance(doc["runtime_version"], str) or not 1 <= len(doc["runtime_version"]) <= 8192:
            raise ValueError("runtime version required")
        if not isinstance(doc["model"], str) or not 1 <= len(doc["model"]) <= 256 or any(c in doc["model"] for c in ",\r\n\x00"):
            raise ValueError("bounded model alias required")
        if not isinstance(doc["artifacts"], list) or not 1 <= len(doc["artifacts"]) <= 512:
            raise ValueError("bounded complete artifact set required")
        result = cls(path.resolve(), root.resolve(), raw, expected_sha256, doc)
        result.verify_files()
        return result

    def verify_files(self):
        declared = set()
        for artifact in self.document["artifacts"]:
            if not isinstance(artifact, dict) or set(artifact) != {"path", "model"}:
                raise ValueError("invalid model artifact entry")
            raw = artifact["path"]
            if not isinstance(raw, str) or len(raw) > 512 or "\\" in raw:
                raise ValueError("invalid artifact path")
            relative = PurePosixPath(raw)
            if relative.is_absolute() or not relative.parts or any(part in {".", ".."} for part in relative.parts) or relative.as_posix() != raw or raw in declared:
                raise ValueError("artifact paths must be unique canonical relative paths")
            declared.add(raw)
            _model(artifact["model"], self.document["workload"])
            path = self.root / raw
            current = path
            while current != self.root:
                if current.is_symlink():
                    raise ValueError("symlinked model artifact is forbidden")
                current = current.parent
            info = path.stat()
            if not stat.S_ISREG(info.st_mode) or info.st_size != artifact["model"]["size_bytes"] or digest_file(path) != artifact["model"]["sha256"]:
                raise ValueError("model artifact size or hash mismatch: " + raw)
        actual = set()
        for path in self.root.rglob("*"):
            if path.is_symlink():
                raise ValueError("symlink in model root")
            if path.is_file() and path.resolve() != self.path:
                actual.add(path.relative_to(self.root).as_posix())
        if actual != declared:
            raise ValueError("undeclared or missing model-associated files")

    def artifact_paths(self):
        return [self.root / artifact["path"] for artifact in self.document["artifacts"]]




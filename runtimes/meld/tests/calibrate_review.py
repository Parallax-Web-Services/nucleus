#!/usr/bin/env python3
"""Opt-in real local reviewer calibration: two known drawings and one photo.

Set NUCLEUS_RUN_REAL_REVIEW_CALIBRATION=1 explicitly. Services/configuration and
approved model files must already exist. This helper starts no service, changes
no settings, downloads nothing and submits exactly three sequential reviews.
It tests photographic APPEARANCE, not camera authenticity or person identity.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import secrets
import sys
import time

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / "tests"))
import test_meld_media_cancel as transport

NEGATIVE_BRIEF = (
    "A photorealistic studio portrait of one adult woman with natural visible anatomy, "
    "realistic skin and clothing materials, in a neutral background. A torso or full-body "
    "composition and ordinary opaque clothes are allowed. Drawn outlines, vector fills "
    "or cartoon features do not satisfy the required photographic appearance."
)
POSITIVE_BRIEF = (
    "Photographic upper-body portrait of one adult woman wearing an orange pressure suit "
    "beside a helmet, with a US flag and space-shuttle display in the background. Natural "
    "visible skin and fabric detail. Suit patches and helmet are permitted scene objects. "
    "This is an upper-body composition; feet and a complete body are not required."
)


def multipart(image, brief):
    boundary = "review-calibration-" + secrets.token_hex(16)
    marker = boundary.encode()
    body = (b"--" + marker + b'\r\nContent-Disposition: form-data; name="prompt"\r\n\r\n' + brief.encode() +
            b"\r\n--" + marker + b'\r\nContent-Disposition: form-data; name="candidate"; filename="control.png"\r\nContent-Type: image/png\r\n\r\n' +
            image + b"\r\n--" + marker + b"--\r\n")
    return body, "multipart/form-data; boundary=" + boundary


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("owner", "profile", "work-dir", "positive", "positive-metadata", "report"):
        parser.add_argument("--" + name, type=Path)
    parser.add_argument("--negative", type=Path, action="append", default=[])
    parser.add_argument("--timeout", type=int, default=900)
    args = parser.parse_args()
    if os.environ.get("NUCLEUS_RUN_REAL_REVIEW_CALIBRATION") != "1":
        print("SKIPPED: set NUCLEUS_RUN_REAL_REVIEW_CALIBRATION=1 explicitly; this executes three real local vision reviews")
        return 0
    if any(getattr(args,name) is None for name in ("owner","profile","work_dir","positive","positive_metadata","report")) or len(args.negative) != 2:
        parser.error("explicit private owner/profile/work-dir/report, positive with metadata, and exactly two negative controls required")
    if not 30 <= args.timeout <= 1800:
        parser.error("timeout must be 30..1800 seconds per real review")
    owner = transport.private_document(args.owner)
    profile = transport.private_document(args.profile)
    work = transport.checked_path(args.work_dir, directory=True, private=True)
    transport.checked_path(args.report.parent, directory=True, private=True)
    if args.report.exists():
        parser.error("report already exists; choose a new private evidence path")
    gateway = profile["gateway_url"]
    transport.endpoint(gateway)
    pin = profile.get("review_manifest_sha256", profile.get("pins",{}).get("review"))
    if pin != owner["meld"]["review_manifest_sha256"]:
        parser.error("profile and owner review manifest pins differ")
    metadata_path = transport.checked_path(args.positive_metadata)
    if metadata_path.stat().st_size > 65536:
        parser.error("positive metadata exceeds 64 KiB")
    metadata = json.loads(metadata_path.read_bytes())
    cases = [("illustration-1",p,False,NEGATIVE_BRIEF) for p in args.negative]
    cases[1] = ("illustration-2",cases[1][1],False,NEGATIVE_BRIEF)
    cases.append(("photographic-positive",args.positive,True,POSITIVE_BRIEF))
    prepared = []
    for name,path,expected,brief in cases:
        path = transport.checked_path(path)
        if not 8 <= path.stat().st_size <= 8 * 1024**2:
            parser.error("each existing PNG must be bounded to 8 MiB")
        raw = path.read_bytes()
        digest = hashlib.sha256(raw).hexdigest()
        if not raw.startswith(b"\x89PNG\r\n\x1a\n"):
            parser.error("calibration controls must be existing PNG files")
        if expected and digest != metadata.get("sha256"):
            parser.error("positive control differs from its provisioned provenance metadata")
        prepared.append((name,raw,digest,expected,brief))
    if len({entry[2] for entry in prepared}) != 3:
        parser.error("three distinct image controls required")
    if list(work.glob("job-*")):
        parser.error("review runtime must be idle before this explicit calibration")
    report = {"schema_version":1, "recorded_at_utc":datetime.now(timezone.utc).isoformat(),
              "real_model_inference":True, "scope":"three local appearance/brief controls; no camera authenticity or identity recognition claim",
              "manifest_sha256":pin, "positive_provenance":{k:metadata[k] for k in ("source","license","evidence","revision") if k in metadata},
              "cases":[], "status":"failed"}
    started = time.monotonic()
    try:
        for name,raw,digest,expected,brief in prepared:
            row = {"case":name,"candidate_sha256":digest,"expected_accepted":expected}
            report["cases"].append(row)
            nonce = secrets.token_hex(32)
            row["nonce_sha256"] = hashlib.sha256(nonce.encode()).hexdigest()
            body,content_type = multipart(raw,brief)
            client = transport.connection(gateway, timeout=args.timeout)
            case_started = time.monotonic()
            try:
                client.request("POST","/v1/reviews",body=body,headers={
                    "Authorization":"Bearer " + owner["api_key"], "Connection":"close", "Content-Type":content_type,
                    transport.MANIFEST:pin,transport.NONCE:nonce})
                response = client.getresponse()
                value = response.read(65537)
                row["http_status"] = response.status
                if len(value) > 65536:
                    raise ValueError("review response exceeded 64 KiB")
                if response.status != 200:
                    row["matched_expected"] = False
                    continue
                proof = (response.getheader(transport.MANIFEST) == pin and response.getheader(transport.NONCE) == nonce and
                         response.getheader("X-Nucleus-Result-SHA256") == hashlib.sha256(value).hexdigest() and
                         response.getheader("X-Candidate-SHA256") == digest and response.getheader("X-Reviewer-Backend") == "llama_cpp_vlm")
                row["proof_valid"] = proof
                verdict = json.loads(value)
                row["verdict"] = verdict
                audit = transport.private_document(work / "last-review-assessment.json")
                audit_bound = audit.get("candidate_sha256") == digest and audit.get("manifest_sha256") == pin and audit.get("status") == "reviewed"
                row["appearance_audit_bound"] = audit_bound
                if audit_bound:
                    row["appearance_assessment"] = audit["appearance_assessment"]
                    row["review_revision"] = audit["review_revision"]
                    row["max_output_tokens_total"] = audit["appearance_max_tokens"] + audit["verdict_max_tokens"]
                correct_medium = audit_bound and ((audit["appearance_assessment"]["appearance"] == "photographic") if expected else (audit["appearance_assessment"]["appearance"] == "illustrated"))
                row["matched_expected"] = bool(proof and correct_medium and verdict.get("accepted") is expected and
                                               (expected or "composition_mismatch" in verdict.get("issues",[])))
            except (OSError,ValueError,KeyError) as error:
                row.update(matched_expected=False,error_class=type(error).__name__)
            finally:
                client.close()
                row["elapsed_seconds"] = round(time.monotonic()-case_started,3)
        report["status"] = "passed" if len(report["cases"]) == 3 and all(row.get("matched_expected") for row in report["cases"]) else "failed"
    finally:
        report["elapsed_seconds"] = round(time.monotonic()-started,3)
        transport.evidence(args.report,report)
    print("Calibration " + report["status"] + ": " + str(sum(row.get("matched_expected",False) for row in report["cases"])) + "/3 controls; private evidence " + str(args.report))
    return 0 if report["status"] == "passed" else 1


if __name__ == "__main__":
    raise SystemExit(main())

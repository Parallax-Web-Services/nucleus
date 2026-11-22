#!/usr/bin/env python3
"""Prepare an explicit local Meld media profile from already provisioned files.

No downloads, model execution, service startup, or application .env changes.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import secrets
import sys
import unicodedata

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from runtimes.meld.manifest import VerifiedManifest

BASELINE_NEGATIVE_PROMPT = 'illustration, cartoon, anime, drawing, painting, vector art, flat shading, posterization, plastic skin, malformed anatomy, text, watermark'

# These are the selected, reviewed Google artifacts, not a publisher-wide
# exception. The explicit CLI acceptance and per-artifact owner note are still
# required; the gateway binds their full provenance as well as these hashes.
GEMMA_DISCLOSURE_HASHES = frozenset({
    '882e8d2db44dc554fb0ea5077cb7e4bc49e7342a1f0da57901c0802ea21a0863',
    '8c0fb064b019a6972856aaae2c7e4792858af3ca4561be2dbf649123ba6c40cb',
})
READOUT_DEPTH_DISCLOSURE_HASHES = frozenset({
    '2fadea2cbb3ec0bd22dc3e925966dcc51dbdbf9ec694d34cb7dc426734ea5d26',
})
READOUT_DISCLOSURE_HASHES = frozenset({
    '649441afc88496808f0f5cb4df7e2b74a78a5ed36f476d1d5eb0c805d8396f10',
    '22846495706b47ac746603a439f02f59531c34fd7789a4f343fa276d7a0f5202',
})


def write_private(path, data):
    if not isinstance(data, bytes):
        data = (json.dumps(data, indent=2) + '\n').encode()
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(descriptor, 'wb') as output:
        output.write(data)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--generation-root', type=Path, required=True)
    parser.add_argument('--review-root', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--generation-catalog', choices=('sdxl-base-1.0-fp16', 'sdxl-readout-guidance', 'sdxl-readout-depth'), default='sdxl-base-1.0-fp16', help='Select a reviewed local generation artifact set; the default remains basic img2img')
    parser.add_argument('--accept-google-published-lineage', action='store_true', help='Explicitly accept the exact selected Google artifacts despite their recorded unpublished training-lineage details')
    parser.add_argument('--review-note', required=True, help='Owner explanation of this specific publisher-disclosure approval; never a model-origin exemption')
    parser.add_argument('--queue-connection', choices=('nucleus-media',), help='Explicit optional durable single-worker queue; application settings remain untouched')
    parser.add_argument('--api-port', type=int, default=19462)
    parser.add_argument('--generation-port', type=int, default=19471)
    parser.add_argument('--review-port', type=int, default=19472)
    args = parser.parse_args()
    if not args.accept_google_published_lineage:
        parser.error('The pinned Gemma manifest has incomplete publisher disclosure; explicit owner acceptance is required. No files were written.')
    if not args.review_note or args.review_note != args.review_note.strip() or len(args.review_note.encode()) > 2000 or any(unicodedata.category(c) == 'Cc' for c in args.review_note):
        parser.error('review-note must be bounded nonempty text without control characters')
    ports = [args.api_port, args.generation_port, args.review_port]
    if len(set(ports)) != 3 or any(not 1 <= port <= 65535 for port in ports):
        parser.error('three distinct ports in 1..65535 are required')
    for path in [args.generation_root, args.review_root, args.output]:
        if not path.is_absolute() or any(parent.is_symlink() for parent in [path, *path.parents]):
            parser.error('model roots and output must be absolute nonsymlink paths')
    # Preserve the caller-spelled symlink checks above, then compare and use
    # canonical paths: lexical containment misses aliases containing '..'.
    args.generation_root = args.generation_root.resolve()
    args.review_root = args.review_root.resolve()
    args.output = args.output.resolve()
    if any(args.output.is_relative_to(model_root) for model_root in [args.generation_root, args.review_root]):
        parser.error('output must be separate from both immutable model roots')
    if args.output.exists():
        parser.error('output already exists; use a new private profile directory')
    specs = [
        ('generation', args.generation_catalog + '.json', args.generation_root),
        ('review', 'gemma-3-4b-it-q4-k-m.json', args.review_root),
    ]
    manifests = {}
    approvals = {}
    disclosure_hashes = GEMMA_DISCLOSURE_HASHES
    if args.generation_catalog in ('sdxl-readout-guidance', 'sdxl-readout-depth'):
        disclosure_hashes = disclosure_hashes | READOUT_DISCLOSURE_HASHES
    if args.generation_catalog == 'sdxl-readout-depth':
        disclosure_hashes = disclosure_hashes | READOUT_DEPTH_DISCLOSURE_HASHES
    for name, filename, model_root in specs:
        catalog = ROOT / 'runtimes/meld/catalog' / filename
        raw = catalog.read_bytes()
        pin = hashlib.sha256(raw).hexdigest()
        manifest = VerifiedManifest.load(catalog.resolve(), model_root, pin)
        manifests[name] = manifest
        for artifact in manifest.document['artifacts']:
            model = artifact['model']
            approval = {'sha256': model['sha256'], 'provenance': model['provenance']}
            if model['provenance'].get('lineage_complete') is False:
                if model['sha256'] not in disclosure_hashes:
                    parser.error('publisher-disclosed exception is not authorized for this exact selected artifact hash')
                approval.update(allow_publisher_disclosed_lineage=True, review_note=args.review_note)
            previous = approvals.get(model['sha256'])
            if previous is not None and previous != approval:
                parser.error('one artifact hash has conflicting model provenance')
            approvals[model['sha256']] = approval
    args.output.mkdir(mode=0o700, parents=True, exist_ok=False)
    tokens = {name: secrets.token_hex(32) for name in ['owner', 'generation', 'review']}
    for name, token in tokens.items():
        write_private(args.output / (name + '-token'), (token + '\n').encode())
    for name, manifest in manifests.items():
        write_private(args.output / (name + '-manifest.json'), manifest.raw)
    owner = {
        'api_key': tokens['owner'], 'approved_models': list(approvals.values()),
        'meld': {'generation_url': 'http://127.0.0.1:' + str(args.generation_port),
                 'generation_token': tokens['generation'],
                 'review_url': 'http://127.0.0.1:' + str(args.review_port),
                 'review_token': tokens['review'],
                 'review_model': manifests['review'].document['model'],
                 'generation_manifest_sha256': manifests['generation'].sha256,
                 'review_manifest_sha256': manifests['review'].sha256,
                 'max_concurrent': 1, 'timeout_seconds': 1800}}
    write_private(args.output / 'owner.json', owner)
    environment = {
        'IMAGE_GENERATOR': 'positronic', 'IMAGE_REVIEW_ENABLED': 'true',
        'IMAGE_REVIEW_DRIVER': 'positronic', 'IMAGE_REVIEW_SOFT_ACCEPT': 'false',
        'NUCLEUS_INFERENCE_BASE_URL': 'http://127.0.0.1:' + str(args.api_port),
        'NUCLEUS_INFERENCE_API_KEY': tokens['owner'],
        'POSITRONIC_IMAGE_TRANSPORT': 'nucleus', 'POSITRONIC_IMAGE_BACKEND': manifests['generation'].document['backend'],
        'POSITRONIC_IMAGE_MODEL': manifests['generation'].document['model'],
        'POSITRONIC_IMAGE_MANIFEST_SHA256': manifests['generation'].sha256,
        'POSITRONIC_IMAGE_TIMEOUT': '1800', 'POSITRONIC_IMAGE_MAX_PIXELS': '262144',
        'POSITRONIC_IMAGE_STEPS': '30', 'POSITRONIC_IMAGE_GUIDANCE_SCALE': '5',
        'IMAGE_REVIEW_MAX_ATTEMPTS': '1',
        # Both Dotenv and systemd EnvironmentFile parse this as a single value.
        'POSITRONIC_IMAGE_NEGATIVE_PROMPT': '"' + BASELINE_NEGATIVE_PROMPT + '"',
        'POSITRONIC_IMAGE_REVIEW_TRANSPORT': 'nucleus', 'POSITRONIC_IMAGE_REVIEW_BACKEND': 'llama_cpp_vlm',
        'POSITRONIC_IMAGE_REVIEW_MODEL': manifests['review'].document['model'],
        'POSITRONIC_IMAGE_REVIEW_MANIFEST_SHA256': manifests['review'].sha256,
        'POSITRONIC_IMAGE_REVIEW_TIMEOUT': '600',
        # Burst pooling can use two generation/review cycles: 2*(1800+600)
        # stays below the worker's 5400s deadline without transport retries.
        'POSITRONIC_IMAGE_REVIEW_RETRY_DELAYS_MS': '""',
    }
    if args.queue_connection is not None:
        environment['IMAGE_GENERATION_QUEUE_CONNECTION'] = args.queue_connection
    write_private(args.output / 'meld.env', ''.join(key + '=' + value + '\n' for key, value in environment.items()).encode())
    write_private(args.output / 'profile.json', {
        'gateway_url': environment['NUCLEUS_INFERENCE_BASE_URL'],
        'generation_root': str(args.generation_root), 'review_root': str(args.review_root),
        'generation_manifest_sha256': manifests['generation'].sha256,
        'review_manifest_sha256': manifests['review'].sha256,
        'generation_model': manifests['generation'].document['model'],
        'generation_backend': manifests['generation'].document['backend'],
        'review_model': manifests['review'].document['model'],
        'shared_lock': str(args.output / 'node-execution.lock'),
        'threads': 2, 'device': 'cpu',
    })
    print('Verified all model files and wrote private profile: ' + str(args.output))
    print('No services started or application environment modified. Credentials remain in private files.')


if __name__ == '__main__':
    main()
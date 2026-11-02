# Meld execution through Nucleus

Ordinary Meld Studio image generation and review now pass a real CPU-only workflow with Modal disabled. The selected backend combines approved SDXL weights with Google's learned Readout appearance guidance, then uses actual Gemma vision review. A case using two photographic references weighted 65/35 passed 42 assertions and human photographic inspection. See the [selected portrait](validation/meld-cpu-portrait-512.png) and [measured evidence](validation/meld-cpu-local.json).

This is the core single-shot/serial-burst path. Advanced anatomy/morphology controls, turnarounds, enhancement, video, 3D and remote image-worker placement remain unavailable in this profile; the UI and request validation enforce that boundary. It is not a claim of exact face identity or trait-percentage preservation.

The model-origin policy is unchanged. China-origin models and all model derivatives are prohibited; unknown or incomplete lineage is denied by default. The operator trusts Google oversight and accepted the published lineage of the exact selected Gemma and Google Research Readout artifacts; that limited exception preserves `lineage_complete: false` and requires matching per-artifact owner approval and a review note. This applies to model weights and their ancestry, not inference software, libraries, operating systems or hardware. See [model provenance policy](MODEL_PROVENANCE_POLICY.md).

## Public API behavior

The owner's inference bearer authentication is required before these routes:

| Request | Result |
| --- | --- |
| `POST /v1/generations` or `/v1/reviews`, no corresponding endpoint | HTTP 503 `workload_unavailable` |
| Configured endpoint without its pinned manifest or owner artifact approvals | HTTP 403 `model_policy_rejected`; no payload read or runtime contact |
| Manifest bytes, identity, complete artifact set or artifact approval fail validation | HTTP 403 before reading the multipart payload or dispatching a model POST |
| Configured runtime cannot supply its authenticated manifest | HTTP 503 `runtime_manifest_unavailable`; no model POST |
| Fully admitted runtime and valid bounded request | One local model POST; success requires matching manifest, nonce, result digest and image/review contract |
| `GET /healthz` | Gateway availability only, not model readiness or approval |
| `/v1/chat/completions` | Separate approved text-inference fleet |

A client alias, backend label, origin header or caller-supplied provenance object cannot override owner approval. Legacy endpoint configuration remains parseable; missing admission material fails closed when execution is requested.

## Runtime manifest and model admission

Each cooperating runtime exposes an authenticated loopback `GET /v1/runtime-manifest`. This is an upstream runtime endpoint, not a new public gateway route. It returns the exact bytes of an operator-provisioned JSON file, with `Content-Type: application/json` and `X-Nucleus-Manifest-SHA256` containing the lowercase SHA-256 of those raw bytes. Whitespace and the final newline affect the pin; do not hash a re-encoded JSON object.

The version-one document contains `schema_version: 1`, `runtime_version`, `backend`, `workload`, `model`, `artifact_set_complete: true`, and an `artifacts` array. Workloads are `image-generation` and `image-review`. Every artifact contains a relative POSIX `path` and a `model` using Nucleus's model metadata/provenance shape. Every model-associated file used by the runtime, including weights, model configuration and tokenizers, must be listed with an exact size, SHA-256 and its owning model's reviewed publisher and lineage disclosure. The model policy does not classify the origins of unrelated runtime software or hardware.

The gateway pins the whole manifest and independently requires every file's hash and provenance to match its owner-controlled `approved_models`. The artifact metadata permits media formats and runtimes; it does not invoke the GGUF-only text catalog validator. Absolute paths, traversal, duplicate files, incomplete artifact sets, missing approval, known blocked artifacts and prohibited ancestry are rejected. An incomplete model lineage additionally requires `lineage_disclosure: "publisher-disclosed"` and its exact owner approval with `allow_publisher_disclosed_lineage: true` plus a bounded nonempty `review_note`. This is separate from `artifact_set_complete`, which must always remain true. Runtime metadata cannot supply its own exception; see the two-artifact scope in the [model policy](MODEL_PROVENANCE_POLICY.md#explicit-publisher-disclosure-exceptions).

Before reading a client multipart body, the gateway inspects the authenticated manifest with a three-second deadline and one-MiB response limit. It checks the raw-byte pin, document schema, intended workload, model identity and every artifact approval. The runtime independently hashes its complete local file set at startup/load and refuses missing, changed or undeclared model files. It loads only local artifacts; runtime startup and model requests must not download weights.

The private owner fleet configuration uses this shape. Replace the placeholders and populate `approved_models` from independent provenance review; the empty example list deliberately grants no execution permission:

```json
{
  "approved_models": [],
  "meld": {
    "generation_url": "http://127.0.0.1:8011",
    "generation_token": "PRIVATE_GENERATION_RUNTIME_TOKEN",
    "generation_manifest_sha256": "EXACT_64_LOWERCASE_HEX_MANIFEST_SHA256",
    "review_url": "http://127.0.0.1:8012",
    "review_token": "PRIVATE_REVIEW_RUNTIME_TOKEN",
    "review_model": "EXACT_REVIEWED_REVIEWER_ALIAS",
    "review_manifest_sha256": "EXACT_64_LOWERCASE_HEX_MANIFEST_SHA256",
    "max_request_bytes": 33554432,
    "max_response_bytes": 67108864,
    "max_concurrent": 1,
    "timeout_seconds": 900
  }
}
```

Keep configuration mode `0600`. Client credentials and the two upstream runtime credentials are distinct. Only the top-level owner `approved_models` entries propagate to the bridge; a runtime cannot approve itself through its manifest.

## Request and artifact binding

The model POST and successful response carry:

- `X-Nucleus-Manifest-SHA256`: the exact operator-pinned manifest digest.
- `X-Nucleus-Request-Nonce`: 64 lowercase hexadecimal characters identifying this request.
- `X-Nucleus-Result-SHA256`: response-only SHA-256 of the exact returned PNG or JSON bytes.

Meld sends its own random nonce and expected manifest pin and verifies all three response values. The gateway checks a supplied client pin against the owner pin and forwards the nonce to the runtime. For older clients that omit a nonce, the gateway generates one. A successful runtime response must echo the same pin and nonce and provide the exact result digest; missing or inconsistent proof fails with HTTP 502. These values bind a response to this request and artifact; they are not durable POST idempotency semantics.

Generation also requires the requested PNG dimensions, non-preview AI flags, the admitted backend/model, a uint32 seed and provenance-record digest. The provenance-record digest is distinct from the new digest of actual result bytes. Review requires the admitted backend/model, a well-formed verdict, known unique issue categories, score 0..100, nonempty summary and SHA-256 of the exact candidate bytes.

Backend identity comes from the pinned manifest. The selected learned-reference generation runtime identifies itself as `sdxl_readout`; the basic experimental img2img variant remains `sdxl_img2img`. The reviewer identifies itself as `llama_cpp_vlm`. Legacy `sdxl_ip_adapter` and `qwen_vllm` labels remain only in explicitly private protocol fixtures and do not authorize their former model weights.

## Local execution and workflow ownership

The reference runtime entry point is `python -m runtimes.meld.server`. Generation uses SDXL with hash-verified Google Research appearance guidance without the prohibited trained IP-Adapter. The deployed strength 1 setting removes direct source-pixel persistence; learned per-source feature losses use the actual requested basis-point weights during four bounded latent updates. These are generic appearance features, not a face-ID encoder. Review uses a separately provisioned Gemma 3 vision model and projector through llama.cpp, configured for CPU execution with four threads and model/projector GPU offload disabled. Exact eligible artifacts, revisions, licenses and reviewed lineage belong in the pinned manifests and approvals; this description is not an approval of arbitrary files with those names.

The runtime accepts explicit manifest/pin, model-root, token-file, memory/reserve, timeout, shared-lock and work-directory options. Each request runs in a bounded child process. Generation and review share an operator-specified local lock so their model processes need not be resident together. Cancellation and timeout must reap the active child before releasing that lock. Source-conditioned generation does not by itself establish identity-preservation or pose-guide quality; these require real Meld acceptance tests.

Meld retains its existing durable `GenerateRender` workflow, render attempts/candidates, visual-review decisions, progress/status and artifact storage. Nucleus supplies admitted model execution; this change does not add another workflow engine. Rejected or unavailable review must continue to preserve candidates under Meld's established behavior. Generation creates artifacts and is dispatched once; an ambiguous failure is not transparently replayed. Review retries remain an explicit read-like client policy.

Only literal loopback HTTP(S) upstreams are permitted. DNS names, remote IPs, URL credentials, path/query destinations, redirects and proxies remain disabled. The gateway forwards only configured runtime tokens and bounded multipart data. HTTP cancellation is necessary but is not proof that an arbitrary upstream engine stopped; the cooperating runtime must enforce child cleanup itself.

This trust boundary matches the existing managed local inference model: an explicitly trusted runtime verifies its own loaded files and reports the pinned state. It is not independent attestation against a malicious runtime or a compromised host. Operator evidence review and complete artifact enumeration remain essential.

Image/review execution is coordinator-local. It is not distributed through the text-worker scheduler. Remote media placement, enhancements, video and 3D are outside this slice.

## Historical blocked models and validation

The former Qwen reviewer is disallowed. The earlier SDXL face pipeline used `h94/IP-Adapter` trained weights linked by the [Tencent IP-Adapter repository](https://github.com/tencent-ailab/IP-Adapter); its [paper](https://arxiv.org/html/2308.06721v1) identifies Tencent AI Lab. A different base diffusion model or display alias does not remove that adapter lineage. Their former CUDA/offload requirements are also distinct from the new reference runtime.

Historical Qwen text measurements remain retained and marked disallowed. They are not approval for present use or a replacement benchmark. No Smol model is required by this runtime path.

`bash scripts/check.sh` verifies formatting, vet and race tests. The manifest protocol suite covers admitted generation/review, policy rejection before payload reads, missing approval, blocked/renamed artifacts, incomplete sets, path traversal, duplicate paths, manifest substitution, forged client pins, redirects, incorrect nonce/result digests and cancellation. Tensor-free fixtures establish transport and admission behavior, not real model output or measured throughput.

The current two-reference CPU run passes actual generation, calibrated review, durable progress, stored output, owner streaming and unrelated-user denial. Earlier illustrated controls and false-positive review verdicts are retained separately as historical failures. Review now assesses visible medium before reading the requested brief and passed two illustrated negatives plus a photographic positive. This small calibration is not an exhaustive reliability or identity benchmark. Optional enhancement, video and 3D require their own admitted runtimes and acceptance runs.

## Runtime dependencies

The selected catalogs are `sdxl-readout-depth.json` and `gemma-3-4b-it-q4-k-m.json` under `runtimes/meld/catalog/`. Together they enumerate 23 model-associated files. Provision those exact files explicitly; the runtime never downloads missing files or remote model code. The local validation reused the existing pinned Python environment read-only, with an isolated Compel overlay. A dedicated CPU environment can use:

```bash
python3 -m venv /absolute/private/meld-runtime-venv
/absolute/private/meld-runtime-venv/bin/pip install torch==2.13.0 torchvision==0.28.0 --index-url https://download.pytorch.org/whl/cpu
/absolute/private/meld-runtime-venv/bin/pip install -r runtimes/meld/requirements.txt
```

The actual tested build was CPU execution using a CUDA-capable PyTorch package; no CUDA execution or offload was used. The tested llama.cpp binary is build 12032, commit `dde879bc4`; its model, operation, KV and projector offload are disabled. Preserve that verified binary's adjacent libraries. Model licenses are distinct from runtime licenses and are recorded in each catalog.

## Tests, diagnostics and limits

```bash
/absolute/private/meld-runtime-venv/bin/python -m unittest discover -s runtimes/meld/tests -p 'test_*.py'
python3 -m unittest discover -s tests -p 'test_configure_meld_media.py'
bash scripts/check.sh
```

The opt-in Meld test is `tests/Feature/NucleusCpuWorkflowTest.php` in the sibling Meld application. Normal runs skip real inference. Set `MELD_REAL_NUCLEUS_TEST=1` and the explicit private endpoint/key, model IDs and manifest pins to execute the ordinary recipe submission, `GenerateRender`, actual review, stored status, owner artifact stream and unrelated-user denial. Optional `MELD_REAL_NUCLEUS_REPORT_PATH` preserves a private report and candidate/output PNG sidecars. Only artifacts listed with hashes in the current report belong to that run; a reused sidecar directory can contain older files. `MELD_REAL_NUCLEUS_STRENGTH` records a validated operator-supplied strength for reporting only: it does not configure the service or independently measure its settings. Set the runtime CLI `--strength` explicitly for an experiment and retain its actual process arguments separately. `MELD_REAL_NUCLEUS_STEPS` controls the requested steps; default eight is a bounded protocol demonstration, not a production image-quality recommendation. Review acceptance must come from the actual model; the test disables soft acceptance and external fallback.

The runtime stores bounded private `last-failure.json`/`.log` records with sanitized engine errors, phase, exit status and sampled resources; `last-success.json` records successful execution measurements. Upload/parse, wall time, memory reserve, process address space, request/result size and concurrency have independent limits. Cancellation reaps the owned engine and any llama child before releasing the shared lock.

`tests/test_meld_media_cancel.py` is separately opt-in via `NUCLEUS_RUN_REAL_MEDIA_CANCEL=1`. It observes an actual owned vision process, disconnects the requesting client and verifies process cleanup and slot/lock release. It starts no normal background benchmark.

The basic `sdxl_img2img` variant remains available for controlled comparisons. The selected `sdxl_readout` portrait profile adds actual learned reference guidance. Advanced UI controls remain unavailable until their separate quality acceptance, even when the underlying API implements an experimental guide algorithm.

## Earlier failed controls

Earlier low-step and synthetic-source runs produced illustrations. The original single-pass reviewer twice accepted illustrated images as photorealistic; that behavior failed human inspection. A later photographic-input control also failed visual review. Those failures remain in [historical control evidence](validation/meld-cpu-controls-2026-11-02.json), with the [illustrated negative](validation/meld-cpu-illustration-negative-512.png).

The current profile uses learned appearance guidance, full denoising at strength 1, explicit photographic negatives and image-only appearance assessment before brief review. Calibration rejected both known illustrations and accepted the known photographic control. Secondary issue labels can still be imperfect; this is not an exhaustive visual-review reliability benchmark.

## Current photographic result and local operation

The final ordinary Meld run used two pinned NASA photographic references, weights 65/35, seed 7, 512×512 output, 30 requested steps and strength 1. It passed **1 real test / 42 assertions**, including actual model review, selected-file integrity, durable progress, authorized owner streaming and unrelated-user 404 denial. Human inspection confirmed a coherent photographic portrait. The [full evidence](validation/meld-cpu-local.json) records source credits, exact catalogs, response proofs, learned feature losses and limitations.

| Measured CPU operation | Result |
| --- | ---: |
| AMD Ryzen 5 5600X / requested threads | 4 |
| SDXL generation | 628.1 seconds |
| Two-stage Gemma review | 122.0 seconds |
| Full ordinary workflow | 750.8 seconds |
| Maximum sampled aggregate runtime RSS | 18.49 GiB |
| New model downloads | 10,351,321,241 bytes of 12,000,000,000 authorized |

RSS is the sampled sum of owned process trees and can count shared pages more than once. The generation 40 GiB address-space cap is separate from observed resident memory. Review has 8 GiB, both preserve 4 GiB host reserve, and a shared lock allows one executing media model in this profile. This was one 64 GB class Linux/WSL node; it does not establish performance on low-memory PCs or distributed image placement.

Use `runtimes/meld/catalog/sdxl-readout-depth.json` for the selected 21-file generation set: the 18 original SDXL files plus Google Readout appearance, pose and depth heads. The separate two-file Gemma catalog is unchanged. Known teacher/conversion limits remain marked publisher-disclosed and require exact per-file owner exceptions; no arbitrary Google-named model is automatically authorized. Google's released generic appearance head is used; the paper's identity-specific head was not released and is not claimed here.

After explicitly provisioning the catalog files, prepare a fresh private profile:

```bash
python3 scripts/configure_meld_media.py \
  --generation-catalog sdxl-readout-depth \
  --generation-root /absolute/models/sdxl-readout-depth \
  --review-root /absolute/models/gemma-3-4b-it \
  --output /absolute/private/meld-profile \
  --queue-connection nucleus-media \
  --accept-google-published-lineage \
  --review-note "Accepted these exact Google-published files using reviewed published lineage; undisclosed checkpoint limits remain recorded."
```

The final profile explicitly uses 30 generation steps, guidance 5, one configured review attempt, generation timeout 1800 seconds, review timeout 600 seconds, empty review-transport retry delays and soft acceptance off. Burst frames can have a two-candidate pool despite max-attempts 1; 2×(1800+600)=4800 seconds fits the 5400-second job/worker deadline and 5460-second reservation lease. The baseline photographic negative prompt is merged before both generation and review and recorded in normal metadata. The UI defaults to 512 and rejects frames beyond the explicit 262144-pixel budget. The selected Readout backend accepts at most four active references: the create form and upload validation cap new Melds at four, and render validation rejects more than four positive weights before queueing. Existing references with zero weight do not count toward that render limit. Other providers retain their existing defaults and ten-reference limit.

`background` dispatch can start multiple frames concurrently and is unsuitable for this one-slot CPU profile. The explicit `nucleus-media` database connection and a single supervised worker preserve normal durable Meld jobs and progress. Real Laravel queue tests confirm serial two-frame dispatch and progress 1/2→2/2 with tensor-free HTTP responses. The real neural quality case above is one ordinary single-shot frame. Startup preflight checks model/pin/key/transport/reviewer settings, sampling/timeout/retry policy, queue schema and core render columns, without printing secrets, migrating or consuming jobs.

Prepare reviewable systemd user units before activation:

```bash
python3 scripts/manage_meld_media.py prepare \
  --profile /absolute/private/meld-profile \
  --python /absolute/meld-runtime-venv/bin/python \
  --llama /absolute/llama-server --nucleus /absolute/nucleus/bin/nucleus \
  --php /usr/bin/php8.5 --meld-app /absolute/meld --strength 1
```

If Compel was installed in an isolated overlay, supply its explicit `--python-dependencies` path. Apply only the selected private `meld.env` settings through normal application configuration, preserve unrelated values and clear stale Laravel config cache. Check the loaded app before starting work:

```bash
/usr/bin/php8.5 /absolute/meld/artisan meld:check-nucleus-profile --env-file=/absolute/private/meld-profile/meld.env
python3 scripts/manage_meld_media.py install --profile /absolute/private/meld-profile
python3 scripts/manage_meld_media.py status --profile /absolute/private/meld-profile
```

Installation revalidates the reviewed plan, checks authenticated local manifests/health, rejects a conflicting managed worker for the same app/queue, and only then enables the selected units. No model request or download is performed by service startup. Logs, tokens and state remain private. User-service persistence follows the Linux user manager's life; the installer does not change linger. Stop only this profile with `manage_meld_media.py stop --profile ...`; worker shutdown requests a graceful drain before the model services stop.

The underlying Readout API implements explicit RGB-pose and grayscale-depth guide formats. Depth maps require the approved depth head and opaque nonflat 8-bit grayscale; RGB photos are not silently treated as depth. Guide algorithm tests are separate from photographic/turnaround quality acceptance, so those advanced UI controls remain unavailable. Real HTTP-disconnect cleanup was measured separately; the original Meld UI has no cancellation action and intentionally preserves background work when leaving the page.

## Activated local profile

The reviewed local Meld environment now selects Nucleus, the exact Readout/Gemma pins, the explicit photographic baseline and durable `nucleus-media` queue. Its previous environment is retained in a private rollback file. Configuration cache was cleared, the actual loaded profile/core/queue schema preflight passed, and all four profile-scoped generation/review/gateway/worker user services were verified active and enabled. Authenticated runtime manifests and gateway health passed after installation. No database migration was needed or performed.

The measured neural result uses the same model catalogs and four-thread CPU execution. Local activation narrows review timeout to 600 seconds and removes transport retries; observed review was 122 seconds. Future package/environment updates require the same pinned-file, loaded-config and health checks. Do not publish the private profile, tokens, environment backup or service logs.

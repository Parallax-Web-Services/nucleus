# Hosted node work

Cloud run sends telemetry alone unless the operator supplies private local runtime
configuration:

    nucleus cloud run --inference /absolute/private/fleet.json

Model installation/removal additionally requires both --model-root DIR and
--allow-model-installs. The FleetConfig remains the local authority for the
absolute binary, threads, context, tokens, hard memory limit, host reserve, and
exact approved_models hashes with reviewed provenance. A remote catalog entry
does not approve itself. An empty installed-model list waits for approved
installation; the existing inference.NewRuntime backend is created lazily.
This client exposes no public listener, fabric service, or local dashboard.

The model directory must be private and contain no symlinks. Downloads require
an exact owner-approved artifact, full 40-character revision, and its matching
HTTPS Hugging Face /resolve/<revision>/...gguf URL. Up to four redirects are
permitted only among the explicit HF/CDN hosts in download.go. No tokens are
sent; Authorization/Cookie headers are stripped on redirects. Private-network
DNS, wrong status/encoding/size/hash, symlinks, and cancellation fail closed.
Checks include effective available RAM, the local memory limit,64 GiB per-file
cap, cache at most twice that budget, and at least1 GiB free disk after download.
Verified files are linked exclusively and revalidated before activation.
The operator FleetConfig is never written. Installed-model state is a private
mode 0600 hosted-models.json overlay in the model root, protected by an exclusive
model-root lock. Operator configuration changes stop further jobs until restart;
operator-pinned model entries cannot be removed remotely.
Removal is limited to a registered hash-named file in the opted-in model root.

## Signed work v1

All paths start /dashboard/api/nodes/<public 64-character hexadecimal node ID>, using the existing
origin/method/path/timestamp/nonce/exact-body-hash Ed25519 signature.

POST /work/lease:
schema_version 1, capabilities {job_types,models,max_concurrent_jobs 1,
approved_model_sha256s,runtime_limits}. Models expose id/revision/sha256, limits
expose memory/context/tokens. Response work:null with retry_after_seconds 5 or a
work object {id,type,lease_id,lease_token,lease_expires_at_ms,deadline_at_ms,payload}.

POST /work/<jobUUID>/renew:
lease_id, lease_token, last_sequence. Response state leased/cancelled and
lease_expires_at_ms;409 on lost ownership.

POST /work/<jobUUID>/events:
lease_id, lease_token, events [{sequence,type,data?}]. Exact duplicate sequences
must be acknowledged idempotently; changed payloads at a sequence conflict.
Response accepted_sequence, state leased/completed/failed/cancelled.

Leases last60 seconds and renew every 10 seconds. Absolute hard deadlines never extend:
120 seconds for synchronous inference, up to 600 seconds for asynchronous
inference, and 20 minutes for install/remove. Loss, expiry, cancellation, revocation,
or subscription failure stops execution/download. Requests are at most64 KiB,
32 events,32 KiB/event, with chunk batching and backpressure. Lost acknowledgment
retries the same event sequence/payload without repeating generation.

Payloads:
- infer: {request:<inference.Request>}; chunk data is inference.Event;
  completed data is {metrics:<inference.Metrics>}.
- install: {model:<inference.Model>,download_url:<immutableHTTPSURL>}.
- remove: {model_id,sha256}.
- install/remove completed: {model:{id,sha256,revision}}.
- failed: bounded generic code, never raw prompts/paths/runtime errors/tokens.

One process lock and one execution slot are permitted per node home. A private
journal is synced with the job ID before execution. Observed jobs never run
again after acknowledgment loss, cancellation, lease loss, restart, or crash.
The journal contains no prompt/output/token. Malformed/full16 MiB state fails
closed and is never silently reset. The service must treat expired inference
as terminal rather than automatically reissuing uncertain generation.

## Verification

    go test -race ./cloud ./hostedworker ./cmd/nucleus

Tests cover signed path/body tamper, limits/redirect refusal, exact event retry,
durable replay rejection, cancel/loss/expiry, process locking, private state,
synthetic artifact tamper/cancel cleanup, immutable URLs, approval-before-network,
and read-only operator configuration and managed overlay. They use synthetic 64-byte fixtures
and fake backends/HTTP; they do not download weights or run a real model.

The separately opted-in cross-language test can also reuse an explicitly
approved existing runtime/model profile for real local acceptance. The observed
Gemma text/context and complete JSON-schema results used context 1024, two
threads, an 8 GiB process budget and a 1 GiB reserve; the structured request used
32 tokens and generated 24. No weights are bundled or downloaded by that test.
The source operator profile stays unchanged. The 8192/256 deployment profile
also passed actual local context/schema generation with the same CPU/memory
budget and a 32-token request. Its complete JSON answer cited the correct
synthetic context document; this is acceptance, not a general benchmark.

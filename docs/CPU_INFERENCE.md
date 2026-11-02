# CPU inference fleet

Nucleus now has an opt-in text inference execution path. Existing pairing, telemetry, resource-map behavior and `zh` membership forwarding remain available. No shell command is accepted through the inference protocol. The initial runtime is a locally provisioned llama.cpp `llama-server` and GGUF model; the core inference runtime performs no automatic downloads. The separate opt-in hosted installer handles explicitly approved installs; see [hosted operation](HOSTED.md).

## Current acceptance status

Model admission now blocks China-origin models and derivatives, including the Qwen model used by the earlier real CPU demonstration. Missing or unknown provenance and models absent from the owner's hash-pinned approvals are denied. See the [model provenance policy](MODEL_PROVENANCE_POLICY.md).

The earlier single-node/two-worker run remains [historical disallowed evidence](validation/cpu-inference-real.json): its real measurements are retained, but it is not an approved model or reproduction target. The exact approved Gemma3 GGUF has now passed real CPU streaming and JSON API requests; see [current text evidence](validation/gemma3-text-cpu-real.json). This is a bounded local acceptance run, separate from the historical Qwen benchmark. The automated fake-runtime suite is a separate protocol test and contains no pretrained weights or claimed inference throughput.

Meld ordinary Studio generation/review has a separate successful real CPU acceptance case. The coordinator-local media gateway now admits generation and review only through exact pinned runtime manifests and independently owner-approved artifacts; missing or prohibited admission material remains denied before payload reads or model dispatch. The reference path uses SDXL img2img generation and a CPU llama.cpp Gemma 3 vision reviewer. The two reviewer artifacts have an explicit owner exception accepting Google's published lineage; their undisclosed training ancestry remains marked incomplete, and configured text runtime admission now honors that exact owner exception after approval, while standalone validation remains strict. See the [exception scope](MODEL_PROVENANCE_POLICY.md#explicit-publisher-disclosure-exceptions). Protocol tests do not establish a real completed Meld job or model quality. CPU text generation alone does not fulfill those workloads. See [Meld execution](MELD_INFERENCE.md).

## Install and provision explicitly

Linux/WSL2, Go 1.23+, and util-linux `prlimit` are required. Build Nucleus with `bash scripts/build.sh`. Install a compatible CPU llama.cpp server into an operator-managed absolute path. The runtime uses the documented server flags including `--device none`, zero GPU layers, a single slot, bounded context/threads, an API key file, a two-thread HTTP pool, and disabled RAM prompt cache. Current upstream reference: [llama.cpp server documentation](https://github.com/ggml-org/llama.cpp/blob/master/tools/server/README.md). Pin your tested binary version; incompatible binaries fail with a bounded startup error.

Review model origin and complete upstream lineage first, record its provenance and owner-pinned approval, then provision an eligible licensed GGUF file on each intended worker through an authorized local transfer. Each configuration records its revision, original source, license, architecture, quantization and SHA-256. The worker checks the file hash and GGUF metadata and calculates a conservative weights plus KV cache requirement. Unsupported architectures/metadata, insufficient memory and inconsistent catalog entries fail before loading. There is no assumption of a shared filesystem.

Create a private file (`chmod 600 /absolute/worker.json`) with this shape. Replace every example value with the real local model's metadata and hash. `required_memory_bytes` must meet the calculated minimum and include operator headroom. The process address-space cap must accommodate mmap, libraries and runtime buffers, not just weights.

```json
{
  "runtime": {
    "binary": "/absolute/llama-server",
    "threads": 2,
    "context_length": 2048,
    "max_tokens": 256,
    "memory_limit_bytes": 4294967296,
    "reserve_memory_bytes": 1073741824,
    "startup_timeout_seconds": 120,
    "models": [
      {
        "id": "my-text-model",
        "revision": "EXACT_REVISION",
        "source": "ORIGINAL_MODEL_SOURCE",
        "license": "ACTUAL_MODEL_LICENSE",
        "architecture": "llama",
        "format": "GGUF",
        "quantization": "Q4_K_M",
        "sha256": "REPLACE_WITH_64_HEX_SHA256",
        "size_bytes": 1000000000,
        "required_memory_bytes": 2147483648,
        "workloads": [
          "text-generation"
        ],
        "runtime": "llama.cpp",
        "path": "/absolute/model.gguf",
        "provenance": {
          "publisher": "REVIEWED_MODEL_PUBLISHER",
          "country": "US",
          "evidence": [
            "https://publisher.example/reviewed-model-card"
          ],
          "lineage_complete": true,
          "base_models": [
            {
              "id": "REVIEWED_UPSTREAM_MODEL",
              "revision": "PINNED_UPSTREAM_REVISION",
              "publisher": "REVIEWED_UPSTREAM_PUBLISHER",
              "country": "US",
              "source": "https://publisher.example/upstream-model",
              "evidence": [
                "https://publisher.example/upstream-model-card"
              ]
            }
          ]
        }
      }
    ]
  },
  "approved_models": [
    {
      "sha256": "REPLACE_WITH_64_HEX_SHA256",
      "provenance": {
        "publisher": "REVIEWED_MODEL_PUBLISHER",
        "country": "US",
        "evidence": [
          "https://publisher.example/reviewed-model-card"
        ],
        "lineage_complete": true,
        "base_models": [
          {
            "id": "REVIEWED_UPSTREAM_MODEL",
            "revision": "PINNED_UPSTREAM_REVISION",
            "publisher": "REVIEWED_UPSTREAM_PUBLISHER",
            "country": "US",
            "source": "https://publisher.example/upstream-model",
            "evidence": [
              "https://publisher.example/upstream-model-card"
            ]
          }
        ]
      }
    }
  ]
}
```

The provenance and country values above are illustrative placeholders, not approval for any real model. Review every upstream model or trained adapter, replace them with actual supported declarations, and keep the installed model's provenance identical to its approval entry. Before copying weights or starting a worker, run `./bin/nucleus validate-models --config /absolute/worker.json`; this performs policy/file validation without inference or downloads.

Thread count is bounded by effective CPU entitlement. Host RAM reserve, cgroup limits, process address-space/RSS cap, context/output limits and one active request per worker protect the workstation. These are cooperating-process controls; complete hostile-code isolation is not provided. Only install trusted runtime binaries and model artifacts.

## Single-node operation

Initialize membership using the existing owner flow, which works on loopback:

```bash
export NUCLEUS_HOME=/absolute/private-owner-state
./bin/nucleus init --name cpu-owner
./bin/nucleus invite --endpoint https://127.0.0.1:9461 --out /absolute/invite.json
export NUCLEUS_INFERENCE_API_KEY="$(python3 -c 'import secrets; print(secrets.token_hex(32))')"
./bin/nucleus run --inference /absolute/worker.json --inference-api 127.0.0.1:9462 --no-open
```

The owner config may contain `runtime` for approved local text execution, `meld` settings for independently admitted coordinator-local image/review runtimes, or neither for a coordinator-only installation. Media endpoints without their manifest pins and artifact approvals remain disabled. The owner requires an API key of at least 32 bytes via the environment or its private config. Application clients use the bearer key; workers use their fabric identity and do not receive this key.

```bash
curl -H "Authorization: Bearer $NUCLEUS_INFERENCE_API_KEY" http://127.0.0.1:9462/v1/models
curl -N -H "Authorization: Bearer $NUCLEUS_INFERENCE_API_KEY" \
  -H 'Content-Type: application/json' http://127.0.0.1:9462/v1/chat/completions \
  -d '{"model":"my-text-model","messages":[{"role":"user","content":"Explain quantization briefly."}],"stream":true,"max_tokens":64}'
```

Nonstreaming chat is supported with `stream:false`. Optional `temperature` and `response_format` are forwarded; tool calls, multimodal content and arbitrary extension fields are rejected. The client sees OpenAI-style model IDs and chunks; `X-Nucleus-Job-ID` identifies the operational record. Closing the request, deleting `/v1/inference/jobs/ID`, deadline expiry, worker disconnection or revocation cancels the job. Running requests are never automatically replayed. A terminal stream failure is emitted as an SSE error followed by `[DONE]`.

## Two trusted workers

Pair each worker using the existing invitation/request/grant flow in the root README. Do not reuse the owner's identity/state on a worker. On the owner, put the exact accepted worker node IDs in its private config:

```json
{
  "allowed_workers": [
    "FIRST_ACCEPTED_NODE_ID",
    "SECOND_ACCEPTED_NODE_ID"
  ],
  "queue_limit": 64,
  "request_timeout_seconds": 300,
  "worker_ttl_seconds": 10,
  "max_cpu_percent": 90,
  "approved_models": [
    {
      "sha256": "REPLACE_WITH_64_HEX_SHA256",
      "provenance": {
        "publisher": "REVIEWED_MODEL_PUBLISHER",
        "country": "US",
        "evidence": [
          "https://publisher.example/reviewed-model-card"
        ],
        "lineage_complete": true,
        "base_models": [
          {
            "id": "REVIEWED_UPSTREAM_MODEL",
            "revision": "PINNED_UPSTREAM_REVISION",
            "publisher": "REVIEWED_UPSTREAM_PUBLISHER",
            "country": "US",
            "source": "https://publisher.example/upstream-model",
            "evidence": [
              "https://publisher.example/upstream-model-card"
            ]
          }
        ]
      }
    }
  ]
}
```

Start the owner with this file and an API key. Start each worker with `NUCLEUS_HOME=/its/private/state nucleus run --inference /its/worker.json --no-open`. Models are provisioned independently on each node. Nodes remain outbound-only and reuse the owner's existing authenticated HTTPS endpoint. No worker inference or RPC port is exposed on the LAN.

For actual machines use the owner's reachable RFC1918 address in the invitation and bind that exact address. The application API remains owner-loopback; run Meld there or use an explicitly managed authenticated tunnel. No new internet overlay or public listener is introduced.

`GET /v1/inference/status` returns authenticated capabilities, online/offline state, model availability, active requests, queue history and measurements. Rejected submissions explain per-node placement exclusions. The scheduler applies membership and the operator allowlist, model identity, RAM budget, CPU load, requested `nucleus_allowed_nodes`, warm state and applicable measured throughput. Busy eligible nodes queue within the configured bound. A queued request may move before its first lease if its worker becomes ineligible; an executed request fails without replay. Network RTT is not currently measured or ranked.

```bash
bash scripts/build.sh
python3 tests/test_inference_fleet.py
bash scripts/check.sh
python3 tests/test_first_contact.py
```

Two processes on one computer demonstrate protocol concurrency, not two machines' aggregate capacity. Multiple workers on one physical host need separate operator memory/CPU budgets; the scheduler does not deduplicate host installations.

## Historical real-model run — disallowed by current policy

The following measurements describe an earlier Qwen execution. Current provenance policy forbids loading or reproducing this model or its derivatives. Recorded values are preserved as historical evidence; they are not a recommendation or a current approved-model acceptance result.

On November 1, 2026 (US Eastern; the evidence measurement timestamp is UTC), the authorized run used an AMD Ryzen 5 5600X host with 6 physical/12 logical cores, WSL2, and 67,377,909,760 bytes of visible RAM. Inventory detected accelerator devices with unverified compatibility; all measured execution explicitly used `--device none`, zero GPU layers, and disabled KV/operation offload.

The model was [official Qwen2.5-0.5B-Instruct Q4_K_M](https://huggingface.co/Qwen/Qwen2.5-0.5B-Instruct-GGUF/blob/9217f5db79a29953eb74d5343926648285ec7e67/qwen2.5-0.5b-instruct-q4_k_m.gguf), revision `9217f5db79a29953eb74d5343926648285ec7e67`, Apache-2.0, 491,400,032 bytes (491.4 MB, within the authorized 500 MB limit). Its verified SHA-256 is `74a4da8c9fdbcd15bd1f6d01d621410d31c6fc00986f5eb687824e7b93d7a9db`. llama.cpp build 12032 (`dde879bc4`) ran with 2 generation threads, 2 HTTP threads, context 1024 and a 64-token output cap; each process had a 4 GiB address-space cap and a 1 GiB host RAM reserve.

| Actual run | Prompt tokens/s | Generation tokens/s | Initialization ms | Client first-content ms |
| --- | ---: | ---: | ---: | ---: |
| Single node, process cold | 167.935 | 55.518 | 1110.191 | 1493.866 |
| Single node, model warm | 166.804 | 58.057 | 0.000 | 337.079 |
| Explicit benchmark | 149.894 | 47.995 | 1260.993 | Not measured |
| Concurrent worker-b, cold | 147.277 | 50.235 | 1366.309 | 1849.775 |
| Concurrent worker-a, warm | 166.428 | 56.359 | 0.000 | 307.237 |

The explicit benchmark recorded 45 prompt tokens, 64 generated tokens and approximately 578.7 MiB of process peak RSS. Two independent requests overlapped in their recorded running-job intervals and executed on distinct trusted workers; real cancellation and subsequent exclusion of a stopped worker also passed. These workers were separate processes on one physical host. This establishes working request distribution and measured CPU execution, without a two-machine scaling or production latency claim.

Phase speeds come directly from llama.cpp timings. Initialization includes hash revalidation and readiness work, and filesystem caches were not cleared. Runtime elapsed time includes initialization and worker event delivery but excludes queueing and the full client path. Client first-content latency includes those effects and measures the first nonempty content chunk. RSS is the runtime process's lifetime high-water value, including startup and potentially earlier warm requests. The fixed benign completion hit its 64-token cap and contains an imprecise reference to training; this was execution validation, not a quality or factual-accuracy benchmark.

Do not reproduce the historical Qwen run. After a different model and its full lineage have passed review and been explicitly authorized for local provisioning, the model-neutral helper can validate an eligible private catalog and run a new demonstration:

```bash
python3 scripts/demo_cpu_inference.py \
  --config /absolute/approved-worker.json \
  --model my-text-model \
  --report .runtime/approved-cpu-inference-report.json
```

The helper first calls `nucleus validate-models`, before copying weights. It propagates the reviewed `approved_models` entries to each isolated node and performs actual CPU work only when explicitly invoked. It creates isolated private fabric state, makes separate local weight copies, runs the bounded single-node/two-worker checks and preserves a private report. It never downloads model weights or runtimes. Normal `nucleus run` does not run this benchmark. Run one benchmark at a time outside active serving; benchmark persistence retains the latest matching model/settings record rather than a complete historical performance database.

## Explicit real benchmarks

Run only when active benchmarking is authorized and the host can spare its configured budget:

```bash
NUCLEUS_HOME=/absolute/worker-state ./bin/nucleus benchmark \
  --config /absolute/worker.json --model my-text-model --max-tokens 64
```

This command loads the real configured model and records initialization latency, prompt/generation tokens and phase speeds, elapsed time, sampled process-lifetime peak RSS, runtime version and execution settings to the private `inference-benchmarks.json` in that node's state directory. If the backend omits measured phase timings, the command fails and saves no claimed throughput. Restart a worker to advertise newly saved benchmark measurements. Normal `run` never initiates active benchmarks. Benchmarks are matched to model identity and settings; ordinary jobs also keep available measured metrics in bounded memory.

## Architecture and remaining limits

`fabric` owns durable identity and TLS; Positronic still owns telemetry and per-request membership checks. Its optional typed-service hook dispatches inference control only after authentication. `inference` owns catalog validation, runtime interface, one-model resident runtime, worker policies, bounded queue, reservations and API. `zh` remains a membership/shell client and need not know the physical worker that executes an inference request.

The worker leases one job, streams bounded JSON events over outbound mTLS and checks cancellation independently. Node load remains fresh during initialization and generation. The coordinator retains at most 256 completed operational records; prompts and responses are not persisted. Catalog configuration and real benchmark records are durable. Jobs and reservations are volatile; coordinator restart fails existing client connections and requires fresh worker registration.

Only text generation is implemented as a distributed workload. Backend interfaces can later support embeddings/reranking, speech and accelerator runtimes. Meld image/review execution uses a separate coordinator-local, manifest-admitted path with trusted cooperating runtimes; it is not scheduled across remote image workers. Its admission/transport tests and [new real CPU media evidence](validation/meld-cpu-local.json) distinguish execution from visual acceptance. Approved SDXL generation and explicitly approved Gemma review now execute locally with Modal disabled, with a successful two-reference photographic acceptance case. Exact identity/pose parity is not claimed, and unsupported advanced controls remain unavailable. Video, 3D, training/fine-tuning and model partitioning are not implemented. Full OpenAI API compatibility, tenant-specific credentials/placement rules, model provisioning automation, CPU time quotas beyond thread entitlement, multi-coordinator durability, certified runtime-version compatibility and physical-machine benchmarks remain engineering work.

The approved Gemma text acceptance run has passed locally. The next deployment milestone is the same test across two physical machines. Meld now has a successful ordinary two-reference photographic CPU run, actual calibrated review, stored artifact/progress/access evidence and a successful client-disconnect cleanup check. Google learned appearance guidance replaces the forbidden adapter for the selected portrait profile. Further identity/pose and advanced-workload quality evaluation remains distinct from this validated core path. See [Meld execution and local CPU setup](MELD_INFERENCE.md). The local Meld Studio generation/review profile is now activated on Nucleus after that end-to-end workflow passed without Modal credentials or traffic. Unsupported advanced workloads remain outside this replacement.

### Verified Linux x86_64 runtime binary

The runtime flags were checked with the official [llama.cpp b12032 CPU archive](https://github.com/ggml-org/llama.cpp/releases/download/b12032/llama-b12032-bin-ubuntu-x64.tar.gz). The binary reports `0.8.0-dev (build 12032, commit dde879bc4)`, built with GNU 11.4.0 for Linux x86_64. Both `--version` and `--help` succeeded, and the configured execution flags were verified. That initial flag probe did not load a model; the subsequent real-model run above additionally verified CPU-only subprocess settings and the bounded HTTP pool.

Install this pinned build inside the ignored workspace tools directory:

```bash
mkdir -p .tools/llama
curl -fL https://github.com/ggml-org/llama.cpp/releases/download/b12032/llama-b12032-bin-ubuntu-x64.tar.gz -o .tools/llama-b12032-bin-ubuntu-x64.tar.gz
printf '%s\n' '9f10432ca3f66ef003a7a540aaffb9da0acadaefd05404521b9ab7a2436af304  .tools/llama-b12032-bin-ubuntu-x64.tar.gz' | sha256sum -c -
tar -xzf .tools/llama-b12032-bin-ubuntu-x64.tar.gz -C .tools/llama
.tools/llama/llama-b12032/llama-server --version
```

Set `runtime.binary` to the absolute path ending in `.tools/llama/llama-b12032/llama-server`. The archive is 22,886,629 bytes; its SHA-256 above was verified before extraction in this workspace. Install `prlimit` from the operating system's util-linux package if it is absent. Keep the archive's adjacent shared libraries with the executable. CPU instruction compatibility is checked when the local executable runs; use a compatible source build on other CPU architectures.

The initial binary-only verification was followed by the earlier authorized Qwen download and historical measurements above; that model is now disallowed. The runtime binary itself is outside the model-origin restriction. Future model execution requires reviewed eligible provenance, owner-pinned approval, and explicit local provisioning before any opt-in benchmark. Normal private-cluster operation has no model download or external cloud dependency.


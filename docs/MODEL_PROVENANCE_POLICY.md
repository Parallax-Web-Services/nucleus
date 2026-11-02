# Model provenance policy

Nucleus blocks China-origin models and model derivatives under the operator's current policy. This restriction applies to model weights and their upstream lineage. It does not ban inference runtimes, software libraries, GGUF architecture support, CPUs, GPUs, or other hardware.

## Admission and approval

Every executable model requires a reviewed provenance declaration and a matching SHA-256 entry in the owner's `approved_models` catalog. Missing or unknown provenance fails closed by default. A publisher's incomplete public disclosure requires a separately recorded, exact-artifact owner exception as described below. Countries `CN`, `HK`, and `MO` are denied. A known blocked publisher, model family, upstream source, or retained denied artifact remains blocked even if a configuration claims another country.

The model's `provenance` object contains:

- `publisher`: the publisher responsible for the supplied model.
- `country`: the reviewed two-letter origin code.
- `evidence`: source URLs supporting the declaration.
- `lineage_complete`: whether the complete upstream model ancestry is known and reviewed. Never set it to true to conceal unpublished teachers or training components.
- `lineage_disclosure`: optional `publisher-disclosed` for an explicitly incomplete published lineage; this field alone grants no permission.
- `base_models`: the model's upstream weights, teachers, merged models, and other model components, each with `id`, `revision`, `publisher`, `country`, `source`, and `evidence`; `sha256` may also be recorded.

Quantization, GGUF conversion, fine-tuning, merging, distillation, adapter packaging, renaming, and redistribution do not erase upstream origin. A permitted base diffusion model paired with a blocked trained adapter is still an ineligible model bundle. Evidence should cover every model component, including image encoders and adapters when used.

The owner pins the exact approved artifact hash and provenance. A trusted worker cannot approve its own replacement model merely by advertising a familiar ID. Supply the same reviewed `approved_models` entries to its local configuration. A coordinator without a local runtime still needs approvals for models offered by workers.

Illustrative shape only; these placeholder values are not an approval for real weights:

```json
{
  "approved_models": [{
    "sha256": "ACTUAL_64_HEX_ARTIFACT_SHA256",
    "provenance": {
      "publisher": "REVIEWED_MODEL_PUBLISHER",
      "country": "US",
      "evidence": ["https://publisher.example/reviewed-model-card"],
      "lineage_complete": true,
      "base_models": [{
        "id": "REVIEWED_UPSTREAM_MODEL",
        "revision": "PINNED_UPSTREAM_REVISION",
        "publisher": "REVIEWED_UPSTREAM_PUBLISHER",
        "country": "US",
        "source": "https://publisher.example/upstream-model",
        "evidence": ["https://publisher.example/upstream-model-card"]
      }]
    }
  }]
}
```

The corresponding installed model must carry the identical `provenance` object. Replace the illustrative country codes with the actual reviewed origins; an allowed country code is not evidence by itself. Existing configurations without this metadata require review before they can execute.

## Explicit publisher-disclosure exceptions

An owner may explicitly accept the publisher's disclosed lineage for one exact artifact without claiming that unpublished teacher or reward-model checkpoints are known. Record `lineage_complete: false`, `lineage_disclosure: "publisher-disclosed"`, the published ancestors that are actually supported by evidence, and their accurate release identities. Keep unknown checkpoint identities absent rather than inventing IDs or presenting a paper version as a checkpoint revision.

Its matching owner approval must additionally contain `allow_publisher_disclosed_lineage: true` and a nonempty `review_note` of at most 2,000 bytes explaining the specific authorization and disclosure limits. The flag defaults to false. Approval still requires the exact artifact SHA-256 and identical reviewed provenance; neither the runtime's manifest nor a model alias can grant an exception. Missing approval, a different artifact hash or changed provenance remains denied. Blocked publisher identities, jurisdictions, artifact hashes and declared ancestors are always rejected. Unknown origins for declared ancestors remain denied. This option does not create a publisher-wide exemption.

On 2026-11-02, the operator explicitly accepted Google's published lineage for the selected Gemma 3 vision reviewer despite undisclosed teacher/reward checkpoint IDs and conversion-source revision limits. The original approval covered these two reviewed artifacts; the same exact GGUF is now admitted for text execution through approval-aware validation:

| Artifact | SHA-256 |
| --- | --- |
| `gemma-3-4b-it-Q4_K_M.gguf` | `882e8d2db44dc554fb0ea5077cb7e4bc49e7342a1f0da57901c0802ea21a0863` |
| `mmproj-model-f16.gguf` | `8c0fb064b019a6972856aaae2c7e4792858af3ca4561be2dbf649123ba6c40cb` |

The [Gemma 3 technical report](https://arxiv.org/html/2503.19786v1) describes distillation, its SigLIP vision encoder and learned reward models without publishing all upstream checkpoint identities. The exception records that disclosure limit; it does not establish complete ancestry or authorize other Gemma files. The media gateway's `ApproveModel` admission consumes the exact owner exception. Standalone provenance/model validation remains strict. Configured text preflight, initial runtime construction and lazy reload require exact owner approval before file access, then perform the unchanged GGUF/hash/size/context/memory checks; this preserves the scoped exception without weakening integrity validation. Other model approvals continue to require complete reviewed lineage unless separately and explicitly authorized.

The operator subsequently clarified that the concern is supply-chain security and government influence, and that Google's oversight is trusted. On that basis, the selected Google Research Readout heads also have exact-hash publisher-disclosure approvals, while unpublished teacher/conversion checkpoint identities remain unknown:

| Google Research artifact | SHA-256 |
| --- | --- |
| `readout_sdxl_drag_appearance.pt` | `649441afc88496808f0f5cb4df7e2b74a78a5ed36f476d1d5eb0c805d8396f10` |
| `readout_sdxl_spatial_pose.pt` | `22846495706b47ac746603a439f02f59531c34fd7789a4f343fa276d7a0f5202` |
| `readout_sdxl_spatial_depth.pt` | `2fadea2cbb3ec0bd22dc3e925966dcc51dbdbf9ec694d34cb7dc426734ea5d26` |

The [official Google Research implementation](https://github.com/google-research/readout_guidance) links the released weights and describes their training. The appearance head uses SDXL/SDEdit and published BLIP captions; its `dreamsim` experiment tag refers to a reused loss formula, not evidence of a DreamSim teacher. The pose head's OpenPose supervision traces to the original CMU weights; wrapper conversion alone does not establish Chinese-trained ancestry. The depth head uses Intel/ISL DPT-Hybrid MiDaS supervision, whose published initialization traces to Google's R50+ViT ImageNet weights. Exact missing annotation/teacher snapshots are recorded as disclosure limits. Neither model names, author ethnicity nor software authorship substitutes for reviewing learned-weight ancestry.

These approvals do not authorize arbitrary Google-named files, trained Tencent adapters, Qwen derivatives or another artifact with changed provenance. The catalogs preserve the exact published files and declared ancestors; runtime model requests never fetch missing components or custom model code.

Validate the private catalog before provisioning or serving:

```bash
./bin/nucleus validate-models --config /absolute/private-worker.json
```

This preflight checks policy, configured hashes, GGUF metadata, and memory requirements. It does not start inference, probe the runtime executable, download weights, or copy them. The optional real-demo helper runs this preflight before making its private weight copies and propagates reviewed approvals to its generated node configurations. Normal execution and worker admission also enforce the policy.

## Disallowed artifacts found in this workspace

The prior real CPU demonstration used Qwen2.5-0.5B-Instruct Q4_K_M, SHA-256 `74a4da8c9fdbcd15bd1f6d01d621410d31c6fc00986f5eb687824e7b93d7a9db`. Its [official model card](https://huggingface.co/Qwen/Qwen2.5-0.5B-Instruct-GGUF) identifies the GGUF model as part of Qwen; the [official Qwen organization](https://github.com/QwenLM) identifies the team at Alibaba Cloud. This model and its derivatives are blocked.

The previous Meld image path also used trained IP-Adapter weights. The [official Tencent AI Lab repository](https://github.com/tencent-ailab/IP-Adapter) links the `h94/IP-Adapter` weight repository, and the [paper](https://arxiv.org/html/2308.06721v1) identifies Tencent AI Lab as the author affiliation. [Tencent's company page](https://www.tencent.com/who-we-are/) identifies its headquarters in Shenzhen, China. The Qwen reviewer and this adapter therefore both need eligible replacements before that Meld pipeline can satisfy the policy. Meld generation/review routes now have an admitted manifest path, while remaining default deny. Unconfigured routes return 503; missing pins or owner approvals return 403 without reading payloads or contacting a runtime. Configured approved paths first inspect an authenticated loopback manifest, verify its exact operator-pinned raw-byte digest and every artifact approval, then permit one bounded model POST. Invalid or prohibited components fail before multipart reads or model dispatch. See [Meld execution](MELD_INFERENCE.md).

The public [CPU demonstration evidence](validation/cpu-inference-real.json) is marked `historical_disallowed`. Its recorded measurements remain unchanged; they describe a past execution and do not authorize present use or reproduction. Private original evidence and quarantined weight files are retained. They must not be loaded, benchmarked, or redistributed as approved models. Replacement artifacts require their own provenance review and pinned approval.

A `qwen2` or `qwen3` GGUF architecture label describes tensor/runtime compatibility; it is not sufficient evidence of a model's origin. Compatibility code remains available while actual prohibited lineage is rejected. Likewise, legacy backend labels such as `qwen_vllm` and `sdxl_ip_adapter` are software contracts; changing their labels cannot make blocked weights eligible.

## Limits and next verification

Provenance declarations and evidence links need manual review. Nucleus does not independently prove publisher location, fetch and authenticate every source document, or infer undisclosed teacher or upstream weights from a GGUF file. The known-family checks are an additional guard, not an exhaustive worldwide model registry. Renamed artifacts require the same lineage review and owner-pinned approval.

Protocol fixtures contain generated metadata and no pretrained model weights. Their explicitly fictional test provenance is for automated tests only and is not evidence that a real model is eligible. The earlier Qwen measurements remain historical and disallowed. New eligible SDXL and explicitly approved Gemma CPU execution is recorded separately in [local media validation](validation/meld-cpu-local.json), including failed controls, the successful two-reference photographic workflow and transport-scoped real cancellation. The approved Gemma text result is recorded separately in [text validation](validation/gemma3-text-cpu-real.json). Provisioning or model execution alone does not establish a successful quality acceptance run or full Modal replacement.

## Media manifest trust boundary

A media manifest enumerates the exact model-associated weights, configuration and tokenizer files, their owning model provenance and their artifact hashes. The gateway pins the whole raw manifest document and requires a matching owner approval for every file; a self-reported country, alias or backend name cannot supply approval. Underlying software and hardware origins remain outside this policy.

The private cooperating runtime independently verifies local files before model load, refuses implicit downloads and undeclared artifacts, and binds responses to the manifest digest, request nonce and actual result digest. This is a trusted-runtime integrity contract, not independent or adversarial attestation. A compromised host or dishonest runtime can misreport its loaded state; the implementation does not claim to infer undisclosed ancestry or isolate malicious model-serving software. Source evidence, lineage declarations and any explicit publisher-disclosure exceptions still require operator review.

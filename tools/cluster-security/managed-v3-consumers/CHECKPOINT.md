# Reviewed managed-v3 consumer source

This is the exact reviewed source packet retained after the managed coordinator handoff. The coordinator is supervised, but monitoring admission and retirement of the four paused legacy controller parents await explicit approval. This checkpoint does not establish live backup, restore, TLS renewal, worker admission, or production readiness.

The two source files change only the reviewed observer dependency pins and fixed Bridge path. The existing four-file backup wire manifest remains unchanged. The original backup checkpoint is retained separately under `../backup/` for review history; its older observer binding is not the current managed-v3 consumer.

Root independently checked all packet manifest entries, reversed the declared substitutions to reproduce both original source files byte for byte and by AST, and ran all 69 orchestrator and 14 Alpha offline tests successfully. The unchanged guest's 27 tests were not repeated in this check. No production helper main, network connection, staging, key generation, backup or restore ran.

The packet preserves its original absolute scratch import paths and source metadata. Its tests depend on external public fixtures named in `alpha-map.json`; it is not a portable standalone test distribution or an installer. Do not populate those paths on production hosts or infer runtime file custody from Git modes. `README-review.md` states the separate operational gates, caller-held checkpoint contract and bounded publisher lifetime requirement. No private plan, overlay, profile, token, key or host capture is included.

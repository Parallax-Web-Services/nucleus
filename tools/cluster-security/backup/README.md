# NEBULA initial backup source checkpoint

This directory retains reviewed source and offline fixtures. It is not a public installer, an admitted operation plan, or evidence that a backup or restore has run. No live keys, host profiles, admission records, runtime state, ciphertext, snapshots, kubeconfigs, logs, or operation receipts are included.

The scripts retain their reviewed fixed role/path bindings. They are not a generic or relocatable Kubernetes backup product. They cover an initial two-target encrypted backup and isolated offline etcd restore check; they do not establish a restored Kubernetes API, application recovery, HA, or ARM64 support.

## Retained bytes and manifests

- `source/` holds the five accepted helpers unchanged.
- `source/manifest.json` preserves the existing schema-1 wire contract: exactly common, envelope policy, guest, and target. The orchestrator is intentionally excluded because its accepted `NAMES` contract rejects extra entries.
- `tests/` retains the six exact public test files. `tests/reference/` holds the accepted public managed-health bridge needed by the orchestrator fixtures. It contains no admission overlay or health observation.
- `SOURCE_MANIFEST.json` describes this outer source checkpoint. `SOURCE_SHA256SUMS` binds every retained file except itself. Neither outer file is a runtime wire manifest.

Verify the checkpoint without importing or executing a helper:

```sh
sha256sum --check SOURCE_SHA256SUMS
```

The Git attribute for `tools/cluster-security/**` preserves these bytes. Repository file modes are source modes, not runtime custody: the separate executors still require their approved private manifest/plan and source ownership/modes. Copying this directory or knowing its hashes admits no operation. No new project license is selected here.

## Required caller-held checkpoint

Every orchestrator invocation requires `--expected-head-sha256` and `--private-result` in addition to its existing reviewed manifest, operation, state, admitted-overlay, step, and execution arguments.

| Input | Contract |
| --- | --- |
| `--expected-head-sha256` | Exactly `none` or 64 lowercase hexadecimal characters. `none` is valid only for an empty accepted chain with no pending attempt. |
| Checkpoint digest | SHA-256 of `bytes_json(encode_record(last_known_complete_record))`: filename, all nine metadata identity fields, raw-content SHA-256, and read limit. The same bytes on a replacement inode are a different checkpoint. |
| Trusted origin | The previous successful invocation's known exclusive post-state. Retain its full head record and digest privately outside the mutable operation directory. Never derive the expected value by rereading current ledger files. |
| `--private-result` | A new canonical path outside operation state, beneath a preexisting actor-owned 0700 parent with no symlink ancestors. The helper creates an exclusive 0600 result and never overwrites or adopts an existing path. |
| Success | Consume the private result only after process exit zero and a passed status. Full `head_record` and `head_sha256` appear only in that private result. Standard output contains only safe status, step, and result path. Do not expose the private checkpoint through public tool output or a journal. |
| Failure | A failed, partial, or timed-out invocation provides no new accepted checkpoint. Preserve all files and stop for review. Lost result persistence after a completed step also requires explicit manual review; do not reconstruct a replacement expected head from the ledger. |
| Read-only checks | Require the same caller-held checkpoint and preserve it. A pending attempt blocks checks as well as mutations. |

There is one typed remote step per invocation, no aggregate loop or automatic retry. The next mutating step must be the exact next entry in the accepted sequence. Existing exclusive phase/journal guards remain authoritative.

## Managed health and remaining lifetime

Operational execution remains gated on separately accepted managed-owner and server-overlay admission. An absent or stale admission must fail closed. Backup must never admit an overlay, rewrite the original plan, start a proof writer, fall back to a retired legacy proof, or construct the original 6b `Lifecycle` directly. It must use the accepted bridge's `Bridge(...).lifecycle(...)`, preserving all original LOCAL Alpha assertions while replacing only external-health evidence.

For **each** future invocation, the operator must:

1. Start a fresh, accepted, bounded 600-second typed publisher only after its owner/overlay admission has been reviewed.
2. Verify that exact owned publisher's PID, start identity, source, overlay, and fresh managed proof. Independently prove enough actual remaining process lifetime for the complete invocation and its cleanup. A health payload's roughly 10-second freshness is not evidence that the publisher has 510 seconds left.
3. Invoke exactly one approved backup step immediately. The whole invocation accepts at most 510 seconds; guard/action limits are 45/420 seconds, with 25 seconds reserved in command timeouts for owned cleanup.
4. Stop only that owned publisher cleanly before another fresh cycle. Preserve unrelated processes and writers. An expired, missing, replaced, or uncertain writer is a refusal, not permission to extend, restart, or adopt one automatically.

This checkpoint supplies no publisher lifecycle admission or runtime acceptance receipt. Private per-role plans, selected SSH identity/known-host bindings, target capacity/reserves, pinned tool provenance, restore memory preconditions, and one-use phase controls require their separate review. Both SSH hops explicitly disable sharing; the outer hop retains existing identity/alias/known-host resolution, and the nested guest hop retains its explicit pinned identity and known-host file. No shared master is started, adopted, or stopped by these settings.

## Offline fixture evidence and limits

The exact retained test coverage is 187 cases: envelope policy 21, common 30, guest 20, target 44, wire 3, and orchestrator 69. The accepted helpers and these byte pins passed their reviewed offline suites; the final orchestrator suite was independently rerun after the checkpoint and SSH-control fixes. Retention does not claim a new live crypto, backup, or restore acceptance.

These are not all fake-only tests. They exercise real local processes, held file descriptors, permissions, locks, process groups and resource limits. The common suite also checks a 10-GiB read-only file-backed virtual mapping without dereferencing it and rejects a 3-GiB anonymous allocation. Its restore profile requires at least 6 GiB current `MemAvailable`. Guest/target cryptographic and etcd operations in the fixtures are simulated; the SSH configuration check uses `ssh -G` with a synthetic configuration and makes no connection.

The unchanged fixtures require 64-bit Linux, Python 3, `/proc`, `waitid`/`WNOWAIT`, fork/process groups, `RLIMIT_AS`/`RLIMIT_DATA`, root ownership fixtures including numeric UID/GID 1000, existing basic POSIX tools, and local OpenSSH. They retain literal `/tmp` imports and use private `/root` and `/run` fixtures. No portable test runner is supplied in this source checkpoint.

Use only a separately reviewed isolated Linux-root lab to materialize the twelve whitelisted Python files under its private `/tmp` (1777, sources root-owned 0644) and run the six explicit test files. Do not overwrite live-host `/tmp` files, create aliases there, use discovery that misses hyphenated filenames, install packages, or execute any helper main as part of source retention. The real private plans and the original foundation/cluster runtime helpers remain external dependencies; their presence and admission must never be inferred from this source tree.

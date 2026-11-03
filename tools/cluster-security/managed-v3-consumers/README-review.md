# Managed v3 consumer source candidate

This packet contains source-only successors to the accepted backup orchestrator (20c1c178) and Alpha kubelet renewal controller (9952511a). It is not installed, admitted, or operationally accepted. The current v3 monitor admission is not yet accepted.

## Exact changes

- `source/nebula-backup-orchestrator.py`: Bridge dc5327 to b8e05a pin in the outer controller and embedded BROKER; the BROKER loads its Bridge from `/usr/local/lib/parallax-nebula-managed-v3/alpha-managed-health-bridge.py`.
- `source/nebula-kubelet-renewal-alpha.py`: Bridge dc5327 to b8e05a, foundation 2c2caf to be3906, and the same new fixed Bridge path. Its existing required `--readonly-source` must name `/usr/local/lib/parallax-nebula-managed-v3/alpha-managed-foundation-readonly.py` during a later reviewed invocation. No new argument or loader behavior was added.
- Copied tests redirect only their imports. They exercise the new candidates and the accepted v3 Bridge/foundation references; original tests remain unchanged. The Alpha test fixture still depends on the explicitly pinned public fixture `/tmp/nebula-managed-v3-source-egkc2mqv/test_foundation.py` and its existing public dependencies, listed in `alpha-map.json`. This packet is not a portable standalone test distribution.

The inverse literal maps reproduce both original files byte for byte and with identical ASTs, including the decoded BROKER. Checkpoint, private-result custody, SSH flags, deadlines, crypto, original local assertions, lock handling, and managed Bridge construction are unchanged. No original 6b constructor path was introduced. Backup `NAMES` and its schema-1 four-file wire manifest remain exact; the orchestrator is still outside that manifest. Only an outer source/artifact binding for the new consumer changes.

## Verification

The copied orchestrator's 69 offline fixtures and Alpha's 14 offline fixtures passed as Linux root (83 total). They use synthetic fixtures and fake remote execution. The local synthetic `ssh -G` case makes no network request. No operational helper invocation, host query, key generation, backup, restore, guest operation, staging, or network call ran. Guest 8dad25eb and its 27 tests were not changed; those tests were not rerun.

The accepted original consumer files, their tests, the backup four helpers, Guest 8dad25eb, all eight frozen v3 sources and their original sources were rehashed unchanged. `static-proof.json`, the literal maps and narrow diffs record these checks.

## Execution gate

Do not execute these consumers until Root reviews this packet and separately accepts the managed-v3 graph and its current monitor/overlay admission. An explicit private admitted overlay is mandatory. Consumers must never admit an overlay, overwrite a plan, start a publisher, fall back to the legacy proof, or weaken original local Alpha guards.

For each future backup invocation Root must start a fresh accepted, owned bounded typed publisher, verify its PID/start/source/overlay and actual remaining lifetime, verify fresh managed proof, then immediately invoke ONE fixed step under the unchanged whole-invocation 510-second deadline. The 600-second writer lifecycle must cover that entire invocation; a proof's 10-second freshness is not evidence of remaining publisher runtime. Stop only that owned writer before the next fresh cycle. These lifecycle commands/receipts still require separate review and acceptance.

The caller must provide the original required `--expected-head-sha256` and an exclusive `--private-result` outside operation state, retain the known full head privately between invocations, and consume it only on exit 0. Never derive the expected head from the current ledger or reconstruct a lost result. Pending/partial operations remain blocked. Existing operations bound to a different Bridge are not adopted by this literal update.

Alpha future invocations must retain the accepted private inputs, the existing bootstrap lock and exact unchanged Guest/common/durability inputs. Supply the v3 foundation path explicitly. This source packet supplies no private plan, overlay, health proof, key, identity, or operational authorization.

# Cross-device prototype verification

A functional cross-device result requires two different machines. Two identities, processes, or installations on the same host remain a local protocol test. Packaging a binary is not a cross-device acceptance result.

## Recorded cross-device result

The [validation summary](VALIDATION.md) and [redacted acceptance report](validation/slipstream-cross-device.json) record a passing networked test between OMEGA (Linux/WSL2) and the user-selected slipstream.host server. The evidence establishes distinct OS installations and device-specific telemetry, not the underlying physical hardware topology.

The report identifies the tested static amd64 binary by SHA-256. Packaging includes those two exact public evidence files when present and records whether the reported binary hash matches each package. The arm64 binary is cross-built and statically inspected; it has not been exercised by this amd64 cross-device run. Runtime access URLs, node keys, and private session metadata remain outside the packages and public evidence.

## Portable builds

From the Nucleus repository on Linux/WSL2, with Go 1.23+, Python 3, and standard archive tools:

```bash
bash scripts/package.sh
cd dist
sha256sum --check SHA256SUMS
```

The script produces:

- `nucleus-0.2.0-alpha-linux-amd64.tar.gz`
- `nucleus-0.2.0-alpha-linux-arm64.tar.gz`

Each archive contains a static `bin/nucleus`, the README, this guide, the protocol, Go license notices, `MANIFEST.json`, `SOURCE_SHA256SUMS`, and internal `SHA256SUMS`. The two allowlisted public validation files are included when available; no runtime report discovery is performed. It contains no node state, private keys, invitation/request/grant files, browser tokens, or test installations.

After extraction, run `sha256sum --check SHA256SUMS` from the extracted directory. Linux `x86_64` uses the `amd64` build; Linux `aarch64` uses `arm64`. The manifest records the Git branch/revision, whether the checkout was dirty, and a digest of the actual build inputs. A dirty prototype cannot be reproduced from the recorded Git commit alone. Archive timestamps use SOURCE_DATE_EPOCH when supplied, otherwise the recorded commit timestamp; this is a reproducibility reference, not a claim about when uncommitted files were authored.

The package has no runtime Go or Python dependency. Python is needed only by the automated verification harness. The CLI currently targets Linux and WSL2; these archives are not native Windows or macOS executables.

## Choose an authorized second device

Use a host that the user has explicitly selected for this prototype. An existing SSH alias does not itself authorize deploying a test service, and a customer or production host must not be selected merely because it is reachable.

The second machine needs:

- Linux `amd64` or `arm64`, a different installation/device identity, and normal `/proc`/`/sys` telemetry.
- An existing SSH account with noninteractive authentication and a host key already trusted through the normal verification process.
- Permission to run the prototype temporarily in its own private directory and remove that directory afterward.
- No Nucleus public port, firewall change, service installation, or administrative package installation.

The local SSH client must preserve strict host-key verification. A host-key mismatch is a failed prerequisite, not a reason to disable checking. The harness does not edit `authorized_keys`, SSH configuration, or the user's normal Nucleus state.

## Two verification paths

For two computers on the same private LAN, follow the invitation/request/grant and `nucleus run` procedure in the main README. Only the fabric owner binds an explicit private IPv4 address. The member makes outbound TLS 1.3 connections. Open both locally authenticated maps.

For an explicitly authorized SSH-accessible second machine, `scripts/test_cross_device.py` provides an automated temporary deployment and lifecycle check. Its transport uses an existing encrypted SSH connection with a loopback forward, then runs Nucleus's normal mutual TLS inside that private path. The owner listens on remote loopback only; no new public Nucleus port is exposed. This tests two actual devices over a controlled private connection; it is not a claim that automatic internet discovery, NAT traversal, or a general IP overlay exists.

Run the harness only after the user has selected the target. From the repository, using a verified extracted package binary:

```bash
python3 scripts/test_cross_device.py \
  --ssh-target AUTHORIZED_SSH_ALIAS \
  --binary /absolute/path/to/extracted-package/bin/nucleus \
  --report .runtime/cross-device-report.json
```

The local binary must match the local machine. If the remote architecture differs, add `--remote-binary /absolute/path/to/extracted-remote-architecture/bin/nucleus`; this is a **local** file that the harness copies to the remote test workspace. Both binaries must be static Linux builds.

The default run cleans up its processes and private test state after reporting the lifecycle result. To leave a verified prototype running for inspection, add `--keep-running --session-dir .runtime/cross-device-session`, choosing a new session directory. Its private session metadata contains the local map access URLs and stop/restart information. Keep that metadata private; stopping the foreground session manager triggers cleanup. Use `python3 scripts/test_cross_device.py --help` for the exact options. Run the offline harness safety checks with `python3 -m unittest discover -s tests -p test_cross_device_harness.py -v`.

The target is a required explicit argument; the script must not discover and choose a deployment host.

## Acceptance evidence

The cross-device report should establish:

1. Different machine/kernel identities, recorded as hashes rather than raw machine IDs. A shared or unavailable machine ID requires additional evidence; different node IDs alone are insufficient.
2. A persistent node identity on each machine and one shared `fabric_id`, established through explicit invitation, signed-request inspection, owner acceptance, and joiner grant acceptance.
3. Real resource snapshots from both machines through authenticated TLS 1.3, shown in each machine's fabric map perspective.
4. Disconnect detection: after the member stops, the owner marks it offline and removes its resources from available inventory.
5. Reconnection with the same node identity and fabric membership, restoring fresh measurements without another pairing exchange.

The report must not contain private keys, enrollment bearer secrets, browser access tokens, or token-bearing map URLs. Store any temporary logs privately. Temporary remote processes and directories must be tied to this run, and cleanup must verify the generated path rather than using broad process or filesystem patterns.

A passing isolated local test, successful package build, or reachable SSH host is not sufficient to declare cross-device acceptance. Record the actual two-device lifecycle outcome before sending the completion notification.


## Add a member to the existing inspection fabric

Use the separate rollout helper to enroll an explicitly selected server into the already running fabric. It issues invitations from the existing owner; it does not create another fabric.

```bash
python3 scripts/rollout_remote.py \
  --ssh-target AUTHORIZED_MEMBER \
  --coordinator-session .runtime/slipstream-prototype/session.json \
  --session-dir .runtime/NEW_MEMBER_SESSION \
  --report .runtime/NEW_MEMBER_REPORT.json \
  --remote-workspace home
```

Remote Python is not required. The helper uploads a checksum-verified static executable, inspects the signed joining identity, completes membership, and supervises loopback-only reverse SSH forwarding into the existing coordinator bridge. It rejects duplicate OS identities recorded in the shared rollout registry.

The default workspace is an isolated generated directory under remote `/tmp`. Use `--remote-workspace home` when that filesystem is `noexec`, or to keep the member's files in the account's private `$HOME/.local/share/nucleus-prototype/node.<nonce>` namespace. Ownership, canonical paths, symlink checks, private permissions, and a unique run marker constrain managed files and cleanup. The HOME option leaves mount protections unchanged.

These remain supervised prototype processes. No system service or automatic boot installation is performed. A member's private `session.json` contains its guarded stop/recovery commands. Stopping its local rollout supervisor revokes and removes only that rollout's member; stop member supervisors before removing the coordinator inspection session.

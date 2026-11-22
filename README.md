# Nucleus Alpha 0.5 — Private Fabric, NEBULA WAN and Hosted Model Work

Nucleus connects explicitly paired Linux/WSL2 installations into a private fabric. Each installation owns a persistent Ed25519 identity. A fabric owner issues short-lived invitations, approves signed join requests, and issues membership certificates. Nodes exchange real resource measurements through TLS 1.3 with mutual certificate authentication.

Version 0.5 adds opt-in NEBULA WAN transport for an already paired fabric. Owners and members make outbound HTTPS connections to an organization-authorized relay; the existing mutual TLS connection remains encrypted between nodes. See [NEBULA setup and limits](docs/NEBULA.md).

Version 0.4 adds explicitly opted-in hosted model work to the outbound NEXUS-backed connection. An organization owner or administrator approves the node identity. Telemetry runs by default; a private local runtime configuration enables signed inference jobs, and additional flags enable exact approved model installation/removal. The operator's configuration stays read-only; managed models use a private overlay. See [hosted setup and user-service instructions](docs/HOSTED.md). No private key or local browser token is uploaded. The local hosted text/context path has passed actual Gemma generation and JSON-schema acceptance with the approved catalog artifact; this does not assert production billing execution or media quality.

Positronic tracks heartbeats and available inventory. A separate, authenticated loopback resource map displays the fabric. CPU inference is an explicit opt-in extension; see [CPU inference](docs/CPU_INFERENCE.md) and [Meld migration](docs/MELD_INFERENCE.md). Hosted work accepts typed generation/model jobs, never arbitrary remote commands. The node opens no public listener. Media runtime documentation describes a separate opt-in path; packaging does not assert media quality or readiness.

The standalone [NEBULA repository](https://github.com/Parallax-Web-Services/nebula) builds its CLI against this Go module. The in-tree command remains available for existing NUCLEUS build and package scripts.

## Build

Go 1.23+ and Linux/WSL2 are required. The NEBULA transport uses [coder/websocket](https://github.com/coder/websocket) v1.8.15 under the ISC license; its notice is included in portable bundles.

```bash
bash scripts/build.sh
bash scripts/check.sh
python3 tests/test_first_contact.py
./bin/nucleus help
```

The scripts use Go on PATH, or the workspace-local `.tools/go/bin/go` when present. Build outputs, toolchains, and test state are ignored by Git. Use `./bin/nucleus` in place of `nucleus` below unless the binary is already on PATH.

Native `zh` remains in the adjacent `../zh` repository. Its real Rust bootstrap, resource measurements, persistent interactive Bash session, arguments, and exit propagation were validated. Build it with `bash scripts/bootstrap.sh` from that repository using an installed Rust toolchain. Set an absolute `NUCLEUS_BIN` to use its membership commands:

```bash
export NUCLEUS_BIN=/absolute/path/to/nucleus/bin/nucleus
zh init --name workstation
```

`zh invite`, `inspect`, `join`, `accept`, `members`, and `revoke` forward directly to Nucleus. `zh fabric` runs the shared fabric map. Existing `zh` Bash behavior and its standalone local `--map` remain available.

## Standalone NEBULA CLI

`bash scripts/build.sh` also builds `bin/nebula`, a standalone development CLI for the existing machine, fabric and network operations. Run `./bin/nebula help`. It reuses existing identities and runs the shared engine directly. See [CLI setup](docs/NEBULA_CLI.md) and the [managed Kubernetes platform contract](docs/NEBULA_PLATFORM.md). The independently versioned NEBULA client imports the Go package `github.com/Parallax-Web-Services/nucleus/cli/nebula` from this repository. [NEBULA source](https://github.com/Parallax-Web-Services/nebula)

The hosted NUCLEUS dashboard is maintained in the marketing repository. [Dashboard source](https://gitlab.com/parallax-web-services/marketing/-/tree/master/apps/nucleus-dashboard)

## First contact on two LAN computers

Use the same build on both computers. Replace the example owner IP with the owner's reachable RFC1918 IPv4 address. Transfer the three pairing documents through a trusted channel, such as a trusted local file transfer or removable drive. They contain enrollment capabilities; the CLI creates them with mode `0600`.

On **A, the fabric owner**:

```bash
nucleus init --name node-a
nucleus identity
nucleus invite --endpoint https://192.168.1.10:9461 --out invite.json
```

On **B**, after receiving `invite.json`:

```bash
nucleus init --name node-b
nucleus identity
nucleus join invite.json --out request.json
```

B is still unjoined. Return `request.json` to A. On **A**, inspect its signed identity and compare the printed node ID with B over the trusted channel before explicitly accepting:

```bash
nucleus inspect request.json
nucleus accept request.json --out grant.json
nucleus members
```

Return `grant.json` to **B**, which explicitly accepts its membership:

```bash
nucleus join --accept grant.json
nucleus identity
nucleus members
```

Both identities now share the same `fabric_id`. Private node keys and the owner's separate CA key never travel in pairing documents. An exact repeated acceptance can reproduce a lost grant; a different request cannot reuse the invitation.

On **A**:

```bash
nucleus run --listen 192.168.1.10:9461
# equivalently: zh fabric --listen 192.168.1.10:9461
```

On **B**:

```bash
nucleus run
# equivalently: zh fabric
```

Each command prints its own authenticated browser URL and tries to open it in a Chromium-compatible browser. Add `--no-open` to print the URL only. The UI always binds `127.0.0.1`, independently of the private node transport.

B makes outbound authenticated connections; it opens no LAN listener. The owner binds only the explicit private IP and port. Public addresses, wildcard addresses, DNS endpoints, proxies, redirects, and unauthenticated node requests are rejected. This is the default direct encrypted LAN transport. The opt-in NEBULA mode carries the same private fabric over outbound HTTPS for WAN connectivity. It does not create an IP overlay or open a node listener to the internet.

### Acceptance

1. Both maps show A and B online with real resources.
2. Stop B with Ctrl+C. Within approximately 12 seconds, A marks it offline and removes its measurements from available capacity. The map labels retained samples as cached.
3. Restart B with `nucleus run`. It returns automatically without another invitation.
4. Restart A. Durable membership survives; remote capacity stays unavailable until a fresh authenticated heartbeat arrives.
5. Optionally revoke B on A with `nucleus revoke B_NODE_ID`. It immediately stops contributing capacity and cannot authenticate using its old certificate.

Available inventory is an observation, not a scheduler reservation or a promise of allocatable resources. WSL measurements describe the WSL VM. Two separate installations on one host are useful protocol tests and must not be counted as two physical computers.

## Architecture

The [architecture walkthrough](docs/ARCHITECTURE.md) traces the running five-node fabric, trust boundaries, and private transport path.

- [fabric/](fabric/) is a reusable package for identity, invitation/acceptance, membership, and standard TLS configuration. It has no UI, Positronic, telemetry, or shell dependency.
- [inventory/](inventory/) collects local CPU utilization/load, RAM, root filesystem space, interface state, and uptime.
- [positronic/](positronic/) owns the authenticated versioned heartbeat API, receipt-time liveness, and online inventory.
- [apps/resource-map/](apps/resource-map/) is a read-only local browser client.
- [cmd/nucleus/](cmd/nucleus/) supplies operator commands and joins these components.

The fetched standalone `zzh` checkout remains unchanged at `.dependencies/zzh`, revision `e3daf67f1154ac7c7669ef418d6fa32a8cd3cecf` on `master`. Its OpenSSH login commands are separate from fabric membership. This milestone supplies a reusable transport package and protocol; it does not replace SSH or add fabric behavior to that CLI. See [protocol](docs/PROTOCOL.md) for future Rust/`zzh` interoperability.

This implementation occupies the Positronic control-plane role in this repository. It does not rewrite the adjacent Laravel/Selenium Positronic application or alter its database. The older Go health-only scaffold under `../zh/services/positronic` remains a separate starter.

## Verified cross-device result

The OMEGA WSL2 installation and the selected slipstream.host server passed the real cross-device pairing, two-map telemetry, offline-capacity, and reconnect workflow on November 1, 2026. See [validation evidence](docs/VALIDATION.md), the [cross-device harness](docs/CROSS_DEVICE.md), and portable packages from `bash scripts/package.sh`.

## State and current limits

State defaults to `$XDG_CONFIG_HOME/nucleus` or the user's platform config directory. Set an absolute `NUCLEUS_HOME` for an isolated installation. State directories use `0700`, state and pairing files `0600`; state updates are locked and atomic.

The private fabric retains the Alpha 0.2 limits: one coordinator/fabric owner and an immutable logical owner endpoint. Direct transport uses private IPv4; NEBULA relays that same paired fabric over outbound HTTPS. Certificate renewal, endpoint migration, key recovery, additional coordinators, IPv6, federation, automatic LAN browsing, and joining another fabric from an already joined identity are not implemented. Paired nodes are discovered when their authenticated heartbeats arrive, not through unauthenticated network scanning. Detected hardware is an observation, not a guarantee that a model runtime can use it.

## License

Parallax Web Services, Inc. licenses NUCLEUS under the [MIT License](LICENSE). Third-party components retain their own terms, including [coder/websocket (ISC)](THIRD_PARTY_NOTICES/coder-websocket-LICENSE) and the [Google Research Readout adaptation (Apache-2.0)](runtimes/meld/LICENSE.readout). Model weights are subject to their publishers’ licenses.


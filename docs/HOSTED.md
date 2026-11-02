# Hosted Nucleus connection — 0.4.0-alpha

Nucleus can register an existing node identity with the NEXUS-backed service at
https://nucleus.parallax.link/dashboard. Organization owners or administrators
approve enrollment in the hosted dashboard. The service checks the organization's
subscription and available machine allowance.

Telemetry remains the default. Version 0.4 also supports typed, leased model work
when the operator explicitly supplies a trusted local runtime configuration.
Model installation/removal needs separate opt-in flags and exact local artifact
approval. No hosted request can choose a binary, shell command, or local model path.
The connection preserves private-fabric membership and keeps private keys local.

## Install and approve the node

Use the Linux amd64 or arm64 0.4.0-alpha archive for the machine. Verify the archive
against the release's SHA256SUMS before extracting it. Packages include no node
state, enrollment capabilities, or credentials.

Copy the archive's bin/nucleus executable to an appropriate executable directory,
such as $HOME/.local/bin. Then run:

    nucleus --version
    nucleus cloud connect --url https://nucleus.parallax.link/dashboard

The command creates a local identity only if none exists. Existing identities and
fabric memberships are preserved. Use the same NUCLEUS_HOME as your existing
installation; it must be an absolute private directory. Without an override,
Nucleus uses the platform's user configuration directory.

The CLI first proves possession of its persistent Ed25519 key. It then prints a
verification URL, the code (formatted XXXX-XXXX), and this node's full SPKI fingerprint, and tries to open your browser. Use
--no-open when connecting through a terminal without a local browser.

Sign in through NEXUS, choose the intended organization, compare the node identity,
and approve the device. Enrollment expires after ten minutes. Registration is
saved only after the server reports approval for that exact node. A denied,
expired, interrupted, or mismatched approval creates no local hosted binding.

Approval is not a heartbeat. Start resource reporting separately:

    nucleus cloud run

This remains in the foreground and reports at the interval assigned by the server.
For a single acknowledged measurement:

    nucleus cloud run --once

A successful report prints "Telemetry acknowledged". HTTP 402
subscription_required and HTTP 403 node_revoked stop reporting with an error;
neither is reported as a successful connection. Transient transport/server errors
are retried without updating the last-successful-contact timestamp.

## Opt in to hosted text generation

First install a trusted compatible CPU llama.cpp runtime and util-linux prlimit.
Nucleus archives contain the Go agent and public metadata, not model weights or
llama-server. Keep the runtime's adjacent shared libraries together. AMD64 users
may use the separately pinned CPU runtime described in the agent install guide;
ARM64 users need a compatible trusted source build. Do not run an AMD64 runtime
on ARM64 or invent a substitute download.

The public inference/catalog/gemma-3-4b-it-text.json records the exact Gemma text
artifact and an example owner approval. It is metadata, not automatic permission.
The owner must review the provenance, explicitly accept Google's Gemma terms,
and adopt the exact hash/provenance exception locally before installation.
The disclosure remains publisher-disclosed and incomplete; blocked-origin rules
continue to apply. The dashboard separately asks the organization to accept the
model license. Do not infer either acceptance from a paid subscription.

Create a dedicated private FleetConfig with the operator-selected absolute
llama-server path, two threads, context 8192, max_tokens 256, memory_limit_bytes
8589934592 (8 GiB), reserve_memory_bytes 1073741824 (1 GiB), and models:[].
Copy only the explicitly accepted example_owner_approval into approved_models.
This is an 8 GiB process budget plus a 1 GiB host reserve, not measured model RSS.
The exact approved artifact passed offline approval/hash/GGUF-memory preflight
and actual local generation at context 8192 with a 256-token configured cap.
The measured request used 32 tokens; this is acceptance evidence, not a general
throughput or service-level guarantee.
Do not change the approval to cover another artifact or hide the incomplete
lineage disclosure. Keep the file mode 0600 and its parent directory private.

After enrollment, run:

    nucleus cloud run --inference /absolute/private/fleet.json \
      --model-root /absolute/private/models --allow-model-installs

The model root must be a dedicated private directory. Without the model flags,
an opted-in runtime can serve already configured local models but cannot install
or remove them. Without --inference, the command sends telemetry alone.

The source FleetConfig stays read-only. Worker-installed models are recorded in
model-root/hosted-models.json and reloaded on restart. An exclusive process lock,
private overlay, exact hash checks, memory/disk limits, pinned revision, and a
restricted HTTPS redirect policy govern installation. Operator-pinned models
cannot be removed by hosted jobs. Changing the source configuration requires
restarting the worker; a remote job cannot overwrite an operator edit.

In the hosted Models page, select the eligible machine, review the exact model
and license, and request installation. Do not download weights while merely
installing the agent. The server reports queued/installing/ready/failed state.
Generation requires a ready matching model on an eligible paid machine.

Work uses the existing node signature over outbound HTTPS. Only one job executes
per node. Leases renew every 10 seconds and stop on cancellation, revocation,
subscription failure, lease loss, or deadline expiry. Synchronous inference has a 120-second hard deadline; asynchronous inference
may allow up to 600 seconds. Install/remove has a 20-minute hard deadline. A durable private journal prevents
executed jobs from replaying after a crash or lost acknowledgment. No node shell
or inbound public RPC port is added. See the packaged HOSTED_WORKER.md or the
source hostedworker/README.md for exact payloads and limits.

## Keep telemetry running with systemd

Run the agent as the same unprivileged user who enrolled the node. Do not copy its
private state into root's account. Create ~/.config/systemd/user/nucleus-cloud.service:

    [Unit]
    Description=Nucleus hosted node agent
    After=network-online.target
    Wants=network-online.target

    [Service]
    Type=simple
    ExecStart=%h/.local/bin/nucleus cloud run
    Restart=on-failure
    RestartSec=30
    UMask=0077
    NoNewPrivileges=true
    PrivateTmp=true

    [Install]
    WantedBy=default.target

For an opted-in model worker, replace ExecStart with the explicit --inference,
--model-root and --allow-model-installs command above using absolute paths.
No configuration flag is implied by enabling the service.

If you use a custom NUCLEUS_HOME, add an Environment=NUCLEUS_HOME=/absolute/path
line using the same directory as the enrollment command. Then run:

    systemctl --user daemon-reload
    systemctl --user enable --now nucleus-cloud.service
    systemctl --user status nucleus-cloud.service

Inspect failures with:

    journalctl --user -u nucleus-cloud.service

A user service normally follows the user's login session. An administrator can
enable lingering for that user when the machine should report after logout. In
WSL2, the distribution must support systemd and remain running; a stopped WSL
instance cannot send telemetry.

The hosted dashboard determines online/offline status from server receipt time.
A saved registration, an old successful heartbeat, or a running service process
does not by itself prove the server currently receives measurements.

## Inspect or disconnect

    nucleus cloud status

This prints local registration metadata and the last acknowledged heartbeat. It
contains no poll token or private key. The accompanying note distinguishes saved
registration from current online status.

Stop the user service before disconnecting:

    systemctl --user disable --now nucleus-cloud.service
    nucleus cloud disconnect

Disconnect sends a signed revocation request, then removes the private local
binding. The node's persistent identity and LAN-fabric membership remain intact.

If the hosted service is unreachable and you explicitly want to forget only the
local association:

    nucleus cloud disconnect --local

This does not revoke the server-side registration. An organization administrator
can revoke that registration in the hosted dashboard.

## Protocol and storage

The service origin is the lowercase scheme and hostname, with a non-default port
when present. The production origin is https://nucleus.parallax.link. All remote
requests require authenticated HTTPS. Redirects and environment HTTP proxies are
disabled. Plain HTTP is accepted only for literal loopback test addresses.

Enrollment begins with POST /dashboard/api/enroll containing node_id, public_key,
fabric_id, hostname, platform, arch, and version. public_key is the base64-encoded
raw 32-byte Ed25519 public key. The existing node_id remains SHA-256 of its SPKI DER:
hex 302a300506032b6570032100 followed by that raw key.

The server returns enrollment_id, user_code, verification_uri, poll_token,
challenge, expires_in, and interval. A proof is posted to
/dashboard/api/enroll/{enrollment_id}/prove with poll_token and a base64 Ed25519
signature over these exact lines, with no trailing newline:

    nucleus-enroll-v1
    <origin>
    <enrollment_id>
    <node_id>
    <challenge>

Only the matching origin's /dashboard/enroll?code=... URL is opened. The CLI polls
/dashboard/api/enroll/{enrollment_id}/poll with poll_token. Only state=approved,
a matching node_id, an organization_id, a matching heartbeat_url, and a valid
heartbeat_interval_seconds finalize local registration. Poll capabilities remain
in process memory and are not written into cloud.json or printed.

Telemetry POSTs the native inventory.Snapshot JSON to
/dashboard/api/nodes/{node_id}/heartbeat. It includes measured CPU, memory,
storage, interface state, uptime, and detected hardware details. Network addresses,
node private keys, CA keys, membership grants, and pairing secrets are not sent.
A reported fabric_id is descriptive metadata, not authority to claim other nodes.

Signed requests have X-Nucleus-Timestamp (Unix seconds), X-Nucleus-Nonce (32 hex
characters), and X-Nucleus-Signature (base64 Ed25519 signature). The exact signed
lines, without a trailing newline, are:

    nucleus-cloud-v1
    <UPPERCASE_METHOD>
    <origin>
    <path>
    <timestamp>
    <nonce>
    <lowercase_sha256_of_exact_body_bytes>

The server enforces its clock window, rejects nonce reuse, checks organization
authorization and subscription state, and can revoke the node. DELETE
/dashboard/api/nodes/{node_id} uses the same signature format and an empty body.

cloud.json and cloud.lock reside beside the existing private node state. They use
private file permissions; binding updates are locked and atomic. cloud.json stores
the service URL, node and organization IDs, reporting interval, registration time,
last acknowledged heartbeat, and known revocation state. It contains no new
long-lived bearer credential. The node's existing private identity remains local.

## Verification scope

Local protocol fixtures verify approval/proof, SPKI identity, origin/body-bound
signatures, real measurements, nonce uniqueness, billing/revocation failures,
redirect refusal, private storage, and unchanged fabric state. Production
enrollment and server receipt are separate checks performed against the deployed
service. Packaging itself does not assert production connectivity.

The opt-in cross-language fixture in hostedworker/php_integration_test.go also
checks real signed lease/renew/event/completion against an isolated PHP service,
idempotent retry after a lost completion acknowledgment, encrypted results,
nonce replay rejection, and cancellation. It uses a fake backend and synthetic
SQLite data, not real model throughput or production acceptance.

## Local hosted text acceptance

On November 2, 2026, an isolated PHP service and SQLite organization passed actual
PHP-to-signed-Go-to-Gemma-to-PHP generation with shared context. The approved
public Gemma text artifact was reused locally without a weight download/copy.
The plain answer contained the synthetic organization codename and cited the
same context document. A complete JSON-schema answer also passed at context
1024 with a 64-token local cap.

The shipping-profile check used context 8192, a 256-token configured cap, two
CPU threads, an 8 GiB address-space limit, and a 1 GiB host reserve. One 32-token
schema request produced {"codename":"ORBIT-73"}, finish_reason=stop, and the
matching context citation. It measured 126 prompt tokens, 25 completion tokens,
6.81 seconds cold initialization, 13.07 seconds runtime elapsed, and
4,506,218,496 bytes peak RSS. The full local request took 18.30 seconds including
the outbound polling path. The process was new; filesystem caches were not
cleared. These are one fixture's observations.

These checks are local acceptance results, not a production paid request,
a throughput guarantee, or a claim about the separate media pipeline. The
fixture retains only synthetic output/citations and safe counters; its database,
bearer credential, node state, and owned processes are cleaned up.

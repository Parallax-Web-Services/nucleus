# First-contact protocol v1

This contract is independent of Chromium and workload execution. The Go `fabric` package exports identity, membership, and TLS primitives; another client, including a future Rust transport used by standalone `zzh`, can implement the same standard certificate and HTTPS contract.

## Identity and enrollment

A node ID is lowercase SHA-256 hex of its Ed25519 public-key SPKI DER. A fabric ID is SHA-256 hex of the fabric CA certificate DER. The owner's identity key and CA signing key are separate. Node leaf certificates have a single logical DNS SAN:

```text
<NODE_ID>.nodes.nucleus
```

They are non-CA certificates with digital-signature usage and both client-auth and server-auth EKUs. IP endpoints are dial addresses, not identities. The TLS client verifies the pinned CA, logical owner name, and owner membership without disabling standard certificate checks.

All pairing documents are strict JSON v1. Certificates and CSRs are base64 DER. Invitations are owner-signed, expire, and carry a random 256-bit bearer secret. The owner persists only its secret hash. Join requests contain an Ed25519-signed CSR binding the invitation, owner/fabric IDs, endpoint, node name, and secret hash. The owner validates proof of key possession and issues its own constrained extensions, ignoring requested privileges. Grants are signed by the owner and bound to the exact pending request and joining key. Inspect the current structs in `fabric/pairing.go` for field names.

Invitation acceptance is explicit and serialized under a state lock. A consumed invitation cannot enroll a different request. An exact acceptance retry reproduces the saved grant; completing the same grant is idempotent. Authorization changes and telemetry do not share a mutable state file.

## Authenticated telemetry

Transport is HTTPS with TLS 1.3 only. Both ends present fabric-issued certificates; session resumption is disabled. The coordinator checks current membership on every connection and every API request. A client always verifies the specific owner node identity. HTTP proxies and redirects are disabled.

Only the owner listens on an explicitly selected RFC1918/private IPv4 or loopback address. Worker nodes send outbound heartbeats.

### POST /v1/heartbeat

```json
{
  "schema_version": 1,
  "fabric_id": "<fabric-id>",
  "node_id": "<client-certificate-node-id>",
  "resources": {
    "schema_version": 1,
    "collected_at_ms": 0,
    "node": {},
    "cpu": {},
    "memory": {},
    "storage": null,
    "network": [],
    "gpu": {}
  }
}
```

The resource object shown here is structural only; a real message requires valid measurements. Generate one with `nucleus snapshot` and use the `resources` field. Content type is `application/json`. The coordinator rejects unsupported schemas, invalid measurements, overlarge bodies, and identities or fabrics that differ from the verified TLS peer. Success is HTTP 204.

Heartbeats arrive every two seconds. Liveness uses coordinator receipt time, never worker-provided timestamps. After ten seconds without a valid heartbeat, that node is offline and contributes zero available inventory. Cached samples remain visible as cached. Restarting the coordinator clears volatile observations; membership survives.

### GET /v1/fabric

Authenticated members receive a v1 fabric view with `fabric_id`, viewer-relative `local_node_id`, `nodes`, and `available_capacity`. Each node includes its ID, registered name, `online`/`offline`/`awaiting` status, last receipt time, and optional resource snapshot. Only online measurements are summed.

No endpoint accepts shell commands, jobs, scheduler leases, or arbitrary remote execution. Unsupported routes and methods are rejected.

## Browser boundary

The resource map is a separate HTTP listener on `127.0.0.1`, with exact Host validation and a random 256-bit per-run bearer token. Its URL carries the token in a fragment; JavaScript retains it in memory and erases the fragment. GET `/api/v1/fabric` requires that token. All writes are rejected; a restrictive CSP permits only bundled assets. TLS node credentials are never delivered to the browser.

The UI's loopback authentication token is distinct from fabric node identity, a pairing secret, or membership authority.

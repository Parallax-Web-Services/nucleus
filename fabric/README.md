# Reusable private-fabric foundation

This Go package has no third-party dependencies and imports no Nucleus UI,
Positronic, shell, or remote-execution code. Standalone zzh can consume the same
identity, membership, and TLS boundary.

1. Call `Init` on each computer. The Ed25519 identity persists; `node_id` is
   SHA-256 of its public SubjectPublicKeyInfo.
2. The owner calls `Invite` with its explicit private IPv4 HTTPS endpoint.
   The first invitation creates a separate CA signing key, the owner membership
   certificate, and the shared `fabric_id` (SHA-256 of the CA certificate).
3. Transfer the invitation through an independently trusted channel. The
   joining computer calls `Join` and returns the signed CSR request.
4. The owner calls `InspectRequest` and compares the displayed node ID with the
   joining computer through that trusted channel. `Accept` is the authorization
   step and emits an owner-signed grant. One invitation authorizes one request.
5. The joining computer calls `FinishJoin`, which checks the exact pending
   invitation, owner signature, certificate, local key, and endpoint.
6. Use `ServerTLS` and `ClientTLS` for TLS 1.3 with mutual certificate
   authentication. The client verifies the owner's logical node DNS SAN while
   connecting to the private IPv4 endpoint.

The JSON invitation and request contain a short-lived enrollment bearer token;
transfer files should be private and must not be logged. Neither node persists
the raw token in its identity store. Private identity and CA keys are never
included in exported documents or the public `State`.

Owner state updates use a cross-process flock, private 0700/0600 storage,
bounded reads, and fsync + atomic rename. Accepted grants are persisted with
their consumed request hash so retrying output after a failure returns the
same grant. Another CSR cannot replay that token. A revoked member cannot
retrieve its old grant to restore owner authorization.

TLS verifies both the CA chain and current local membership on each new
handshake. Session tickets and client resumption are disabled. Applications
must also check current membership on each authenticated request or close
active connections on revocation; TLS cannot retroactively revoke an already
established connection. Nucleus's coordinator does both request checks and
disables keep-alive. Owner revocation applies at the owner coordinator; this
alpha is not a distributed peer-to-peer membership synchronization protocol.

This LAN alpha accepts only literal RFC1918 or loopback IPv4 HTTPS endpoints
with explicit nonzero ports. Fabric endpoints are immutable after creation.
Invitation lifetime defaults to ten minutes and is capped at 24 hours. A live pending join cannot be replaced; after it expires, an explicit new Join may replace the pending invitation while preserving the node identity key.
Membership certificates last one year; automatic renewal and CA rotation are
not implemented. No discovery broadcast, public listener, execution, scheduler,
or workload permissions are supplied by this package.

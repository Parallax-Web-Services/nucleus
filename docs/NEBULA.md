# NEBULA WAN transport

NEBULA connects an explicitly paired Nucleus fabric through an outbound HTTPS relay. It preserves each node’s existing Ed25519 identity and the fabric’s end-to-end TLS 1.3 authentication. The relay routes opaque bytes and has no node private keys, application keys, database credentials, or arbitrary TCP target.

## Run a paired fabric across networks

Both installations need the same accepted private fabric membership. Complete the invitation/request/grant exchange in the main README first. Hosted machine approval alone does not issue private fabric membership.

Each installation also needs an active registration in the same paid Positronic organization:

1. Enroll each machine with `nucleus cloud connect --url https://nucleus.parallax.link/dashboard`. An organization owner or administrator approves its fingerprint.
2. In [Positronic → Machines](https://positronic.app/dashboard/machines), enable NEBULA relay access for both machines. Machine enrollment and private fabric membership are separate approvals.
3. Start the fabric owner, then its members:

```bash
nucleus run --nebula --no-open
```

Keep this command running on each machine. To continue hosted telemetry or model work, run the existing `nucleus cloud run` command separately under the same account and `NUCLEUS_HOME`. The command prints the existing locally authenticated resource map. A node opens no public TCP listener and requires no TUN device or administrator privileges. The configured private owner endpoint remains the logical TLS destination; NEBULA supplies the transport underneath it.

The signed machine service remains `https://nucleus.parallax.link/dashboard`. Its browser approval page opens the canonical Positronic management interface. Never change an existing machine registration’s origin to move the browser dashboard.

## Relay operator

The standalone relay runs under a dedicated unprivileged service account:

```bash
nucleus nebula relay --issuer-public-key-file /absolute/path/issuer-public.key --listen 127.0.0.1:8743
```

The public-key file is a protected regular file containing the issuer’s raw 32-byte Ed25519 public key or its unpadded base64url encoding. Private signing keys stay with the managed authority.

The owned HTTPS ingress proxies only `/nebula/v1/relay` to this loopback listener, using HTTP 1.1 WebSocket upgrades, buffering disabled, and an upstream idle timeout longer than the 10-second renewal interval. `/healthz` is a local readiness endpoint.

The production client obtains every capability by an origin-bound Ed25519-signed request to its existing hosted machine service. It never accepts an arbitrary client-supplied organization, relay, target address, port, shell command, or execution request.

## Authorization and connection lifecycle

A 30-second capability binds the organization, existing node public key, accepted fabric, fixed `nucleus-fabric` service and one connection. Each WebSocket presents both that capability and proof from the node’s existing private identity. Initial and renewal capabilities are one-use. Renewals run every 10 seconds; missing, rejected or expired authorization closes the connection.

The owner keeps one listening control connection. A member opens a dial connection; the relay notifies the registered owner, which opens a matching accept connection. Only the same organization and fabric can pair. Every data connection then performs the existing node-to-node mutual TLS handshake. Revoked private fabric members fail that handshake or the coordinator’s current-membership request checks.

The relay permits eight connections per node, 256 total connections and 64 pending/active streams by default. Frames are bounded to 64 KiB, authenticated control messages to 16 KiB, and capabilities to 8 KiB of decoded JSON. Slow writes close after 10 seconds; idle data streams close after 60 seconds. Listener control connections reconnect with a fresh capability. Failed data frames are never replayed.

NEBULA v1 connects members to their paired owner. It does not provide a general IP network, arbitrary port forwarding, direct peer NAT traversal, or an SSH replacement.

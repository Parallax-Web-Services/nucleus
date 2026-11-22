# Cross-device validation — November 1, 2026

The prototype was exercised between **OMEGA (Linux/WSL2)** and the explicitly selected **slipstream.host** server. Separate machine-ID and kernel boot-ID hashes, SSH target identity, and device-specific telemetry establish distinct OS installations. This is a real networked cross-device test; it does not attest the hosts' underlying physical hardware topology.

| Device | Reported logical cores | Reported RAM |
| --- | ---: | ---: |
| OMEGA (WSL2) | 12 | 67,377,909,760 bytes |
| slipstream | 8 | 16,768,643,072 bytes |

Both installations used the same verified static Linux amd64 binary:

```text
SHA256 2a2af26679b30f2f10da849e294bc4108787d35add34fedb226721d867ecca2a
```

The [redacted acceptance report](validation/slipstream-cross-device.json) records the device identity hashes, node identities, shared fabric ID, binary checksums, real resource summaries, and successful checks. It contains no private keys, pairing secrets, browser tokens, or access URLs.

Verified on the actual two devices:

- Explicit invitation, signed-request inspection, owner authorization, and joiner grant acceptance.
- Independent persistent node keys and one shared fabric ID.
- TLS 1.3 mutual authentication and live telemetry in both map perspectives.
- Offline CPU and memory inventory exclusion after stopping the local member.
- Automatic reconnection with the same identity and membership.
- Owner-side revocation removes capacity and denies the still-running remote member.

Transport used Nucleus mutual TLS inside verified SSH loopback forwarding. The owner listened only on remote loopback; no public Nucleus port or firewall/service change was needed. Existing SSH host-key verification remained enabled, using the already pinned ECDSA server key.

The temporary acceptance run removed its private test state and processes afterward. A separate supervised inspection session may be retained under `.runtime/slipstream-prototype`; its access URLs and stop command are in its private `session.json`, never in the public evidence report. See [cross-device operations](CROSS_DEVICE.md) for reproduction and lifecycle details.

Native `zh`, Go vet/race tests, isolated protocol tests, browser authentication, and desktop/mobile map layout were also validated. Standalone `zzh` source remains unchanged.

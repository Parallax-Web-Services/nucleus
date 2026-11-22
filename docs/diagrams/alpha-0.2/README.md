# Nucleus Alpha 0.2 - shareable diagrams

Three matching 16:9 diagrams of the implemented prototype, documented on November 1, 2026.

## Files
- SVG: editable vector artwork with accessible titles and descriptions.
- PNG: 3200 x 1800 pixels for chat, documents and slides.
- PDF: three vector pages, one diagram per page.
- build_share_diagrams.py: reproducible source for all vector artwork.

SVG text uses Segoe UI with Arial and sans-serif fallbacks. The PDF embeds its fonts.
All artwork is self-contained; no private keys, bearer tokens, or live status links are included.

## Use
1. Logical topology: introduce the fabric and the roles of Nucleus and Positronic.
2. Private transport: explain the prototype's SSH forwarding path and end-to-end mTLS.
3. Secure pairing: explain explicit authorization and the signed document exchange.

These are architecture diagrams, not a live health report. Alpha 0.2 provides identity,
membership, and resource telemetry. Resource inventory is not scheduled or pooled compute.

## Architecture references
Repository: docs/ARCHITECTURE.md and docs/PROTOCOL.md.
Transport verification: docs/validation/fleet-rollout.json.
This set illustrates the recorded prototype and does not query the running fleet.

## Alt text

1. Four members (OMEGA, Alpha, Iota, and Tarragon) use mutual TLS 1.3 with the Slipstream fabric owner. The owner's single runtime contains membership authority, local inventory, and Positronic's aggregated telemetry. A browser on OMEGA reads only OMEGA's loopback API with a separate browser token.

2. Alpha, Iota, and Tarragon reach Slipstream using a reverse SSH forward into OMEGA, then a local SSH forward to Slipstream's loopback coordinator. OMEGA initiates both SSH connections. Nucleus mutual TLS remains end-to-end between member and owner, and no public Nucleus listener is exposed.

3. The owner sends a signed expiring one-use invitation. The joining node accepts it and returns a signed certificate request. The owner inspects and approves, then issues a signed grant and membership certificate. The joining node verifies and accepts membership before mutual TLS telemetry begins. Private keys remain on their originating machines.

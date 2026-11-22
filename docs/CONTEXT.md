# Accepted Alpha 0.2 scope

Source: the user's supplied First Contact / Secure Node Pairing brief in this chat, supplementing [the INGEST conversation](https://chatgpt.com/c/6ae60434-ca68-83ea-8fc7-eacf412b501c). The chat connector exposed only its last five turns; no claim is made that the entire earlier conversation was retrieved.

The accepted milestone is two real computers with persistent cryptographic identity, a shared fabric ID, explicit invitation and acceptance, mutually authenticated encrypted LAN connections, and Positronic telemetry/heartbeats feeding one Chromium resource map. Disconnecting removes available capacity; reconnecting restores the node without rebuilding membership.

No remote execution, scheduling, self-healing, payments, database rewrite, or browser-embedded Bash terminal belong to this milestone. Native `zh` and its Bash compatibility must be validated first. Connectivity must remain reusable outside the map; standalone `zzh` stays independent. The user prefers `master`.

Implementation choices made for this slice: standard-library Go cryptography/TLS, one owner CA/coordinator, offline invitation/request/grant exchange through a trusted channel, outbound worker heartbeats, and a separate loopback browser API. These are implementation choices, not claims about previously existing capabilities.

The two-process automated acceptance test exercises the actual protocol and real local telemetry. It does not replace the two-physical-machine LAN acceptance test.

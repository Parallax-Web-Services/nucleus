# Existing NEBULA capacity inventory

Verified November 2, 2026. Authenticated owner and member views of the existing Nucleus fabric agreed on five registered, known, online members for three observations spanning at least twelve seconds. No membership or workload changed during inspection.

| Installation | Current role | Kubernetes observed | Isolation readiness |
| --- | --- | --- | --- |
| OMEGA / WSL | Existing Nucleus member | Client/config present; local Docker Desktop API unreachable | Local Docker works; KVM API query failed despite device permissions. |
| Slipstream | Existing coordinator and managed relay | No installation found | KVM query passed; VM tooling must be installed separately. |
| Alpha | Existing member | No installation found | KVM, QEMU, libvirt, virt-install, default network and pool available; preserve its existing VM. |
| Iota | Existing member and cPanel host | No installation found | KVM query passed; current available RAM fails a 4 GiB VM plus 2 GiB host reserve. Keep existing services. |
| Tarragon | Existing member | No installation found | KVM query passed; VM tooling must be installed separately. |

These are point-in-time observations. They do not reserve resources or establish independent physical failure domains. Recheck identity, current resources and existing workloads before every allocation.

Alpha is the first isolated control-plane bootstrap candidate. Create a new uniquely identified VM and volume; never reuse its existing VM or disk. A single validation control plane is not an HA offering. Slipstream and Tarragon are further candidates after explicit tooling and admission checks; retain Iota and OMEGA in their existing fabric roles until the missing isolation prerequisites are satisfied.

The running Nucleus membership/telemetry cluster remains useful as the capacity inventory. It does not itself supply Kubernetes scheduling, pod networking, persistent volumes, or a replicated Kubernetes control plane.

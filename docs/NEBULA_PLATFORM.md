# NEBULA managed Kubernetes

This is the working implementation contract. The running 0.5 release provides private fabric connectivity. Kubernetes provisioning and the standalone panel are new work; a fabric heartbeat does not establish a Kubernetes cluster.

## Product decisions

- NEBULA has its own primary hosted panel, API, and `nebula` executable.
- cPanel and WHM are optional integrations with that API.
- Both Parallax-supplied servers and customer-owned machines are supported from launch.
- Use the existing Nucleus fleet as the first capacity inventory. Reconcile current identity, health, workload ownership, and free capacity before placement.
- NEXUS remains the organization and user authority. Use the shared Parallax shell/catalog where appropriate.
- Kubernetes engine choice is proposed upstream Kubernetes with extensions. A source fork needs a concrete upstream limitation; product branding and lifecycle management alone do not require one.

## Existing fleet

The recorded Nucleus rollout includes OMEGA, Slipstream, Alpha, Iota, and Tarragon. These are real fleet members. Their resource measurements describe observed capacity, not a reservation for Kubernetes. Check the retained sessions and current hosts before deploying.

Each eligible host gets isolated Kubernetes VMs or dedicated nodes. Preserve its existing websites, databases, inference workers, Nucleus membership and relay. A cPanel host remains a plugin host; it does not receive a Kubernetes/container runtime installation from the plugin.

## Operator and customer panels

| Role | Authority |
| --- | --- |
| Platform operator | Owned server inventory, suppliers, capacity reservations, cluster lifecycle, service packages, infrastructure billing and audited support access. |
| Reseller | Only explicitly delegated customer organizations and packages within the reseller's allocation. |
| Organization owner/admin | Its clusters, projects, machines, members, quotas and billing. |
| Project operator/viewer | Assigned applications and permitted deployment, log and usage actions. |

Organization administration is distinct from platform administration. Enforce ownership and quotas in the API for every interface, including the CLI and integrations.

## Resource contract

- `Cluster`: organization, region, engine/version, desired generation and observed generation/status.
- `NodePool`: cluster, capacity policy, infrastructure mode and placement constraints.
- `Machine`: immutable node identity, owner, operator, bill-to party and allocation state.
- `CapacityReservation`: explicit resources and expiry tied to an operation and a machine/VM.
- `Project`: namespace, membership, limits and application access.
- `PackagePolicy`: versioned capabilities, quotas and billing treatment.
- `Operation`: idempotent, durable lifecycle action with lease, progress, cancellation and audit history.

The infrastructure modes are `parallax_supplied` and `customer_owned`. Keep customer-controlled nodes within their owner's cluster and trust boundary. Do not place unrelated customer workloads on a customer-root-controlled worker.

Cluster mutations return an operation identifier. `ready` requires authenticated observations of the actual Kubernetes API, expected cluster identity, node readiness and matching configuration generation. A database row, running agent or successful shell exit is insufficient.

## CLI

The first implementation exposes existing machine, fabric, relay and network operations through a standalone executable sharing the tested runtime engine. It preserves existing identities and `nucleus` compatibility. It does not present unimplemented cluster creation as a successful operation.

The managed platform will add:

```text
nebula login
nebula org list / use
nebula cluster create / list / inspect / scale / upgrade / delete
nebula cluster credentials
nebula node-pool create / inspect / scale
nebula project create / inspect
nebula app deploy / inspect / logs
nebula operation inspect / watch
```

User login needs a separately registered public PKCE client and private credential storage. NEXUS's disabled device grant is not a usable login mechanism. Machine enrollment remains a machine identity operation, not user authentication.

## Kubernetes runtime and networking

Provide separate tenant control planes and isolated worker VMs/nodes for customers receiving cluster administration, CRDs and arbitrary Helm charts. Namespace-only limits do not provide that boundary.

Keep etcd quorum regional. A geographically distributed Nucleus fleet can supply workers or separate regional clusters; its membership does not make it a suitable worldwide etcd quorum.

A production cluster requires an API endpoint, a tested CNI, service/load-balancer integration, persistent storage, certificate rotation, encrypted backups and restore checks, audit records, and a controlled upgrade path. Advertise HA only when failure-domain and quorum requirements are actually met.

For customer-owned nodes, enrollment binds an owner-approved node key to an organization and cluster. Use separate short-lived Kubernetes bootstrap credentials and explicit CSR approval, followed by Node authorization and NodeRestriction. Root-level host changes belong to a separate privileged infrastructure agent, not the existing inference worker.

Outbound Kubernetes API access and Konnectivity handle control-plane communication. Pod and node routing need a real isolated network underlay and CNI. The current `nucleus-fabric` relay carries only the existing fabric protocol; it is not a Kubernetes CNI or general IP tunnel. A regional WireGuard gateway is a candidate for outbound-initiated BYO connectivity. HTTPS-only networks need a separately supported L3 transport.

## cPanel and WHM integration

WHM uses AppConfig and explicit action ACLs. cPanel Jupiter uses `install.json`, Feature Manager and account-context LiveAPI/UAPI. They have different installation and execution models.

The plugins link to NEBULA's primary panel and call the same scoped API. Do not embed a root WHM credential or Kubernetes administrator credential in browser code.

A panel installation has its own enrolled identity. Account linking requires trusted local account identity plus fresh NEXUS organization-owner/admin consent. Store installation/account-generation to organization/project bindings. Do not infer ownership from email, domain, username alone, or submitted organization IDs. Account deletion/recreation invalidates the old binding and must not automatically delete workloads.

## Billing and existing services

Preserve the agreed Nucleus/Positronic machine-management prices. Do not silently include supplied compute, storage, control-plane capacity or supplier charges in the unlimited-machine allowance. NEBULA cluster prices remain an explicit product decision.

Do not repurpose current context/inference API keys for infrastructure administration. Add explicit scopes and fresh role/ownership checks. Keep provisioning credentials and privileged job workers separate from the existing model-worker protocol.

## Primary references

- https://kubernetes.io/docs/concepts/extend-kubernetes/
- https://cluster-api.sigs.k8s.io/introduction.html
- https://kubernetes.io/docs/concepts/security/multi-tenancy/
- https://kubernetes.io/docs/reference/access-authn-authz/kubelet-tls-bootstrapping/
- https://kubernetes.io/docs/reference/access-authn-authz/node/
- https://kubernetes.io/docs/concepts/architecture/control-plane-node-communication/
- https://docs.k3s.io/faq
- https://api.docs.cpanel.net/guides/guide-to-whm-plugins
- https://api.docs.cpanel.net/guides/guide-to-cpanel-plugins/guide-to-cpanel-plugins-add-plugins
- https://support.cpanel.net/hc/en-us/articles/360062418794-Can-I-run-docker-on-a-cPanel-server

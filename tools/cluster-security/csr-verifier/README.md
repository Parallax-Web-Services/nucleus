# NEBULA kubelet CSR policy verifier

Prepared source only. This standard-library Go utility evaluates one projected Kubernetes CSR and returns a typed decision. It has no Kubernetes client, approval action, network transport, file-loading option, private-key input, or certificate signer. It does not authenticate its caller or prove that supplied API/enrollment observations are trustworthy.

Root must review the source before a release binary is built or distributed. No host deployment or CSR approval has occurred. Synthetic tests create test keys and real signed CSRs only in local process memory; they create no CA, kubeconfig, host profile, combined PEM, or operational credential.

## Trust boundary and protocol

The caller must independently obtain:

- Fresh CSR metadata and authenticated `spec` fields from the Kubernetes API.
- A separately admitted node name, Node UID, DNS names and IP addresses. Do not infer admitted names from the CSR or from mutable `Node.status` addresses.
- The fresh current Node object, with name and UID equal to that admission.
- Authentication UID/extra from the independently CA-, lifetime-, CN- and O-validated **current kubelet client public certificate**. Refresh this after rotation; do not permanently pin an old credential ID or copy arbitrary CSR `spec.extra` into the admission.

Current Kubernetes X509 authentication derives `X509SHA256=…` from the complete leaf certificate DER. The caller must confirm its deployed-version rule. This utility requires exactly one `authentication.kubernetes.io/credential-id` value, equal to the independent current-certificate binding; it rejects all other extra fields. An empty authenticated user UID is allowed only when explicitly present and independently expected.

Input is one JSON object on stdin, at most 256 KiB:

```json
{
  "schema_version": 1,
  "policy_kind": "serving",
  "csr": {
    "metadata": {
      "name": "csr-synthetic-example",
      "uid": "11111111-1111-4111-8111-111111111111",
      "resource_version": "42"
    },
    "spec": {
      "request_base64": "<fresh API request bytes encoded as canonical base64>",
      "signer_name": "kubernetes.io/kubelet-serving",
      "usages": ["digital signature", "server auth"],
      "username": "system:node:node-a",
      "uid": "",
      "groups": ["system:nodes", "system:authenticated"],
      "extra": {
        "authentication.kubernetes.io/credential-id": ["X509SHA256=<current validated public leaf DER SHA256>"]
      }
    }
  },
  "enrollment": {
    "node_name": "node-a",
    "node_uid": "22222222-2222-4222-8222-222222222222",
    "allowed_dns_names": ["node-a"],
    "allowed_ip_addresses": ["192.0.2.10"],
    "allowed_auth_uid": "",
    "allowed_auth_extra": {
      "authentication.kubernetes.io/credential-id": ["X509SHA256=<same independently derived current public leaf digest>"]
    }
  },
  "current_node": {
    "name": "node-a",
    "uid": "22222222-2222-4222-8222-222222222222"
  }
}
```

The example is a protocol illustration, not a runnable admission or CSR. All fields shown are required. `spec.expiration_seconds` is optional; omit it when unset. Explicit nulls, duplicate keys, unknown fields, multiple JSON values, type substitutions and oversized input are rejected. Arrays/maps remain explicit when empty. The current profile requires a nonempty current X509 credential binding. Resource version is retained as an opaque bounded string.

A valid result has `schema_version:1`, `decision:"valid"`, `code:"csr_policy_valid"`, and `binding` with:

- `policy_kind`, `csr_name`, `csr_uid`, `resource_version`, `node_name`, `node_uid`.
- `request_der_sha256`, `request_pem_sha256`, `spki_sha256`, `input_sha256`.

A rejected result contains only the schema, `decision:"reject"` and a fixed code. It never echoes raw input, key/CSR bytes, addresses, credential IDs, parser errors or paths. Exit status is 0 for a valid policy decision and 2 for rejection/output failure. A valid decision is **not approval**.

The caller must retain the exact input/result poststates, re-fetch and compare the current enrollment/Node UID, and use the exact CSR UID and resource version as API update preconditions. It must independently require a pending/unissued CSR and reject changed signer, request, authenticated context, usages or conditions. Kubernetes has no atomic transaction across a CSR and Node: this utility does not claim cross-resource atomicity, freshness after its input snapshot, certificate issuance, or successful TLS service operation.

## Constrained certificate profile

Both policies require exact authenticated username `system:node:<admitted name>`, exactly the groups `system:nodes` and `system:authenticated`, and the current authentication UID/extra binding. The raw CSR subject must contain exactly one CN of that name and one O of `system:nodes`, each in its own RDN. Other, duplicate, multivalued or surprising subject attributes are rejected.

`serving` requires signer `kubernetes.io/kubelet-serving`. It accepts only a single noncritical DNS/IP SAN extension in exactly one extension-request attribute, with the **exact admitted DNS/IP sets**, at least one name, and no other attributes/extensions. Wildcards, email, URI, other GeneralName kinds, duplicate names, noncanonical DNS/IP spellings, mapped IPv4, loopback, link-local, unspecified and multicast addresses are rejected.

`selfnodeclient-renewal` is separate and requires signer `kubernetes.io/kube-apiserver-client-kubelet`. It permits no SAN, extension or attribute at all. It does not support bootstrap users or groups and never treats client renewal as serving approval.

Usages must be exactly digital signature plus server/client auth for the selected policy. RSA may additionally request key encipherment; ECDSA may not. CA signing, mixed server/client usages and duplicate/extra usages are rejected. An explicit requested lifetime must be 600–31,536,000 seconds; unset lifetime remains the independent signer's responsibility.

Supported public keys are RSA 2048–8192 bits with exponent 65537 and an odd positive modulus, or ECDSA P-256/P-384/P-521 with a valid point. Supported signatures are the corresponding SHA-256/384/512 RSA PKCS#1 v1.5, canonical RSA-PSS with matching hash/MGF/salt, or ECDSA variants. SHA-1, MD5, DSA, Ed25519, unknown algorithms, extra parameters and noncanonical SPKI encodings are rejected. Ed25519 is intentionally excluded from this initial profile; no custom curve arithmetic or new crypto dependency is added.

The request must contain exactly one canonical LF `CERTIFICATE REQUEST` PEM block, without headers, prefix, suffix or additional blocks, inside canonical standard base64. Raw DER child counts, subject, attributes, extension-request values, SAN GeneralName forms and signature algorithm encoding are checked before the standard X509 signature verification. This closes permissive-parser cases such as ignored trailing SEQUENCE fields and unrecognized SAN kinds.

## Offline validation

Use the already installed Go 1.27.3 toolchain with network resolution disabled:

```sh
GOTOOLCHAIN=local GOPROXY=off GOSUMDB=off GOENV=off go test -race -count=1 ./...
GOTOOLCHAIN=local GOPROXY=off GOSUMDB=off GOENV=off go vet ./...
```

Fixtures cover genuine RSA/PSS/ECDSA signatures, genuine self-node renewal, proof-of-possession failure, current credential refresh, stale Node UID, wrong authenticated identities/groups, cross-policy signer/usages, weak keys/SHA-1, hidden raw ASN.1 fields, duplicate/multivalued subjects, extra request attributes/extension values, CA/unknown extensions, every forbidden SAN GeneralName class, PEM/base64 ambiguity, JSON ambiguity, resource bounds and output privacy. Fuzz seeds verify typed failures without host data. No operational API, SSH, real host key, deployment, approval or recovery operation is exercised.

## Primary-source references

- [Kubernetes CSR signer profiles](https://kubernetes.io/docs/reference/access-authn-authz/certificate-signing-requests/#kubernetes-signers): kubelet serving and client signers have distinct usages/SAN rules; serving is not automatically approved by the controller manager.
- [Kubernetes X509 authentication](https://raw.githubusercontent.com/kubernetes/kubernetes/master/staging/src/k8s.io/apiserver/pkg/authentication/request/x509/x509.go): current leaf credential-ID derivation. Bind the deployed release when integrating.
- [Go X509 source](https://go.dev/src/crypto/x509/x509.go), [parser](https://go.dev/src/crypto/x509/parser.go), and [ASN.1 source](https://go.dev/src/encoding/asn1/asn1.go): signature validation and the parser behavior that motivates raw structure checks.

This source is separate from the frozen foundation checkpoint. There is no generic Kubernetes/HA installer or blanket CSR approval policy here.

# Standalone NEBULA CLI

The development build supplies a separate `nebula` executable. It shares the tested Nucleus engine in process and does not require an installed `nucleus` command.

## Build

```bash
bash scripts/build.sh
./bin/nebula version
./bin/nebula help
```

The current CLI version is `0.6.0-dev`. Build preview archives with `python3 scripts/package-nebula.py`; each source snapshot has its own immutable output directory under `dist/nebula`. The published Nucleus 0.5 packages and running relay remain unchanged.

## Use the existing machine

By default NEBULA uses `NUCLEUS_HOME`, or the existing Nucleus user configuration directory. It keeps that machine's identity, membership and hosted binding.

```bash
./bin/nebula machine identity
./bin/nebula machine status
./bin/nebula fabric members
```

For a separate installation, set an absolute `NEBULA_HOME` before initializing it. Use the same directory for its later commands. Help and version do not initialize state.

## Enroll and connect

For a machine that should use the managed relay:

```bash
./bin/nebula machine enroll --url https://nucleus.parallax.link/dashboard
./bin/nebula network connect --no-open
```

An organization owner or administrator approves the fingerprint. Both machines need accepted membership in the same private fabric, an eligible managed organization registration, and relay access enabled in Positronic. Start the owner first. Network connection remains a foreground process.

Ongoing hosted telemetry or an explicitly configured model worker runs separately:

```bash
./bin/nebula machine run
```

The existing `--inference`, `--model-root` and model-management flags remain explicit choices. Pairing commands are grouped under `nebula fabric`; use `nebula fabric help` for the invitation/request/grant exchange.

## Relay operator

```bash
./bin/nebula relay serve --issuer-public-key-file /absolute/path/issuer.pub --listen 127.0.0.1:8743
```

The relay uses the existing capability and inner mTLS protocol. It accepts a protected public issuer key and binds loopback behind HTTPS ingress. Existing `nucleus nebula relay` commands remain compatible.

## Hosted login and cluster reads

The hosted panel is at <https://nebula.parallax.link/dashboard>. The development CLI supports browser sign-in, organization selection and cluster reads after the panel's separately registered CLI client is activated:

```bash
./bin/nebula login --url https://nebula.parallax.link
./bin/nebula org list
./bin/nebula org use ORGANIZATION_ID
./bin/nebula cluster list
./bin/nebula cluster show CLUSTER_ID
./bin/nebula logout
```

Sign-in opens the NEXUS flow through NEBULA with PKCE and a temporary loopback callback. The CLI stores its own credentials in private local state. Machine enrollment remains a separate approval of a machine key; it does not sign in the user or create fabric membership.

## Managed Kubernetes

This CLI build exposes machine, fabric and network operations plus hosted organization and cluster reads. Kubernetes provisioning, cluster credentials and deployment commands are not implemented by this build. See [the platform contract](NEBULA_PLATFORM.md) for the agreed standalone panel, hosting modes and optional cPanel/WHM integration.

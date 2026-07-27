Deferred until Internal Test Alpha passes

# Release image narrative

`docker/release/Dockerfile` and [`manifest.json`](../../docker/release/manifest.json)
define the immutable `dirextalk/vnet-server` runtime image used by the
optional production profile. It contains the unified node, realtime gateway,
Agent Control, identity provision, and opaque-push binaries; production
selection remains profile-scoped.

Build and publish only through the checked-in command:

```text
bash scripts/publish-production-release.sh
```

Runtime execution accepts only
`dirextalk/vnet-server@sha256:<64 lowercase hex>`. The release-image contract
check is:

```text
bash scripts/check-release-image.sh
```

The image has no shell entrypoint, development CA generator, legacy adapter, or
embedded credential. Production mounts regular root-owned files for node
identity, database URLs, TLS material, private CA, and MLS sequencer keys;
runtime processes use UID/GID `10001:10001`. Release retention, host
installation, and cross-environment update/rollback remain outside Internal
Test Alpha.

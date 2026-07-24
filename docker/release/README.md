# Product Core Alpha release image

`docker/release/Dockerfile` and [`manifest.json`](manifest.json) define the immutable `dirextalk/vnet-server`
runtime image used by the fresh-only production Compose stack. It contains
the unified `dtx-node`, realtime sync gateway (`/usr/local/bin/dtx-realtime-sync-gateway`),
Agent Control (`/usr/local/bin/dtx-agent-control`), identity provision, and
opaque-push binaries; production Compose selects only the
entrypoints needed for the current Product Core services.

Build and publish from a clean commit with the documented release command:

```text
bash scripts/publish-production-release.sh
```

The publisher targets `linux/amd64`, uses the checked-in Dockerfiles and
locked dependency graph, and reads back immutable registry digests. Runtime
execution accepts only `dirextalk/vnet-server@sha256:<64 lowercase hex>`
(`dirextalk/vnet-server@sha256:<64>` in the contract notation);
`latest` is a discovery pointer and is never written into production
environment files. `scripts/check-release-image.sh` validates the Dockerfile,
manifest, binary paths, digest inputs, and publication contract without
starting a server.

The image has no shell entrypoint, development CA generator, legacy database
adapter, or embedded credential. Production mounts regular root-owned files
for node identity, group/mailbox/realtime database URLs, TLS certificates and
keys, the private CA, and the MLS sequencer key. Runtime processes use UID/GID `10001:10001`; the one-shot identity binding issuer is root-only and receives
only its fixed request/output mounts from the host helper.

The default stack keeps Public/Indexer discovery and opaque push disabled.
The opaque-push broker is not a production service or ingress route in this
release. Agent Control remains a separately reviewed, opt-in Compose profile;
its fixed invocation is `/usr/local/bin/dtx-agent-control --config /etc/dirextalk/agent-control.json`;
its image artifact and shared PostgreSQL grants are retained for that profile,
but Product Core Alpha does not claim Agent execution or Connector deployment.

Product Core Alpha is fresh-only: there is no release bundle format, host
provisioner, cross-version update/rollback, compatibility marker, retained
release catalog, receipt chain, or historical compiler-cache cleanup in the
release image or its operating scripts.

# vNext server release image

`docker/release/Dockerfile` builds the production image containing the
independent `dtx-node`, `dtx-opaque-push-broker`, `dtx-realtime-sync-gateway`,
and `dtx-agent-control` artifacts used by the
new Rust release CLI. The production repository is exactly
`dirextalk/vnet-server`. Releases use an immutable version/commit tag and must
be read back by digest after publication. A `latest` discovery pointer may be
updated, but deployment execution accepts only the read-back
`dirextalk/vnet-server@sha256:<64>` reference.

The exact four binaries, their Cargo packages, fixed image paths, and runtime
permission contract are recorded in [`manifest.json`](manifest.json). Both the
release Dockerfile and this manifest are source-controlled inputs; a release
must not add an unlisted executable.

The default entrypoint remains the unified Rust node. A separately scheduled
Gateway container must override the entrypoint with
`/usr/local/bin/dtx-realtime-sync-gateway`; it uses its own listener, runtime
login, session authentication and resource limits and is never merged into
`dtx-node` or Agent Control. Both processes run as UID/GID `10001`. The image
has no shell entrypoint, local
test CA generator, development database environment adapter, or embedded
credential. Production must mount separate regular files and configure:

Both build and runtime bases are pinned to exact multi-platform index digests;
dependency updates require an explicit Dockerfile review.

- `DTX_NODE_PUBLIC_ORIGIN`
- `DTX_NODE_TENANT_ID`
- `DTX_NODE_INDEXER_ID`
- `DTX_IDENTITY_DATABASE_URL_FILE`
- `DTX_GROUP_DATABASE_URL_FILE`
- `DTX_GROUP_MLS_SEQUENCER_KEY_FILE`
- `DTX_MAILBOX_DATABASE_URL_FILE`
- `DTX_PUBLIC_FEED_DATABASE_URL_FILE`
- `DTX_INDEXER_DATABASE_URL_FILE`
- `DTX_NODE_TLS_CERTIFICATE_FILE`
- `DTX_NODE_TLS_PRIVATE_KEY_FILE`

The independent Gateway container exposes `9444` and requires:

- `DTX_REALTIME_SYNC_DATABASE_URL_FILE` (preferred production credential file;
  raw `DTX_REALTIME_SYNC_DATABASE_URL` is retained only for bounded local use)
- `DTX_REALTIME_SYNC_TLS_CERTIFICATE_FILE`
- `DTX_REALTIME_SYNC_TLS_PRIVATE_KEY_FILE`
- optional `DTX_REALTIME_SYNC_BIND` (default `0.0.0.0:9444`)

Release orchestration must schedule one Gateway service beside each logical
node, mount only that node's realtime database credential and TLS files, set
the fixed Gateway entrypoint above, publish only the WSS listener, and retain
the image digest and process identity as separate rollout/rollback evidence.

The process fails closed when a public listener has no TLS configuration. Run
database migrations and least-privilege grants as a separate, explicitly
authorized operation; the local-development migrator is deliberately not
included in this image.

## Opaque Push Broker

Production schedules the opaque-push broker as a separate container beside
each logical node. It must override the image entrypoint with the fixed
`/usr/local/bin/dtx-opaque-push-broker` command and override the image user to
`0:0` only for its secure startup reads. The process itself clears supplementary
groups and drops to `DTX_PUSH_UID=10001` and `DTX_PUSH_GID=10001` before it
creates pools, starts the FCM provider, or binds listeners. Its scheduler
identity, resource limits, rollout evidence, and process identity remain
independent of `dtx-node` and Gateway; do not merge it into either process.

Each broker receives a root-only, read-only mount containing regular mode
`0400` files. Mount only the matching node's files and set these references:

- `DTX_PUSH_TENANT_ID`
- `DTX_PUSH_IDENTITY_DATABASE_URL_FILE`
- `DTX_PUSH_REGISTRATION_DATABASE_URL_FILE`
- `DTX_PUSH_BROKER_DATABASE_URL_FILE`
- `DTX_PUSH_ROOT_KEY_FILE`
- `DTX_PUSH_FCM_SERVICE_ACCOUNT_FILE`
- `DTX_PUSH_TLS_CERTIFICATE_FILE`
- `DTX_PUSH_TLS_PRIVATE_KEY_FILE`
- `DTX_PUSH_UID=10001` and `DTX_PUSH_GID=10001`
- `DTX_PUSH_BIND=0.0.0.0:9448` and `DTX_PUSH_READY_BIND=127.0.0.1:9488`
- `DTX_PUSH_IDENTITY_LOGIN=dtx_push_identity_auth`
- `DTX_PUSH_REGISTRATION_LOGIN=dtx_push_registration`
- `DTX_PUSH_BROKER_LOGIN=dtx_push_broker`

The three database URL files carry distinct least-privilege login URLs for
`dtx_push_identity_auth`, `dtx_push_registration`, and `dtx_push_broker`.
Provision the matching migration and grants separately before scheduling the
broker. Publish only TLS listener `9448`; readiness `9488` is internal loopback
health checking and is never exposed. The public same-origin ingress sends only
`PUT` and `DELETE /v1/devices/push-registrations/fcm` to this broker. Durable
Mailbox Pull/ACK and the account read cursor remain elsewhere as delivery
truth.

## Agent Control

Production schedules Agent Control as a separate non-root service beside the
node and the other independent services. Select it only with the fixed
entrypoint `/usr/local/bin/dtx-agent-control` and the fixed argument
`--config /etc/dirextalk/agent-control.json`; the image default remains
`/usr/local/bin/dtx-node`. Do not pass an arbitrary command or Agent Control
environment interface, and do not merge this process into the node, Gateway,
or push broker.

Run it as UID/GID `10001:10001`. Mount the existing operator-owned config file
and only the database URL, TLS, CA, and issuer files named by
[`bins/dtx-agent-control/config.example.json`](../../bins/dtx-agent-control/config.example.json)
and [`docs/agent-acceptance-operator.md`](../../docs/agent-acceptance-operator.md).
No new secret, credential, listener, or public port is introduced by the
release image; schedule and publish the configured listeners as a separate
service according to those existing documents. This packaging does not claim
that Agent Control is deployed or live.

Dry-run the release command from `dirextalk-vnext-deployer`:

```powershell
cargo run --locked -- plan --manifest release.example.json
```

## Executable publication contract

`production-release.json` is the canonical authoritative input. It fixes schema
version 1, the only authorized repository `dirextalk/vnet-server`, platform
`linux/amd64`, both Dockerfiles, the workspace SemVer, and the decision to
maintain a runtime-only `latest` discovery pointer. Update the workspace and
input versions together, commit them, and publish only from a clean worktree:

```text
bash scripts/publish-production-release.sh
```

After proving the clean `HEAD`, the no-argument publisher extracts that exact
commit with `git archive` into a private, verified source snapshot under
`target/production-release`. It reruns the source check after the mandatory
cross-version gate and before creating a unique disposable Buildx builder.
Both runtime and migrator builds use the same read-only snapshot, so a later
working-tree change cannot alter either build context. The publisher first
proves all four immutable tags absent. It publishes the runtime Dockerfile as
`dirextalk/vnet-server:<semver>` and `:git-<40hex>`, and the production migrator
as `:migrate-<semver>` and `:migrate-git-<40hex>`. Both builds target only
`linux/amd64`. It independently reads the registry manifest digest back for
each immutable tag and requires each pair to match its Buildx push metadata.
Only after both products pass that check does it repoint
`dirextalk/vnet-server:latest` to the runtime digest and read that pointer back.
The migrator is never published as or selected through `latest`. The snapshot
is removed on every normal publisher exit together with its builder state.

On success, canonical digest facts are written to
`target/production-release/release-facts.json`. Runtime execution uses only its
`server_image` and `migrator_image` repository-at-digest values. The bundle
builder consumes those facts directly:

```text
python3 tools/vnext-stack-bundle.py build --source-root . \
  --release-facts target/production-release/release-facts.json \
  --output target/production-release/dirextalk-vnext.bundle
```

The publisher always removes its own disposable builder and dedicated cache;
it never deletes registry tags, local tagged images, containers, or volumes.
If the process is interrupted before its trap runs, the bounded cleanup command
reads the exact recorded builder name and removes only that builder/cache:

```text
bash scripts/cleanup-production-release.sh
```

An immutable runtime tag may remain when a later migrator step fails. This is
intentional evidence, not cleanup debris; `latest` is left unchanged and the
same immutable tag is never overwritten. Publication therefore requires an
exclusive publisher for the repository in addition to the preflight checks.

The generated Buildx plan uses the Dockerfile above, exact platforms, source
revision labels, and an immutable version tag.

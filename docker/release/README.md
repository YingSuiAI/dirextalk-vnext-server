# vNext server release image

`docker/release/Dockerfile` builds the production image containing the
independent `dtx-node` and `dtx-realtime-sync-gateway` artifacts used by the
new Rust release CLI. The default repository is `dirextalk/vent`, but the
release manifest may select another repository. Releases use an exact SemVer
tag and must be read back by digest after publication; no floating `latest` tag
is produced.

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

Dry-run the release command from `dirextalk-vnext-deployer`:

```powershell
cargo run --locked -- plan --manifest release.example.json
```

The generated Buildx plan uses the Dockerfile above, exact platforms, source
revision labels, and an immutable version tag.

# vNext server release image

`docker/release/Dockerfile` builds the production `dtx-node` image used by the
new Rust release CLI. The default repository is `dirextalk/vent`, but the
release manifest may select another repository. Releases use an exact SemVer
tag and must be read back by digest after publication; no floating `latest` tag
is produced.

The image contains only the unified Rust node and CA roots. It runs as UID/GID
`10001`, listens on container port `8443`, and has no shell entrypoint, local
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

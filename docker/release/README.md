Deferred until Internal Test Alpha passes

# Release image pointer

The release-image narrative moved to
[`docs/deferred-production/release-image.md`](../../docs/deferred-production/release-image.md).
The image contract remains an immutable
`dirextalk/vnet-server@sha256:<64 lowercase hex>` reference.

Image membership is fixed by `manifest.json`, including
`/usr/local/bin/dtx-agent-control`. Production starts that binary with
`--config /etc/dirextalk/agent-control.json` under UID/GID `10001:10001`.
Registry evidence records the exact `dirextalk/vnet-server@sha256:<64>` value.

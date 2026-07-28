Deferred until Internal Test Alpha passes

# Production stack pointer

The production-stack narrative moved to
[`docs/deferred-production/production-stack.md`](../../docs/deferred-production/production-stack.md).
The Compose contract still uses immutable
`dirextalk/vnet-server@sha256:<64 lowercase hex>` inputs. Opaque push is a required Product Core service in that optional hardening profile.

The runtime image contents are fixed by `docker/release/manifest.json`. The
bundle installs `/usr/local/bin/dtx-agent-control` and starts it with
`--config /etc/dirextalk/agent-control.json` under UID/GID `10001:10001`.

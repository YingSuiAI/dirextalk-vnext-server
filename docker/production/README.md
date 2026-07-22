# Single-node production bundle

This directory is the immutable single-EC2 bundle for one logical vNext node.
It is deliberately independent from `docker-compose.local.yml` and does not
copy the legacy ProductCore stack. Three independent hosts can use the same
bundle with different `DTX_NODE_*` values (the checked-in x6/x7/x8 examples).

The runtime image is published under an immutable version or commit tag and
read back from the registry before use as:

```text
dirextalk/vnet-server@sha256:<64 lowercase hex>
```

The four-binary release contract is unchanged. `Dockerfile.migrate` builds a
separate one-shot `dtx-production-migrate` image. It accepts only the fixed
operations `bootstrap-roles`, `migrate`, `grant-roles`, and guarded
`teardown-roles`; all database credentials are root-owned URL files, never
raw environment values. Role teardown only disables login and requires an
explicit confirmation string.

Provision `/etc/dirextalk/vnext/{config,secrets,tls}` as root. Secret and key
files must be regular files owned by `root:root` with mode `0400`; non-secret
configuration is `0644` and root-owned. The scripts reject symlinks, writable
secret directories, mutable image tags, and missing TLS material. Populate one
password file per fixed role under `secrets/role-passwords/`; the migrator
escapes those values in memory and never emits them. Caddy routes
node HTTPS/MCP and realtime WSS only. Agent Control remains on its dedicated
native TLS/mTLS listeners and is not terminated by Caddy.

Use the bounded scripts from the repository root:

```text
scripts/production-stack/install.sh
scripts/production-stack/bootstrap.sh
scripts/production-stack/update.sh
scripts/production-stack/verify.sh
scripts/production-stack/down.sh
```

They accept no positional command or arbitrary path. `cleanup-cache.sh` only
removes Docker dangling images and the BuildKit cache after a successful
bootstrap/update; it never touches volumes, active images, logs, or secrets.

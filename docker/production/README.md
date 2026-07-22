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

The registry may also publish `dirextalk/vnet-server:latest` as a discovery
pointer. It is never an execution input. `validate-images.sh` checks the exact
repository and digest form of the runtime, migrator, PostgreSQL, Caddy, and
probe images immediately before every pull or up. Replace the digest-shaped
values in the examples with registry read-back results before installation.

The four-binary release contract is unchanged. `Dockerfile.migrate` builds a
separate one-shot `dtx-production-migrate` image. It accepts only the fixed
operations `bootstrap-roles`, `migrate`, `grant-roles`, `verify-roles`, and guarded
`teardown-roles`; all database credentials are root-owned URL files, never
raw environment values. Role teardown only disables login and requires an
explicit confirmation string. It preloads the complete password set, uses
`O_NOFOLLOW`, verifies a root-owned non-writable ancestor chain, reads and
checks one descriptor, and mutates roles in one transaction. The PostgreSQL
gate normalizes role attributes/memberships and tests Agent Control's required
and forbidden privileges before any application starts.

Provision `/etc/dirextalk/vnext/{config,secrets,tls}` as root. Secret and key
files read by UID/GID `10001:10001` are `root:10001` mode `0440`. PostgreSQL's
admin password, the admin URL, and role-password inputs are root-loaded and
remain `root:root` mode `0400`. Public certificates/CA bundles are
`root:root` mode `0444`; private keys are never world-readable. Non-secret
configuration is `0644` and root-owned. Populate one password file per fixed
role, including `dtx_agent_control`, under `secrets/role-passwords/`; the
migrator never emits them. Caddy normally routes node HTTPS/MCP and realtime
WSS only. The fixed fresh-host provisioner is the sole exception: it runs Caddy
in Agent Control's network namespace, publishes 80/443 there, and routes only
`/mcp*` to loopback `127.0.0.1:9081`; no other owner route is public. Agent
Control remains on its dedicated
native TLS/mTLS listeners and is not terminated by Caddy.

Set `DTX_AGENT_CONTROL_BIND` to the EC2 private/VPC address. Docker publishes
9443 (enrollment server-auth TLS), 9444 (Connector mTLS), and 9445 (legacy
gateway mTLS) only on that address. The security group and host firewall must
allow 9443 solely from approved enrollment clients, 9444 solely from approved
Connector networks, and 9445 solely from the legacy gateway. Do not allow
these ports from `0.0.0.0/0`; health/owner ports 9080/9081 stay unpublished.

Opaque push is fail-closed disabled in this bundle: no broker service and no
public registration route are present. Enabling FCM requires a separately
reviewed profile with tenant binding, exact PUT/DELETE ingress, credentials,
and readiness checks; passing an `opaque-push` profile cannot start anything.

Use the bounded scripts from the repository root:

```text
scripts/production-stack/install.sh
scripts/production-stack/bootstrap.sh
scripts/production-stack/update.sh
scripts/production-stack/verify.sh
scripts/production-stack/down.sh
```

They accept no positional command or arbitrary path. `cleanup-cache.sh` only
removes Docker dangling images and the BuildKit cache after retained success
evidence exists; it never touches volumes, active images, logs, or secrets.
Bootstrap records the executed digest set. Update records both prior and
candidate immutable sets plus the compose checksum, waits for real node,
realtime, Agent Control, and PostgreSQL privilege readiness, and only attempts
the retained prior set when both releases declare
`forward-schema-compatible-v1` and the compose checksum is unchanged.

This stage supports fresh installation and digest changes within the same
`DTX_RELEASE_VERSION`. Cross-version database-history compatibility, skipped
release upgrades, and rollback across schema changes are not implemented yet;
both the production updater and host installer reject a version change before
mutation. SemVer is an identity value only—there is no adjacent-version or
`current + 1` rule. That explicit migration-history contract is the next stage,
and `latest` remains an external discovery pointer outside execution inputs.

## Hash-bound deployment bundle

`tools/vnext-stack-bundle.py build` emits a deterministic uncompressed tar
with the single root `dirextalk-vnext-stack/`. Its canonical `manifest.json`
uses schema `dirextalk.vnext-stack-bundle` version 1 and binds the SemVer,
40-character source commit, `linux-amd64` target, independently digest-pinned
server/migrator `dirextalk/vnet-server@sha256:<64>` references, fixed installer
digest, and a sorted exact file/hash/mode allowlist. The archive SHA-256 is a
separate deployment-manifest fact. Symlinks, hard links, special files,
absolute or parent paths, mutable tags,
unexpected entries, owners, or modes are rejected. An immutable published tag
and its registry-read-back digest are authoritative; `latest` remains only an
external discovery pointer that Deployer may compare and is never written into
the bundle, install request, runtime environment, update, or rollback input.

Cloud-init installs these repository files, independently of the bundle, as
root-owned mode `0555` executables and records their SHA-256 values in
deployment state:

```text
scripts/production-stack/host/install-vnext
  -> /usr/local/libexec/dirextalk/install-vnext
scripts/production-stack/host/read-vnext-receipt
  -> /usr/local/libexec/dirextalk/read-vnext-receipt
```

Both accept no arguments. The installer exclusively consumes root-owned mode
`0400` regular files `/home/ubuntu/dirextalk-vnext.bundle` and
`/home/ubuntu/dirextalk-vnext.request`. The canonical request schema is
`dirextalk.vnext-install-request` version 1 with exact fields `target`,
`domain`, `version`, `source_commit`, `bundle_sha256`, `manifest_sha256`,
`server_image`, `migrator_image`, and nullable
`previous_receipt_sha256`. It rechecks every archive and manifest invariant,
materializes only `/opt/dirextalk-vnext/releases/<bundle_sha256>/`, invokes
only that release's digest-bound `scripts/production-stack/install.sh`, and
atomically writes root-owned mode `0600`
`/var/lib/dirextalk-vnext/receipts/current.json`.

The canonical receipt schema is `dirextalk.vnext-installed-release` version 1.
It repeats the request facts, adds `state` (`installed` or `rolled_back`),
`installed_at_ms`, and `receipt_sha256`; the receipt digest is SHA-256 of the
canonical object with `receipt_sha256` omitted. Every request must chain from
the current receipt. A failed candidate restores only the retained fixed
release, only when both releases contain the exact compatibility marker, then
writes a chained `rolled_back` receipt and still exits unsuccessfully. The
reader validates type, owner, mode, canonical encoding, exact keys, immutable
image references, and the self-hash before emitting only the receipt bytes.

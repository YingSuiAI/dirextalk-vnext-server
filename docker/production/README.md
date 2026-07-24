# Product Core Alpha production stack

This directory contains the fresh-only, single-node Docker Compose stack for
Dirextalk Product Core Alpha. It starts from an empty PostgreSQL schema and
fresh client state. Existing schema histories, legacy Matrix state, upgrades,
rollbacks, retained releases, host bundles, and incident recovery are outside
this release and are intentionally rejected rather than migrated.

Every image input is an immutable registry read-back digest. The server and
migrator use `dirextalk/vnet-server@sha256:<64 lowercase hex>`; PostgreSQL,
Caddy, and the curl probe use their exact repository-at-digest references.
`latest`, mutable tags, and arbitrary image repositories are never execution
inputs. Validate the checked-in generic example after replacing its sample
digests:

```text
python3 tools/validate-production-images.py docker/production/examples/production.env.example
```

## Install and operate

Run the bounded root-only scripts in order. They accept no positional command
or arbitrary path:

```text
scripts/production-stack/install.sh
scripts/production-stack/bootstrap.sh
scripts/production-stack/verify.sh
scripts/production-stack/down.sh
```

`install.sh` creates only the fixed `/etc/dirextalk/vnext/{config,secrets,tls}`
and `/var/lib/dirextalk/vnext` roots, installs the Compose/Caddy templates,
validator, and a generic `production.env` example. It does not create release,
receipt, current-environment, cache, or recovery records. Before bootstrap,
replace the example values and provision all required files as root.

`bootstrap.sh` validates Compose interpolation, file ownership/modes, and
immutable image references, then runs `docker compose up -d` and the same node
and realtime readiness verification used by `verify.sh`. It writes no state
outside Docker's named volumes. `verify.sh` repeats the file/image checks and
recreates only the readiness probes; `down.sh` stops the stack without volume
removal.

Secret and key files read by UID/GID `10001:10001` are `root:10001` mode
`0440`; admin URLs/passwords and role-password files are root-owned mode
`0400`. Public certificates and the private CA are `root:root` mode `0444`;
private keys remain non-world-readable. Database URLs are mounted as regular
files through the `*_DATABASE_URL_FILE` variables; raw URL environment values
are forbidden. The fixed TLS/CA files, node hostname/public origin, tenant
identifier, and role/password grants must remain aligned with the Compose and
Caddy templates.

The migrator performs only the fresh baseline operations
`bootstrap-roles`, `migrate`, `grant-roles`, and `verify-roles`. The shared
PostgreSQL role contract, including `dtx_agent_control`, `dtx_agent_peer_admin`,
MCP credential digest functions, Connector bootstrap issuance tables, and
directory index cache grants, remains unchanged.

Agent Control is deferred and default-off. Its Compose services are available
only through the reviewed `agent-control` profile, with a private/VPC
`DTX_AGENT_CONTROL_BIND`; the default stack neither mounts its config/secrets
nor publishes its readiness service. Public Channel/Indexer services and all
opaque-push broker/registration routes are also default-off; opaque push is fail-closed disabled in this bundle.

The fixed client-binding helpers under
`scripts/production-stack/host/client-binding-*` accept no caller-selected
paths or commands. They enforce root-owned `0700` directories, exact CA and
request/export modes, same-filesystem atomic moves, one-link regular files,
and bounded shred cleanup. Run the artifact contract test before release:

```text
python3 tools/test-client-binding-release-artifacts.py
```

Historical deployment, cross-version update/rollback, and compiler-cache
machinery are not part of Product Core Alpha.

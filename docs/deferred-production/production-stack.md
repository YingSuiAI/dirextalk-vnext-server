Deferred until Internal Test Alpha passes

# Production stack narrative

This directory contains the fresh-only, single-node Docker Compose stack for
the optional Product Core production profile. It starts from an empty
PostgreSQL schema and fresh client state; historical state and cross-environment
operations are outside this hardening work.

Every image input is an immutable registry read-back digest. The server and
migrator use `dirextalk/vnet-server@sha256:<64 lowercase hex>`; PostgreSQL,
Caddy, and probe images use their exact repository-at-digest references.
Validate the checked-in example after replacing sample digests:

```text
python3 tools/validate-production-images.py docker/production/examples/production.env.example
```

The bounded root-only scripts are run in order:

```text
scripts/production-stack/install.sh
scripts/production-stack/bootstrap.sh
scripts/production-stack/verify.sh
scripts/production-stack/down.sh
```

They validate ownership/modes, Compose interpolation, immutable images, fresh
roles/migrations, and node/realtime readiness. They do not publish or mutate
the Internal Test Alpha evidence bundle. Agent Control and Public/Indexer
services remain explicit profiles, and opaque push remains a separate reviewed
service. Fixed client-binding helpers accept only closed, root-owned files.

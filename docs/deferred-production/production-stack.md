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

The deployment-binding ticket issuer is also a root-only one-shot profile.
Its host helper copies the shared identity database URL into the isolated
deployment-binding directory as a root-owned `0600` transient file; the
container never relaxes the protected-file reader to accept the runtime
service group's `0440` secret. Ticket cleanup shreds that transient copy with
the request, CA copy, ticket, and exported fallback file. This path shipped in
0.1.12 and was exercised on a fresh Hong Kong EC2 deployment through live
ticket redemption.

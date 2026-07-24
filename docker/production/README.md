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
login role, including `dtx_agent_control`, under `secrets/role-passwords/`; the
migrator never emits them. `dtx_agent_peer_admin` is instead a passwordless
`NOLOGIN NOINHERIT` capability role: it has no runtime membership or table
access and receives only `agent` schema usage plus the two exact MCP credential
digest register/revoke functions. Caddy normally routes node HTTPS/MCP and realtime
WSS only, and accepts MCP only as `POST /mcp`. The fixed fresh-host provisioner
is the sole exception: it runs Caddy in Agent Control's network namespace,
publishes 80/443 there, and forwards to loopback `127.0.0.1:9081` only the
authenticated, method-specific Owner API allowlist registered in `owner_http.rs`
(Connector control, bindings, conversation grants and route runs, route
bootstraps, identity approvals, provisioning targets/deliveries, and
revocations). All other Owner paths and methods fall through to the node route;
the Owner listener itself remains loopback-only. The shared Caddy template does
not receive this allowlist because its network topology cannot reach that
loopback listener. Agent Control remains on its dedicated
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

They accept no positional command or arbitrary path. `cleanup-cache.sh` removes
the retired pre-bundle compiler tree at the exact fixed path
`/opt/dirextalk-vnext/build` only after authenticating its root ownership,
non-writable directory tree, file types, link counts, device boundary, and lack
of symlinks or mount points. Current and recovery releases live under the
separate `/opt/dirextalk-vnext/releases` root. The helper also removes dangling
images older than 24 hours and unused BuildKit cache after retained success
evidence exists. Each operation has a 120-second termination bound; BuildKit is
reduced toward a fixed 1 GiB maximum while reserving 512 MiB. The cleanup never
touches releases, volumes, containers, active images, logs, source trees,
configuration, TLS, or secrets.
Bootstrap records the executed digest set. Update records both prior and
candidate immutable sets plus the compose checksum, waits for real node,
realtime, Agent Control, and PostgreSQL privilege readiness, and only attempts
the retained prior set when both releases declare
`forward-schema-compatible-v1` and the compose checksum is unchanged.

This stage supports fresh installation, digest changes, and the strictly
forward `0.1.1` → `0.1.4` schema-history transition. A candidate and its
retained prior release must both carry the authenticated
`forward-schema-compatible-v1` marker. The migrator runs only forward `up`
migrations; no installer or rollback path invokes a down migration. Named
volumes, operator configuration, secret files, and TLS material are preserved.
If readiness fails after the forward migration, rollback is code-only: the
retained prior images and configuration are reconciled with `--no-deps` while
the new schema remains in place. The prior release is retained for this
recovery and the receipt chain records the rollback outcome.

Admission is replay-safe: an already-installed authenticated candidate receipt
is a no-op, and a crash-recovered prior/rolled-back receipt can be retried only
when its receipt digest chain and compatibility marker validate. Version
changes must be strictly increasing SemVer values; same-version digest updates
remain supported. `latest` remains an external discovery pointer outside
execution inputs.

Before the first pull or Compose mutation, `update.sh` durably writes a
self-authenticating root-owned intent under
`/var/lib/dirextalk/vnext/update-intent/`. It binds the retained and candidate
environment digests, compose digest, versions, and compatibility contract.
New intents use schema v2 and include a kernel-generated 128-bit attempt ID
inside the self-hash. Terminal attempts are archived append-only as
`update.<attempt-id>.<intent-sha256>`; identical candidate material therefore
receives a distinct authenticated archive identity and no archive is
overwritten. Schema-v1 intents remain readable for interrupted upgrade
recovery. The complete admission, intent/archive mutation, retention, update
state machine, and cache cleanup sequence is serialized by a root-owned mode
`0600`, non-symlink `flock` under the root-owned production state directory.
Explicit durable phases distinguish the pre-call `candidate_started` phase from
`candidate_applied`, which is written only after Compose returns successfully,
as well as candidate readiness, the two desired-active promotions, rollback
start/readiness, completion, and `recovery_failed`. Canonical `production.env`
and `current.env` remain on the retained release until candidate readiness is
durable; each atomic replacement and its parent directory are synced. A replay
from `candidate_started` reconciles the exact authenticated candidate Compose
invocation, while a replay from `candidate_applied` skips Compose and resumes
at readiness. A replay from `candidate_ready` performs only the pending
promotions.

Rollback first durably restores both canonical environment files, then
reconciles only the retained long-running services with `--no-deps`. It writes
`rolled_back` only after the same node, realtime, and Agent Control readiness
probes used by `verify.sh` succeed. If retained services do not become ready,
the durable phase and receipt remain `recovery_failed`; this is nonterminal and
requires operator repair rather than claiming rollback success. A later
invocation under the same authenticated intent first reconciles the exact prior
`dtx-node`, realtime, Agent Control, and Caddy services with `--no-deps`, then
performs one bounded prior-readiness attempt. It never re-enters candidate
Compose or migrations and publishes `rolled_back` only after prior readiness
succeeds.

Update archive admission reserves 1 MiB for the next attempt and a 64 MiB free
space floor. Each authenticated terminal archive is limited to 1 MiB; at most
16 archives and 32 MiB are allowed. Retention keeps the newest eight
unreferenced attempts plus the newest copies that bind the current/prior
recovery digests, deleting only fully validated flat update archives. Active
intent state, named volumes, configuration, TLS, and secrets are outside the
deletion allowlist.

`scripts/test-production-postgres.sh` verifies the current Product Core Alpha
baseline against an empty ephemeral PostgreSQL database and its production role
matrix. Existing database histories are not accepted.

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

These programs accept no arguments. The installer exclusively consumes root-owned mode
`0400` regular files `/home/ubuntu/dirextalk-vnext.bundle` and
`/home/ubuntu/dirextalk-vnext.request`. The canonical request schema is
`dirextalk.vnext-install-request` version 1 with exact fields `target`,
`domain`, `version`, `source_commit`, `bundle_sha256`, `manifest_sha256`,
`server_image`, `migrator_image`, and nullable
`previous_receipt_sha256`. It rechecks every archive and manifest invariant,
and materializes only `/opt/dirextalk-vnext/releases/<bundle_sha256>/`. A true
initial install invokes only that release's digest-bound
`scripts/production-stack/install.sh` to materialize the baseline and publishes
the initial root-owned mode `0600`
`/var/lib/dirextalk-vnext/receipts/current.json`; later host provisioning owns
runtime activation. Only when a current release already exists does a candidate
path stage provisioned host material, select its server image, migrator image,
and release version while preserving operator environment fields, invoke that
candidate's authenticated `update.sh` forward migration/readiness state
machine, prove the resulting runtime and fixed migrations, and then write its
canonical sanitized runtime attestation before publishing the candidate receipt.

The same hash-pinned `install-vnext` artifact is a root-only no-argument fixed
incident helper when it is staged and invoked with the exact basename
`recover-vnext-011-to-014-r2`.
When staged under `attest-vnext-011-to-014-r2`, the same bytes perform only a
fresh candidate-runtime proof and atomically refresh its sanitized attestation;
they never recover or change the configured runtime.
It accepts only a current `0.1.4` receipt directly chained to retained `0.1.1`,
proves exact retained runtime material before mutation, and reuses the retained
candidate's `update.sh`; it needs neither a new bundle nor a request upload.
A matching candidate-ready attestation is a no-op. Mixed, forged, incomplete,
or runtime-mismatched receipt/release/env/compose material fails before
mutation. It never rewrites receipt history or performs a down migration.

The r2 basenames above retain that deployed incident contract unchanged. The
immutable r3 basenames `recover-vnext-011-to-014-r3` and
`attest-vnext-011-to-014-r3` add an explicit migration proof mode. Recovery
accepts only an authenticated 0.1.1 environment and required images with the
provision binary absent and either the exact SQLx baseline (55 successful rows,
056/057/058 absent) or the exact migrated-old state (58 successful rows with
056/057/058 all present and successful). Any failed row, incident subset,
different total, image/environment drift, binary presence, receipt/history
change, or unexpected attestation fails closed. Candidate-ready is a no-op;
activation uses the existing candidate update path and succeeds only after the
candidate image/environment, executable provision binary, 58 successful rows,
all three incident migrations, and canonical runtime attestation are proved,
without rewriting receipt history.
Recovery persists a root-owned mode `0600` self-authenticating transition marker
under `/var/lib/dirextalk-vnext/` before the first candidate mutation. The
marker is bound to both receipt and retained-release identities, permits only
idempotent activation replay after a crash, and is removed only after the
candidate proof and receipt/history byte checks succeed. The standalone r3
attester refuses while that marker exists.

Host installation performs retention and free-space admission while holding
the same exclusive install lock. Every bundle and materialized release remains
limited to 32 MiB. The release store is bounded to eight releases/256 MiB and
reserves a 64 MiB free-space floor plus the incoming candidate; it preserves
the current release, directly prior release, request candidate, and every
release referenced by a crash-recoverable candidate receipt, plus the newest
two unreferenced releases. Receipt history is bounded to 64 files/4 MiB and
reserves an 8 MiB free-space floor plus three receipt-sized atomic-write
slots. Before deleting anything, the installer validates the complete
authenticated predecessor closure from current/request roots and every
crash-recoverable candidate; a missing or corrupt referenced receipt fails
closed with all receipt and release artifacts untouched. Retention preserves
that closure plus the newest sixteen unreferenced receipts. Only validated
root-owned release trees, receipt histories, and stale installer temporaries
inside those exact roots can be removed. Volumes, images, containers,
configuration, TLS, and secrets are never part of this retention pass.

The canonical receipt schema is `dirextalk.vnext-installed-release` version 1.
It repeats the request facts, adds `state` (`installed` or `rolled_back`),
`installed_at_ms`, and `receipt_sha256`; the receipt digest is SHA-256 of the
canonical object with `receipt_sha256` omitted. Every request must chain from
the current receipt. A failed candidate restores only the retained fixed
release, only when both releases contain the exact compatibility marker, and
exits unsuccessfully without rewriting receipt history or claiming the
candidate. The
reader validates type, owner, mode, canonical encoding, exact keys, immutable
image references, and the self-hash before emitting only the receipt bytes.

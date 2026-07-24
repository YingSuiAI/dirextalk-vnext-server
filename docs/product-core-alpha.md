# Product Core Alpha

This document is the canonical current-status and scope contract for
`dirextalk-vnext-server`. It replaces the historical cross-workspace
implementation plan as the server's active documentation source.

## Release boundary

Product Core Alpha is the current release for exactly two implementation owners:

- `dirextalk-vnext-server` — protocol, persistence, authorization, delivery,
  recovery, and server composition;
- `dirextalk-vnext-client` — the native Rust client core and Flutter product
  surface that consumes those contracts.

The product in this release is the Matrix-independent IM path. The server is
not a second Matrix implementation and does not use Matrix rooms, timelines, or
sync as a parallel source of truth.

## Present server capability

The workspace currently contains the production-oriented foundations for:

- self-authenticated identity logs, device enrollment/session, device revoke,
  and scoped history-recovery authorization;
- private conversations, group membership commands, and server-side MLS
  sequencing/receipt boundaries while message plaintext remains opaque;
- durable opaque Mailbox enqueue, Pull/ACK, account read cursors, and realtime
  invalidation/recovery paths;
- PostgreSQL fresh-schema baseline, authorization/RLS boundaries,
  protocol schemas, generated consumers, and byte-exact test vectors;
- the unified `dtx-node` HTTP composition used by the IM services.

These are implementation and focused-test facts, not a declaration that every
client workflow or live environment has passed final acceptance.

## Fresh-only state

Alpha intentionally starts clean:

- install the documented current schema baseline into an empty database;
- use fresh client-native identity, enrollment, sync, and local-store state;
- do not import or dual-write legacy Matrix/workspace-monolith state;
- do not add a compatibility shim merely to make an old state appear usable.

Historical protocol baselines, compatibility validators, upgrade tests, and
rollback-only branches have been deleted. The exact current wire inventory is
`protocol/alpha/manifest.json`; artifacts outside that inventory are either
frozen next-version source or are not part of Product Core Alpha.

The database baseline is an exact schema epoch: its complete version and
checksum set must match the embedded baseline. Existing databases from earlier
schema histories are intentionally rejected; Alpha does not provide an
upgrade, downgrade, or partial-incident recovery path for them.

## Frozen and deferred scope

Agent execution, Connector installation, cloud-task orchestration, and public
Channel/Agent discovery or discussion are not Product Core Alpha acceptance
surfaces. Their schemas and code may exist as reviewed foundations, but new
Agent/Public expansion is frozen at this boundary.

`dirextalk-vnext-deployer` and `dirextalk-agent-connector` are deferred to the
next **Platform Integration Alpha**. Do not describe their deferred work as
current server capability or use it to widen the IM contract.

The production composition starts only the Product Core services by default.
Opaque Push is a required Product Core service with a private-CA HTTPS
registration route and loopback readiness probe. Agent Control requires an
explicit profile. Public/Indexer components are similarly non-default and
cannot be readiness dependencies for identity, Mailbox, Realtime, or Push.

## Current architecture

```text
Android / Flutter
       |
       v
Rust ClientRuntime + encrypted client.redb
       |
       +-- Identity / Contact / Device
       +-- MLS / Conversation / Group
       +-- Outbox / Inbox / Attachment
       `-- Reconcile / Snapshot streams
                    |
                    v
Identity + Group + Opaque Mailbox + Realtime + Opaque Push
                    |
                    v
             PostgreSQL current baseline
```

The client database is the UI truth. WSS and Push are wake-up signals only:
the client Pulls to a durable high-water mark, atomically commits domain state,
MLS state, deduplication state, ACK state, and cursors, increments
`state_revision`, and then publishes a new immutable snapshot.

The server stores and orders protocol facts but never becomes a second
plaintext timeline. Mailbox ACK is recovery state, not an instruction for a
widget to refresh.

## Acceptance and recovery invariants

X3, X4, and X5 are disposable, resettable acceptance environments. They are
used to exercise the server/client IM path and may be rebuilt from a clean
schema and client state; they are not durable production records.

Every current slice must preserve the following externally visible behavior:

1. Persist an intent before an external side effect.
2. Bind retries to an idempotency key and exact request/digest material; changed
   retries fail closed.
3. Fence stale sessions, leases, revisions, and device generations.
4. Recover after process/database restart without losing committed state or
   creating a second side effect.
5. Treat delivery as durable, replayable, and at-least-once; Pull/ACK and the
   account read cursor remain the recovery and unread authorities.

Product Core Alpha is therefore an active implementation boundary, not a
completed acceptance certificate. Final X3/X4/X5 end-to-end evidence must be
reported with the affected server and client commits and must not be inferred
from crate presence or a green focused test alone.

## Verification entry points

- [`README.md`](../README.md) — repository status and boundaries;
- [`COMMANDS.md`](../COMMANDS.md) — the small set of supported focused and
  release checks;
- [`protocol/README.md`](../protocol/README.md) — the current Alpha wire
  inventory;
- [`docs/security-boundary.md`](security-boundary.md) — current visibility,
  secret-handling, and fail-closed rules.

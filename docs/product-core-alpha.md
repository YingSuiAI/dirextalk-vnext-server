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
- PostgreSQL persistence, forward migrations, authorization/RLS boundaries,
  protocol schemas, generated consumers, and byte-exact test vectors;
- the unified `dtx-node` HTTP composition used by the IM services.

These are implementation and focused-test facts, not a declaration that every
client workflow or live environment has passed final acceptance.

## Fresh-only state

Alpha intentionally starts clean:

- deploy a fresh schema and run the documented forward migrations;
- use fresh client-native identity, enrollment, sync, and local-store state;
- do not import or dual-write legacy Matrix/workspace-monolith state;
- do not add a compatibility shim merely to make an old state appear usable.

Historical protocol artifacts remain available for explicit wire validation, but
they are not alternate runtime writers or a migration source for Product Core
Alpha.

## Frozen and deferred scope

Agent execution, Connector installation, cloud-task orchestration, and public
Channel/Agent discovery or discussion are not Product Core Alpha acceptance
surfaces. Their schemas and code may exist as reviewed foundations, but new
Agent/Public expansion is frozen at this boundary.

`dirextalk-vnext-deployer` and `dirextalk-agent-connector` are deferred to the
next **Platform Integration Alpha**. Do not describe their deferred work as
current server capability or use it to widen the IM contract.

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
- [`COMMANDS.md`](../COMMANDS.md) — documented focused and full checks;
- [`protocol/README.md`](../protocol/README.md) — versioned wire artifacts and
  frozen baselines;
- [`docs/history-recovery-v1.md`](history-recovery-v1.md),
  [`docs/realtime-sync-v1.md`](realtime-sync-v1.md), and
  [`docs/opaque-push-v1.md`](opaque-push-v1.md) — focused recovery and delivery
  contracts.

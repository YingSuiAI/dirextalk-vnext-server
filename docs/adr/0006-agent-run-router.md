# ADR-0006: Fenced Agent Run routing

- Status: Accepted for MC3
- Date: 2026-07-13

## Context

One Agent Installation may be served by multiple isolated Connector processes,
but a user invocation must produce at most one execution authority. Runtime
capability and capacity reports are observations, not authorization. Reconnect,
response loss, concurrent claims, policy revocation, and timeout recovery must
not revive an old Connector or cause two runtimes to execute the same Run.

The first release supports explicit Agent targets and two routing modes only:
`single` over an `exclusive` Binding, and `failover` over an
`ordered_failover` Binding. Broadcast, race, workflow fan-out, and automatic
substitution of another Agent Installation are outside MC3.

## Decision

### Durable request and route snapshot

Agent Control persists one `AgentRun` before attempting delivery. A Run is
identified by a UUIDv7 `run_id`, a caller `request_id`, and a 256-bit
idempotency digest. Exact retries compare caller-owned request fields and return
the existing Run; current Binding order, policy revision, or server-generated
candidate snapshots are not allowed to turn a response-loss retry into a new
Run.

Creation requires an enabled Installation, an active Agent Device, a live
Conversation Grant version, an explicit target, and an eligible Binding. The
ordered candidate list is copied into immutable Run rows. This snapshot makes
replay deterministic, while every offer and claim still rechecks current
Installation, Device, Binding, Connector control lease, runtime capability,
and capacity authority. Revocation therefore takes effect before new execution
authority can be granted.

### State and execution authority

The durable routing state is:

```text
Queued -> Offered -> Leased -> ReconcileRequired
   |         |          |
   |         +-> Queued |  (offer expired before execution authority)
   +--------------------+-> Expired
```

`RunAvailable` is only a delivery offer. `RunClaim` acknowledges one exact
offer and does not authorize execution. Only the matching `RunLeaseGranted`
frame grants execution authority. It contains the immutable Run lease ID and
epoch, deadline, exact Connector fence, offer ID and attempt, request ID, and
Installation identity.

An execution lease timeout or explicit release enters `ReconcileRequired` and
frees routing reservations. It is never automatically failed over because the
previous Connector may already have performed work. AR3 owns checkpoint,
result, and side-effect reconciliation on top of this routing boundary.

### Fencing and idempotency

Offers and claims echo the complete Connector control fence:

```text
(tenant_id, connector_id, generation, boot_id, connector_lease_id,
 connector_lease_epoch)
```

Claims additionally echo Run revision, offer ID, attempt, and deadline.
Releases echo both that live Connector fence and the exact Run lease ID/epoch.
The server checks the current mTLS credential and all durable fences again in
the same tenant transaction. Exact claim and release retries return the prior
result only while the echoed Connector fence is still the live control fence.
Missing or stale Run identifiers use the stable `STALE_LEASE` result at this
stream boundary so they cannot be used as a tenant-local existence oracle.

PostgreSQL unique constraints allow one active offer and one active execution
lease per Run. The claim transaction locks the Run, Connector capacity,
Binding capacity, authorization rows, and current control lease before sampling
server time. A second concurrent claim is either the exact existing lease or a
rejection; it cannot reserve another slot.

### Capacity admission

Connector heartbeat capacity is an observation keyed by the exact control
lease, heartbeat sequence, and runtime-claim revision. The Router records the
reservation baseline at the first observation and admits no more than:

```text
min(binding limit, runtime maximum, observation baseline + reported available)
```

This prevents a Connector reporting `maximum=4, available=1` from receiving
four new claims. Connector and Binding active reservations are advanced in the
same claim/release/expiry transaction and protected by transition triggers.
Reported capacity never creates a Binding, capability, permission, or control
lease.

### Locking, fairness, and reconciliation

All multi-candidate offers pre-lock Connector capacity heads in sorted
Connector-ID order and then Binding heads in sorted Binding-ID order before
following business priority. Claims, releases, and expiry use the same
Run-before-Connector-before-Binding order. Production reconciliation gives
each due or queued Run its own outer tenant transaction, so locks from opposite
route orders cannot accumulate across a batch.

Unavailable single-route attempts durably advance `updated_at`; bounded queued
pages ordered by `(updated_at, run_id)` therefore rotate fairly instead of
letting an offline prefix starve later healthy Runs. Deadline selection is
driven by partial indexes over queued deadlines, offered expiries, and active
lease expiries rather than scanning completed history.

Every negotiated Agent Control `1.1` stream performs an initial bounded
reconcile and then a five-second bounded reconcile. PostgreSQL state and
`SKIP LOCKED` remain authoritative when several streams for one tenant wake at
once. With no eligible stream there is no execution destination; persisted
state is reconciled before offers are delivered when a `1.1` stream returns.
A later process-level scheduler may coalesce tenant wakeups for scale without
changing the repository or wire contract.

Offer delivery uses PostgreSQL notification plus a durable per-Connector
sequence cursor. One control-loop slice drains at most two 128-offer pages and
then self-wakes, allowing Heartbeat and `RunClaim` frames to regain the stream.
Lost notifications are repaired by the bounded reconcile path.

### Protocol compatibility

Agent Control `1.0` remains frozen. MC3 publishes additive `1.1` source and
baseline artifacts for `RunAvailable`, `RunClaim`, `RunLeaseGranted`, and
`RunRelease` on the existing service and logical stream. Minor `0` never
receives or accepts Router frames. Negotiation rejects a minor newer than the
server implementation, and the `run-routing` capability is valid only at
minor `1` or later.

## Consequences

- The first release provides at-least-once delivery with idempotent Run and
  lease transitions; it does not claim exactly-once execution.
- Ordered failover can move an unclaimed expired offer, but never a Run whose
  execution lease was granted.
- Routing decisions remain PostgreSQL-consistent and horizontally safe without
  adding a consensus system.
- Active-stream reconciliation may duplicate bounded tenant scans; MC8 soak
  testing decides whether a coalescing process-level scheduler is needed.
- Result persistence, tool side effects, cancellation, and completion evidence
  remain AR3 contracts and cannot be inferred from Router release state.

# ADR-0005: Connector control identity, enrollment, and resumable stream

- Status: Accepted for MC2b
- Date: 2026-07-13

## Context

One Host can run many isolated Connector processes. Each Connector needs its
own control identity, lease, runtime claims, desired configuration, and replay
cursor. The server must never dial a Connector or require an inbound port.
Reconnects, response loss, process replacement, credential rotation, and
server failover must not repeat an accepted command or revive an old process.

`Connector` is not an `AgentInstallation`. A Connector can participate in more
than one Binding only after trusted adapter conformance permits it. Therefore a
control identity and `connect.hello` are scoped to `(tenant_id, connector_id)`,
not to one `installation_id`. Agent Device and Binding proofs remain separate
application records and cannot be inferred from runtime capability claims.

## Decision

### Transport and trust boundaries

Agent Control exposes two outbound-only HTTP/2 endpoints:

1. `EnrollConnector` uses ordinary server-authenticated TLS and a one-time,
   high-entropy enrollment token.
2. `Control` uses mandatory per-Connector mTLS and a bidirectional tonic
   stream. The Connector initiates every connection.

The wire protocol is `agent-control/1`, encoded by Protobuf in the
`dirextalk.agent_control.v1` package. MC2b publishes its reviewed `1.0`
artifact without rewriting any older baseline entry. Future Router frames are
not silently added to that contract: MC3 must publish an additive `1.1`
baseline (or a separate versioned service), negotiate the minor explicitly,
and preserve the single logical lease, command cursor, and downgrade rules
while `1.0` remains supported.

MC3 publishes that additive contract as the disjoint full
`agent_control/v1_1` source artifact frozen by baseline v3 while retaining the
`dirextalk.agent_control.v1` package, service name, and single logical stream.
`RunAvailable` is an offer, `RunClaim` is only its acknowledgement, and only a
matching `RunLeaseGranted` authorizes execution. `RunRelease` must echo both the
live Connector fence and run-lease fence. Application dispatch and AR3 result
frames are intentionally outside this wire-only slice.

The exact Connector URI SAN is:

```text
spiffe://dirextalk.internal/v1/tenants/<tenant_id>/connectors/<connector_id>
```

The TLS verifier requires a WebPKI-valid client certificate, client-auth-only
EKU, one exact URI SAN, certificate-time validity, and an exact leaf
fingerprint. It authenticates cryptographic possession only; it deliberately
does not decide whether that fingerprint is the live credential. The
tenant-scoped PostgreSQL application checks the exact current credential for
`Hello` and every ordinary frame. The in-process authorization index is an
advisory optimization whose refresh is best-effort after commit and can never
grant or deny durable authority. Host, Executor, internal-service, and
control-server identities cannot authenticate as a Connector. TLS tickets,
resumption, and early data are disabled at this boundary.

TLS handshakes have a ten-second timeout and a global pending-handshake bound.
After mTLS authentication and before reading `Hello`, a second RAII admission
guard limits the global pending window, the direct transport source IP, and the
canonical certificate identity. The defaults are 256 global, 32 concurrent
per source with a 64-token/100 ms bucket, and two concurrent per identity with
a four-token/one-second bucket. Both key maps have TTL cleanup and hard
cardinality limits. Forwarding headers and untrusted `Hello` fields are never
admission keys. The TLS permit is released when the handshake completes; the
second permit is released after the first `Hello` is accepted and its
`ConnectLease` is sent, or on any earlier failure. These pending-work ceilings
therefore do not cap legitimate long-lived streams or Connectors behind one
NAT. Established-connection limits, HTTP/2 keepalive, and listener-wide socket
budgets are a separate configurable server boundary. The first frame and every
blocked response send each have a ten-second deadline, so a silent or
non-reading RPC cannot retain pending application capacity indefinitely.

### One-time enrollment

The owner-facing caller supplies a stable request ID, a caller-generated raw
256-bit token, and a bounded lifetime. The application creates an
`EnrollmentIntent` bound to that exact operation, tenant, Host, Connector,
Connector generation, spec revision, token digest, and expiration. The create
response contains only durable intent metadata and never echoes the raw token.
Only the domain-separated SHA-256 digest is stored. The default lifetime is
five minutes and cannot exceed ten minutes. Retrying the exact operation,
token, Connector, and lifetime returns the same metadata; changing any member
is an idempotency conflict.

The Connector generates two Ed25519 key pairs locally:

- an online control key used by the mTLS leaf certificate;
- an offline refresh key used only to prove credential rotation.

Neither private key leaves the Connector. Enrollment carries both public keys
and proof-of-possession signatures over the complete, domain-separated request
transcript. A successful transaction consumes the token, creates credential
authorization, stores the public certificate chain and exact request/result
digests, and advances no unrelated aggregate.

An exact retry of a consumed token returns the already persisted public
certificate result. A changed retry is an idempotency conflict. No secret
response needs to be retained because the refresh credential is client-owned
key material rather than a server-generated bearer token.

### Stream handshake and lease

The first client frame must be `Hello` and includes the exact Connector,
Host, boot ID, generation, spec revision, protocol range, runtime/build facts,
reported capabilities, capacity, and last durably applied server-command
sequence. The authenticated certificate identity is authoritative; duplicate
or conflicting IDs in the frame fail closed.

After an O(1) durable-current-credential check and loading the current
Connector in one tenant-scoped transaction, Agent Control records/replays the
boot, issues one monotonically fenced lease, and returns `ConnectLease`. The existing
`(connector_id, generation, boot_id, lease_id, lease_epoch)` domain fence is
used unchanged. A newer boot, generation, or lease makes every older stream
stale.

### Heartbeats and capability claims

Heartbeat sequence is positive and JSON-safe. New sequences are strictly
monotonic per lease and must not arrive faster than half the negotiated
heartbeat interval. An exact retry at the same sequence is exempt and returns
the original persisted observation time and acknowledgement; changed content
at that sequence conflicts. The server clock determines observation time and
lease expiry. `offline` and `revoked` remain server-derived.

Runtime kind/version, adapter build digest, queue depth, active Run IDs, stable
error code, and capability names are bounded non-secret claims. Claims are
persisted for health and compatibility decisions, but they never create an
`AdapterConformance`, permission, Binding, or routing authority.

Heartbeat writes use a constant-size Connector head and compare-and-swap
instead of rehydrating lease history. Current runtime claims are read by head,
and their immutable diagnostic history is pruned to the newest 4,096 records
per Connector. This keeps steady-state cost independent of process lifetime
without weakening the current projection.

### Durable server commands and resume cursor

Every state-changing server instruction is first appended to a per-Connector
command log with a positive sequence, operation ID, generation, spec revision,
payload digest, and exact Protobuf bytes. Initial MC2b commands are closed:

- `ApplyConfig`: non-secret adapter/runtime configuration and desired state;
- `RotateCredential`: nonce, successor revision, and deadline;
- `CloseStream`: terminal revoke or explicit reconnect reason.

Drain and stop are desired-state values in `ApplyConfig`; they are not generic
shell/process commands. Host process lifecycle remains owned by the Host
Supervisor boundary from ADR-0004.

`ApplyConfig` is staged under the current envelope fence but carries exactly
the next configuration revision. Its closed adapter-specific schema rejects
unknown keys, raw secret values, and `secret://` references. The exact command
ACK atomically advances both the Connector configuration fence and command-log
fence, so delivery-before-commit and apply-before-ACK reconnects remain
recoverable.

Secret references are intentionally outside Agent Control `1.0`; a later Host
Supervisor minor contract may carry opaque, policy-bound handles and resolve
them locally. Raw secret material never becomes an Agent Control command value.

The Connector durably applies a command before acknowledging its exact
sequence and digest. The server advances the cursor only by one contiguous
command and rejects gaps, stale generations, or digest changes. On reconnect,
commands after the acknowledged cursor are replayed byte-for-byte. Ephemeral
lease and heartbeat acknowledgements are not placed in the durable command
log.

Committed commands publish a lossy/coalesced wakeup through an in-process
watch channel and PostgreSQL `LISTEN/NOTIFY`. A stream subscribes before its
final durable suffix query, closing the commit-between-replay-and-wait race.
The database head and O(k) suffix remain authoritative; a stable per-Connector
30-45 second reconciliation delay covers lost notifications, listener
reconnects, and bounded idle-stream revocation detection. There is no fixed
one-hertz database poll.

### Rotation and revocation

Rotation is a two-key handoff:

1. Agent Control durably emits `RotateCredential`.
2. The current mTLS stream submits a new control public key plus signatures by
   both the current refresh key and new control key over the rotation nonce.
3. Agent Control issues and stores one exact pending successor certificate.
4. A CA-valid successor certificate still receives only cryptographic TLS
   authentication; PostgreSQL authorizes only the exact matching pending
   successor on reconnect.
5. The first valid successor `Hello` atomically promotes it, retires the old
   credential, advances the Connector generation, and fences the old stream.

Exact rotation retries return the same public certificate. A second different
pending successor conflicts. Revocation is terminal: current and pending
credentials, active leases, and further enrollment/rotation all fail closed;
historical IDs and fingerprints remain durable to prevent resurrection.

### Persistence and limits

PostgreSQL stores enrollment history, credential head/history, runtime-claim
head/history, durable commands, and the contiguous acknowledgement cursor
under composite tenant foreign keys and FORCE RLS. Token digests, public keys,
certificate fingerprints, public certificate bytes, stable codes, and bounded
redacted text are non-secret. Raw tokens and private keys are never stored or
logged.

Enrollment and every owner command first claim one immutable row in a shared
tenant operation namespace keyed by `(tenant_id, operation_id)`. Composite
foreign keys bind the claim to the exact Connector and closed operation kind;
a deferred publication assertion requires the matching enrollment intent or
durable command in the same transaction. This removes cross-table and
cross-Connector `RequestId` races while preserving exact response-loss retry.

Limits are fixed in both domain validation and database constraints: token and
certificate validity, frame and string sizes, capability count, active Run
count, 4,096 ordinary unacknowledged commands plus one reserved terminal-revoke
safety slot, bounded runtime-claim history, heartbeat interval/TTL/cadence, and
safe-integer counters. No command can follow that terminal slot. Ordinary
heartbeat, ready, command poll, and credential authorization paths read
constant-size heads plus only the requested bounded command suffix; they do not
scan lifetime history. Full-history repository APIs are bounded diagnostic/test
materializers rather than production decision paths. Runtime-history pruning
uses a tenant-checked, fixed-search-path `SECURITY DEFINER` function whose
execute privilege must be granted explicitly to the runtime role.

## Failure semantics

- Authentication, identity, lease, cursor, and revision mismatches fail before
  state mutation.
- Database commit is the boundary for enrollment consumption, command append,
  cursor advancement, credential promotion, and heartbeat acknowledgement.
- A dropped response is recovered by exact request replay or stream resume.
- A lost command notification delays delivery only until durable reconciliation;
  it never loses or authorizes a command.
- Unknown required capabilities and unsupported protocol majors are rejected;
  unknown optional fields remain Protobuf-compatible.
- A control-stream disconnect never means that a command was applied and never
  changes durable desired state by itself.

## MC2b acceptance

MC2b is complete only when automated tests prove:

1. one token produces one exact Connector credential and changed replay fails;
2. two Connector certificates cannot cross tenant/Connector boundaries;
3. stale generation, boot, lease, heartbeat, config revision, and cursor are
   rejected without partial writes;
4. a dropped stream replays only commands after the contiguous cursor;
5. drain, stop, revoke, and rotation survive server/Connector restart;
6. rotation overlaps only the exact pending successor and then retires the old
   certificate and lease;
7. runtime claims cannot create trusted conformance or authorization;
8. migrations are reversible, RLS hides cross-tenant rows, concurrent token
   use has one winner, and the full repository verification gate passes;
9. heartbeat/authentication hot paths remain O(1), retained runtime history is
   bounded, and an idle stream does not restore one-hertz polling;
10. slow TLS/Hello/response clients, excess direct sources, and excess
    certificate identities release bounded admission capacity without leaking
    whether a durable credential exists;
11. enrollment and command operations share one tenant-global `RequestId`
    namespace, including concurrent cross-kind conflicts with exactly one
    committed winner.

## Consequences

This adds a dedicated Agent Control domain/transport boundary and durable
control records, but does not add Router Run dispatch, Matrix consumption,
Agent Device Binding activation, arbitrary remote execution, or Connector
inbound listeners. Those remain MC3-MC5 concerns.

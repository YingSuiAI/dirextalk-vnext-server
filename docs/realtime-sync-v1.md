# Realtime Sync V1/V2

Realtime Sync is an independent digest-only notification service. Durable
opaque Mailbox Pull/ACK and account read-cursor HTTPS APIs remain the recovery
truth; WSS never becomes a business-write or authentication authority.

## Contracts

- Migration 045 creates identity-scoped delivery/realtime journals, per-device
  ACK/lease state, and signed device-history grants.
- Migration 046 adds opaque account read-cursor CAS claims and bounded realtime
  outbox claim/mark/compaction functions. Migration 045 is not rewritten.
- Migration 047 adds exact identity-head, device-revocation, and key-authorization
  invalidations plus contiguous-prefix-only compaction. Migrations 045 and 046
  remain frozen.
- WSS uses binary canonical CBOR. The Gateway prefers the additive
  `dirextalk.realtime-sync.v2` subprotocol and retains
  `dirextalk.realtime-sync.v1` compatibility. Protocol baselines 37 and 38
  remain frozen; the V2 wire and identity Mailbox Pull V3 are baseline 39.
- Account read-cursor HTTPS bodies are frozen additively in baseline 38. They
  contain only a conversation digest, opaque ciphertext, revision, and identity
  head digest—never a plaintext conversation ID, unread graph, or contact fact.

## Device-history recovery

An active device, the current root key, or the current recovery key may sign a
history grant over the exact current identity head and the new device's active
signing-key proof of possession. Root/recovery `authorizer_id` values are
domain-separated key digests; public or private authority key bytes are not
copied into the grant table. Every request reauthenticates its device session,
rehydrates the current identity projection, and rejects stale heads, rotated
authorities, revoked devices/grants, or mismatched PoP.

## Post-commit publication

Business writes append the journal and outbox in their own PostgreSQL
transaction. The Gateway can claim only committed rows through narrow
`SECURITY DEFINER` functions. It broadcasts digest-only notifications, then
marks the claim published.

- Crash before broadcast: the 15-second claim expires and is reclaimed.
- Crash after broadcast but before mark: the batch is broadcast again, so
  delivery is at-least-once.
- No connected receiver: later WSS replay reads the durable journal.
- Expired rows are compacted in pages of at most 256. Compaction removes the
  matching outbox row first, but only for the contiguous expired prefix that
  starts at the current journal floor. An expired interior row cannot advance
  the floor past a live row. Replay validates every adjacent cursor; a cursor
  behind the floor or any retained gap receives `CatchUpRequired`.
- Claim, mark, and compaction timestamps must remain within 60 seconds of the
  PostgreSQL clock, so the privileged functions cannot be used to forge future
  expiry even if the dedicated runtime login is compromised.

The Gateway role cannot select mailbox ciphertext or mutate arbitrary realtime
tables. Its only outbox write/cleanup capabilities are the three bounded
functions granted by migration 046. Identity writes call the narrow migration
047 append function inside their business transaction, so their typed
invalidation and outbox row commit or roll back together. Subjects are only
domain-separated 32-byte digests.

## Offline and multi-device continuity

`POST /v2/mailbox/pull` selects identity Mailbox Pull V3 with the exact request
media type `application/vnd.dirextalk.identity-mailbox-pull.v3+cbor`. Its
receipt reports a resumable floor and an ordered segment stream. Live segments
contain the existing opaque envelope; terminal ranges represent expired
delivery sequences without ciphertext. A client advances through both kinds
and sends the existing per-device V2 ACK. Pull V2 remains accepted unchanged.

Each authorized device has an independent delivery cursor. An ACK from one
device never consumes another device's delivery. A newly authorized device can
recover retained identity history before joining WSS deltas. Durable Mailbox
Pull/ACK and the account-level encrypted conversation read cursor remain the
only offline/unread truth; terminal ranges only make an otherwise permanent
expired-sequence gap resumable.

## Ephemeral routing

V2 clients explicitly subscribe to an opaque active-scope digest with a TTL of
at most 10 seconds before sending or receiving typing, read-hint, or presence
signals. Signals go only to other authenticated peer connections that hold the
matching unexpired scope; the sender and its own identity do not receive the
signal. Presence additionally requires both sides to opt in. The registry is
bounded, process-local, and removed at disconnect—active scope is never written
to PostgreSQL or included in durable replay. V1 remains wire compatible but can
only establish an implicit scope by sending a signal.

The scope digest is a possession capability: clients must derive it from the
current private conversation authorization/epoch, never from a public or stable
conversation identifier, and rotate it when authorization changes. The Gateway
does not persist or resolve it to conversation membership. A removed peer that
cannot derive the current digest is therefore outside the relay scope.

## Runtime

`dtx-realtime-sync-gateway` is a separate artifact, listener, database role,
and authentication boundary from `dtx-node` and Agent Control. Local Compose
starts one Gateway beside each node; the release image contains both binaries
but a Gateway container uses the fixed
`/usr/local/bin/dtx-realtime-sync-gateway` entrypoint. It requires:

- `DTX_REALTIME_SYNC_DATABASE_URL_FILE` for the production least-privilege
  login (`DTX_REALTIME_SYNC_DATABASE_URL` is retained for bounded local use);
- `DTX_REALTIME_SYNC_TLS_CERTIFICATE_FILE` and
  `DTX_REALTIME_SYNC_TLS_PRIVATE_KEY_FILE`;
- optional `DTX_REALTIME_SYNC_BIND` (default `0.0.0.0:9444`).

The process claims the outbox every 100 ms, uses bounded exponential retry on
database failure, and retains a one-second journal replay safety pass for
broadcast lag. Device heartbeat remains 15 seconds with a 45-second lease TTL.
It requires Hello within five seconds and admits at most 4,096 connections
globally and 32 connections per source address.

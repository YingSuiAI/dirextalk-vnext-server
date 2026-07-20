# Realtime Sync V1

Realtime Sync is an independent digest-only notification service. Durable
opaque Mailbox Pull/ACK and account read-cursor HTTPS APIs remain the recovery
truth; WSS never becomes a business-write or authentication authority.

## Contracts

- Migration 045 creates identity-scoped delivery/realtime journals, per-device
  ACK/lease state, and signed device-history grants.
- Migration 046 adds opaque account read-cursor CAS claims and bounded realtime
  outbox claim/mark/compaction functions. Migration 045 is not rewritten.
- WSS uses binary canonical CBOR and the exact
  `dirextalk.realtime-sync.v1` subprotocol. Protocol baseline 37 remains frozen.
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
  matching outbox row first and advances each affected journal floor; a cursor
  behind that floor receives `CatchUpRequired`.
- Claim, mark, and compaction timestamps must remain within 60 seconds of the
  PostgreSQL clock, so the privileged functions cannot be used to forge future
  expiry even if the dedicated runtime login is compromised.

The Gateway role cannot select mailbox ciphertext or mutate arbitrary realtime
tables. Its only outbox write/cleanup capabilities are the three bounded
functions granted by migration 046.

## Runtime

`dtx-realtime-sync-gateway` requires:

- `DTX_REALTIME_SYNC_DATABASE_URL` for the dedicated least-privilege login;
- `DTX_REALTIME_SYNC_TLS_CERTIFICATE_FILE` and
  `DTX_REALTIME_SYNC_TLS_PRIVATE_KEY_FILE`;
- optional `DTX_REALTIME_SYNC_BIND` (default `0.0.0.0:9444`).

The process claims the outbox every 100 ms, uses bounded exponential retry on
database failure, and retains a one-second journal replay safety pass for
broadcast lag. Device heartbeat remains 15 seconds with a 45-second lease TTL.

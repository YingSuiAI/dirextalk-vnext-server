# ADR-0016: Public conditional cache V1

- Status: Accepted
- Date: 2026-07-15
- Owners: public Feed and Indexer HTTP nodes

## Context

Public descriptors, feed pages, and Indexer results are read frequently but
must converge quickly after publisher updates or permanent revocation. An
unbounded in-memory map would exchange database pressure for a memory denial
of service.

## Decision

Baseline V26 adds an optional, backward-compatible conditional-cache extension
to the V24 and V25 GET contracts. Every successful public GET returns a strong
ETag derived from the exact response bytes. One strictly formed strong
`If-None-Match` value may produce an empty 304; weak, wildcard, list, duplicate,
or malformed forms are rejected. Both 200 and 304 retain ETag,
`Cache-Control`, and `X-Content-Type-Options: nosniff`.

Descriptor and Indexer-subject responses use 60 seconds, Indexer search uses
15 seconds, mutable root feed pages use 10 seconds, and cursor pages whose
cursor binds an immutable snapshot use 300 seconds. All policies use
`must-revalidate`; Agent descriptors never use stale-while-revalidate.
Mutations and registration receipts remain `no-store`.

Each process uses a count- and byte-bounded cache keyed by tenant, fixed
Indexer where applicable, resource, and the complete canonical query. Misses
for one key are coalesced. Failed or cancelled loads leave no flight entry,
and oversized responses are returned without caching. Successful local writes
invalidate the exact tenant/resource prefix. Other replicas converge through
short TTLs and validators; no process claims synchronous global invalidation.

## Consequences

Old clients that omit `If-None-Match` continue receiving 200 responses. Hot
reads avoid duplicate database work, while updates and tombstones cannot serve
a pre-mutation body from the writing instance.

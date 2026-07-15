# ADR-0015: Independently operated public Indexer V1

- Status: Accepted for PD3
- Date: 2026-07-15
- Owners: `dtx-indexer`, `dtx-indexer-node`, and `protocol/indexer/v1`

## Context

PD1 and PD2 make public descriptors and feeds portable signed facts. PD3 needs
discoverability without making one directory authoritative or allowing an
untrusted public origin to turn an Indexer into an internal-network fetch
proxy. The same subject must be registerable at independent Indexers, and a
failed registration at one operator must not affect another.

## Decision

Indexer V1 is frozen in baseline V25. Each node is configured with one
immutable logical Indexer ID. Registration commands bind that ID, a unique
registration ID, and the exact signed descriptor bytes. The node persists a
pending intent before any remote request, then records one of `published`,
`rejected`, `stale`, or `revoked`. Exact command replay resumes or returns the
durable outcome; a lower descriptor sequence is persisted as stale, while
conflicting bytes at an accepted sequence are rejected.

The registration ID is the immutable handle for one `(Indexer, stable
subject)` head. A successor reuses it and must be exactly the next signed
sequence with `previous_descriptor_hash` equal to the accepted head. Attempts
are retained independently from the searchable head: a failed refresh records
its durable outcome without replacing the last published projection. A
successful refresh replaces descriptor and search state in one transaction.
An accepted descriptor tombstone permanently revokes the head, clears search
content, and prevents every older descriptor from becoming active again.

Remote fetching is HTTPS-only. The node resolves the descriptor's canonical
origin once, rejects the complete answer if any address is non-public, and
pins the validated socket addresses into the HTTP connector. Redirects,
proxies, cookies, referrers, and response compression are disabled. Exact
content types, bounded bodies, page counts and total bytes, plus request and
operation deadlines are enforced. The fetched descriptor must exactly match
the registered proof, and every descriptor and feed signature, stable subject
binding, sequence, expiry, hash link, snapshot, and tombstone is verified
before publication.

Each Indexer owns an isolated PostgreSQL projection protected by tenant RLS.
Stable subject ID equality is ranked first; bounded PostgreSQL full-text and
trigram matching provide discovery without an external search dependency.
Indexed feed entries retain exact bytes and hashes, and a same-sequence
conflict is rejected transactionally. A database-backed per-Indexer rate
bucket prevents callers from bypassing admission by supplying another ID.

Moderation remains an independent signed fact and does not rewrite publisher
proofs. OpenSearch, OHTTP relay privacy, deployment tooling, Server Agent, and
Job orchestration are outside PD3.

## Consequences

Operators can run multiple independent nodes and users can register the same
subject with several of them without a central directory. A hostile or broken
origin fails closed and changes only that operator's durable registration.
PostgreSQL search is intentionally the first validation implementation; a
future search backend can consume the verified projection without changing
the signed registration contract.

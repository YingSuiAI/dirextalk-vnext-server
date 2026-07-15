# ADR-0014: Publisher-signed public feed V1

- Status: Accepted for PD2
- Date: 2026-07-15
- Owners: `dtx-public-feed`, `dtx-public-feed-node`, and `protocol/public-feed/v1`

## Context

PD1 freezes self-certifying Channel and Agent descriptors and derives one
well-known subject path from the signed V1.2 DNS origin. PD2 needs a portable
public timeline that independent relays and clients can verify and replay
without trusting a database, while remaining structurally separate from
private MLS and mailbox timelines.

## Decision

Public Feed V1 is frozen in baseline V24. Channel and Agent use the same exact
canonical CBOR codec. Every event binds the `dtxc1` or `dtxa1` subject, PD1
publisher identity and genesis key, positive contiguous sequence, previous
complete-entry digest, publication time, typed payload, and Ed25519 signature.
The signature and entry hash domains are:

```text
unsigned_digest = SHA-256(
  "dirextalk.public-feed-event.v1\0" || canonical_cbor(fields 1..9)
)
signature_input = "dirextalk.public-feed-signature.v1\0" || unsigned_digest
entry_hash = SHA-256(
  "dirextalk.public-feed-entry.v1\0" || canonical_cbor(fields 1..10)
)
```

V1 post attachments contain only a public SHA-256 digest, bounded media type,
and byte size. They cannot encode bytes, URLs, capabilities, file keys, MLS
state, or mailbox tokens. A feed tombstone is empty and permanent. Moderation
labels are independent signed statements stored in `directory.moderation_labels`;
they never consume a publisher feed sequence or rewrite signed entries.

The opaque page cursor is canonical CBOR encoded as unpadded base64url and
binds subject, last returned sequence, snapshot sequence, and snapshot head
hash. The relay verifies the advertised snapshot entry before reading the
next page, so concurrent appends do not change an in-progress traversal.

`directory.public_subjects` holds descriptor and feed CAS heads;
`descriptor_versions` and `feed_entries` retain exact immutable bytes.
PostgreSQL serializes a subject append, enforces unique subject/sequence and
entry hashes, and updates the head only from the expected sequence/hash.
Exact byte replay returns the original success outcome; equivocation, gaps,
expired/revoked descriptors, and post-tombstone resurrection are rejected.
All four PD2 relations use tenant policy and `FORCE ROW LEVEL SECURITY`.

The production node exposes the fixed PD1 subject path for exact descriptor
GET/PUT and its `/feed` child for page GET and signed-event POST. Writes require
the exact media type, no content encoding, a bounded body, and a deadline no
more than 30 seconds in the future. Public GET responses use short explicit
revalidation cache policy; write and error responses are `no-store`.

## Consequences

Relays can lose responses and safely receive the same signed append again;
clients converge on exact bytes and stable snapshot pages. Public content is
intentionally correlatable and is never represented as private E2EE content.
PD3 owns DNS resolution, SSRF/rebinding/redirect policy, remote fetching,
registration proofs, Indexer search, rate limits, and partial registration;
this node performs no outbound network request and adds no deployer, Server
Agent, or Job behavior.

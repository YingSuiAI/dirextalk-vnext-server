# ADR-0017: Origin-hosted Public Discussion V1

- Status: Accepted for PD7/PD8a first validation
- Date: 2026-07-19
- Owners: `dtx-public-discussion`, `dtx-public-feed-node`, and
  `protocol/public-discussion/v1`

## Context

Baseline V24 froze exact publisher-signed Public Feed V1 posts but did not
define continued-post response-loss recovery or discussion below a Channel
post. Public comments and reactions must remain independently verifiable,
must not create follower state, and must not weaken the private MLS boundary.
An origin also needs to reject a revoked or substituted actor device without
accepting an unsigned identity-origin header.

## Decision

Baseline V36 leaves every V24 feed byte unchanged. Feed sequence 1 retains the
legacy HTTP append path. A sequence-2-or-later append requires one visible
ASCII `Idempotency-Key` of 16 through 128 bytes; UUIDv7 is recommended. The key
is neither signed nor echoed. The origin stores only its domain-separated hash,
the exact request digest, and the exact response. Receipt lookup occurs before
current-head validation so response-loss replay converges.

Each Channel has one owner-root-signed discussion policy. V1 exposes only
`verified_identity`: revision 1 has no prior digest and every later revision
CAS-binds the exact previous policy digest. The fixed routes are:

```text
GET|PUT /.well-known/dirextalk/public/v1/{channel_id}/discussion-policy
GET|POST /.well-known/dirextalk/public/v1/{channel_id}/posts/{post_hash}/comments
GET|POST /.well-known/dirextalk/public/v1/{channel_id}/posts/{post_hash}/reactions
```

`post_hash` is the 64-character lower-case hash of an immutable Public Feed V1
post entry. A comment binds a UUIDv7 event, Channel, post, optional parent root
comment entry, bounded UTF-8 body, actor identity/device, canonical signed
identity origin, current policy fence, creation time, and device signature.
Only root comments and one-level replies are valid. The append-only thread
receipt binds sequence, prior thread hash, current thread-entry hash, and the
exact signed comment. Comment pages use a snapshot-bound canonical-CBOR cursor
encoded as unpadded base64url. A root read revalidates after 10 seconds; an
immutable cursor page after 300 seconds. An existing post without a comment
thread returns 404 and clients render it as empty.

A reaction is actor-state CAS, not a count increment. V1 supports only `like`
against a post or exact comment-entry hash. Revision 1 has no previous digest;
later revisions bind the exact prior actor event digest. `active=false` is the
durable unlike state. Projection bytes contain one exact latest signed event
per actor sorted by identity, retain inactive states, and hash the length-bound
exact event sequence. A valid target with no actor state returns a canonical
empty 200 projection; an unknown post or comment target returns 404.

Every mutation requires the exact media type, no content encoding, a deadline,
and its own idempotency receipt. Exact receipt replay precedes current actor
authorization. A new comment or reaction resolves the complete current signed
identity log from the origin inside the signed event and accepts only the exact
active device key. Production HTTPS resolution disables proxies and redirects,
resolves once, rejects IP literals and every non-public address, bounds the
answer set, and pins the selected public addresses. Plain HTTP is available
only through an explicit development allowlist. Clients independently verify
the signed event and identity-log chain.

The database stores policy versions, immutable comment and reaction histories,
thread and actor-state heads, event-ID uniqueness, bounded per-actor rate
limits, and opaque exact receipts. All ten V36 relations use tenant policy and
`FORCE ROW LEVEL SECURITY`; immutable histories reject update/delete and the
runtime role receives no delete privilege. No subscriber, follower, unread,
private-MLS plaintext, credential, or moderation state is represented.

Public policy, root comment, and reaction reads use strong ETags with
`must-revalidate`; any credential-bearing read is `no-store`. Mutation and
error responses are always `no-store`.

## Compatibility overlays in V36

The native private group-reaction V8 golden vector is mirrored byte-for-byte.
It exists only inside MLS ciphertext. V8 senders require every active roster
device to authenticate reserved V1 text of the exact form
`dirextalk.private-event-capability.v1;kind=8;version=8;epoch=<positive canonical decimal>;head=<64 lower-case non-zero hex>`
for the exact current epoch/head; any roster, epoch, or head change invalidates
the evidence. Servers never decode or persist this plaintext.

V36 also documents the already-deployed group-query proof without rewriting
V32. `DTX-Group-Query-Proof` is the single canonical header. Binding action 1
authorizes pending join-request discovery only; action 2 authorizes the MLS
commit feed only. Cross-action replay fails closed. V32's inaccurate
`DTX-MLS-Commit-Proof` OpenAPI name remains frozen historical text and does not
define a second accepted header.

## Consequences

Clients can continue a public Channel timeline, render bounded discussion, and
recover lost mutation responses without trusting mutable server projections.
Origins can moderate through policy evolution later without changing V1 event
bytes. Follower graphs, counts-only reaction APIs, deeper reply trees, deletion,
editing, and generalized reaction kinds remain outside this first validation.

# ADR-0011: Self-certifying public Channel and Agent descriptors

- Status: Accepted for PD1
- Date: 2026-07-14
- Owners: `dtx-domain`, `dtx-public-descriptor`, and `protocol/public-descriptor/v1`

## Context

Public Channels and Agent definitions need a portable discovery record that a
relay, Indexer, or client can verify without trusting an HTTP origin, tenant
record, Matrix room, alias, or database UUID. The record must retain a stable
subject across feed-endpoint migration, reject stale/forked descriptor heads,
and expose only intentional public metadata.

PD1 is a protocol core. It does not implement public-feed transport, HTTP
registration, PostgreSQL storage, full-text search, client UI, private MLS
content, mailbox tokens, or Agent installation. Those boundaries remain PD2,
PD3, PD4, and PD6.

## Decision

### Subject and publisher authority

The existing ADR-0003 formulas remain the only V1 stable subject derivation:

```text
channel_id = dtxc1 + base32lower(
  SHA-256("dirextalk.channel.v1\0" || subject_genesis_ed25519_public_key)
)

agent_id = dtxa1 + base32lower(
  SHA-256("dirextalk.agent.v1\0" || subject_genesis_ed25519_public_key)
)
```

The exact descriptor contains both the stable Channel/Agent ID and its
canonical subject genesis signing key; the verifier recomputes the ID and
rejects a type-prefix mismatch. An alias, local/remote feed URL, Matrix room
ID, internal `AgentDefinition`/installation UUID, tenant ID, or email token is
never a public descriptor ID.

The descriptor also contains a self-certifying `publisher_identity_id` and the
identity genesis signing key from which it derives. V1 deliberately requires
that publisher key to be byte-equal to the subject genesis signing key, and
the same key strictly signs the descriptor. This avoids an authority gap in
which an arbitrary publisher could establish a new head for a publicly known
subject key. The three domain-separated IDs may be different because their ID
hash domains differ, even though the one V1 authority key is the same.

Delegated publishers, rotated identity roots, and organization multi-signature
control are not silently accepted by this rule. They require a new versioned
descriptor wire with an identity-log proof or explicit co-signature that binds
the delegation to the exact subject, sequence, predecessor, and expiry.

### Exact wire and signatures

Public descriptor V1 is a disjoint, frozen contract under baseline v7. It
uses deterministic CBOR from ADR-0003 and closes all typed maps. The unsigned
fields are, in numeric CBOR-key order:

1. exact writer/minimum-reader version `1.0`;
2. subject kind (`1 = Channel`, `2 = Agent`);
3. stable subject ID;
4. subject genesis signing key;
5. publisher identity ID;
6. publisher identity genesis signing key;
7. positive contiguous sequence;
8. predecessor complete-descriptor hash, or null only at genesis;
9. issued timestamp;
10. expiry timestamp;
11. payload kind (`1 = Channel`, `2 = Agent`, `3 = tombstone`);
12. exact typed payload.

Key 13 holds the Ed25519 signature. The domains, including trailing NUL, are:

```text
unsigned_digest = SHA-256(
  "dirextalk.public-descriptor.v1\0" || deterministic_cbor(fields 1..12)
)
signature_input =
  "dirextalk.public-descriptor-signature.v1\0" || unsigned_digest
entry_hash = SHA-256(
  "dirextalk.public-descriptor-entry.v1\0" || deterministic_cbor(fields 1..13)
)
```

Channel payloads contain a literal bounded HTTPS feed endpoint and a capability
digest. Agent payloads add a manifest/provenance digest. Endpoint strings are
ASCII literal authority strings with no userinfo, query, fragment, control
character, or backslash; the protocol does not guess a URL normalization.
Tombstones carry an empty payload and use `expires_at == issued_at`, so live
URLs or artifact references cannot survive in a revocation entry.

### Reduction and time

`DescriptorHeadV1` admits only an exact next descriptor for the original
subject and publisher binding. It keeps full signed-entry hashes and
per-sequence hashes. An exact known hash is replay; a different record at an
accepted sequence, a stale sequence, or an expected sequence with a different
parent is equivocation; a future sequence is a gap. No state changes on an
error. Storage later must use a unique `(stable_id, sequence)`, unique entry
hash, exact canonical bytes, and compare-and-swap on `(head_sequence,
head_hash)` in one transaction.

The caller provides a trusted `now`. A live descriptor is usable only while
`issued_at <= now < expires_at`; expired or future live candidates are not
admitted. A valid tombstone is permanent: it removes the active head and
prevents all later descriptors from reactivating the same subject. The reducer
retains expired/tombstoned exact bytes for audit and replay detection but never
returns them as an active descriptor.

## Alternatives considered

- Trusting the Indexer/relay to select a current descriptor was rejected: an
  untrusted endpoint could return an old or forked record.
- Using an internal AgentDefinition UUID or a Matrix room ID was rejected:
  those values change with a deployment or gateway and are not a portable
  self-certifying public subject.
- Letting any self-certifying publisher sign a descriptor for a separate known
  subject key was rejected: it has no proof that the publisher controls the
  subject and permits first-head squatting.
- Adding HTTP, a search database, or a generic package/manifest execution
  layer here was rejected: they would mix PD2/PD3/PD6 side effects into a
  deterministic verification boundary.

## Consequences

V1 makes public discovery records independently verifiable and resistant to
replay, stale head replacement, and tombstone resurrection. It intentionally
does not hide that published IDs, endpoints, timestamps, capability digests,
and manifest digests are correlatable public metadata. No private key,
credential, mailbox token, decrypted content, or cloud secret is representable
in its schema or vectors.

The V1 single-key authority rule keeps first deployment small and secure but
requires a versioned migration before an identity-log root rotation or a
delegated organization publisher can update a descriptor. PD2 must sign public
feed events under the verified descriptor authority; PD3/PD4 must revalidate
the exact descriptor chain rather than treating Indexer responses as truth.
